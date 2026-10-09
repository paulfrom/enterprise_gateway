"""Synchronous encrypted snapshots with mandatory audit before plaintext release."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from infra.durable_write import durable_commit
from infra.envelope_crypto import KmsProvider, decrypt_record, encrypt_record, parse_record, serialize_record
from request_history.database import assert_history_connection
from request_history.models import (
    ERROR_CODES, FINAL_STATUSES, MEDIA_TYPES, PROTOCOLS, PURPOSE, STAGES, STAGE_STATES, STATUSES,
    HistoryNotFound, HistoryUnavailable,
)

_METADATA_COLUMNS = 'request_id,protocol,model,created_at,expires_at,status,error_code'


def _canonical_id(value) -> str:
    if not isinstance(value, (str, UUID)):
        raise HistoryNotFound()
    try:
        parsed = UUID(str(value))
        if str(parsed) != str(value):
            raise ValueError()
        return str(parsed)
    except (ValueError, AttributeError):
        pass
    raise HistoryNotFound()


def _metadata(row) -> dict:
    if row[1] not in PROTOCOLS or row[5] not in STATUSES or row[6] is not None and row[6] not in ERROR_CODES:
        raise HistoryUnavailable()
    return {'request_id': str(row[0]), 'protocol': row[1], 'model': row[2],
            'created_at': row[3].isoformat(), 'expires_at': row[4].isoformat(),
            'status': row[5], 'error_code': row[6]}


class PostgresHistoryStore:
    """Bound service tenant/domain, never supplier credentials or employee identity."""

    def __init__(self, connection_uri: str, kms: KmsProvider, *, tenant_id: str, domain: str,
                 retention_days: int, bucket: str, audit_directory: str | Path,
                 max_stage_bytes: int = 16777216) -> None:
        if (not isinstance(connection_uri, str) or not connection_uri.strip()
                or any(not isinstance(value, str) or not value.strip() or len(value)>256
                       for value in (tenant_id, domain, bucket))
                or type(retention_days) is not int or retention_days<=0
                or type(max_stage_bytes) is not int or max_stage_bytes<=0
                or not isinstance(kms, KmsProvider)):
            raise HistoryUnavailable()
        converted = None
        try:
            converted = (make_conninfo(connection_uri, connect_timeout=10),Path(audit_directory).absolute())
        except Exception:
            pass
        if converted is None:
            raise HistoryUnavailable()
        self._connection_uri,self._audit_directory = converted
        self.kms = kms
        self.tenant_id, self.domain, self.bucket = tenant_id, domain, bucket
        self.retention_days, self.max_stage_bytes = retention_days, max_stage_bytes
        self._expected_schema = self._expected_role = None

    @contextmanager
    def _connection(self, mode: str):
        with psycopg.connect(self._connection_uri) as conn:
            schema, role = assert_history_connection(
                conn, expected_schema=self._expected_schema, expected_role=self._expected_role,
            )
            if self._expected_schema is None:
                self._expected_schema, self._expected_role = schema, role
            conn.execute("SELECT set_config('request_history.tenant',%s,true),"
                         "set_config('request_history.domain',%s,true),"
                         "set_config('request_history.mode',%s,true)",
                         (self.tenant_id, self.domain, mode))
            # Explicit namespace qualification makes even a configured later search_path harmless.
            conn.execute(sql.SQL('SET LOCAL search_path TO {}').format(sql.Identifier(schema)))
            yield conn

    def _check_audit_directory(self) -> None:
        if not self._audit_directory.is_dir() or any(
            path.is_symlink() for path in (self._audit_directory, *self._audit_directory.parents)
        ):
            raise HistoryUnavailable()

    def check_ready(self) -> None:
        try:
            with self._connection('reader') as conn:
                conn.execute('SELECT request_id FROM request_records LIMIT 1').fetchall()
            probe = encrypt_record(self.kms, b'request-history-readiness', domain=self.domain,
                                   bucket=self.bucket, record_id=str(uuid4()), purpose=PURPOSE)
            if decrypt_record(self.kms, probe) != b'request-history-readiness':
                raise HistoryUnavailable()
            self.audit_access(operation='readiness', outcome='success')
            return
        except Exception:
            pass
        raise HistoryUnavailable()

    def has_records(self) -> bool:
        """Metadata-only presence check, including expired records, before explicit KEK provisioning."""
        try:
            with self._connection('reader') as conn:
                if conn.execute('SELECT EXISTS(SELECT 1 FROM request_records)').fetchone()[0]:
                    return True
                conn.execute("SELECT set_config('request_history.mode','purger',true)")
                return bool(conn.execute('SELECT EXISTS(SELECT 1 FROM request_records)').fetchone()[0])
        except Exception:
            pass
        raise HistoryUnavailable()

    def _binding(self, request_id: str, stage: str, state: str, media_type: str) -> str:
        return json.dumps([self.tenant_id,self.domain,request_id,stage,state,media_type],
                          ensure_ascii=False, separators=(',', ':'))

    def _encrypt(self, request_id: str, stage: str, body: bytes, state: str, media_type: str) -> bytes:
        return serialize_record(encrypt_record(
            self.kms, body, domain=self.domain, bucket=self.bucket, purpose=PURPOSE,
            record_id=self._binding(request_id,stage,state,media_type),
        ))

    def _decrypt(self, request_id: str, stage: str, envelope, state: str, media_type: str) -> bytes:
        if len(envelope)>4*self.max_stage_bytes+4096:
            raise HistoryUnavailable()
        record = parse_record(bytes(envelope))
        if (record.domain != self.domain or record.bucket != self.bucket or record.purpose != PURPOSE
                or record.record_id != self._binding(request_id,stage,state,media_type)):
            raise HistoryUnavailable()
        result = decrypt_record(self.kms, record)
        if len(result)>self.max_stage_bytes:
            raise HistoryUnavailable()
        return result

    def begin(self, *, protocol: str, model: str, raw_body: bytes) -> HistoryRecorder:
        try:
            if (protocol not in PROTOCOLS or not isinstance(model,str)
                    or not 1<=len(model)<=256 or not isinstance(raw_body,bytes)
                    or len(raw_body)>self.max_stage_bytes):
                raise HistoryUnavailable()
            request_id = str(uuid4())
            envelope = self._encrypt(request_id,'input',raw_body,'complete','application/json')
            with self._connection('writer') as conn:
                conn.execute('INSERT INTO request_records '
                             '(request_id,tenant_id,domain,protocol,model,expires_at,status) '
                             "VALUES (%s,%s,%s,%s,%s,clock_timestamp()+%s*INTERVAL '1 day','processing')",
                             (request_id,self.tenant_id,self.domain,protocol,model,self.retention_days))
                conn.execute('INSERT INTO request_stage_contents '
                             '(tenant_id,domain,request_id,stage,state,media_type,envelope) '
                             "VALUES (%s,%s,%s,'input','complete','application/json',%s)",
                             (self.tenant_id,self.domain,request_id,envelope))
            return HistoryRecorder(self,request_id)
        except Exception:
            pass
        raise HistoryUnavailable()

    def audit_access(self, *, operation: str, request_id=None, outcome: str) -> None:
        try:
            if operation not in {'readiness','list','get','purge','authenticate'} or outcome not in {
                'success','denied','not_found','unavailable','failure','attempted',
            }:
                raise HistoryUnavailable()
            request_id = None if request_id is None else _canonical_id(request_id)
            self._check_audit_directory()
            audit_id = str(uuid4())
            document = json.dumps({'audit_id':audit_id,'operation':operation,'outcome':outcome,
                                   'request_id':request_id,'tenant_id':self.tenant_id,'domain':self.domain,
                                   'created_at':datetime.now(timezone.utc).isoformat()},
                                  ensure_ascii=False,separators=(',',':')).encode('utf-8')
            durable_commit(self._audit_directory,audit_id+'.json',document)
            return
        except Exception:
            pass
        raise HistoryUnavailable()

    def list_requests(self, *, limit=50, cursor=None, query='', status=None) -> dict:
        try:
            if (type(limit) is not int or not 1<=limit<=100 or not isinstance(query,str)
                    or len(query)>256 or status is not None and status not in STATUSES):
                raise HistoryUnavailable()
            params = []
            where = ['expires_at>clock_timestamp()']
            if status is not None:
                where.append('status=%s')
                params.append(status)
            if query:
                where.append("(strpos(lower(model),lower(%s))>0 OR strpos(lower(protocol),lower(%s))>0 "
                             "OR strpos(request_id::text,%s)>0)")
                params.extend([query,query,query])
            if cursor is not None:
                if not isinstance(cursor,str) or len(cursor)>512:
                    raise HistoryUnavailable()
                values = json.loads(base64.urlsafe_b64decode(cursor+'='*(-len(cursor)%4)))
                if not isinstance(values,list) or len(values)!=2:
                    raise HistoryUnavailable()
                created = datetime.fromisoformat(values[0])
                if created.tzinfo is None:
                    raise HistoryUnavailable()
                identifier = _canonical_id(values[1])
                where.append('(created_at,request_id)<(%s,%s)')
                params.extend([created,identifier])
            params.append(limit+1)
            with self._connection('reader') as conn:
                rows = conn.execute('SELECT '+_METADATA_COLUMNS+' FROM request_records WHERE '
                                    +' AND '.join(where)+' ORDER BY created_at DESC,request_id DESC LIMIT %s',params).fetchall()
            items = [_metadata(row) for row in rows[:limit]]
            next_cursor = None
            if len(rows)>limit:
                final = rows[limit-1]
                next_cursor = base64.urlsafe_b64encode(json.dumps(
                    [final[3].isoformat(),str(final[0])],separators=(',',':')).encode()).decode().rstrip('=')
            self.audit_access(operation='list',outcome='success')
            return {'items':items,'next_cursor':next_cursor}
        except Exception:
            pass
        raise HistoryUnavailable()

    def get_request(self, request_id) -> dict:
        try:
            identifier = _canonical_id(request_id)
        except HistoryNotFound:
            self.audit_access(operation='get',outcome='not_found')
            raise HistoryNotFound() from None
        missing = False
        failed = False
        try:
            with self._connection('reader') as conn:
                row = conn.execute('SELECT '+_METADATA_COLUMNS+' FROM request_records '
                                   'WHERE request_id=%s AND expires_at>clock_timestamp()', (identifier,)).fetchone()
                if row is None:
                    missing = True
                else:
                    stages = conn.execute('SELECT stage,state,media_type,envelope FROM request_stage_contents '
                                          'WHERE request_id=%s', (identifier,)).fetchall()
                    by_stage = {}
                    for stage,state,media_type,envelope in stages:
                        body = self._decrypt(identifier,stage,envelope,state,media_type)
                        by_stage[stage] = {'stage':stage,'state':state,'media_type':media_type,
                                           'body':body.decode('utf-8',errors='replace')}
                    result = _metadata(row)
                    result['stages'] = [by_stage.get(stage,{'stage':stage,'state':'not_produced',
                                                          'media_type':None,'body':None}) for stage in STAGES]
                    self.audit_access(operation='get',request_id=identifier,outcome='success')
                    # Use database clock after audit fsync/KMS, not an earlier application timestamp.
                    if not conn.execute('SELECT 1 FROM request_records WHERE request_id=%s '
                                        'AND expires_at>clock_timestamp()', (identifier,)).fetchone():
                        missing = True
            if not missing:
                return result
        except Exception:
            failed = True
        if failed:
            raise HistoryUnavailable()
        self.audit_access(operation='get',request_id=identifier,outcome='not_found')
        raise HistoryNotFound()

    def purge_expired(self) -> int:
        try:
            with self._connection('purger') as conn:
                count = conn.execute('DELETE FROM request_records WHERE expires_at<=clock_timestamp()').rowcount
                # A commit failure must not leave a false deletion-success event.
                # Returned success still requires the transaction to commit.
                self.audit_access(operation='purge',outcome='attempted')
            return count
        except Exception:
            pass
        raise HistoryUnavailable()


class HistoryRecorder:
    """Serial, bounded snapshots; transaction protects multi-stage updates."""

    def __init__(self, store: PostgresHistoryStore, request_id: str) -> None:
        self._store = store
        self.request_id = request_id
        self.max_stage_bytes = store.max_stage_bytes
        self._lock = RLock()

    def write(self, stage: str, body: bytes, *, media_type='application/json', state='complete',
              append=False) -> None:
        self.write_many([{'stage':stage,'body':body,'media_type':media_type,'state':state,'append':append}])

    def write_many(self, updates) -> None:
        with self._lock:
            try:
                if not isinstance(updates,(list,tuple)) or not 1<=len(updates)<=4:
                    raise HistoryUnavailable()
                normalized = []
                for item in updates:
                    if not isinstance(item,dict) or set(item)-{'stage','body','media_type','state','append'}:
                        raise HistoryUnavailable()
                    stage,body = item['stage'],item['body']
                    media_type,state,append = item.get('media_type','application/json'),item.get('state','complete'),item.get('append',False)
                    if (stage not in STAGES or not isinstance(body,bytes) or len(body)>self.max_stage_bytes
                            or media_type not in MEDIA_TYPES or state not in STAGE_STATES or type(append) is not bool):
                        raise HistoryUnavailable()
                    normalized.append((stage,body,media_type,state,append))
                with self._store._connection('writer') as conn:
                    record = conn.execute('SELECT status FROM request_records WHERE request_id=%s FOR UPDATE',
                                          (self.request_id,)).fetchone()
                    if record is None or record[0]!='processing':
                        raise HistoryUnavailable()
                    for stage,body,media_type,state,append in normalized:
                        if append:
                            old = conn.execute('SELECT state,media_type,envelope FROM request_stage_contents '
                                               'WHERE request_id=%s AND stage=%s', (self.request_id,stage)).fetchone()
                            if old is not None:
                                if old[1]!=media_type:
                                    raise HistoryUnavailable()
                                previous = self._store._decrypt(self.request_id,stage,old[2],old[0],old[1])
                                if len(previous)+len(body)>self.max_stage_bytes:
                                    raise HistoryUnavailable()
                                body = previous+body
                        encrypted = self._store._encrypt(self.request_id,stage,body,state,media_type)
                        conn.execute('INSERT INTO request_stage_contents '
                                     '(tenant_id,domain,request_id,stage,state,media_type,envelope) VALUES (%s,%s,%s,%s,%s,%s,%s) '
                                     'ON CONFLICT(request_id,stage) DO UPDATE SET state=EXCLUDED.state,media_type=EXCLUDED.media_type,envelope=EXCLUDED.envelope',
                                     (self._store.tenant_id,self._store.domain,self.request_id,stage,state,media_type,encrypted))
                return
            except Exception:
                pass
            raise HistoryUnavailable()

    def finish(self, status: str, error_code=None) -> None:
        with self._lock:
            try:
                if status not in FINAL_STATUSES or error_code is not None and error_code not in ERROR_CODES:
                    raise HistoryUnavailable()
                with self._store._connection('writer') as conn:
                    existing = conn.execute('SELECT status,error_code FROM request_records WHERE request_id=%s FOR UPDATE',
                                            (self.request_id,)).fetchone()
                    if existing is None:
                        raise HistoryUnavailable()
                    if existing[0]!='processing':
                        if existing != (status,error_code):
                            raise HistoryUnavailable()
                    else:
                        conn.execute('UPDATE request_records SET status=%s,error_code=%s WHERE request_id=%s',
                                     (status,error_code,self.request_id))
                return
            except Exception:
                pass
            raise HistoryUnavailable()
