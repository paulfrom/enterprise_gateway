"""Scoped PostgreSQL dictionary drafts and immutable published snapshots.

DDL is exported for infrastructure deployment. Service methods perform ordinary
DML only and never create tables, schemas, users, policies or grants.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import json
import re
import threading
from typing import Annotated, Callable
import uuid

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
from pydantic import BaseModel, ConfigDict, Field, field_validator

from detection.dictionary import CompiledDictionary, DictionaryEntry, compile_dictionary, compute_dictionary_hash
from knowledge.database_security import assert_no_history_access, assert_restricted_application_role
from masking.mapping import reject_reserved_literals

TABLES = ('redaction_dictionary_state', 'redaction_dictionary_entries',
          'redaction_dictionary_versions', 'redaction_dictionary_changes')
MAX_ENTRIES = 20000

SCHEMA_SQL = """
CREATE TABLE redaction_dictionary_versions (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL, revision BIGINT NOT NULL CHECK (revision > 0),
 dictionary_id TEXT NOT NULL CHECK (btrim(dictionary_id) <> ''),
 sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 entries JSONB NOT NULL CHECK (jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) BETWEEN 1 AND 20000),
 created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, domain, revision)
);
CREATE TABLE redaction_dictionary_state (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 dictionary_id TEXT NOT NULL CHECK (btrim(dictionary_id) <> ''),
 revision BIGINT NOT NULL CHECK (revision > 0),
 published_revision BIGINT NOT NULL CHECK (published_revision > 0 AND published_revision <= revision),
 updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, domain),
 FOREIGN KEY (tenant_id, domain, published_revision) REFERENCES redaction_dictionary_versions(tenant_id, domain, revision)
);
CREATE TABLE redaction_dictionary_entries (
 entry_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 text TEXT NOT NULL CHECK (btrim(text) <> '' AND char_length(text) <= 512),
 entity_type TEXT NOT NULL CHECK (entity_type ~ '^[A-Z][A-Z0-9_]{0,31}$'),
 enabled BOOLEAN NOT NULL DEFAULT true,
 updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, domain, text),
 FOREIGN KEY (tenant_id, domain) REFERENCES redaction_dictionary_state(tenant_id, domain)
);
CREATE INDEX redaction_dictionary_entries_scope ON redaction_dictionary_entries(tenant_id, domain, text, entry_id);
CREATE TABLE redaction_dictionary_changes (
 change_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK (revision > 0),
 action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'publish')),
 entry_id UUID, actor_id TEXT NOT NULL CHECK (btrim(actor_id) <> ''),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id, domain) REFERENCES redaction_dictionary_state(tenant_id, domain)
);
CREATE FUNCTION enforce_dictionary_version_immutable() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog AS $dictionary_immutable$
 BEGIN
  RAISE EXCEPTION 'Published dictionary versions are immutable';
 END;
 $dictionary_immutable$;
CREATE TRIGGER dictionary_version_immutable BEFORE UPDATE OR DELETE ON redaction_dictionary_versions
 FOR EACH ROW EXECUTE FUNCTION enforce_dictionary_version_immutable();
"""
RLS_SQL = '\n'.join(
    f"""ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {table} FORCE ROW LEVEL SECURITY;
CREATE POLICY dictionary_admin_scope ON {table} FOR ALL USING (
 current_user = __ADMIN_ROLE__
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
) WITH CHECK (
 current_user = __ADMIN_ROLE__
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
);""" for table in TABLES
)


class DictionaryError(Exception):
    def __init__(self, code: str = 'DICTIONARY_UNAVAILABLE'):
        self.code = code
        super().__init__(code)


class DictionaryEdit(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: Annotated[int, Field(ge=1)]
    text: Annotated[str, Field(min_length=1, max_length=512)]
    entity_type: Annotated[str, Field(pattern=r'^[A-Z][A-Z0-9_]{0,31}$')]
    enabled: bool = True

    @field_validator('text')
    @classmethod
    def valid_text(cls, text):
        if not text.strip():
            raise ValueError('blank dictionary entry')
        reject_reserved_literals(text)
        return text


class DictionaryRevisionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_revision: Annotated[int, Field(ge=1)]


class DictionaryEntryView(BaseModel):
    entry_id: str
    text: str
    entity_type: str
    enabled: bool
    updated_at: datetime


class DictionaryState(BaseModel):
    dictionary_id: str
    revision: int
    published_revision: int
    published_sha256: str
    published_entries: int
    updated_at: datetime


class DictionaryPage(DictionaryState):
    items: list[DictionaryEntryView]
    total: int
    offset: int
    limit: int


class DictionaryVersion(BaseModel):
    revision: int
    sha256: str
    entries: int
    created_at: datetime
    created_by: str


class DictionaryVersions(BaseModel):
    items: list[DictionaryVersion]


def snapshot_payload(dictionary_id: str, revision: int, domain: str, entries) -> dict:
    items = tuple(DictionaryEntry.model_validate(entry) for entry in entries)
    version = f'db-{revision}'
    return {'dictionary_id': dictionary_id, 'version': version, 'domain': domain,
            'entries': [entry.model_dump() for entry in items],
            'sha256': compute_dictionary_hash(dictionary_id, version, domain, items)}


class PostgresDictionaryStore:
    def __init__(self, connection_uri: str, *, tenant_id: str, domain: str):
        if not tenant_id or not domain:
            raise DictionaryError('DICTIONARY_SCOPE_REJECTED')
        self.connection_uri = connection_uri
        self.tenant_id, self.domain = tenant_id, domain
        self.scope = f'{tenant_id}/{domain}'
        self._slots = threading.BoundedSemaphore(2)

    @contextmanager
    def transaction(self, *, verify: bool = False):
        if not self._slots.acquire(timeout=5):
            raise DictionaryError()
        try:
            with psycopg.connect(self.connection_uri, connect_timeout=5) as connection:
                assert_restricted_application_role(connection)
                assert_no_history_access(connection)
                connection.execute("SELECT set_config('statement_timeout','5000',true)")
                connection.execute("SELECT set_config('lock_timeout','5000',true)")
                connection.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant_id,))
                connection.execute("SELECT set_config('app.domain',%s,true)", (self.domain,))
                connection.execute("SELECT set_config('app.admin_context','true',true)")
                if verify:
                    self.verify_schema(connection)
                yield connection
        except DictionaryError:
            raise
        except Exception:
            raise DictionaryError() from None
        finally:
            self._slots.release()

    @staticmethod
    def verify_schema(connection):
        rows = connection.execute(
            "SELECT relname,relrowsecurity,relforcerowsecurity,pg_has_role(current_user,relowner,'MEMBER'),"
            "has_table_privilege(current_user,oid,'SELECT') AND has_table_privilege(current_user,oid,'INSERT') "
            "AND has_table_privilege(current_user,oid,'UPDATE') AND has_table_privilege(current_user,oid,'DELETE') "
            "FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)",
            (list(TABLES),)).fetchall()
        if {row[0] for row in rows} != set(TABLES) or any(
                not enabled or not forced or owner or not grants for _, enabled, forced, owner, grants in rows):
            raise DictionaryError()
        policies = connection.execute(
            "SELECT tablename,policyname,qual,with_check,cmd,roles FROM pg_policies "
            "WHERE schemaname=current_schema() AND tablename=ANY(%s)", (list(TABLES),)).fetchall()
        role = sql.Literal(connection.info.user).as_string()
        expected = (
            f"current_user={role} AND tenant_id=current_setting('app.tenant',true) "
            "AND domain=current_setting('app.domain',true) "
            "AND current_setting('app.admin_context',true)='true'")
        normalize = lambda expression: re.sub(r'[()\s]', '', re.sub(r'::(?:text|name)', '', expression or '')).lower()
        if {row[0] for row in policies} != set(TABLES) or len(policies) != len(TABLES) or any(
                name != 'dictionary_admin_scope' or command != 'ALL' or roles != ['public']
                or normalize(qual) != normalize(expected) or normalize(check) != normalize(expected)
                for _, name, qual, check, command, roles in policies):
            raise DictionaryError()
        trigger = connection.execute(
            "SELECT t.tgenabled,t.tgtype,p.prosrc,p.prosecdef,p.proconfig FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid "
            "WHERE t.tgrelid='redaction_dictionary_versions'::regclass "
            "AND t.tgname='dictionary_version_immutable' AND p.proname='enforce_dictionary_version_immutable' "
            "AND NOT t.tgisinternal").fetchall()
        body = "BEGIN RAISE EXCEPTION 'Published dictionary versions are immutable'; END;"
        if (len(trigger) != 1 or trigger[0][:2] != ('O', 27)
                or re.sub(r'\s+', '', trigger[0][2]) != re.sub(r'\s+', '', body)
                or trigger[0][3] or trigger[0][4] != ['search_path=pg_catalog']):
            raise DictionaryError()

    def check_ready(self):
        with self.transaction(verify=True):
            pass

    def bootstrap(self, seed: CompiledDictionary | None = None) -> CompiledDictionary:
        with self.transaction(verify=True) as connection:
            # Serialize first initialization across application processes.
            connection.execute('SELECT pg_advisory_xact_lock(hashtextextended(%s,0))',
                               (json.dumps([self.tenant_id, self.domain]),))
            existing = self._state(connection, required=False)
            if existing is not None:
                return self._active(connection, existing[2])
            if callable(seed):
                seed = seed()
            if seed is None or seed.domain != self.domain or len(seed.entries) > MAX_ENTRIES:
                raise DictionaryError('DICTIONARY_INITIAL_SEED_REQUIRED')
            entries = [entry.model_dump() for entry in seed.entries]
            for entry in entries:
                DictionaryEdit(expected_revision=1, **entry)
            payload = snapshot_payload(seed.dictionary_id, 1, self.domain, entries)
            compiled = compile_dictionary(payload)
            self._insert_version(connection, payload, 1, 'initial-import')
            connection.execute(
                'INSERT INTO redaction_dictionary_state(tenant_id,domain,dictionary_id,revision,published_revision,updated_by) '
                'VALUES (%s,%s,%s,1,1,%s)', (self.tenant_id, self.domain, seed.dictionary_id, 'initial-import'))
            for entry in entries:
                connection.execute(
                    'INSERT INTO redaction_dictionary_entries(entry_id,tenant_id,domain,text,entity_type,enabled,updated_by) '
                    'VALUES (%s,%s,%s,%s,%s,true,%s)',
                    (uuid.uuid4(), self.tenant_id, self.domain, entry['text'], entry['entity_type'], 'initial-import'))
            return compiled

    def _state(self, connection, *, lock=False, required=True):
        row = connection.execute(
            'SELECT dictionary_id,revision,published_revision,updated_at FROM redaction_dictionary_state '
            'WHERE tenant_id=%s AND domain=%s' + (' FOR UPDATE' if lock else ''),
            (self.tenant_id, self.domain)).fetchone()
        if row is None and required:
            raise DictionaryError()
        return row

    def _active(self, connection, revision):
        row = connection.execute(
            'SELECT dictionary_id,sha256,entries FROM redaction_dictionary_versions '
            'WHERE tenant_id=%s AND domain=%s AND revision=%s',
            (self.tenant_id, self.domain, revision)).fetchone()
        if row is None:
            raise DictionaryError()
        payload = snapshot_payload(row[0], revision, self.domain, row[2])
        if payload['sha256'] != row[1]:
            raise DictionaryError()
        return compile_dictionary(payload)

    def active(self, known_revision: int | None = None):
        with self.transaction() as connection:
            state = self._state(connection)
            return state[2], None if state[2] == known_revision else self._active(connection, state[2])

    def _summary(self, connection, state) -> dict:
        row = connection.execute(
            'SELECT sha256,jsonb_array_length(entries) FROM redaction_dictionary_versions '
            'WHERE tenant_id=%s AND domain=%s AND revision=%s',
            (self.tenant_id, self.domain, state[2])).fetchone()
        if row is None:
            raise DictionaryError()
        return dict(dictionary_id=state[0], revision=state[1], published_revision=state[2],
                    updated_at=state[3], published_sha256=row[0], published_entries=row[1])

    def list_entries(self, *, query='', entity_type=None, enabled=None, offset=0, limit=50):
        with self.transaction() as connection:
            state = self._state(connection, lock=True)
            where = 'tenant_id=%s AND domain=%s'
            args = [self.tenant_id, self.domain]
            if query:
                where += ' AND strpos(text,%s)>0'
                args.append(query)
            if entity_type:
                where += ' AND entity_type=%s'
                args.append(entity_type)
            if enabled is not None:
                where += ' AND enabled=%s'
                args.append(enabled)
            total = connection.execute('SELECT count(*) FROM redaction_dictionary_entries WHERE ' + where, args).fetchone()[0]
            rows = connection.execute(
                'SELECT entry_id,text,entity_type,enabled,updated_at FROM redaction_dictionary_entries WHERE '
                + where + ' ORDER BY text COLLATE "C",entry_id LIMIT %s OFFSET %s', [*args, limit, offset]).fetchall()
            return DictionaryPage(**self._summary(connection, state), total=total, offset=offset, limit=limit,
                                  items=[DictionaryEntryView(entry_id=str(row[0]), text=row[1],
                                  entity_type=row[2], enabled=row[3], updated_at=row[4]) for row in rows])

    def _check_revision(self, state, expected):
        if state[1] != expected:
            raise DictionaryError('DICTIONARY_REVISION_CONFLICT')

    def _change(self, connection, revision, actor, action, entry_id=None):
        connection.execute(
            'UPDATE redaction_dictionary_state SET revision=%s,updated_by=%s,updated_at=now() '
            'WHERE tenant_id=%s AND domain=%s', (revision, actor, self.tenant_id, self.domain))
        connection.execute(
            'INSERT INTO redaction_dictionary_changes(change_id,tenant_id,domain,revision,action,entry_id,actor_id) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s)',
            (uuid.uuid4(), self.tenant_id, self.domain, revision, action, entry_id, actor))

    def edit(self, edit: DictionaryEdit, actor: str, entry_id: str | None = None):
        with self.transaction() as connection:
            state = self._state(connection, lock=True)
            self._check_revision(state, edit.expected_revision)
            identity = uuid.UUID(entry_id) if entry_id is not None else uuid.uuid4()
            conflict = connection.execute(
                'SELECT entry_id FROM redaction_dictionary_entries WHERE tenant_id=%s AND domain=%s AND text=%s',
                (self.tenant_id, self.domain, edit.text)).fetchone()
            if conflict and conflict[0] != identity:
                raise DictionaryError('DICTIONARY_ENTRY_CONFLICT')
            if entry_id is None:
                count = connection.execute(
                    'SELECT count(*) FROM redaction_dictionary_entries WHERE tenant_id=%s AND domain=%s',
                    (self.tenant_id, self.domain)).fetchone()[0]
                if count >= MAX_ENTRIES:
                    raise DictionaryError('DICTIONARY_LIMIT_EXCEEDED')
                connection.execute(
                    'INSERT INTO redaction_dictionary_entries(entry_id,tenant_id,domain,text,entity_type,enabled,updated_by) '
                    'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                    (identity, self.tenant_id, self.domain, edit.text, edit.entity_type, edit.enabled, actor))
            else:
                row = connection.execute(
                    'UPDATE redaction_dictionary_entries SET text=%s,entity_type=%s,enabled=%s,updated_by=%s,updated_at=now() '
                    'WHERE entry_id=%s AND tenant_id=%s AND domain=%s RETURNING entry_id',
                    (edit.text, edit.entity_type, edit.enabled, actor, identity, self.tenant_id, self.domain)).fetchone()
                if row is None:
                    raise DictionaryError('DICTIONARY_ENTRY_NOT_FOUND')
            self._change(connection, state[1] + 1, actor, 'create' if entry_id is None else 'update', identity)
            return DictionaryState(**self._summary(connection, self._state(connection)))

    def delete(self, entry_id: str, expected_revision: int, actor: str):
        with self.transaction() as connection:
            state = self._state(connection, lock=True)
            self._check_revision(state, expected_revision)
            identity = uuid.UUID(entry_id)
            row = connection.execute(
                'DELETE FROM redaction_dictionary_entries WHERE entry_id=%s AND tenant_id=%s AND domain=%s RETURNING entry_id',
                (identity, self.tenant_id, self.domain)).fetchone()
            if row is None:
                raise DictionaryError('DICTIONARY_ENTRY_NOT_FOUND')
            self._change(connection, state[1] + 1, actor, 'delete', identity)
            return DictionaryState(**self._summary(connection, self._state(connection)))

    def _insert_version(self, connection, payload, revision, actor):
        connection.execute(
            'INSERT INTO redaction_dictionary_versions(tenant_id,domain,revision,dictionary_id,sha256,entries,created_by) '
            'VALUES (%s,%s,%s,%s,%s,%s,%s)',
            (self.tenant_id, self.domain, revision, payload['dictionary_id'], payload['sha256'], Jsonb(payload['entries']), actor))

    def publish(self, expected_revision: int, actor: str, prepare: Callable):
        with self.transaction() as connection:
            state = self._state(connection, lock=True)
            self._check_revision(state, expected_revision)
            if state[1] == state[2]:
                return DictionaryState(**self._summary(connection, state)), None
            rows = connection.execute(
                'SELECT text,entity_type FROM redaction_dictionary_entries '
                'WHERE tenant_id=%s AND domain=%s AND enabled ORDER BY text COLLATE "C"',
                (self.tenant_id, self.domain)).fetchall()
            if not rows:
                raise DictionaryError('DICTIONARY_EMPTY_PUBLICATION')
            payload = snapshot_payload(state[0], state[1], self.domain,
                                       [{'text': text, 'entity_type': entity_type} for text, entity_type in rows])
            compiled = compile_dictionary(payload)
            prepared = prepare(compiled)
            self._insert_version(connection, payload, state[1], actor)
            connection.execute(
                'UPDATE redaction_dictionary_state SET published_revision=%s WHERE tenant_id=%s AND domain=%s',
                (state[1], self.tenant_id, self.domain))
            self._change(connection, state[1], actor, 'publish')
            return DictionaryState(**self._summary(connection, self._state(connection))), prepared

    def versions(self):
        with self.transaction() as connection:
            rows = connection.execute(
                'SELECT revision,sha256,jsonb_array_length(entries),created_at,created_by '
                'FROM redaction_dictionary_versions WHERE tenant_id=%s AND domain=%s '
                'ORDER BY revision DESC LIMIT 50', (self.tenant_id, self.domain)).fetchall()
            return DictionaryVersions(items=[DictionaryVersion(revision=row[0], sha256=row[1],
                entries=row[2], created_at=row[3], created_by=row[4]) for row in rows])
