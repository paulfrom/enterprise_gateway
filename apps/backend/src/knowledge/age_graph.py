"""Apache AGE graph projection manager, sync worker, and governed Cypher query interface.

Architectural Guarantees:
1. PostgreSQL relational tables are the authoritative Single Source of Truth (SSOT).
2. Apache AGE (openCypher) acts strictly as a reconstructed, read-heavy query projection.
3. Outbox transactional events drive asynchronous projection synchronization:
   - KNOWLEDGE_PUBLISHED: MERGE vertices (subject, object) and MERGE claim edge.
   - KNOWLEDGE_REVOKED / KNOWLEDGE_WITHDRAWN: Deactivate claim edges (soft-tombstone is_active=false).
4. Full idempotent rebuild allows dropping and reconstructing the entire AGE graph directly from
   committed publications, claims, and entities in PostgreSQL.
5. Governed Cypher queries enforce strict parameter-based tenant/domain isolation and sanitize
   forbidden write operations (CREATE, MERGE, SET, DELETE, DROP, REMOVE).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any, Mapping, Sequence
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from knowledge.graph_query import compile_governed_cypher
from knowledge.knowledge import KnowledgeError, Predicate, Polarity, Modality

logger = logging.getLogger(__name__)

DEFAULT_GRAPH_NAME = "kg_projection"


def parse_agtype(val: Any) -> Any:
    """Parse raw Apache AGE agtype string into python primitive / dict."""
    if not isinstance(val, str):
        return val
    cleaned = re.sub(r"::(vertex|edge|path)$", "", val.strip())
    try:
        return json.loads(cleaned)
    except Exception:
        return val


def infer_cypher_column_count(cypher: str) -> int:
    """Infer the number of returned columns from an openCypher RETURN clause."""
    in_single = False
    in_double = False
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0

    i = 0
    n = len(cypher)
    return_pos = -1

    while i < n:
        c = cypher[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth = max(0, paren_depth - 1)
            elif c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif c == '{':
                brace_depth += 1
            elif c == '}':
                brace_depth = max(0, brace_depth - 1)
            elif paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                if (
                    cypher[i : i + 6].upper() == "RETURN"
                    and (i == 0 or not cypher[i - 1].isalnum())
                    and (i + 6 == n or not cypher[i + 6].isalnum())
                ):
                    return_pos = i + 6
        i += 1

    if return_pos == -1:
        return 1

    i = return_pos
    in_single = False
    in_double = False
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    commas = 0
    has_content = False

    while i < n:
        c = cypher[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth = max(0, paren_depth - 1)
            elif c == '[':
                bracket_depth += 1
            elif c == ']':
                bracket_depth = max(0, bracket_depth - 1)
            elif c == '{':
                brace_depth += 1
            elif c == '}':
                brace_depth = max(0, brace_depth - 1)
            elif paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                rem = cypher[i:].upper()
                if (
                    rem.startswith("ORDER BY")
                    or rem.startswith("SKIP ")
                    or rem.startswith("LIMIT ")
                    or rem.startswith("UNION")
                ) and (i == 0 or cypher[i - 1].isspace()):
                    break
                if c == ",":
                    commas += 1
                elif not c.isspace():
                    has_content = True
        i += 1

    return max(1, commas + 1 if has_content else 1)


@dataclass(frozen=True)
class GraphNode:
    id: str
    name: str
    type: str
    tenant_id: str
    domain: str
    properties: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    claim_id: str
    source_id: str
    target_id: str
    predicate: str
    polarity: str
    modality: str
    publication_id: str
    valid_until: str
    is_active: bool
    properties: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphQueryResult:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    raw_records: tuple[dict[str, Any], ...]
    execution_time_ms: float


class AgeGraphManager:
    """Controls AGE graph lifecycle, initialization, permissions, and raw Cypher execution."""

    def __init__(self, dsn: str, graph_name: str = DEFAULT_GRAPH_NAME):
        self.dsn = dsn
        self.graph_name = graph_name

    def _prepare_session(self, conn: psycopg.Connection) -> None:
        """Ensure search_path includes ag_catalog and age extension is loaded."""
        with conn.cursor() as cur:
            current_path = cur.execute("SHOW search_path").fetchone()[0]
            if "ag_catalog" not in current_path:
                cur.execute(f"SET search_path = ag_catalog, {current_path}")

    def ensure_graph(self, *, application_role: str | None = None) -> None:
        """Create extension and graph if they do not exist, and grant permissions to application role."""
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("CREATE EXTENSION IF NOT EXISTS age CASCADE")
                cur.execute("SET search_path = ag_catalog, '$user', public")
                exists = cur.execute(
                    "SELECT 1 FROM ag_catalog.ag_graph WHERE name = %s",
                    (self.graph_name,),
                ).fetchone()
                if not exists:
                    cur.execute(sql.SQL("SELECT create_graph(%s)"), (self.graph_name,))
                if application_role:
                    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA ag_catalog TO {}").format(sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT ALL ON ALL TABLES IN SCHEMA ag_catalog TO {}").format(sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA ag_catalog TO {}").format(sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT ALL ON ALL FUNCTIONS IN SCHEMA ag_catalog TO {}").format(sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(self.graph_name), sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT ALL ON ALL TABLES IN SCHEMA {} TO {}").format(sql.Identifier(self.graph_name), sql.Identifier(application_role)))
                    cur.execute(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA {} TO {}").format(sql.Identifier(self.graph_name), sql.Identifier(application_role)))

    def drop_graph(self) -> None:
        """Drop the graph and all associated objects."""
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SET search_path = ag_catalog, '$user', public")
                exists = cur.execute(
                    "SELECT 1 FROM ag_catalog.ag_graph WHERE name = %s",
                    (self.graph_name,),
                ).fetchone()
                if exists:
                    cur.execute(sql.SQL("SELECT drop_graph(%s, true)"), (self.graph_name,))

    def execute_cypher(
        self,
        conn: psycopg.Connection,
        cypher_query: str,
        params: Mapping[str, Any] | None = None,
        column_count: int = 1,
    ) -> list[tuple[Any, ...]]:
        """Execute a cypher query on the graph within an existing connection."""
        if type(column_count) is not int or not 1 <= column_count <= 16:
            raise KnowledgeError('Invalid Cypher column count')
        self._prepare_session(conn)
        col_defs = ", ".join(f"c{i} agtype" for i in range(column_count))
        # AGE requires a dollar-quoted query constant. Choose a delimiter absent
        # from the query so user text cannot escape into the enclosing SQL.
        tag = 'gateway_cypher'
        while f'${tag}$' in cypher_query:
            tag += '_'
        cypher_literal = sql.SQL(f'${tag}$' + cypher_query + f'${tag}$')
        query = sql.SQL('SELECT * FROM cypher({}, {}' + (', %s::agtype' if params is not None else '')
                        + ') AS ({})').format(sql.Literal(self.graph_name), cypher_literal, sql.SQL(col_defs))
        if params is not None:
            res = conn.execute(query, (json.dumps(params),)).fetchall()
        else:
            res = conn.execute(query).fetchall()
        return [[parse_agtype(col) for col in row] for row in res]


class OutboxGraphSyncer:
    """Asynchronously projects outbox events from PostgreSQL to Apache AGE graph."""

    def __init__(self, dsn: str, graph_manager: AgeGraphManager):
        self.dsn = dsn
        self.graph = graph_manager

    def sync_outbox_events(self, limit: int = 100, *, tenant_id: str | None = None,
                           domain: str | None = None) -> int:
        """Fetch pending outbox events, apply projection to AGE graph, and mark as processed."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise KnowledgeError('Invalid graph outbox batch size')
        if (tenant_id is None) != (domain is None) or (tenant_id is not None and (not tenant_id or not domain)):
            raise KnowledgeError('Graph outbox requires a complete scope')
        with psycopg.connect(self.dsn) as conn:
            if tenant_id is not None:
                conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant_id,))
                conn.execute("SELECT set_config('app.domain',%s,true)", (domain,))
                conn.execute("SELECT set_config('app.admin_context','true',true)")
            self.graph._prepare_session(conn)
            with conn.cursor(row_factory=dict_row) as cur:
                events = cur.execute(
                    """
                    SELECT outbox_id, event_type, aggregate_type, aggregate_id,
                           tenant_id, domain, payload, status, created_at
                    FROM knowledge_outbox
                    WHERE status = 'pending'
                        AND event_type IN ('KNOWLEDGE_PUBLISHED','KNOWLEDGE_REVOKED','KNOWLEDGE_WITHDRAWN')
                        AND (%s::text IS NULL OR (tenant_id,domain)=(%s,%s))
                    ORDER BY created_at ASC
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                    """,
                      (tenant_id, tenant_id, domain, limit),
                ).fetchall()

            if not events:
                return 0

            processed_ids = []
            for event in events:
                event_type = event["event_type"]
                payload = event["payload"]
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except Exception:
                        payload = {}

                if event_type == "KNOWLEDGE_PUBLISHED":
                    self._project_publication(conn, event["aggregate_id"], event["tenant_id"], event["domain"], payload)
                elif event_type in ("KNOWLEDGE_REVOKED", "KNOWLEDGE_WITHDRAWN"):
                    self._project_revocation(conn, event["aggregate_id"], event["tenant_id"], event["domain"], payload)
                processed_ids.append(event["outbox_id"])

            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE knowledge_outbox
                    SET status = 'processed', processed_at = CURRENT_TIMESTAMP
                    WHERE outbox_id = ANY(%s)
                    """,
                    (processed_ids,),
                )
            conn.commit()
            return len(processed_ids)

    def _project_publication(
        self,
        conn: psycopg.Connection,
        publication_id: UUID,
        tenant_id: str,
        domain: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Upsert vertices and active claim edge into AGE graph from publication metadata."""
        with conn.cursor(row_factory=dict_row) as cur:
            pub_row = cur.execute(
                """
                SELECT p.publication_id, p.candidate_id, p.claim_id, p.valid_until,
                       c.predicate, c.polarity, c.modality,
                       sub.entity_id as sub_id, sub.name as sub_name, sub.entity_type as sub_type,
                       obj.entity_id as obj_id, obj.name as obj_name, obj.entity_type as obj_type
                FROM knowledge_publications p
                JOIN knowledge_claims c ON c.claim_id = p.claim_id
                JOIN knowledge_entities sub ON sub.entity_id = c.subject_id
                JOIN knowledge_entities obj ON obj.entity_id = c.object_id
                WHERE p.publication_id = %s
                """,
                (publication_id,),
            ).fetchone()

        if not pub_row:
            return

        valid_until_str = pub_row["valid_until"].isoformat() if isinstance(pub_row["valid_until"], datetime) else str(pub_row["valid_until"])

        merge_stmt = """
        MERGE (s:Entity {id: $subject_id})
        SET s.name = $subject_name, s.type = $subject_type, s.tenant_id = $tenant_id, s.domain = $domain
        MERGE (o:Entity {id: $object_id})
        SET o.name = $object_name, o.type = $object_type, o.tenant_id = $tenant_id, o.domain = $domain
        MERGE (s)-[r:Claim {publication_id: $pub_id}]->(o)
        SET r.claim_id = $claim_id,
            r.predicate = $predicate,
            r.polarity = $polarity,
            r.modality = $modality,
            r.valid_until = $valid_until,
              r.valid_until_epoch = $valid_until_epoch,
            r.tenant_id = $tenant_id,
            r.domain = $domain,
            r.is_active = true
        RETURN r
        """
        params = {
            "subject_id": str(pub_row["sub_id"]),
            "subject_name": pub_row["sub_name"],
            "subject_type": pub_row["sub_type"],
            "object_id": str(pub_row["obj_id"]),
            "object_name": pub_row["obj_name"],
            "object_type": pub_row["obj_type"],
            "pub_id": str(pub_row["publication_id"]),
            "claim_id": str(pub_row["claim_id"]),
            "predicate": pub_row["predicate"],
            "polarity": pub_row["polarity"],
            "modality": pub_row["modality"],
            "valid_until": valid_until_str,
            "valid_until_epoch": pub_row['valid_until'].timestamp(),
            "tenant_id": tenant_id,
            "domain": domain,
        }
        self.graph.execute_cypher(conn, merge_stmt, params, column_count=1)

    def _project_revocation(
        self,
        conn: psycopg.Connection,
        publication_id: UUID,
        tenant_id: str,
        domain: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Deactivate claim edge in AGE graph."""
        stmt = """
        MATCH ()-[r:Claim {publication_id: $pub_id}]->()
        SET r.is_active = false
        RETURN count(r)
        """
        params = {"pub_id": str(publication_id)}
        self.graph.execute_cypher(conn, stmt, params, column_count=1)

    def rebuild_all_projections(self, *, batch_size: int = 500) -> dict[str, int]:
        """Idempotently reconstruct the entire AGE graph from PostgreSQL Single Source of Truth."""
        self.graph.drop_graph()
        self.graph.ensure_graph()

        nodes_count = 0
        edges_count = 0

        with psycopg.connect(self.dsn) as conn:
            self.graph._prepare_session(conn)
            with conn.cursor(row_factory=dict_row) as cur:
                # 1. Rebuild active published claims
                cur.execute(
                    """
                    SELECT p.publication_id, p.tenant_id, p.domain, p.valid_until,
                           c.claim_id, c.predicate, c.polarity, c.modality,
                           sub.entity_id as sub_id, sub.name as sub_name, sub.entity_type as sub_type,
                           obj.entity_id as obj_id, obj.name as obj_name, obj.entity_type as obj_type
                    FROM knowledge_publications p
                    JOIN knowledge_claims c ON c.claim_id = p.claim_id
                    JOIN knowledge_entities sub ON sub.entity_id = c.subject_id
                    JOIN knowledge_entities obj ON obj.entity_id = c.object_id
                    WHERE NOT EXISTS (SELECT 1 FROM knowledge_tombstones t WHERE t.publication_id = p.publication_id)
                      AND p.valid_until > clock_timestamp()
                    ORDER BY p.published_at ASC
                    """
                )
                rows = cur.fetchall()

            for row in rows:
                valid_until_str = row["valid_until"].isoformat() if isinstance(row["valid_until"], datetime) else str(row["valid_until"])
                merge_stmt = """
                MERGE (s:Entity {id: $subject_id})
                SET s.name = $subject_name, s.type = $subject_type, s.tenant_id = $tenant_id, s.domain = $domain
                MERGE (o:Entity {id: $object_id})
                SET o.name = $object_name, o.type = $object_type, o.tenant_id = $tenant_id, o.domain = $domain
                MERGE (s)-[r:Claim {publication_id: $pub_id}]->(o)
                SET r.claim_id = $claim_id,
                    r.predicate = $predicate,
                    r.polarity = $polarity,
                    r.modality = $modality,
                    r.valid_until = $valid_until,
                      r.valid_until_epoch = $valid_until_epoch,
                    r.tenant_id = $tenant_id,
                    r.domain = $domain,
                    r.is_active = true
                RETURN r
                """
                params = {
                    "subject_id": str(row["sub_id"]),
                    "subject_name": row["sub_name"],
                    "subject_type": row["sub_type"],
                    "object_id": str(row["obj_id"]),
                    "object_name": row["obj_name"],
                    "object_type": row["obj_type"],
                    "pub_id": str(row["publication_id"]),
                    "claim_id": str(row["claim_id"]),
                    "predicate": row["predicate"],
                    "polarity": row["polarity"],
                    "modality": row["modality"],
                    "valid_until": valid_until_str,
                    "valid_until_epoch": row['valid_until'].timestamp(),
                    "tenant_id": row["tenant_id"],
                    "domain": row["domain"],
                }
                self.graph.execute_cypher(conn, merge_stmt, params, column_count=1)
                edges_count += 1

            # Count total nodes
            res = self.graph.execute_cypher(conn, "MATCH (n:Entity) RETURN count(n)", column_count=1)
            if res and res[0]:
                nodes_count = int(res[0][0])

            conn.commit()

        return {"nodes_rebuilt": nodes_count, "edges_rebuilt": edges_count}


class GovernedGraphQueryService:
    """Multi-tenant, parameterized, read-only openCypher query service over Apache AGE."""

    def __init__(self, dsn: str, graph_manager: AgeGraphManager):
        self.dsn = dsn
        self.graph = graph_manager

    def validate_readonly_cypher(self, cypher: str) -> None:
        """Accept only syntax that can be fully scoped before execution."""
        compile_governed_cypher(cypher)

    def query(
        self,
        *,
        tenant_id: str,
        domain: str,
        cypher: str,
        params: Mapping[str, Any] | None = None,
        column_count: int | None = None,
    ) -> GraphQueryResult:
        """Execute governed read-only openCypher query with tenant and active claim scoping."""
        if not tenant_id or not domain:
            raise KnowledgeError("Query requires authenticated tenant_id and domain scope")

        scoped_query, cols = compile_governed_cypher(cypher)
        if column_count is not None and (type(column_count) is not int or column_count != cols):
            raise KnowledgeError('Cypher column count does not match RETURN')

        bound_params = dict(params or {})
        bound_params["_tenant_id"] = tenant_id
        bound_params["_domain"] = domain
        bound_params['_now_epoch'] = time.time()

        started = time.monotonic()
        with psycopg.connect(self.dsn) as conn:
            conn.execute('SET TRANSACTION READ ONLY')
            conn.execute("SET LOCAL statement_timeout = '5s'")
            self.graph._prepare_session(conn)
            raw_rows = self.graph.execute_cypher(conn, scoped_query, bound_params, column_count=cols)
        elapsed_ms = (time.monotonic() - started) * 1000.0

        nodes_map: dict[str, GraphNode] = {}
        edges_map: dict[str, GraphEdge] = {}
        records: list[dict[str, Any]] = []

        for row in raw_rows:
            record_dict = {}
            for col_idx, item in enumerate(row):
                record_dict[f"c{col_idx}"] = item
                self._extract_graph_elements(item, nodes_map, edges_map, tenant_id, domain)
            records.append(record_dict)

        return GraphQueryResult(
            nodes=tuple(nodes_map.values()),
            edges=tuple(edges_map.values()),
            raw_records=tuple(records),
            execution_time_ms=round(elapsed_ms, 2),
        )

    def _extract_graph_elements(
        self,
        item: Any,
        nodes: dict[str, GraphNode],
        edges: dict[str, GraphEdge],
        expected_tenant: str,
        expected_domain: str,
    ) -> None:
        """Inspect vertex/edge items and populate structured GraphNode/GraphEdge."""
        if not isinstance(item, dict):
            return

        label = item.get("label")
        props = item.get("properties", {})
        if label in ('Entity', 'Claim') and (
                props.get('tenant_id') != expected_tenant or props.get('domain') != expected_domain):
            raise KnowledgeError('Graph result scope mismatch')
        if label == "Entity":
            # Vertex
            node_id = str(props.get("id"))
            if node_id not in nodes:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    name=str(props.get("name", "")),
                    type=str(props.get("type", "UNKNOWN")),
                    tenant_id=str(props.get("tenant_id", "")),
                    domain=str(props.get("domain", "")),
                    properties={k: v for k, v in props.items() if k not in ("id", "name", "type", "tenant_id", "domain")},
                )
        elif label == "Claim":
            # Edge
            if (props.get('is_active') is not True
                    or not isinstance(props.get('valid_until_epoch'), (int, float))
                    or props['valid_until_epoch'] <= time.time()):
                raise KnowledgeError('Graph result is no longer active')
            claim_id = str(props.get("claim_id"))
            if claim_id not in edges:
                edges[claim_id] = GraphEdge(
                    claim_id=claim_id,
                    source_id=str(item.get("start_id", "")),
                    target_id=str(item.get("end_id", "")),
                    predicate=str(props.get("predicate", "")),
                    polarity=str(props.get("polarity", "positive")),
                    modality=str(props.get("modality", "asserted")),
                    publication_id=str(props.get("publication_id", "")),
                    valid_until=str(props.get("valid_until", "")),
                    is_active=bool(props.get("is_active", True)),
                    properties={k: v for k, v in props.items() if k not in (
                        "claim_id", "predicate", "polarity", "modality", "publication_id", "valid_until", "is_active"
                    )},
                )
