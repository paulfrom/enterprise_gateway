"""Real AGE regression tests for scoped records, aggregates and query escapes."""

import json
import time
import unittest
from uuid import uuid4

import psycopg

from knowledge.age_graph import AgeGraphManager, GovernedGraphQueryService
from knowledge.knowledge import KnowledgeError
from tests.pg_support import get_admin_dsn


class GovernedGraphIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = get_admin_dsn()
        cls.graph = AgeGraphManager(cls.dsn, graph_name='test_scoped_' + uuid4().hex[:12])
        cls.graph.ensure_graph()
        cls.addClassCleanup(cls.graph.drop_graph)
        cls.service = GovernedGraphQueryService(cls.dsn, cls.graph)
        with psycopg.connect(cls.dsn) as conn:
            for entity_id, name, tenant, domain in (
                ('a', 'Alpha', 'tenant-1', 'corp'), ('b', 'Beta', 'tenant-1', 'corp'),
                ('foreign', 'FOREIGN_TENANT_CANARY', 'tenant-2', 'corp'),
                ('other-domain', 'FOREIGN_DOMAIN_CANARY', 'tenant-1', 'other'),
            ):
                cls.graph.execute_cypher(conn,
                    'CREATE (n:Entity {id: $id, name: $name, type: \'ORG\', tenant_id: $tenant, domain: $domain}) RETURN n',
                    {'id': entity_id, 'name': name, 'tenant': tenant, 'domain': domain})
            for claim, target, tenant, domain, active, expiry in (
                ('live', 'b', 'tenant-1', 'corp', True, time.time() + 3600),
                ('inactive', 'b', 'tenant-1', 'corp', False, time.time() + 3600),
                ('expired', 'b', 'tenant-1', 'corp', True, time.time() - 3600),
                ('foreign-edge', 'b', 'tenant-2', 'corp', True, time.time() + 3600),
                ('other-domain-edge', 'b', 'tenant-1', 'other', True, time.time() + 3600),
                ('foreign-endpoint', 'foreign', 'tenant-1', 'corp', True, time.time() + 3600),
            ):
                cls.graph.execute_cypher(conn,
                    "MATCH (s:Entity {id: 'a'}), (o:Entity {id: $target}) "
                    'CREATE (s)-[r:Claim {claim_id: $claim, publication_id: $claim, predicate: \'supplies\', '
                    'tenant_id: $tenant, domain: $domain, is_active: $active, valid_until_epoch: $expiry}]->(o) RETURN r',
                    {'target': target, 'claim': claim, 'tenant': tenant, 'domain': domain,
                     'active': active, 'expiry': expiry})

    def query(self, cypher, **kwargs):
        return self.service.query(tenant_id='tenant-1', domain='corp', cypher=cypher, **kwargs)

    def test_vertices_scalar_records_and_aggregates_are_scoped(self):
        result = self.query('MATCH (n:Entity) RETURN n')
        self.assertEqual({node.name for node in result.nodes}, {'Alpha', 'Beta'})
        result = self.query('MATCH (n:Entity) RETURN n.name')
        self.assertEqual({record['c0'] for record in result.raw_records}, {'Alpha', 'Beta'})
        result = self.query('MATCH (n:Entity) RETURN count(n)')
        self.assertEqual(result.raw_records, ({'c0': 2},))

    def test_every_endpoint_and_edge_must_be_scoped_active_and_unexpired(self):
        result = self.query('MATCH (s:Entity)-[r:Claim]->(o:Entity) RETURN s, r, o LIMIT 50')
        self.assertEqual([edge.claim_id for edge in result.edges], ['live'])
        serialized = json.dumps(result.raw_records)
        for canary in ('FOREIGN_TENANT_CANARY', 'FOREIGN_DOMAIN_CANARY', 'inactive', 'expired', 'foreign-edge'):
            self.assertNotIn(canary, serialized)
        result = self.query('MATCH (s:Entity)-[r:Claim]->(o:Entity) RETURN count(r)')
        self.assertEqual(result.raw_records, ({'c0': 1},))

    def test_scoping_cannot_be_overridden_by_params_or_property_filters(self):
        result = self.query('MATCH (n:Entity) RETURN n', params={'_tenant_id': 'tenant-2', '_domain': 'other'})
        self.assertEqual({node.name for node in result.nodes}, {'Alpha', 'Beta'})
        result = self.query('MATCH (n:Entity) WHERE n.tenant_id = $tenant RETURN n', params={'tenant': 'tenant-2'})
        self.assertEqual(result.raw_records, ())

    def test_parameterized_filters_and_bounded_multihop_queries(self):
        result = self.query('MATCH (n:Entity {id: $id}) RETURN n.name AS name', params={'id': 'a'})
        self.assertEqual(result.raw_records, ({'c0': 'Alpha'},))
        result = self.query('MATCH (a:Entity)-[r:Claim]->(b:Entity)-[q:Claim]->(c:Entity) RETURN a, r, b, q, c')
        self.assertEqual(result.raw_records, ())

    def test_query_escapes_and_unhandled_syntax_are_rejected(self):
        for query in (
            'MATCH (n) RETURN n',
            'MATCH (n:Entity) RETURN n UNION MATCH (m:Entity) RETURN m',
            'MATCH (n:Entity) WITH n MATCH (m:Entity) RETURN m',
            'OPTIONAL MATCH (n:Entity) RETURN n',
            'MATCH (n:Entity) WHERE n.name = $name OR true RETURN n',
            'MATCH (a:Entity)-[r:Claim*]->(b:Entity) RETURN a',
            'MATCH (n:Entity) RETURN n $$) AS (v agtype); SELECT current_user; --',
            'MATCH (n:Entity) RETURN n // trailing comment',
            'MATCH (n:Entity) RETURN n LIMIT 1001',
            'CREATE (n:Entity) RETURN n',
        ):
            with self.subTest(query=query), self.assertRaises(KnowledgeError):
                self.query(query)
        for columns in (True, 0, 2, '1'):
            with self.subTest(columns=columns), self.assertRaises(KnowledgeError):
                self.query('MATCH (n:Entity) RETURN n', column_count=columns)

    def test_sql_dollar_delimiters_are_literal_cypher_data(self):
        with psycopg.connect(self.dsn) as conn:
            literal = '$$; $gateway_cypher$; $gateway_cypher_$; SELECT current_user; --'
            rows = self.graph.execute_cypher(conn, f"RETURN '{literal}'")
        self.assertEqual(rows, [[literal]])
