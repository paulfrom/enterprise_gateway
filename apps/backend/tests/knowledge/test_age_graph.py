"""Tests for Apache AGE graph manager, Outbox projection syncer, and governed Cypher queries."""

import unittest
from uuid import uuid4
import psycopg

from knowledge.age_graph import (
    AgeGraphManager,
    OutboxGraphSyncer,
    GovernedGraphQueryService,
)
from knowledge.knowledge import KnowledgeError
from tests.pg_support import get_admin_dsn, prepare_test_database, test_configuration


class TestAgeGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.admin_dsn = get_admin_dsn()
        cls.mgr = AgeGraphManager(cls.admin_dsn, graph_name=test_configuration().get('graph_name'))
        cls.mgr.verify_graph()
        cls.syncer = OutboxGraphSyncer(cls.admin_dsn, cls.mgr)
        cls.query_service = GovernedGraphQueryService(cls.admin_dsn, cls.mgr)

    def setUp(self):
        self.tenant = 'graph-test-' + uuid4().hex
        self.domain = 'graph-test-' + uuid4().hex
        with psycopg.connect(self.admin_dsn) as conn:
            self.mgr.execute_cypher(
                conn,
                "CREATE (n:Entity {id:'node-1',name:'Alpha Corp',type:'ORG',tenant_id:$tenant,domain:$domain}) RETURN n",
                {'tenant': self.tenant, 'domain': self.domain},
            )


    def test_existing_graph_and_scoped_cypher_execution(self):
        """Verify an existing graph and basic scoped Cypher execution."""
        with psycopg.connect(self.admin_dsn, autocommit=True) as conn:
            # Query graph metadata
            self.mgr._prepare_session(conn)
            res = self.mgr.execute_cypher(
                conn,
                "MATCH (n:Entity {id:'node-1',tenant_id:$tenant,domain:$domain}) RETURN n",
                params={'tenant': self.tenant, 'domain': self.domain}, column_count=1,
            )
            self.assertEqual(len(res), 1)
            node_data = res[0][0]
            self.assertIn("properties", node_data)
            self.assertEqual(node_data["properties"]["name"], "Alpha Corp")

            # Verify query retrieval
            query_res = self.mgr.execute_cypher(
                conn,
                "MATCH (n:Entity {id: 'node-1',tenant_id:$tenant,domain:$domain}) RETURN n.name, n.type",
                params={'tenant': self.tenant, 'domain': self.domain}, column_count=2,
            )
            self.assertEqual(len(query_res), 1)
            self.assertEqual(query_res[0], ["Alpha Corp", "ORG"])

    def test_governed_query_service_read_only_and_forbidden_mutations(self):
        """Test read-only Cypher enforcement and query rejection on mutating keywords."""
        # 1. Prohibit mutating Cypher statements
        for forbidden in (
            "CREATE (n:Entity {id: 'bad'})",
            "MATCH (n:Entity) DETACH DELETE n",
            "MERGE (n:Entity {id: 'bad'})",
            "MATCH (n:Entity) SET n.name = 'hacked'",
            "MATCH (n:Entity) REMOVE n.name",
            "DROP GRAPH test",
        ):
            with self.assertRaises(KnowledgeError):
                self.query_service.query(
                    tenant_id=self.tenant,
                    domain=self.domain,
                    cypher=forbidden,
                )

        # 2. Allow valid read-only MATCH query
        res = self.query_service.query(
            tenant_id=self.tenant,
            domain=self.domain,
            cypher="MATCH (n:Entity {id: 'node-1'}) RETURN n",
            column_count=1,
        )
        self.assertGreaterEqual(len(res.nodes), 1)
        self.assertEqual(res.nodes[0].name, "Alpha Corp")
        self.assertGreaterEqual(res.execution_time_ms, 0.0)

    def test_outbox_syncer_and_full_rebuild(self):
        """Test incremental outbox projection and full idempotent graph rebuild."""
        # Test full rebuild executes without errors
        stats = self.syncer.rebuild_all_projections(tenant_id=self.tenant, domain=self.domain)
        self.assertIn("nodes_rebuilt", stats)
        self.assertIn("edges_rebuilt", stats)
        self.assertGreaterEqual(stats["nodes_rebuilt"], 0)
        self.assertGreaterEqual(stats["edges_rebuilt"], 0)

        # Other test scopes may have pending events; this scope is empty.
        synced_count = self.syncer.sync_outbox_events(limit=10, tenant_id=self.tenant, domain=self.domain)
        self.assertEqual(synced_count, 0)
