"""Projection events cannot cross scope or revive a revoked publication."""

from uuid import UUID

import psycopg

from knowledge.age_graph import AgeGraphManager, GovernedGraphQueryService, OutboxGraphSyncer
from tests.knowledge.test_governance import GovernancePgTestCase


class GraphOutboxScopeTests(GovernancePgTestCase):
    def setUp(self):
        super().setUp()
        self.graph = AgeGraphManager(self.config['admin_app_dsn'], graph_name=self.config.get('graph_name'))
        self.graph.verify_graph()
        self.syncer = OutboxGraphSyncer(self.config['admin_dsn'], self.graph)
        self.query_service = GovernedGraphQueryService(self.config['admin_dsn'], self.graph)

    def publication(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'source')
            candidate = self.seed_candidate(conn, 'source')
        self.confirm('source', audiences=('legal',))
        return self.publish(candidate, audiences=('legal',))

    def query(self, *, tenant=None):
        return self.query_service.query(tenant_id=tenant or self.tenant, domain=self.domain,
                                        cypher='MATCH (n:Entity) RETURN n')

    def test_scoped_consumption_leaves_other_tenants_pending_and_cannot_revoke_their_edges(self):
        publication = self.publication()
        with self.admin_conn(tenant='foreign-tenant') as conn:
            conn.execute("INSERT INTO knowledge_outbox(event_type,aggregate_type,aggregate_id,tenant_id,domain,acl,purpose,payload) "
                         "VALUES('KNOWLEDGE_REVOKED','publication',%s,'foreign-tenant',%s,ARRAY['legal'],'knowledge','{}')",
                         (UUID(publication), self.domain))
        self.assertEqual(self.syncer.sync_outbox_events(tenant_id=self.tenant, domain=self.domain), 1)
        with self.admin_conn(tenant='foreign-tenant') as conn:
            self.assertEqual(conn.execute("SELECT status FROM knowledge_outbox WHERE aggregate_id=%s "
                                          "AND event_type='KNOWLEDGE_REVOKED'", (UUID(publication),)).fetchone()[0], 'pending')
        self.assertEqual(self.syncer.sync_outbox_events(tenant_id='foreign-tenant', domain=self.domain), 1)
        result = self.query_service.query(tenant_id=self.tenant, domain=self.domain,
                                          cypher='MATCH (s:Entity)-[r:Claim]->(o:Entity) RETURN r')
        self.assertEqual([edge.publication_id for edge in result.edges], [publication])
        self.assertEqual(self.query(tenant='foreign-tenant').nodes, ())

    def test_forged_publication_scope_does_not_copy_foreign_fact_names(self):
        publication = self.publication()
        with self.admin_conn() as conn:
            conn.execute("DELETE FROM knowledge_outbox WHERE aggregate_id=%s AND event_type='KNOWLEDGE_PUBLISHED'",
                         (UUID(publication),))
        with self.admin_conn(tenant='foreign-tenant') as conn:
            conn.execute("INSERT INTO knowledge_outbox(event_type,aggregate_type,aggregate_id,tenant_id,domain,acl,purpose,payload) "
                         "VALUES('KNOWLEDGE_PUBLISHED','publication',%s,'foreign-tenant',%s,ARRAY['legal'],'knowledge','{}')",
                         (UUID(publication), self.domain))
        self.assertEqual(self.syncer.sync_outbox_events(tenant_id='foreign-tenant', domain=self.domain), 1)
        self.assertEqual(self.query(tenant='foreign-tenant').nodes, ())
        self.assertEqual(self.query().nodes, ())

    def test_delayed_publish_event_does_not_project_an_already_revoked_fact(self):
        publication = self.publication()
        self.service.revoke_publication(publication, basis='withdrawn before projection', context=self.context)
        self.assertEqual(self.syncer.sync_outbox_events(tenant_id=self.tenant, domain=self.domain), 2)
        self.assertEqual(self.query().nodes, ())

    def test_restricted_admin_rebuild_preserves_other_tenant_nodes(self):
        self.publication()
        self.syncer.sync_outbox_events(tenant_id=self.tenant, domain=self.domain)
        with self.admin_conn() as conn:
            self.graph.execute_cypher(conn,
                "CREATE (n:Entity {id:'foreign',name:'FOREIGN_REBUILD_CANARY',tenant_id:'foreign-tenant',domain:$domain}) RETURN n",
                {'domain': self.domain})
        restricted_dsn = self.config['admin_app_dsn']
        restricted_manager = AgeGraphManager(restricted_dsn, graph_name=self.graph.graph_name)
        stats = OutboxGraphSyncer(restricted_dsn, restricted_manager).rebuild_all_projections(
            tenant_id=self.tenant, domain=self.domain)
        self.assertEqual(stats, {'nodes_rebuilt': 2, 'edges_rebuilt': 1})
        foreign = self.query(tenant='foreign-tenant')
        self.assertEqual([node.name for node in foreign.nodes], ['FOREIGN_REBUILD_CANARY'])
