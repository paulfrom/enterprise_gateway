"""Real PostgreSQL startup checks for the independent consumer."""
import unittest
from knowledge.storage import PostgresKnowledgeStorage
import start_knowledge_worker as launcher
from tests.pg_support import get_test_dsn, prepare_test_database


class WorkerDatabaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_test_database()

    def test_restricted_application_role_and_all_forced_rls_assets_are_accepted(self):
        launcher._validate_database(PostgresKnowledgeStorage(get_test_dsn()))


if __name__ == "__main__":
    unittest.main()
