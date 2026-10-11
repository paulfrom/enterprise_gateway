"""History fixtures share the gateway test schema with purpose-bound grants."""
from tests.pg_support import history_configuration


def configuration() -> dict:
    return history_configuration()


def get_test_dsn() -> str:
    return configuration()['app_dsn']


def get_admin_dsn() -> str:
    return configuration()['admin_dsn']
