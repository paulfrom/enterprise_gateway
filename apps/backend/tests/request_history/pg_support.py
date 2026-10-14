"""History fixtures reuse existing shared tables with purpose-bound service logins."""
from tests.pg_support import history_configuration


def configuration() -> dict:
    return history_configuration()


def get_test_dsn() -> str:
    return configuration()['app_dsn']


def get_admin_dsn() -> str:
    return configuration()['admin_dsn']
