"""Schedulers must see failed single-pass delivery as a failed command."""
from io import StringIO
import unittest
from unittest.mock import Mock, patch

from infra.spool_relay import RelayStats
import start_knowledge_worker as launcher


class WorkerExitStatusTests(unittest.TestCase):
    def stats(self, *, submitted=0, skipped=0, failed=0, quarantined=0):
        return RelayStats(submitted=submitted, skipped=skipped, failed=failed,
                          quarantined=quarantined, failures=(), quarantined_records=())

    def invoke(self, stats):
        worker = Mock()
        worker.run_once.return_value = stats
        with patch.object(launcher, "build_worker", return_value=worker), patch("sys.stdout", StringIO()):
            return launcher.main(["--once"])

    def test_successful_delivery_and_idempotent_replay_exit_zero(self):
        self.assertEqual(self.invoke(self.stats(submitted=2)), 0)
        self.assertEqual(self.invoke(self.stats(skipped=2)), 0)

    def test_failed_delivery_is_nonzero_even_when_some_records_committed(self):
        self.assertEqual(self.invoke(self.stats(submitted=1, failed=1)), 1)

    def test_quarantine_is_nonzero(self):
        self.assertEqual(self.invoke(self.stats(quarantined=1)), 1)


if __name__ == "__main__":
    unittest.main()
