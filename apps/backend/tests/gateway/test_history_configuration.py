"""Explicit history selection and key-loss refusal at the launcher boundary."""
import os
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import start_gateway as launcher
from scripts import purge_request_history
from infra.envelope_crypto import KmsUnavailableError
from infra.errors import SafetyError


class HistoryConfigurationTests(unittest.TestCase):
    def test_purge_cli_uses_gateway_master_secret_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / 'master.txt'
            secret.write_text('ab' * 32, encoding='ascii')
            config = root / 'purge.json'
            config.write_text(json.dumps({'app_dsn':'synthetic', 'tenant_id':'tenant',
                'domain':'test', 'retention_days':1, 'bucket':'history',
                'audit_directory':str(root), 'kms_directory':str(root / 'keys')}))
            for env in ({'GATEWAY_KMS_MASTER_KEY':'ab' * 32},
                        {'GATEWAY_KMS_MASTER_KEY_FILE':str(secret)}):
                store = Mock()
                store.purge_expired.return_value = 0
                with patch.dict(os.environ, env, clear=True), \
                     patch.object(purge_request_history, 'FileKmsProvider') as kms, \
                     patch.object(purge_request_history, 'PostgresHistoryStore', return_value=store), \
                     patch('builtins.print'):
                    self.assertEqual(0, purge_request_history.main(['--config', str(config)]))
                    kms.assert_called_once_with(root / 'keys', bytes.fromhex('ab' * 32))
                    store.check_ready.assert_called_once()
                    store.purge_expired.assert_called_once()

    def settings(self):
        return {"GATEWAY_HISTORY_PG_DSN": "synthetic-dsn",
                "GATEWAY_HISTORY_READ_KEY": "ab" * 32,
                "GATEWAY_HISTORY_RETENTION_DAYS": "1",
                "GATEWAY_HISTORY_BUCKET": "synthetic-history"}

    def test_absent_group_does_not_select_history(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(launcher._history_spec())

    def test_partial_group_and_unapproved_retention_refuse(self):
        for days in (None, "0", "-1", "01", "36501", "", " 1"):
            config = self.settings()
            if days is None:
                del config['GATEWAY_HISTORY_RETENTION_DAYS']
            else:
                config['GATEWAY_HISTORY_RETENTION_DAYS'] = days
            with patch.dict(os.environ, config, clear=True), self.assertRaises(SafetyError):
                launcher._history_spec()

    def test_complete_group_and_exclusive_secret_sources(self):
        config = self.settings()
        with patch.dict(os.environ, config, clear=True):
            self.assertEqual(launcher._history_spec()['read_key'], bytes.fromhex('ab' * 32))
        config['GATEWAY_HISTORY_READ_KEY_FILE'] = 'synthetic-secret-file'
        with patch.dict(os.environ, config, clear=True), self.assertRaises(SafetyError):
            launcher._history_spec()

    def test_historical_ciphertext_never_reprovisions_missing_key(self):
        with tempfile.TemporaryDirectory() as directory:
            kms, store = Mock(), Mock()
            store.has_records.return_value = True
            kms.wrap.side_effect = KmsUnavailableError('synthetic missing history key')
            with patch.dict(os.environ, {'GATEWAY_PROCESSING_DOMAIN':'test',
                                        'GATEWAY_PROCESSING_TENANT':'tenant'}, clear=True), \
                 patch.object(launcher, '_key_store', return_value=(Path(directory), 'evidence', kms)), \
                 patch.object(launcher, '_history_spec', return_value=self.settings() | {'bucket':'history'}), \
                 patch.object(launcher, '_assemble_history', return_value=store), \
                 self.assertRaises(KmsUnavailableError):
                launcher.provision_keys()
            self.assertNotIn(unittest.mock.call(purpose='request-history', bucket='history'), kms.provision.call_args_list)
