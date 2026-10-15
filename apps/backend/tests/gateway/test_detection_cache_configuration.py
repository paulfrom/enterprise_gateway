"""Operator detection-cache measurement switch is parsed without echoing supplied values."""

import os
import unittest
from unittest.mock import patch

from starlette.testclient import TestClient

import start_gateway
from infra.errors import SafetyCode, SafetyError
from tests.gateway import test_runtime


class DetectionCacheConfigurationTests(unittest.TestCase):
    def test_absent_switch_defaults_to_off(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(start_gateway._detection_cache_options(),
                             {'detection_cache_enabled': False})

    def test_explicit_switch_and_bounds(self):
        with patch.dict(os.environ, {'GATEWAY_DETECTION_CACHE': 'on'}, clear=True):
            self.assertEqual(start_gateway._detection_cache_options(),
                             {'detection_cache_enabled': True})
        with patch.dict(os.environ, {'GATEWAY_DETECTION_CACHE': 'off',
                         'GATEWAY_DETECTION_CACHE_ENTRIES': '128',
                         'GATEWAY_DETECTION_CACHE_MAX_SPANS': '2048',
                         'GATEWAY_DETECTION_CACHE_TTL_SECONDS': '30.5'}, clear=True):
            self.assertEqual(start_gateway._detection_cache_options(), {
                'detection_cache_enabled': False,
                'detection_cache_entries': 128,
                'detection_cache_max_spans': 2048,
                'detection_cache_ttl_seconds': 30.5,
            })

    def test_invalid_values_are_controlled(self):
        for name, value in (('GATEWAY_DETECTION_CACHE', 'maybe'),
                            ('GATEWAY_DETECTION_CACHE', 'private-cache-canary'),
                            ('GATEWAY_DETECTION_CACHE_ENTRIES', '0'),
                            ('GATEWAY_DETECTION_CACHE_ENTRIES', '-1'),
                            ('GATEWAY_DETECTION_CACHE_ENTRIES', '1.5'),
                            ('GATEWAY_DETECTION_CACHE_ENTRIES', 'private-entries-canary'),
                            ('GATEWAY_DETECTION_CACHE_MAX_SPANS', '0'),
                            ('GATEWAY_DETECTION_CACHE_MAX_SPANS', 'private-spans-canary'),
                            ('GATEWAY_DETECTION_CACHE_TTL_SECONDS', '0'),
                            ('GATEWAY_DETECTION_CACHE_TTL_SECONDS', '-1'),
                            ('GATEWAY_DETECTION_CACHE_TTL_SECONDS', 'nan'),
                            ('GATEWAY_DETECTION_CACHE_TTL_SECONDS', 'inf'),
                            ('GATEWAY_DETECTION_CACHE_TTL_SECONDS', 'private-ttl-canary')):
            with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}, clear=True):
                with self.assertRaises(SafetyError) as caught:
                    start_gateway._detection_cache_options()
                self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
                self.assertNotIn(value, str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)


class DetectionCacheRuntimeBindingTests(unittest.TestCase):
    def test_runtime_binds_result_cache_and_second_request_hits(self):
        fixture = test_runtime.RuntimeAssemblyTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        app = fixture.app(detection_cache_enabled=True, detection_cache_entries=64,
                          detection_cache_max_spans=4096, detection_cache_ttl_seconds=60.0)
        prompt = "甲公司向乙公司采购设备。联系人张三的电话是13800138000。"
        with TestClient(app) as client:
            pipeline = app.state.runtime_pipelines[0]
            cache = pipeline._detection_result_cache
            self.assertIsNotNone(cache)
            self.assertEqual(200, fixture.post(client, prompt).status_code)
            self.assertEqual(200, fixture.post(client, prompt).status_code)
        snapshot = cache.snapshot()
        self.assertGreater(snapshot.hits, 0)
        self.assertGreater(snapshot.entries, 0)
        self.assertNotIn(prompt.encode("utf-8"), b"".join(cache._entries.keys()))


if __name__ == "__main__":
    unittest.main()
