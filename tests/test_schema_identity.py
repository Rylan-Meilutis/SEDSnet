from __future__ import annotations
import json
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace
import schema_identity
import telemetry_config_editor as editor

ROOT = Path(__file__).resolve().parents[1]

class GenericIdentityTests(unittest.TestCase):
    def test_generated_mirrors_do_not_drift(self):
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-schema-identity.py'), '--check'], check=True)

    def test_only_network_protocol_ids_are_reserved(self):
        for table, endpoint in [(schema_identity.ENDPOINT_PROTOCOL, True), (schema_identity.TYPE_PROTOCOL, False)]:
            for name, value in table.items():
                self.assertTrue(name.startswith('SEDSNET_'))
                self.assertEqual(schema_identity.resolve_id(name, endpoint=endpoint), value)
                with self.assertRaises(ValueError):
                    schema_identity.resolve_id('APPLICATION', value, endpoint=endpoint)
                with self.assertRaises(ValueError):
                    schema_identity.resolve_id(name, 100, endpoint=endpoint)
        for name in ['IMU_DATA', 'GPS_DATA', 'HEARTBEAT', 'IPC_MESSAGE']:
            self.assertGreaterEqual(schema_identity.resolve_id(name), 0x10000)
            self.assertEqual(schema_identity.resolve_id(name, 100), 100)
        self.assertGreaterEqual(schema_identity.resolve_id('SOFTWARE_BUS', endpoint=True), 0x10000)

    def test_editor_preserves_explicit_ids_and_rejects_collision(self):
        config = json.loads((ROOT / 'tests/fixtures/generic-identity.json').read_text())
        fake = SimpleNamespace(config_objs={editor.SCHEMA_SCOPE_BASE: config, editor.SCHEMA_SCOPE_IPC: {'endpoints': [], 'types': []}})
        editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)
        self.assertEqual(config['endpoints'][0]['id'], 100)
        config['types'][1]['id'] = 101
        with self.assertRaisesRegex(RuntimeError, 'collision'):
            editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)
        config['types'][1]['id'] = 1
        with self.assertRaisesRegex(RuntimeError, 'reserved'):
            editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)
        for bad in [-1, 2**32, True, 1.5, '100']:
            config['types'][1]['id'] = bad
            with self.assertRaisesRegex(RuntimeError, 'u32'):
                editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)

if __name__ == '__main__':
    unittest.main()
