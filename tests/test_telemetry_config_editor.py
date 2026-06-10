from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

import telemetry_config_editor as editor


class TelemetryConfigEditorPathTests(unittest.TestCase):
    def test_find_ipc_schema_json_returns_none_when_env_unset(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SEDSNET_IPC_SCHEMA_PATH", None)
            self.assertIsNone(editor.find_ipc_schema_json())

    def test_find_ipc_schema_json_resolves_relative_env_path(self) -> None:
        with mock.patch.dict(
                os.environ,
                {"SEDSNET_IPC_SCHEMA_PATH": "tmp/ipc_overlay.json"},
                clear=False,
        ):
            path = editor.find_ipc_schema_json()
            self.assertIsNotNone(path)
            expected = (Path(editor.__file__).resolve().parent / "tmp" / "ipc_overlay.json").resolve()
            self.assertEqual(path, expected)

    def test_find_ipc_schema_json_preserves_absolute_env_path(self) -> None:
        absolute = Path("/tmp/test_ipc_overlay.json").resolve()
        with mock.patch.dict(
                os.environ,
                {"SEDSNET_IPC_SCHEMA_PATH": str(absolute)},
                clear=False,
        ):
            self.assertEqual(editor.find_ipc_schema_json(), absolute)

    def test_type_row_text_includes_priority_when_nonzero(self) -> None:
        row = editor._type_row_text(
            {
                "rust": "GpsData",
                "name": "GPS_DATA",
                "reliable_mode": "None",
                "priority": 7,
            }
        )
        self.assertIn("[Prio:7]", row)


if __name__ == "__main__":
    unittest.main()
