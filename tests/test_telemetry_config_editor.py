from __future__ import annotations

import os
import builtins
import importlib.util
import unittest
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

import telemetry_config_editor as editor


class TelemetryConfigEditorPathTests(unittest.TestCase):
    def test_validation_imports_without_tk_and_only_window_creation_requires_it(self):
        original_import = builtins.__import__
        def without_tk(name, *args, **kwargs):
            if name == "tkinter" or name.startswith("tkinter."):
                raise ModuleNotFoundError("optional Tk unavailable")
            return original_import(name, *args, **kwargs)
        spec = importlib.util.spec_from_file_location("headless_schema_editor", editor.__file__)
        headless = importlib.util.module_from_spec(spec)
        with mock.patch("builtins.__import__", side_effect=without_tk):
            spec.loader.exec_module(headless)
        self.assertIsNone(headless.tk)
        config = {"endpoints": [{"rust": "TestEp", "name": "TEST_EP"}], "types": [{
            "rust": "TestValue", "name": "TEST_VALUE", "class": "Data",
            "element": {"kind": "Static", "data_type": "Float32", "count": 1},
            "endpoints": ["TestEp"], "reliable": "Off"}]}
        fake = SimpleNamespace(config_objs={headless.SCHEMA_SCOPE_BASE: config,
                                           headless.SCHEMA_SCOPE_IPC: {"endpoints": [], "types": []}})
        headless.TelemetryConfigEditor.validate_current_config(fake, headless.SCHEMA_SCOPE_BASE)
        with self.assertRaisesRegex(RuntimeError, "Tkinter is required"):
            headless.TelemetryConfigEditor(Path.cwd(), Path("config.rs"), None, None)
        with self.assertRaisesRegex(SystemExit, "Tkinter is required"):
            headless.main()

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

    def test_editor_accepts_one_enum_and_rejects_legacy_dual_fields(self):
        ty = {"rust": "TestValue", "name": "TEST_VALUE", "class": "Data",
              "element": {"kind": "Static", "data_type": "Float32", "count": 1},
              "endpoints": ["TestEp"], "reliable": "Off"}
        obj = {"endpoints": [{"rust": "TestEp", "name": "TEST_EP"}], "types": [ty]}
        fake = SimpleNamespace(config_objs={editor.SCHEMA_SCOPE_BASE: obj,
                                           editor.SCHEMA_SCOPE_IPC: {"endpoints": [], "types": []}})
        for mode in editor.RELIABLE_MODE_OPTIONS:
            ty["reliable"] = mode
            editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)
        for mode in [False, True, "None", "bad"]:
            ty["reliable"] = mode
            with self.assertRaises(RuntimeError):
                editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)
        ty["reliable"] = "Off"
        ty["reliable_mode"] = "Unordered"
        with self.assertRaises(RuntimeError):
            editor.TelemetryConfigEditor.validate_current_config(fake, editor.SCHEMA_SCOPE_BASE)

    def test_type_row_text_includes_priority_when_nonzero(self) -> None:
        row = editor._type_row_text(
            {
                "rust": "GpsData",
                "name": "GPS_DATA",
                "reliable": "Off",
                "priority": 7,
            }
        )
        self.assertIn("[Prio:7]", row)


if __name__ == "__main__":
    unittest.main()
