from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

try:
    import sedsnet  # noqa: F401
except Exception as exc:  # pragma: no cover - environment dependent
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


def _load_system_suite():
    root = pathlib.Path(__file__).resolve().parents[1]
    example_dir = root / "python-example"
    sys.path.insert(0, str(example_dir))
    spec = importlib.util.spec_from_file_location(
        "sedsnet_python_example_system_suite",
        example_dir / "system_suite.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@unittest.skipIf(IMPORT_ERROR is not None, f"sedsnet binding unavailable: {IMPORT_ERROR}")
class PythonSystemSuiteTests(unittest.TestCase):
    def test_python_system_suite_exercises_runtime_network_stack(self) -> None:
        suite = _load_system_suite()
        result = suite.run_python_system_suite()
        self.assertEqual(len(result.p2p_messages), 2)
        self.assertGreaterEqual(result.topology_router_count, 2)
        self.assertLessEqual(result.memory_used, result.memory_allocated)
        self.assertGreater(len(result.packet_bytes), 0)


if __name__ == "__main__":
    unittest.main()
