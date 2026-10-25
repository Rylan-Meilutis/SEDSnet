"""Run Python API/script tests; full campaigns must load the current native binding."""
from __future__ import annotations
import argparse
import importlib
from pathlib import Path
import sys
import unittest

# These tests exercise build/release/editor tooling independently of the loaded
# native feature profile. Unknown/new modules remain in each profile by default.
SHARED_SCRIPT_MODULES = frozenset({
    'test_build_cli', 'test_cargo_output_directory', 'test_ci_release_contracts',
    'test_cmake_inputs', 'test_embedded_path_remaps', 'test_publish_crates',
    'test_publisher_token_handling', 'test_python_campaign_loader',
    'test_release_credential_store', 'test_release_redaction',
    'test_telemetry_config_editor',
})

def binding_suite(suite: unittest.TestSuite) -> unittest.TestSuite:
    selected = unittest.TestSuite()
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            selected.addTests(binding_suite(test))
        elif type(test).__module__.rsplit('.', 1)[-1] not in SHARED_SCRIPT_MODULES:
            selected.addTest(test)
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--require-bindings', action='store_true')
    parser.add_argument('--bindings-only', action='store_true', help='Run API/process checks for an additional native profile; shared script contracts were run by the first qualification profile.')
    args = parser.parse_args(argv)
    if args.require_bindings:
        try:
            importlib.import_module('sedsnet')
        except Exception:
            print('error: Current host Python binding could not be loaded; full qualification cannot skip its API tests.', file=sys.stderr)
            return 1
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / 'tests'), pattern='test_*.py')
    if args.bindings_only:
        suite = binding_suite(suite)
        if not suite.countTestCases():
            print('error: Additional native profile selected no API/process tests.', file=sys.stderr)
            return 1
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    binding_skips = any('binding unavailable' in reason.lower() for _, reason in result.skipped)
    if args.require_bindings and binding_skips:
        print('error: Full qualification rejected unavailable-binding skips.', file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
