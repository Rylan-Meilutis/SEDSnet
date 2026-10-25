"""Run Python API/script tests; full campaigns must load the current native binding."""
from __future__ import annotations
import argparse
import importlib
from pathlib import Path
import sys
import unittest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-bindings', action='store_true')
    args = parser.parse_args(argv)
    if args.require_bindings:
        try:
            importlib.import_module('sedsnet')
        except Exception:
            print('error: Current host Python binding could not be loaded; full qualification cannot skip its API tests.', file=sys.stderr)
            return 1
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent / 'tests'), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    binding_skips = any('binding unavailable' in reason.lower() for _, reason in result.skipped)
    if args.require_bindings and binding_skips:
        print('error: Full qualification rejected unavailable-binding skips.', file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
