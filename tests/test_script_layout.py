"""Internal helper migration, preserving the supported root CLI modules."""
from pathlib import Path
import unittest

import build
import publish_crates
from scripts import release_credentials, release_logging


ROOT = Path(__file__).parents[1]


class ScriptLayoutTests(unittest.TestCase):
    def test_internal_helpers_removed_from_root(self):
        for name in ("release_credentials.py", "release_logging.py"):
            self.assertFalse((ROOT / name).exists())
            self.assertTrue((ROOT / "scripts" / name).is_file())

    def test_entrypoints_share_same_patchable_credential_module(self):
        self.assertIs(build.release_credentials, release_credentials)
        self.assertIs(publish_crates.release_credentials, release_credentials)
        self.assertIs(build.redact_output, release_logging.redact_output)
        self.assertIs(publish_crates.safe_command, release_logging.safe_command)

    def test_credential_reference_remains_at_repository_root(self):
        self.assertEqual(publish_crates.REPO_ROOT, ROOT)
        self.assertEqual(
            publish_crates.RELEASE_CONFIG, ROOT / ".sedsnet-release.toml"
        )
        self.assertEqual(release_credentials.CONFIG_FILE, ".sedsnet-release.toml")

    def test_supported_entrypoints_and_cmake_package_inputs_remain(self):
        for name in (
            "build.py",
            "publish_crates.py",
            "python_test_runner.py",
            "cargo_paths.py",
        ):
            self.assertTrue((ROOT / name).is_file())
        self.assertIn(
            '"${RUST_DIR}/scripts/*.py"',
            (ROOT / "CMakeLists.txt").read_text(),
        )
