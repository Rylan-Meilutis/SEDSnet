"""Publishing credentials must never appear in displayed command arguments."""
import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).resolve().parents[1] / "publish_crates.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublishingTokenTests(unittest.TestCase):
    def test_token_uses_environment_for_dry_run_and_actual_publish(self):
        for publish in (False, True):
            with self.subTest(publish=publish), \
                 mock.patch.object(publisher, "manifest_package", return_value=("SEDSnet", "4.2.0")), \
                 mock.patch.object(publisher, "crate_version_exists", return_value=False), \
                 mock.patch.object(publisher, "cargo_env", return_value={}), \
                 mock.patch.object(publisher, "run") as run, \
                 mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 0, "")) as optional:
                publisher.cargo_publish(Path("Cargo.toml"), publish=publish,
                    allow_dirty=False, token="test-token-never-a-real-secret",
                    ignore_errors=False, timeout_s=60)
                call = (optional if publish else run).call_args
                self.assertNotIn("--token", call.args[0])
                self.assertNotIn("test-token-never-a-real-secret", " ".join(call.args[0]))
                self.assertEqual(call.kwargs["env"]["CARGO_REGISTRY_TOKEN"], "test-token-never-a-real-secret")


if __name__ == "__main__":
    unittest.main()
