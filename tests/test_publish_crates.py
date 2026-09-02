import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import publish_crates


class PublishCratesTests(unittest.TestCase):
    def test_pypi_artifacts_from_dir_finds_nested_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "wheels-linux-x86_64"
            nested.mkdir()
            wheel = nested / "sedsnet-4.0.6-cp38-abi3-manylinux.whl"
            sdist = root / "sdist" / "sedsnet-4.0.6.tar.gz"
            sdist.parent.mkdir()
            wheel.touch()
            sdist.touch()
            (nested / "ignored.txt").touch()

            self.assertEqual(
                publish_crates.pypi_artifacts_from_dir(tmp),
                sorted([wheel, sdist]),
            )

    def test_twine_upload_sends_credentials_via_environment(self) -> None:
        artifact = Path("dist/sedsnet-4.0.6.tar.gz")
        completed = subprocess.CompletedProcess([], 0, "")

        with (
            mock.patch.object(publish_crates, "require_python_module"),
            mock.patch.object(
                publish_crates, "run_optional", return_value=completed
            ) as run_optional,
        ):
            publish_crates.twine_upload(
                token_env="MATURIN_PYPI_TOKEN",
                skip_existing=False,
                username="__token__",
                token="secret-token",
                artifacts=[artifact],
            )

        command = run_optional.call_args.args[0]
        environment = run_optional.call_args.kwargs["env"]
        self.assertNotIn("--skip-existing", command)
        self.assertNotIn("--password", command)
        self.assertNotIn("secret-token", command)
        self.assertEqual(environment["TWINE_USERNAME"], "__token__")
        self.assertEqual(environment["TWINE_PASSWORD"], "secret-token")

    def test_pypi_upload_does_not_skip_existing_by_default(self) -> None:
        with mock.patch.object(sys, "argv", ["publish_crates.py"]):
            args = publish_crates.parse_args()

        self.assertFalse(args.pypi_skip_existing)


if __name__ == "__main__":
    unittest.main()
