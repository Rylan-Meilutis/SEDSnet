import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import publish_crates


class PublishCratesTests(unittest.TestCase):
    def test_dry_run_requires_the_exact_macro_version_before_main_package(self) -> None:
        for exact_version_available in (False, True):
            with self.subTest(available=exact_version_available), \
                 mock.patch.object(sys, "argv", ["publish_crates.py", "--skip-tests", "--skip-package"]), \
                 mock.patch.object(publish_crates, "require_clean_tree"), \
                 mock.patch.object(publish_crates, "cargo_search", return_value=True), \
                 mock.patch.object(publish_crates, "crate_version_exists", return_value=exact_version_available) as version, \
                 mock.patch.object(publish_crates, "cargo_publish", return_value=publish_crates.PUBLISH_DRY_RUN_OK) as publish:
                self.assertEqual(publish_crates.main(), 0)
                expected = [publish_crates.MACROS_MANIFEST]
                if exact_version_available:
                    expected.append(publish_crates.MAIN_MANIFEST)
                self.assertEqual([call.args[0] for call in publish.call_args_list], expected)
                version.assert_any_call("sedsnet_macros", tomllib.loads(
                    publish_crates.MACROS_MANIFEST.read_text())["package"]["version"])

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
