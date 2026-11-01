"""Publishing reuses only successful verification from the current invocation."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

import publish_crates as publisher


class PublisherVerificationTests(unittest.TestCase):
    def setUp(self):
        self.version = publisher.manifest_package(publisher.MAIN_MANIFEST)[1]

    def publish(self, **kwargs):
        options = dict(publish=False, allow_dirty=False, token=None, ignore_errors=False, timeout_s=60)
        options.update(kwargs)
        return publisher.cargo_publish(publisher.MAIN_MANIFEST, **options)

    def test_no_verify_requires_explicit_successful_package_proof(self):
        for publish in [False, True]:
            for verified in [False, True]:
                with self.subTest(publish=publish, verified=verified), \
                     mock.patch.object(publisher, "crate_version_exists", return_value=False), \
                     mock.patch.object(publisher, "run") as dry, \
                     mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 0, "")) as upload:
                    self.publish(publish=publish, package_verified=verified)
                command = (upload if publish else dry).call_args.args[0]
                self.assertEqual("--no-verify" in command, verified)
                self.assertEqual("--dry-run" in command, not publish)
        with mock.patch.object(publisher, "run") as dry:
            self.publish()
        self.assertNotIn("--no-verify", dry.call_args.args[0])

    def test_main_packages_once_before_each_proof_backed_dry_run(self):
        events = []
        def package(manifest, **kwargs):
            events.append(("package", manifest))
        def run(command, **kwargs):
            events.append(("publish", command))
        with mock.patch.object(sys, "argv", ["publish_crates.py", "--skip-tests"]), \
             mock.patch.object(publisher, "require_clean_tree"), \
             mock.patch.object(publisher, "crate_version_exists", return_value=True), \
             mock.patch.object(publisher, "cargo_package", side_effect=package), \
             mock.patch.object(publisher, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publisher.main(), 0)
        self.assertEqual([event[0] for event in events], ["package", "publish", "package", "publish"])
        for package_event, publish_event in zip(events[::2], events[1::2]):
            self.assertEqual(str(package_event[1]), publish_event[1][publish_event[1].index("--manifest-path") + 1])
            self.assertIn("--no-verify", publish_event[1])
            self.assertIn("--dry-run", publish_event[1])

    def test_skip_package_does_not_skip_publish_verification(self):
        with mock.patch.object(sys, "argv", ["publish_crates.py", "--skip-tests", "--skip-package"]), \
             mock.patch.object(publisher, "require_clean_tree"), \
             mock.patch.object(publisher, "crate_version_exists", return_value=True), \
             mock.patch.object(publisher, "cargo_package") as package, \
             mock.patch.object(publisher, "run") as dry, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publisher.main(), 0)
        package.assert_not_called()
        self.assertEqual(dry.call_count, 2)
        self.assertTrue(all("--no-verify" not in c.args[0] for c in dry.call_args_list))

    def test_failed_package_never_supplies_verification_or_publishes(self):
        with mock.patch.object(sys, "argv", ["publish_crates.py", "--skip-tests"]), \
             mock.patch.object(publisher, "require_clean_tree"), \
             mock.patch.object(publisher, "cargo_package", side_effect=subprocess.CalledProcessError(101, ["cargo", "package"])), \
             mock.patch.object(publisher, "cargo_publish") as publish, \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
            publisher.main()
        publish.assert_not_called()

    def test_already_published_preflight_skips_upload(self):
        with mock.patch.object(publisher, "crate_version_exists", return_value=True), \
             mock.patch.object(publisher, "run_optional") as upload:
            self.assertEqual(self.publish(publish=True), publisher.PUBLISH_ALREADY_EXISTS)
        upload.assert_not_called()

    def test_actual_duplicate_registry_reply_is_safe_to_retry(self):
        duplicate = f"crate version `{self.version}` is already uploaded"
        outputs = ["error: " + duplicate,
                   "error: failed to publish to registry\nCaused by:\n  "
                   "the remote server responded with an error (status 400 Bad Request): " + duplicate]
        for output in outputs:
            with self.subTest(output=output), mock.patch.object(publisher, "crate_version_exists", return_value=False), \
                 mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 101, output)):
                self.assertEqual(self.publish(publish=True), publisher.PUBLISH_ALREADY_EXISTS)

    def test_real_upload_errors_are_not_treated_as_existing_versions(self):
        duplicate_warning = f"warning: crate version `{self.version}` is already uploaded"
        errors = ["error: failed to verify: No space left on device (os error 28)",
                  "error: failed to write object: file already exists",
                  "error: failed to publish: 403 Forbidden: invalid token",
                  "error: registry network request timed out",
                  "error[E0080]: compilation failed",
                  f"error: failed to verify crate version {self.version}\nCaused by: File already exists (os error 17)",
                  duplicate_warning + "\nerror: No space left on device (os error 28)",
                  duplicate_warning + "\nerror: 403 Forbidden: invalid token",
                  duplicate_warning,
                  f"error: crate version `{self.version}-unrelated` is already uploaded",
                  f"crate version {self.version} already exists"]
        for output in errors:
            with self.subTest(output=output), mock.patch.object(publisher, "crate_version_exists", return_value=False), \
                 mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 101, output)), \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
                self.publish(publish=True)

    def test_twine_successful_skip_existing_remains_successful(self):
        with mock.patch.object(publisher, "require_python_module"), \
             mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 0, "Skipping existing registry artifact")) as run:
            publisher.twine_upload(token_env="MATURIN_PYPI_TOKEN", skip_existing=True,
                                   username=None, token=None, artifacts=[Path("fixture.whl")])
        self.assertIn("--skip-existing", run.call_args.args[0])

    def test_twine_nonzero_filesystem_and_mixed_errors_propagate(self):
        outputs = ["File already exists while opening local fixture.whl",
                   "Skipping existing artifact: file already exists\nHTTPError: 403 Forbidden invalid token",
                   "HTTPError: 400 Bad Request: File already exists\nNo space left on device"]
        for output in outputs:
            with self.subTest(output=output), mock.patch.object(publisher, "require_python_module"), \
                 mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 1, output)), \
                 contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.CalledProcessError):
                publisher.twine_upload(token_env="MATURIN_PYPI_TOKEN", skip_existing=True,
                                       username=None, token=None, artifacts=[Path("fixture.whl")])

    def test_registry_lookup_failure_propagates_without_publishing(self):
        with mock.patch.object(publisher, "cargo_search_output", side_effect=subprocess.CalledProcessError(101, ["cargo", "search"])), \
             mock.patch.object(publisher, "run_optional", return_value=subprocess.CompletedProcess([], 0, "")) as upload, self.assertRaises(subprocess.CalledProcessError):
            self.publish(publish=True)
        upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
