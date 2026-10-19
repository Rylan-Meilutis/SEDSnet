"""Local release logs must not expose credentials, including child failures."""
import contextlib
import io
import os
import subprocess
import sys
import unittest
import urllib.error
from unittest import mock

import build
import publish_crates as publisher


class ReleaseRedactionTests(unittest.TestCase):
    secret = "synthetic-secret-for-redaction-tests"

    def environment(self):
        return {**os.environ, "TWINE_PASSWORD": self.secret}

    def test_child_stdout_stderr_and_exception_are_redacted(self):
        code = "import os,sys; print(os.environ['TWINE_PASSWORD']); print(os.environ['TWINE_PASSWORD'],file=sys.stderr); sys.exit(7)"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(subprocess.CalledProcessError) as error:
                publisher.run([sys.executable, "-c", code], env=self.environment())
        self.assertNotIn(self.secret, output.getvalue() + str(error.exception))
        self.assertEqual(output.getvalue().count("[REDACTED]"), 2)
        self.assertEqual(error.exception.returncode, 7)

    def test_captured_child_output_is_sanitized_before_return(self):
        result = publisher.run_optional(
            [sys.executable, "-c", "import os; print(os.environ['TWINE_PASSWORD'])"],
            env=self.environment(),
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "[REDACTED]")

    def test_timeout_partial_bytes_are_redacted(self):
        timeout = subprocess.TimeoutExpired(["fake"], 1, output=self.secret.encode())
        with mock.patch.object(publisher.subprocess, "run", side_effect=timeout):
            result = publisher.run_optional(["fake", "--password", self.secret],
                                            env=self.environment(), timeout_s=1)
        self.assertEqual(result.returncode, 124)
        self.assertNotIn(self.secret, result.stdout + str(result.args))
        self.assertIn("timed out", result.stdout)

    def test_commands_and_saved_token_formats_are_redacted(self):
        args = ["fake", "--token", self.secret, "--password=another-secret", "pypi-synthetic", "ciosynthetic"]
        safe = publisher.safe_command(args, self.environment())
        self.assertNotIn(self.secret, " ".join(safe))
        self.assertNotIn("another-secret", " ".join(safe))
        self.assertEqual(safe[-2:], ["[REDACTED]", "[REDACTED]"])
        self.assertEqual(publisher.redact_output("Authorization: Basic synthetic"),
                         "Authorization: Basic [REDACTED]")

    def test_twine_error_is_sanitized_even_if_runner_is_replaced(self):
        result = subprocess.CompletedProcess([], 1, self.secret)
        output = io.StringIO()
        with mock.patch.object(publisher, "require_python_module"), \
             mock.patch.object(publisher, "run_optional", return_value=result), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(subprocess.CalledProcessError) as error:
                publisher.twine_upload(token_env="TWINE_PASSWORD", skip_existing=False,
                    username="__token__", token=self.secret, artifacts=[publisher.Path("synthetic.whl")])
        self.assertNotIn(self.secret, output.getvalue() + str(error.exception.output))

    def test_credential_status_only_reports_availability(self):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", ["publish_crates.py", "--credential-status"]), \
             mock.patch.object(publisher, "load_pypi_credentials", return_value=("__token__", self.secret)), \
             mock.patch.object(publisher, "require_clean_tree") as tree, \
             mock.patch.object(publisher, "run") as run, \
             contextlib.redirect_stdout(output):
            self.assertEqual(publisher.main(), 0)
        self.assertNotIn(self.secret, output.getvalue())
        self.assertIn('"pypi": "configured"', output.getvalue())
        tree.assert_not_called()
        run.assert_not_called()

    def test_login_network_error_does_not_repeat_server_credentials(self):
        failure = urllib.error.URLError(self.secret)
        with mock.patch.object(build.urllib.request, "urlopen", side_effect=failure):
            with self.assertRaises(SystemExit) as error:
                build.validate_pypi_credentials("__token__", self.secret)
        self.assertNotIn(self.secret, str(error.exception))
        self.assertTrue(error.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
