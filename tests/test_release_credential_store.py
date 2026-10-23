"""No real credentials or OS keychain are used by these regression tests."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import sys
import tomllib
import traceback
import types
import unittest
from unittest import mock

import build
import publish_crates as publisher
import release_credentials as credentials


class MemoryStore:
    def __init__(self):
        self.values = {}
    def set_password(self, service, account, password):
        self.values[service, account] = password
    def get_password(self, service, account):
        return self.values.get((service, account))


class CredentialStoreTests(unittest.TestCase):
    secret = "pypi-synthetic-test-secret-never-a-real-token"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / credentials.CONFIG_FILE
        self.store = MemoryStore()
        patcher = mock.patch.object(credentials, "_secure_backend", return_value=self.store)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_reference_only(self):
        self.assertNotIn(self.secret, self.path.read_text())
        config = tomllib.loads(self.path.read_text())
        self.assertEqual(config["pypi"]["credential_store"], "keyring")
        self.assertNotIn("token", config["pypi"])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        for p in self.root.iterdir():
            self.assertNotIn(self.secret.encode(), p.read_bytes())

    def test_login_storage_roundtrip_writes_only_reference(self):
        credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        self.assert_reference_only()
        self.assertEqual(credentials.load_pypi_credentials(self.path), ("__token__", self.secret))

    def test_plaintext_legacy_is_migrated_without_backup(self):
        self.path.write_text('[pypi]\nusername="__token__"\ntoken="'+self.secret+'"\n')
        self.assertEqual(credentials.load_pypi_credentials(self.path), ("__token__", self.secret))
        self.assert_reference_only()
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_failed_secure_write_preserves_legacy_and_sanitizes_exception(self):
        legacy = '[pypi]\ntoken="'+self.secret+'"\n'
        self.path.write_text(legacy)
        with mock.patch.object(self.store, "set_password", side_effect=RuntimeError(self.secret)):
            with self.assertRaises(credentials.CredentialStoreError) as error:
                credentials.load_pypi_credentials(self.path)
        self.assertEqual(self.path.read_text(), legacy)
        self.assertNotIn(self.secret, ''.join(traceback.format_exception(error.exception)))
        self.assertTrue(error.exception.__suppress_context__)

    def test_failed_verification_never_creates_plaintext_fallback(self):
        with mock.patch.object(self.store, "get_password", return_value="wrong"):
            with self.assertRaises(credentials.CredentialStoreError):
                credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        self.assertFalse(self.path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_atomic_replace_leaves_existing_reference_and_no_temp_files(self):
        credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        before = self.path.read_bytes()
        with mock.patch.object(credentials.os, "replace", side_effect=OSError(self.secret)):
            with self.assertRaises(credentials.CredentialStoreError) as error:
                credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn(self.secret, str(error.exception))
        self.assertEqual(len(list(self.root.iterdir())), 1)

    def test_backend_read_error_and_malformed_config_hide_secret(self):
        credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        with mock.patch.object(self.store, "get_password", side_effect=RuntimeError(self.secret)):
            with self.assertRaises(credentials.CredentialStoreError) as error:
                credentials.load_pypi_credentials(self.path)
        self.assertNotIn(self.secret, ''.join(traceback.format_exception(error.exception)))
        self.path.write_text('[pypi]\ntoken="'+self.secret)
        with self.assertRaises(credentials.CredentialStoreError) as error:
            credentials.load_pypi_credentials(self.path)
        self.assertNotIn(self.secret, ''.join(traceback.format_exception(error.exception)))

    def test_backend_stdout_and_stderr_are_not_forwarded(self):
        output = io.StringIO()
        original_set = self.store.set_password
        def noisy_set(*args):
            print(self.secret)
            print(self.secret, file=sys.stderr)
            original_set(*args)
        with mock.patch.object(self.store, "set_password", side_effect=noisy_set), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        self.assertNotIn(self.secret, output.getvalue())
        self.assert_reference_only()

    def test_username_cannot_write_a_token_into_reference_metadata(self):
        with self.assertRaises(credentials.CredentialStoreError):
            credentials.save_pypi_credentials(self.path, self.secret, self.secret)
        self.assertFalse(self.path.exists())

    def test_missing_reference_returns_missing(self):
        self.assertEqual(credentials.load_pypi_credentials(self.path), (None, None))
        credentials.save_pypi_credentials(self.path, "__token__", self.secret)
        self.store.values.clear()
        self.assertEqual(credentials.load_pypi_credentials(self.path), (None, None))

    def test_interactive_login_never_prints_or_writes_secret(self):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(build.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(build, "getpass", return_value=self.secret), \
             mock.patch.object(build, "validate_pypi_credentials") as validate, \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            build.write_maturin_login_config(self.root)
        validate.assert_called_once_with("__token__", self.secret)
        self.assert_reference_only()
        self.assertNotIn(self.secret, output.getvalue())

    def test_validation_failure_never_saves_credentials(self):
        with mock.patch.dict(os.environ, {"MATURIN_PYPI_TOKEN": self.secret}, clear=True), \
             mock.patch.object(build, "validate_pypi_credentials", side_effect=SystemExit("rejected")):
            with self.assertRaises(SystemExit):
                build.write_maturin_login_config(self.root)
        self.assertEqual(self.store.values, {})
        self.assertFalse(self.path.exists())

    def test_publisher_migrates_and_redacts_credential_backed_child_failure(self):
        self.path.write_text('[pypi]\ntoken="'+self.secret+'"\n')
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(publisher, "RELEASE_CONFIG", self.path):
            username, token = publisher.load_pypi_credentials("PYPI_API_TOKEN")
        self.assertEqual((username, token), ("__token__", self.secret))
        self.assert_reference_only()
        self.assertEqual(publisher.redact_output(self.secret, {"TWINE_PASSWORD": token}), "[REDACTED]")

    def test_environment_credentials_skip_local_store(self):
        with mock.patch.dict(os.environ, {"PYPI_API_TOKEN": self.secret}, clear=True), \
             mock.patch.object(credentials, "load_pypi_credentials") as load:
            self.assertEqual(publisher.load_pypi_credentials("PYPI_API_TOKEN"), ("__token__", self.secret))
        load.assert_not_called()


class BackendSelectionTests(unittest.TestCase):
    def test_plaintext_null_and_fallback_backends_are_refused(self):
        for module in ['keyrings.alt.file', 'keyring.backends.null', 'keyring.backends.fail', 'keyring.backends.chainer']:
            backend = type('FakeBackend', (), {'__module__': module})()
            fake = types.SimpleNamespace(get_keyring=lambda: backend)
            with self.subTest(module=module), mock.patch.dict('sys.modules', {'keyring': fake}):
                with self.assertRaises(credentials.CredentialStoreError):
                    credentials._secure_backend()

    def test_supported_os_backends_are_accepted(self):
        for module in credentials._SECURE_MODULES:
            backend = type('FakeBackend', (), {'__module__': module})()
            fake = types.SimpleNamespace(get_keyring=lambda: backend)
            with self.subTest(module=module), mock.patch.dict('sys.modules', {'keyring': fake}):
                self.assertIs(credentials._secure_backend(), backend)

    def test_backend_initialization_error_is_sanitized(self):
        fake = types.SimpleNamespace(get_keyring=mock.Mock(side_effect=RuntimeError('synthetic-secret')))
        with mock.patch.dict('sys.modules', {'keyring': fake}):
            with self.assertRaises(credentials.CredentialStoreError) as error:
                credentials._secure_backend()
        self.assertNotIn('synthetic-secret', ''.join(traceback.format_exception(error.exception)))


if __name__ == '__main__':
    unittest.main()
