"""Local PyPI secrets live in a supported OS credential store, never repo files.

Environment credentials remain available to CI. Do not log returned secrets or
backend exceptions. Legacy plaintext config is migrated only after a verified
secure write; failed migration never falls back to using plaintext credentials.
"""
from __future__ import annotations

import contextlib
import io
import hmac
import json
import os
from pathlib import Path
import tempfile

SERVICE = "org.ub.seds.sedsnet.pypi"
USERNAME = "__token__"
CONFIG_FILE = ".sedsnet-release.toml"
_SECURE_MODULES = frozenset({
    "keyring.backends.macOS", "keyring.backends.Windows",
    "keyring.backends.SecretService", "keyring.backends.kwallet",
    "keyring.backends.libsecret",
})


class CredentialStoreError(RuntimeError):
    """A deliberately secret-free release configuration error."""


def _secure_backend():
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            import keyring
            backend = keyring.get_keyring()
            if type(backend).__module__ == "keyring.backends.chainer":
                # Linux commonly chains several installed OS stores. Select
                # the first supported child in keyring's configured order;
                # never delegate to a chain that may include plaintext stores.
                backend = next((child for child in backend.backends
                                if type(child).__module__ in _SECURE_MODULES), None)
    except Exception:
        raise CredentialStoreError(
            "OS credential storage is unavailable. Install keyring with "
            "`python3 -m pip install keyring` and unlock/configure its OS backend."
        ) from None
    if type(backend).__module__ not in _SECURE_MODULES:
        raise CredentialStoreError(
            "A supported OS credential backend is required (macOS Keychain, "
            "Windows Credential Locker, Secret Service or KWallet). "
            "Plaintext, null and third-party fallback backends are refused. "
            "CI can provide its token through the environment."
        ) from None
    return backend


def _write_reference(path: Path) -> None:
    # Only fixed, non-secret metadata reaches disk, even in a temporary file.
    body = ("# Token stored in the OS credential store; this file contains no secret.\n"
            "version = 2\n[pypi]\nusername = " + json.dumps(USERNAME) +
            '\ncredential_store = "keyring"\nservice = ' + json.dumps(SERVICE) + '\n')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".sedsnet-release-ref-", delete=False) as file:
            temporary = Path(file.name)
            os.chmod(temporary, 0o600)
            file.write(body)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    except Exception:
        raise CredentialStoreError(
            "Could not write the non-secret credential reference. "
            "Existing configuration was not intentionally removed."
        ) from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_pypi_credentials(path: Path, username: str, token: str) -> None:
    if username != USERNAME or not isinstance(token, str) or not token:
        raise CredentialStoreError(
            "PyPI API-token login requires username __token__ and a nonempty token."
        ) from None
    backend = _secure_backend()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            backend.set_password(SERVICE, USERNAME, token)
            stored = backend.get_password(SERVICE, USERNAME)
        if not isinstance(stored, str) or not hmac.compare_digest(stored, token):
            raise ValueError("credential verification failed")
    except Exception:
        raise CredentialStoreError(
            "Could not save and verify the PyPI token in the OS credential store. "
            "No plaintext fallback was written."
        ) from None
    _write_reference(path)


def load_pypi_credentials(path: Path) -> tuple[str | None, str | None]:
    if not path.exists():
        return None, None
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        config = data.get("pypi", {})
        if not isinstance(config, dict):
            raise ValueError("invalid section")
        if config.get("username", USERNAME) != USERNAME:
            raise ValueError("invalid username")
    except Exception:
        raise CredentialStoreError(
            "Local release credential configuration is unreadable or invalid. "
            "Run `python3 build.py maturin-login` with Python 3.11 or newer."
        ) from None
    legacy = config.get("token")
    if legacy:
        # Do not make a plaintext backup. Replace the old file only after the
        # secure store can read back the identical secret.
        save_pypi_credentials(path, USERNAME, legacy)
        return USERNAME, legacy
    if not config:
        return None, None
    if (config.get("credential_store") != "keyring"
            or config.get("service") != SERVICE):
        raise CredentialStoreError(
            "Unknown local credential reference. Run `python3 build.py maturin-login`."
        ) from None
    backend = _secure_backend()
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            token = backend.get_password(SERVICE, USERNAME)
    except Exception:
        raise CredentialStoreError(
            "Could not read the PyPI token from the OS credential store. "
            "Unlock it or run `python3 build.py maturin-login`."
        ) from None
    return (USERNAME, token) if token else (None, None)
