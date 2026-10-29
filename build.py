#!/usr/bin/env python3
from __future__ import annotations

import os
import argparse
import re
import shlex
import subprocess
import sys
import time
import tempfile
import shutil
import sysconfig
from contextlib import contextmanager
import urllib.error
import urllib.parse
import urllib.request
import ssl
from base64 import b64encode
from getpass import getpass
from pathlib import Path
from cargo_paths import cargo_target_directory
import release_credentials
from release_logging import redact_output, safe_command

RELEASE_CONFIG_FILE = ".sedsnet-release.toml"
PYPI_LEGACY_UPLOAD_URL = "https://upload.pypi.org/legacy/"


FEATURE_OPTIONS = ("embedded", "python", "timesync", "cryptography", "fair-admission", "ingress-target-filter", "compact-packet-store", "compact-packet-compression", "latest-value-egress")

def qualification_profiles(features: list[str]) -> list[list[str]]:
    """Exercise feature-OFF normal storage and feature-ON compact/fair storage.

    The existing long codec soak runs once, in the compact enabled profile.
    Shared minimal-std checks independently cover both feature states.
    """
    storage = {"compact-packet-store", "compact-packet-compression", "fair-admission", "latest-value-egress"}
    common = list(dict.fromkeys([*(f for f in features if f not in storage), "cryptography"]))
    return [common, [*common, "compact-packet-compression", "fair-admission", "latest-value-egress"]]

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and validate SEDSnet with Cargo-style commands and flags.", allow_abbrev=False)
    parser.add_argument("command", nargs="?", default="build", choices=("build", "check", "test", "maturin-build", "maturin-develop", "maturin-install", "maturin-login"), help="Action (default: build).")
    parser.add_argument("--release", action="store_true", help="Use the release profile (release-embedded on embedded targets).")
    parser.add_argument("--features", action="append", default=[], metavar="FEATURES", help="Comma/space-separated features; repeatable: " + ", ".join(FEATURE_OPTIONS))
    parser.add_argument("--target", default="", help="Rust target triple (host by default).")
    parser.add_argument("--device-id", default="", help="Compile-time DEVICE_IDENTIFIER.")
    parser.add_argument("--full", action="store_true", help="Include ignored long-duration tests with test.")
    parser.add_argument("--all", action="store_true", help="With test, run the feature-OFF normal and feature-ON compact/fair qualification matrix; not Cargo --all-features. Common --features apply to both profiles.")
    parser.add_argument("--static-schema-path", help="Runtime registry seed JSON path.")
    parser.add_argument("--static-ipc-schema-path", help="Runtime IPC overlay seed JSON path.")
    for flag, description in (("max-stack-payload", "Maximum stack payload bytes"), ("max-queue-budget", "Shared router/relay queue budget bytes"), ("max-recent-rx-ids", "Preallocated recent packet-ID entries")):
        parser.add_argument("--" + flag, type=int, help=description + ".")
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE", help="Build environment override; repeatable, e.g. --env QUEUE_GROW_STEP=1.25.")
    args = parser.parse_args(argv)
    args.features = list(dict.fromkeys(f for value in args.features for f in re.split(r"[,\s]+", value) if f))
    unknown = set(args.features) - set(FEATURE_OPTIONS)
    if unknown: parser.error("unsupported features: " + ", ".join(sorted(unknown)))
    if "embedded" in args.features and "python" in args.features: parser.error("build embedded and python targets separately")
    if args.full and args.command != "test": parser.error("--full requires test")
    if args.all and args.command != "test": parser.error("--all requires test")
    args.env_overrides = {}
    for key in ("max_stack_payload", "max_queue_budget", "max_recent_rx_ids"):
        value = getattr(args, key)
        if value is not None:
            if value <= 0: parser.error("--" + key.replace("_", "-") + " must be positive")
            args.env_overrides[key.upper()] = str(value)
    for flag, key in (("static_schema_path", "SEDSNET_STATIC_SCHEMA_PATH"), ("static_ipc_schema_path", "SEDSNET_STATIC_IPC_SCHEMA_PATH")):
        if getattr(args, flag) is not None:
            if not getattr(args, flag): parser.error("--" + flag.replace("_", "-") + " requires a path")
            args.env_overrides[key] = getattr(args, flag)
    for item in args.env:
        key, separator, value = item.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key): parser.error("--env requires a valid KEY=VALUE")
        args.env_overrides[key] = value
    return args


def _fmt_secs(s: float) -> str:
    if s < 1:
        return f"{s * 1000:.0f}ms"
    if s < 60:
        return f"{s:.2f}s"
    m = int(s // 60)
    r = s - 60 * m
    return f"{m}m{r:.0f}s"


def _banner(title: str) -> None:
    print("\n" + "-" * 60)
    print(title)
    print("-" * 60)


def _supports_emoji() -> bool:
    try:
        "✅".encode(sys.stdout.encoding or "utf-8")
    except Exception:
        return False
    return True


_EMOJI_OK = _supports_emoji()


def _success(msg: str) -> None:
    prefix = "✅" if _EMOJI_OK else "OK"
    print(f"{prefix} {msg}")


def _fail(msg: str) -> None:
    prefix = "❌" if _EMOJI_OK else "ERROR"
    print(f"{prefix} {msg}", file=sys.stderr)


def _fmt_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    x = float(n)
    u = 0
    while x >= 1024.0 and u < len(units) - 1:
        x /= 1024.0
        u += 1
    if u == 0:
        return f"{int(x)} {units[u]}"
    return f"{x:.2f} {units[u]}"


def validate_pypi_credentials(username: str, token: str) -> None:
    auth = b64encode(f"{username}:{token}".encode("utf-8")).decode("ascii")
    body = urllib.parse.urlencode(
        {
            ":action": "file_upload",
            "protocol_version": "1",
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        PYPI_LEGACY_UPLOAD_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "SEDSnet-release-helper",
        },
    )
    context = None
    try:
        import certifi  # type: ignore[import-not-found]

        context = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        context = None

    try:
        urllib.request.urlopen(req, timeout=20, context=context).close()
    except urllib.error.HTTPError as e:
        response_body = e.read().decode("utf-8", "replace").lower()
        if e.code in (401, 403) or "invalid or non-existent authentication" in response_body:
            raise SystemExit("PyPI rejected the credentials; config was not written.") from None
        # Valid credentials should get a non-auth upload/form error because this validation
        # deliberately does not include a distribution file.
        return
    except urllib.error.URLError as e:
        raise SystemExit("Could not validate PyPI credentials: network request failed; config was not written.") from None


def write_maturin_login_config(repo_root: Path) -> None:
    config_path = repo_root / RELEASE_CONFIG_FILE
    print("Saving the PyPI token in the OS credential store; repo config contains no secret.")
    print("Use a PyPI API token. Username defaults to __token__.")

    username = os.environ.get("MATURIN_PYPI_USERNAME", "").strip()
    token = os.environ.get("MATURIN_PYPI_TOKEN", "").strip()

    username = username or "__token__"
    if username != "__token__":
        raise SystemExit("PyPI API tokens require username __token__; unset MATURIN_PYPI_USERNAME.")

    if not token and sys.stdin.isatty():
        token = getpass("PyPI API token: ").strip()

    if not token:
        raise SystemExit(
            "No PyPI token provided. Set MATURIN_PYPI_TOKEN or run interactively."
        )

    print("Validating PyPI credentials before saving...")
    validate_pypi_credentials(username, token)

    try:
        release_credentials.save_pypi_credentials(config_path, username, token)
    except release_credentials.CredentialStoreError as error:
        raise SystemExit(str(error)) from None
    _success("Saved PyPI token in OS credential store; repository reference contains no secret.")


def shared_lib_name() -> str:
    if sys.platform == "darwin":
        return "libsedsnet.dylib"
    if os.name == "nt":
        return "sedsnet.dll"
    return "libsedsnet.so"


def print_artifact_sizes(repo_root: Path, *, target: str, profile: str, env: dict[str, str] | None = None) -> None:
    out_dir = cargo_target_directory(repo_root, env=env) / target / profile if target else cargo_target_directory(repo_root, env=env) / profile
    staticlib = out_dir / "libsedsnet.a"
    sharedlib = out_dir / shared_lib_name()
    rlib = out_dir / "libsedsnet.rlib"

    printed = False
    for p, label in ((staticlib, "staticlib"), (sharedlib, "sharedlib"), (rlib, "rlib")):
        if p.exists():
            sz = p.stat().st_size
            print(f"info: {label} size: {_fmt_bytes(sz)} ({p})")
            printed = True
    if not printed:
        print(f"info: no direct crate artifacts found in {out_dir}")


def collect_artifact_sizes(repo_root: Path, *, target: str, profile: str, env: dict[str, str] | None = None) -> dict[str, int]:
    out_dir = cargo_target_directory(repo_root, env=env) / target / profile if target else cargo_target_directory(repo_root, env=env) / profile
    staticlib = out_dir / "libsedsnet.a"
    sharedlib = out_dir / shared_lib_name()
    rlib = out_dir / "libsedsnet.rlib"
    out: dict[str, int] = {}
    if staticlib.exists():
        out["staticlib"] = staticlib.stat().st_size
    if sharedlib.exists():
        out["sharedlib"] = sharedlib.stat().st_size
    if rlib.exists():
        out["rlib"] = rlib.stat().st_size
    return out


def print_artifact_size_delta(before: dict[str, int], after: dict[str, int]) -> None:
    labels = ("staticlib", "sharedlib", "rlib")
    any_delta = False
    for label in labels:
        b = before.get(label)
        a = after.get(label)
        if b is None and a is None:
            continue
        if b is None and a is not None:
            print(f"info: {label} size delta: +{_fmt_bytes(a)} (new artifact)")
            any_delta = True
            continue
        if b is not None and a is None:
            print(f"info: {label} size delta: artifact removed (was {_fmt_bytes(b)})")
            any_delta = True
            continue
        if b is not None and a is not None:
            d = a - b
            sign = "+" if d >= 0 else "-"
            print(f"info: {label} size delta: {sign}{_fmt_bytes(abs(d))} ({_fmt_bytes(b)} -> {_fmt_bytes(a)})")
            any_delta = True
    if not any_delta:
        print("info: no prior artifacts available for size delta comparison.")


def _format_cmd(cmd: list[str]) -> str:
    return " ".join(safe_command(cmd))


def output_hint_for_cmd(
        cmd: list[str],
        *,
        repo_root: Path,
        target: str = "",
        release_build: bool = False,
        embedded_profile: bool = False,
        env: dict[str, str] | None = None,
) -> str | None:
    """
    Best-effort output location hint for common commands.
    """
    if not cmd:
        return None

    if cmd[:2] == ["cargo", "test"] or cmd[:3] == ["cargo", "nextest", "run"]:
        # cargo test builds test artifacts (and deps) under target/...
        return f"Build artifacts: {cargo_target_directory(repo_root, env=env)}"

    if cmd[:2] == ["cargo", "bench"]:
        return f"Bench artifacts/results: {cargo_target_directory(repo_root, env=env) / 'criterion'}"

    if cmd[:2] == ["cargo", "build"]:
        # Determine target dir
        tgt = ""
        if "--target" in cmd:
            try:
                tgt = cmd[cmd.index("--target") + 1]
            except Exception:
                tgt = ""
        tgt = tgt or target

        # Determine profile
        prof = None
        if "--profile" in cmd:
            try:
                prof = cmd[cmd.index("--profile") + 1]
            except Exception:
                prof = None

        if prof:
            # Custom profile output is still under target/<target?>/<profile> (cargo profile name)
            if tgt:
                return f"Output: {cargo_target_directory(repo_root, env=env) / tgt / prof}"
            return f"Output: {cargo_target_directory(repo_root, env=env) / prof}"

        # Standard debug/release
        std = "release" if release_build else "debug"
        if embedded_profile:
            # Your embedded release uses --profile release-embedded
            # but if embedded_profile is True we already handled prof above.
            pass
        if tgt:
            return f"Output: {cargo_target_directory(repo_root, env=env) / tgt / std}"
        return f"Output: {cargo_target_directory(repo_root, env=env) / std}"

    if cmd and cmd[0] == "maturin" and len(cmd) >= 2:
        if cmd[1] == "build":
            return f"Wheels: {cargo_target_directory(repo_root, env=env) / 'wheels'}"
        if cmd[1] == "develop":
            return "Installs into the active Python environment (editable/dev install)."

    if cmd[:3] == ["uv", "pip", "install"]:
        return "Installed into the active Python environment."

    return None


def cargo_lib_build_cmd(
        *,
        build_mode: list[str],
        build_args: list[str],
        build_shared: bool,
) -> list[str]:
    cmd = ["cargo", "rustc", "--lib", *build_mode, *build_args]
    crate_types = ["rlib", "staticlib"]
    if build_shared:
        crate_types.append("cdylib")
    cmd.extend(["--crate-type", ",".join(crate_types)])
    return cmd


def cargo_nextest_available(env: dict[str, str]) -> bool:
    try:
        subprocess.run(
            ["cargo", "nextest", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            env=env,
        )
        return True
    except (FileNotFoundError, PermissionError, OSError, subprocess.CalledProcessError):
        return False


def test_runner_cmds(
        *,
        env: dict[str, str],
        features: list[str],
        include_ignored: bool = False,
) -> tuple[str, list[list[str]]]:
    feature_arg = ",".join(features)
    runner = env.get("SEDSNET_TEST_RUNNER", "auto").strip().lower()
    if runner not in ("auto", "nextest", "cargo"):
        raise SystemExit(
            "SEDSNET_TEST_RUNNER must be one of: auto, nextest, cargo "
            f"(got {runner!r})"
        )

    has_nextest = cargo_nextest_available(env)
    if runner == "nextest" and not has_nextest:
        raise SystemExit(
            "SEDSNET_TEST_RUNNER=nextest was requested, but `cargo nextest` is not installed. "
            "Install it with `cargo install cargo-nextest --locked` or use SEDSNET_TEST_RUNNER=cargo."
        )

    if runner == "nextest" or (runner == "auto" and has_nextest):
        nextest_cmd = ["cargo", "nextest", "run", "--features", feature_arg]
        if include_ignored:
            nextest_cmd.extend(["--run-ignored", "all"])
        return (
            "cargo nextest",
            [
                nextest_cmd,
                ["cargo", "test", "--doc", "--features", feature_arg],
            ],
        )

    if runner == "auto":
        print("info: cargo-nextest not found; falling back to `cargo test`.")
    cargo_cmd = [
        "cargo",
        "test",
        "--features",
        feature_arg,
        "--",
        "--test-threads=1",
    ]
    if include_ignored:
        cargo_cmd.append("--include-ignored")
    return "cargo test", [cargo_cmd]


def run_cmd(
        cmd: list[str],
        *,
        env: dict[str, str],
        repo_root: Path,
        title: str | None = None,
        target: str = "",
        release_build: bool = False,
        embedded_profile: bool = False,
) -> None:
    """
    Run a command with nicer user feedback:
    - Section banner
    - Timing
    - PASS/FAIL
    - Output location hints
    """
    shown = " ".join(safe_command(cmd, env))
    if title:
        _banner(redact_output(title, env))
    else:
        _banner("Running: " + shown)

    hint = output_hint_for_cmd(
        cmd,
        repo_root=repo_root,
        target=target,
        release_build=release_build,
        embedded_profile=embedded_profile,
        env=env,
    )
    if hint:
        print(redact_output(f"info: {hint}", env))

    print("Running:", shown)
    t0 = time.monotonic()
    try:
        with subprocess.Popen(cmd, env=env, text=True, errors="replace",
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as child:
            assert child.stdout is not None
            for line in child.stdout:
                print(redact_output(line, env), end="", flush=True)
            code = child.wait()
        if code:
            raise subprocess.CalledProcessError(code, safe_command(cmd, env))
    except FileNotFoundError as e:
        _fail(f"Command not found: {redact_output(str(e.filename), env)}")
        _fail(f"While running: {shown}")
        raise SystemExit(127) from None
    except PermissionError as e:
        _fail(f"Permission denied when running command: {redact_output(str(e), env)}")
        _fail(f"While running: {shown}")
        raise SystemExit(1) from None
    except subprocess.CalledProcessError as e:
        dt = time.monotonic() - t0
        _fail(f"FAILED ({_fmt_secs(dt)}): {shown}")
        # Keep the same exit code
        raise SystemExit(e.returncode) from None
    dt = time.monotonic() - t0
    _success(f"OK ({_fmt_secs(dt)}): {shown}")


@contextmanager
def python_test_environment(repo_root: Path, env: dict[str, str], features: str,
                            build_mode: list[str], title: str):
    """Build the current host ABI and expose a private copy without installing it."""
    python_env = env.copy()
    python_env["PYO3_PYTHON"] = sys.executable
    verbose = subprocess.check_output(["rustc", "-vV"], env=python_env, text=True)
    host = next((line.removeprefix("host: ").strip() for line in verbose.splitlines()
                 if line.startswith("host: ")), "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", host):
        raise SystemExit("Could not determine the host target for Python API tests.")
    extension_args: list[str] = []
    if sys.platform == "darwin":
        # Maturin supplies these for wheels, but this test-only direct Cargo
        # build must let the loading interpreter resolve the Python symbols.
        extension_args = ["--", "-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"]
        # Keep cc-built dependencies and rustc on the same minimum OS version.
        python_env.setdefault("MACOSX_DEPLOYMENT_TARGET", "11.0")
    run_cmd(["cargo", "rustc", "--lib", "--features", features, "--target", host,
             "--crate-type", "cdylib", *build_mode, *extension_args], env=python_env, repo_root=repo_root,
            title=title, target=host, release_build="--release" in build_mode)
    profile = "release" if "--release" in build_mode else "debug"
    filename = "sedsnet.dll" if sys.platform == "win32" else "libsedsnet.dylib" if sys.platform == "darwin" else "libsedsnet.so"
    library = cargo_target_directory(repo_root, env=python_env) / host / profile / filename
    if not library.is_file():
        raise SystemExit("The host Python extension build did not produce its expected library.")
    with tempfile.TemporaryDirectory(prefix="sedsnet-python-tests-") as directory:
        package = Path(directory) / "sedsnet"
        package.mkdir()
        shutil.copy2(repo_root / "python-files/sedsnet/__init__.py", package / "__init__.py")
        suffix = sysconfig.get_config_var("EXT_SUFFIX") or (".pyd" if sys.platform == "win32" else ".so")
        # Copy rather than link: isolated schema tests rebuild the ordinary Cargo outputs.
        shutil.copy2(library, package / ("sedsnet" + suffix))
        python_env["PYTHONPATH"] = directory + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        yield python_env


def ensure_rust_target_installed(target: str) -> None:
    if not target:
        return

    try:
        result = subprocess.run(
            ["rustup", "target", "list", "--installed"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print(
            "warning: `rustup` not found; cannot ensure Rust target is installed. "
            "Build may fail if the target is missing.",
            file=sys.stderr,
        )
        return

    installed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    if target in installed:
        print(f"info: Rust target `{target}` already installed.")
        return

    _banner(f"Installing Rust target: {target}")
    try:
        subprocess.run(["rustup", "target", "add", target], check=True)
    except FileNotFoundError as e:
        raise SystemExit(
            "Required tool `rustup` was not found while trying to install target "
            f"`{target}`. Install Rust with rustup and try again."
        ) from e
    except subprocess.CalledProcessError as e:
        raise SystemExit(
            f"Failed to install Rust target `{target}` (exit code {e.returncode})."
        ) from e
    _success(f"Installed Rust target `{target}`.")


def _first_token(cmd: str) -> str:
    s = cmd.strip()
    if not s:
        return ""
    return s.split()[0]


def _has_cmd(cmd: str) -> bool:
    exe = _first_token(cmd)
    if not exe:
        return False
    try:
        subprocess.run(
            [exe, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return True
    except (FileNotFoundError, PermissionError, OSError):
        return False


def preferred_cross_compilers(target: str) -> list[str]:
    t = target.lower()

    if t.startswith("thumb") or "none-eabi" in t:
        return ["arm-none-eabi-gcc"]
    if t.startswith("riscv"):
        return ["riscv64-unknown-elf-gcc", "riscv-none-elf-gcc"]
    if t.startswith("avr-"):
        return ["avr-gcc"]
    if t.startswith("msp430-"):
        return ["msp430-elf-gcc"]
    if t.startswith("aarch64-") and "none" in t:
        return ["aarch64-none-elf-gcc"]

    return []


def has_embedded_c_toolchain(target: str, env: dict[str, str]) -> bool:
    """
    Best-effort check for a usable C compiler for cross-target C deps (e.g. zstd-sys).
    """
    if not target:
        return True

    k_dash = f"CC_{target}"
    k_us = f"CC_{target.replace('-', '_')}"
    candidates = [
        env.get(k_dash, ""),
        env.get(k_us, ""),
        env.get("TARGET_CC", ""),
    ]
    for c in candidates:
        if c and _has_cmd(c):
            return True

    for cc in preferred_cross_compilers(target):
        if _has_cmd(cc):
            return True
    return False


def _run_install_cmd(cmd: list[str]) -> bool:
    try:
        run_cmd(cmd, env=os.environ.copy(), repo_root=Path(__file__).parent,
                title="Installing embedded C toolchain")
        return True
    except SystemExit:
        return False


def try_install_embedded_c_toolchain(target: str, env: dict[str, str]) -> bool:
    """
    Try to install a cross C toolchain for the requested embedded target.
    Returns True if a usable compiler is found after the attempt.
    """
    if has_embedded_c_toolchain(target, env):
        return True

    # Allow caller/CI to provide an explicit install command.
    override = env.get("SEDSNET_INSTALL_C_TOOLCHAIN_CMD", "").strip()
    if override:
        cmd = shlex.split(override)
        if not cmd:
            return has_embedded_c_toolchain(target, env)
        _run_install_cmd(cmd)
        return has_embedded_c_toolchain(target, env)

    # Best-effort built-in installers.
    pref = preferred_cross_compilers(target)

    if _has_cmd("apt-get"):
        _run_install_cmd(["sudo", "apt-get", "update"])
        if "arm-none-eabi-gcc" in pref:
            _run_install_cmd(["sudo", "apt-get", "install", "-y", "gcc-arm-none-eabi"])
        elif "riscv64-unknown-elf-gcc" in pref or "riscv-none-elf-gcc" in pref:
            _run_install_cmd(["sudo", "apt-get", "install", "-y", "gcc-riscv64-unknown-elf"])
        elif "avr-gcc" in pref:
            _run_install_cmd(["sudo", "apt-get", "install", "-y", "gcc-avr"])
        elif "msp430-elf-gcc" in pref:
            _run_install_cmd(["sudo", "apt-get", "install", "-y", "gcc-msp430"])
        return has_embedded_c_toolchain(target, env)

    if _has_cmd("brew"):
        if "arm-none-eabi-gcc" in pref:
            _run_install_cmd(["brew", "install", "arm-none-eabi-gcc"])
        elif "riscv64-unknown-elf-gcc" in pref or "riscv-none-elf-gcc" in pref:
            _run_install_cmd(["brew", "install", "riscv-gnu-toolchain"])
        elif "avr-gcc" in pref:
            _run_install_cmd(["brew", "install", "avr-gcc"])
        elif "msp430-elf-gcc" in pref:
            _run_install_cmd(["brew", "install", "msp430-gcc"])
        elif "aarch64-none-elf-gcc" in pref:
            _run_install_cmd(["brew", "install", "aarch64-elf-gcc"])
        return has_embedded_c_toolchain(target, env)

    print(
        "warning: no supported package manager detected for auto-install "
        "(tried apt-get, brew), or target has no built-in package mapping.",
        file=sys.stderr,
    )
    return False


def _append_flag(existing: str, flag: str) -> str:
    if not existing:
        return flag
    tokens = existing.split()
    if flag in tokens:
        return existing
    return existing + " " + flag


def apply_embedded_path_remaps(target: str, env: dict[str, str]) -> None:
    """Shorten embedded panic-source paths without changing generated logic.

    Only augment explicit environment flags; otherwise Cargo configuration
    may provide target flags that an encoded override would accidentally hide.
    Encoded flags preserve source paths containing whitespace.
    """
    if "-none-" not in target or env.get("SEDSNET_EMBEDDED_PATH_REMAP_AUTO", "1").lower() in ("0", "false"):
        return
    if "CARGO_ENCODED_RUSTFLAGS" not in env and "RUSTFLAGS" not in env:
        return
    try:
        sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], env=env, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        print("warning: could not query Rust sysroot; keeping original source paths.")
        return
    if not sysroot:
        return
    flags = (env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
             if "CARGO_ENCODED_RUSTFLAGS" in env else env["RUSTFLAGS"].split())
    library = Path(sysroot) / "lib/rustlib/src/rust/library"
    registry = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/src"
    roots = [(str(library), "rust"), (str(registry), "crates")]
    # Distributed rust-src/rlibs use a virtual /rustc/<commit> source root.
    # Generic std/alloc code may retain those locations when instantiated here.
    try:
        version = subprocess.check_output(["rustc", "--version", "--verbose"], env=env, text=True)
        commit = next((line.partition(":")[2].strip() for line in version.splitlines()
                       if line.startswith("commit-hash:")), "")
        if len(commit) == 40 and all(char in "0123456789abcdef" for char in commit):
            virtual_library = Path("/rustc") / commit / "library"
            roots.append((str(virtual_library), "rust"))
            roots.extend((str(virtual_library / module / "src"), module)
                         for module in ("core", "alloc", "std"))
    except (OSError, subprocess.CalledProcessError):
        pass  # The physical sysroot mappings remain useful without metadata.
    # Keep useful module/crate paths, omitting toolchain paths and registry
    # hostname hashes repeated throughout embedded panic-location strings.
    roots.extend((str(library / module / "src"), module) for module in ("core", "alloc", "std"))
    roots.extend((str(directory), "crates") for directory in sorted(registry.glob("*")) if directory.is_dir())
    additions = [f"--remap-path-prefix={source}={destination}" for source, destination in roots
                 if not any(flag.startswith(f"--remap-path-prefix={source}=") for flag in flags)]
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(additions + flags)


def apply_embedded_cflags_defaults(target: str, env: dict[str, str]) -> None:
    """
    For embedded cross builds with C deps (e.g. zstd-sys), apply size-oriented
    defaults unless the caller opts out.
    """
    if not target:
        return

    apply_embedded_path_remaps(target, env)

    if env.get("SEDSNET_EMBEDDED_CFLAGS_AUTO", "1") in ("0", "false", "False"):
        print("info: embedded CFLAGS auto-tuning disabled by SEDSNET_EMBEDDED_CFLAGS_AUTO.")
        return

    defaults = [
        "-Oz",
        "-ffunction-sections",
        "-fdata-sections",
        "-fomit-frame-pointer",
        "-fno-unwind-tables",
        "-fno-asynchronous-unwind-tables",
        "-DZSTD_DISABLE_ASM=1",
        "-DZSTD_LEGACY_SUPPORT=0",
    ]

    keys = [
        "CFLAGS",
        "TARGET_CFLAGS",
        f"CFLAGS_{target}",
        f"CFLAGS_{target.replace('-', '_')}",
    ]
    for k in keys:
        cur = env.get(k, "")
        new_val = cur
        for f in defaults:
            new_val = _append_flag(new_val, f)
        env[k] = new_val

    print(
        "info: applied embedded CFLAGS defaults for size (override with --env CFLAGS=... "
        "or disable via --env SEDSNET_EMBEDDED_CFLAGS_AUTO=0)."
    )


def install_wheel_file(build_mode: list[str], *, env: dict[str, str], repo_root: Path, target: str = "", feature_parts: list[str] | None = None) -> None:
    run_cmd(
        ["maturin", "build", *build_mode, *(["--target", target] if target else []), *(["--features", ",".join(feature_parts)] if feature_parts else [])],
        env=env,
        repo_root=repo_root,
        title="maturin build (wheel)",
    )

    wheels_dir = cargo_target_directory(repo_root, env=env) / "wheels"
    wheels = sorted(wheels_dir.glob("sedsnet-*.whl"))
    if not wheels:
        raise SystemExit(f"No wheels found in {wheels_dir}")
    wheel = wheels[-1]

    _banner("Installing wheel with uv")
    print(f"info: Selected wheel: {wheel}")
    run_cmd(
        ["uv", "pip", "install", str(wheel)],
        env=env,
        repo_root=repo_root,
        title="uv pip install (wheel)",
    )
    _success("Wheel installed.")
    print(f"info: Wheel file remains at: {wheel}")


def _apply_env_overrides(env: dict[str, str], overrides: dict[str, str]) -> None:
    for k, v in overrides.items():
        env[k] = v
        print(redact_output(f"info: env override: {k}={v}", env))


def cargo_bench_smoke_cmd() -> list[str]:
    cmd = [
        "cargo",
        "bench",
        "--profile",
        "release",
        "--bench",
        "packet_paths",
        "--bench",
        "router_system_paths",
    ]
    cmd.extend([
        "--",
        "--save-baseline",
        "sedsnet_smoke",
        "--noplot",
        "--sample-size",
        "30",
        "--warm-up-time",
        "1",
        "--measurement-time",
        "2",
        "--noise-threshold",
        "0.15",
    ])
    return cmd


def cargo_clippy_cmd(
        *,
        build_mode: list[str],
        build_args: list[str],
        target_args: list[str] | None = None,
) -> list[str]:
    return [
        "cargo",
        "clippy",
        *build_mode,
        *build_args,
        *(target_args or ["--all-targets"]),
        "--",
        "-D",
        "warnings",
    ]


def run_clippy_checks(
        *,
        env: dict[str, str],
        repo_root: Path,
        build_mode: list[str],
        release_build: bool,
        feature_parts: list[str],
        target: str,
        start_step: int | None = None,
        total_steps_override: int | None = None,
) -> None:
    feature_suffix = ("," + ",".join(feature_parts)) if feature_parts else ""
    embedded_target = target or "thumbv7em-none-eabihf"
    can_check_embedded = has_embedded_c_toolchain(embedded_target, env)
    if not can_check_embedded:
        expected = ", ".join(preferred_cross_compilers(embedded_target)) or "CC_<target>/TARGET_CC"
        print(
            "info: embedded cross C toolchain missing; attempting auto-install "
            "(set SEDSNET_INSTALL_C_TOOLCHAIN_CMD to override)."
        )
        can_check_embedded = try_install_embedded_c_toolchain(embedded_target, env)

    total_steps = total_steps_override if total_steps_override is not None else (3 if can_check_embedded else 2)
    default_step = start_step if start_step is not None else 1
    python_step = default_step + 1
    embedded_step = python_step + 1

    run_cmd(
        cargo_clippy_cmd(build_mode=build_mode, build_args=(["--features", ",".join(feature_parts)] if feature_parts else [])),
        env=env,
        repo_root=repo_root,
        title=f"{default_step}/{total_steps} cargo clippy (default)",
        target=target,
        release_build=release_build,
    )

    run_cmd(
        cargo_clippy_cmd(
            build_mode=build_mode,
            build_args=["--features", f"python{feature_suffix}"],
        ),
        env=env,
        repo_root=repo_root,
        title=f"{python_step}/{total_steps} cargo clippy (python feature)",
        target=target,
        release_build=release_build,
    )

    if can_check_embedded:
        ensure_rust_target_installed(embedded_target)
        apply_embedded_cflags_defaults(embedded_target, env)

        embedded_mode: list[str] = []
        uses_custom_profile = False
        if release_build:
            embedded_mode = ["--profile", "release-embedded"]
            uses_custom_profile = True

        run_cmd(
            cargo_clippy_cmd(
                build_mode=embedded_mode,
                build_args=[
                    "--no-default-features",
                    "--target",
                    embedded_target,
                    "--features",
                    f"embedded{feature_suffix}",
                ],
                target_args=["--lib"],
            ),
            env=env,
            repo_root=repo_root,
            title=f"{embedded_step}/{total_steps} cargo clippy (embedded feature)",
            target=embedded_target,
            release_build=release_build,
            embedded_profile=uses_custom_profile,
        )
    else:
        expected = ", ".join(preferred_cross_compilers(embedded_target)) or "CC_<target>/TARGET_CC"
        print(
            "info: Skipping embedded clippy check: "
            f"no cross C toolchain found for target `{embedded_target}` "
            f"(expected {expected} or CC_<target>/TARGET_CC override)."
        )


def main(argv: list[str], *, _qualification_profile: list[str] | None = None,
         _shared_test_steps: bool = True) -> None:
    repo_root = Path(__file__).parent.resolve()
    os.chdir(repo_root)

    args = parse_args(argv)
    if args.all and _qualification_profile is None:
        for index, profile in enumerate(qualification_profiles(args.features)):
            _banner("QUALIFICATION PROFILE " + str(index + 1) + "/2: " + ",".join(profile))
            main(argv, _qualification_profile=profile, _shared_test_steps=index == 0)
        _success("All qualification profiles passed.")
        return
    if _qualification_profile is not None:
        args.features = _qualification_profile
    build_mode: list[str] = []
    checks = args.command == "check"
    tests = args.command == "test"
    test_full = args.full
    build_embedded = "embedded" in args.features
    build_python = "python" in args.features
    build_timesync = "timesync" in args.features
    build_cryptography = "cryptography" in args.features
    extra_features = [f for f in args.features if f not in ("embedded", "python", "timesync", "cryptography")]
    build_wheel = args.command == "maturin-build"
    develop_wheel = args.command == "maturin-develop"
    release_build = args.release
    install_wheel = args.command == "maturin-install"
    maturin_login = args.command == "maturin-login"
    target = args.target
    device_id = args.device_id
    env_overrides: dict[str, str] = args.env_overrides

    env = os.environ.copy()
    if device_id:
        env["DEVICE_IDENTIFIER"] = device_id
    if (tests and "SEDSNET_STATIC_SCHEMA_PATH" not in env_overrides and "SEDSNET_STATIC_SCHEMA_PATH" not
            in env):
        env_overrides["SEDSNET_STATIC_SCHEMA_PATH"] = str(
            (repo_root / "telemetry_config.test.json").resolve()
        )
    if (tests and "SEDSNET_STATIC_IPC_SCHEMA_PATH" not in env_overrides and
            "SEDSNET_STATIC_IPC_SCHEMA_PATH" not in env):
        test_ipc_schema = (repo_root / "telemetry_config.ipc.test.json").resolve()
        if test_ipc_schema.exists():
            env_overrides["SEDSNET_STATIC_IPC_SCHEMA_PATH"] = str(test_ipc_schema)
    _apply_env_overrides(env, env_overrides)

    if maturin_login:
        write_maturin_login_config(repo_root)
        return

    if release_build:
        build_mode = ["--release"]

    # ---- CHECK MODE: lint default + python + embedded variants ----
    if checks:
        _banner("CHECK MODE")
        feature_parts = list(extra_features)
        if build_timesync:
            feature_parts.append("timesync")
        if build_cryptography:
            feature_parts.append("cryptography")
        run_clippy_checks(
            env=env,
            repo_root=repo_root,
            build_mode=build_mode,
            release_build=release_build,
            feature_parts=feature_parts,
            target=target,
        )
        _success("All clippy checks passed.")
        return

    # ---- TEST MODE: also validate embedded + python builds ----
    if tests:
        _banner("TEST MODE")
        feature_parts = ["timesync", *extra_features]
        if build_cryptography:
            feature_parts.append("cryptography")
        feature_suffix = ("," + ",".join(feature_parts)) if feature_parts else ""
        embedded_target = target or "thumbv7em-none-eabihf"
        can_check_embedded = has_embedded_c_toolchain(embedded_target, env)
        if not can_check_embedded:
            expected = ", ".join(preferred_cross_compilers(embedded_target)) or "CC_<target>/TARGET_CC"
            print(
                "info: embedded cross C toolchain missing; attempting auto-install "
                "(set SEDSNET_INSTALL_C_TOOLCHAIN_CMD to override)."
            )
            can_check_embedded = try_install_embedded_c_toolchain(embedded_target, env)
        total_steps = (10 if can_check_embedded else 9) - (0 if _shared_test_steps else 2) + int(test_full)

        run_clippy_checks(
            env=env,
            repo_root=repo_root,
            build_mode=build_mode,
            release_build=release_build,
            feature_parts=feature_parts,
            target=target,
            start_step=1,
            total_steps_override=total_steps,
        )
        _success("Clippy checks passed.")
        if _shared_test_steps:
            for minimal_features in ("std", "std,latest-value-egress"):
                run_cmd(
                    ["cargo", "clippy", *build_mode, "--no-default-features", "--features", minimal_features, "--lib", "--", "-D", "warnings"],
                    env=env, repo_root=repo_root,
                    title="Minimal std/discovery-OFF strict Clippy: " + minimal_features,
                    release_build=release_build,
                )
            _success("Minimal std feature-OFF/ON checks passed.")

        runner_name, test_cmds = test_runner_cmds(
            env=env,
            features=feature_parts,
            include_ignored=test_full,
        )
        for idx, cmd in enumerate(test_cmds):
            title_suffix = runner_name if idx == 0 else "cargo test (doctests)"
            run_cmd(
                cmd,
                env=env,
                repo_root=repo_root,
                title=f"4/{total_steps} {title_suffix}",
                release_build=release_build,
            )
        _success("Tests passed.")

        next_step = 5

        # These regressions inspect a compiled flash catalog. Do not depend on
        # an ignored telemetry_config.json left by an earlier application build.
        # Fileless registration is covered separately by isolated process tests;
        # the production cross-build below retains the caller's original env.
        embedded_test_env = env.copy()
        embedded_test_env["SEDSNET_EMBEDDED_SCHEMA_PATH"] = str(repo_root / "telemetry_config.test.json")
        run_cmd(
            [
                "cargo",
                "test",
                *build_mode,
                "--no-default-features",
                "--features",
                f"embedded{feature_suffix}",
                "--test",
                "embedded_memory_behavior_test",
                "--test", "embedded_schema_memory",
                "--test", "embedded_schema_identity",
                "--test", "embedded_cached_transit",
                "--test", "embedded_lookup_cache",
            ],
            env=embedded_test_env,
            repo_root=repo_root,
            title=f"{next_step}/{total_steps} cargo test (hosted no_std memory behavior)",
            release_build=release_build,
        )
        _success("Hosted no_std memory regression passed.")
        next_step += 1

        if _shared_test_steps:
            run_cmd(
                ["cargo", "test", *build_mode, "--no-default-features",
                 "--features", "std,discovery,timesync",
                 "--test", "packet_packing_memory", "--test", "packet_routing_memory",
                 "--test", "accepted_queue_delivery"],
                env=env, repo_root=repo_root,
                title=f"{next_step}/{total_steps} cargo test (uncompressed forwarding memory)",
                release_build=release_build,
            )
            next_step += 1
            run_cmd(
                cargo_bench_smoke_cmd(),
                env=env,
                repo_root=repo_root,
                title=f"{next_step}/{total_steps} cargo bench (smoke)",
                release_build=True,
            )
            _success("Benchmark smoke pass finished.")
            next_step += 1

        with python_test_environment(repo_root, env, f"python{feature_suffix}", build_mode,
                                     f"{next_step}/{total_steps} host Python extension") as python_env:
            next_step += 1
            run_cmd([sys.executable, str(repo_root / "python_test_runner.py"),
                     *(["--require-bindings"] if test_full else []),
                     *([] if _shared_test_steps else ["--bindings-only"])],
                    env=python_env, repo_root=repo_root,
                    title=f"{next_step}/{total_steps} python unittest")
        _success("Python unittest checks finished against the newly built host extension.")
        next_step += 1

        if test_full:
            # Rust field layout differs between 32-bit x86 and ARM. Check the
            # Python release target even when the host extension is 64-bit;
            # cargo check needs no cross linker or target Python interpreter.
            python_target = "i686-unknown-linux-gnu"
            ensure_rust_target_installed(python_target)
            python_cross_env = dict(env)
            python_cross_env.update(PYO3_CROSS="1", PYO3_CROSS_PYTHON_VERSION="3.9", PYO3_NO_PYTHON="1")
            run_cmd(
                ["cargo", "check", *build_mode, "--target", python_target,
                 "--features", f"python{feature_suffix}"],
                env=python_cross_env, repo_root=repo_root,
                title=f"{next_step}/{total_steps} i686 Python release compile check",
                release_build=release_build,
            )
            next_step += 1

        if can_check_embedded:
            ensure_rust_target_installed(embedded_target)
            apply_embedded_cflags_defaults(embedded_target, env)

            embedded_mode: list[str] = []
            embedded_profile_name = "release" if release_build else "debug"
            uses_custom_profile = False
            if release_build:
                embedded_mode = ["--profile", "release-embedded"]
                embedded_profile_name = "release-embedded"
                uses_custom_profile = True

            before_sizes = collect_artifact_sizes(
                repo_root,
                target=embedded_target,
                profile=embedded_profile_name,
                env=env,
            )

            run_cmd(
                [
                    "cargo",
                    "build",
                    *embedded_mode,
                    "--no-default-features",
                    "--target",
                    embedded_target,
                    "--features",
                    f"embedded{feature_suffix}",
                ],
                env=env,
                repo_root=repo_root,
                title=f"{next_step}/{total_steps} cargo build (embedded feature)",
                target=embedded_target,
                release_build=release_build,
                embedded_profile=uses_custom_profile,
            )

            print(f"info: Embedded output: {cargo_target_directory(repo_root, env=env) / embedded_target / embedded_profile_name}")
            print_artifact_sizes(repo_root, target=embedded_target, profile=embedded_profile_name, env=env)
        else:
            expected = ", ".join(preferred_cross_compilers(embedded_target)) or "CC_<target>/TARGET_CC"
            print(
                "info: Skipping embedded build check in test mode: "
                f"no cross C toolchain found for target `{embedded_target}` "
                f"(expected {expected} or CC_<target>/TARGET_CC override)."
            )

        _success("All test-mode checks passed.")
        return

    # ---- Non-test modes ----
    ensure_rust_target_installed(target if target else ("thumbv7em-none-eabihf" if build_embedded else ""))

    build_args: list[str] = []
    embedded_profile = False
    feature_parts = list(extra_features)
    if build_timesync:
        feature_parts.append("timesync")
    if build_cryptography:
        feature_parts.append("cryptography")
    feature_suffix = ("," + ",".join(feature_parts)) if feature_parts else ""
    build_shared = not build_embedded and not build_python

    if build_embedded:
        if not target:
            print("info: no target specified using thumbv7em-none-eabihf")
            target = "thumbv7em-none-eabihf"
        apply_embedded_cflags_defaults(target, env)
        if not has_embedded_c_toolchain(target, env):
            expected = ", ".join(preferred_cross_compilers(target)) or "CC_<target>/TARGET_CC"
            print(
                "info: embedded cross C toolchain missing; attempting auto-install "
                "(set SEDSNET_INSTALL_C_TOOLCHAIN_CMD to override)."
            )
            if not try_install_embedded_c_toolchain(target, env):
                print(
                    "warning: could not auto-install embedded cross C toolchain; "
                    f"embedded build may fail if C deps are enabled (expected {expected}).",
                    file=sys.stderr,
                )
        build_args = [
            "--no-default-features",
            "--target",
            target,
            "--features",
            f"embedded{feature_suffix}",
        ]
        if release_build:
            build_mode = ["--profile", "release-embedded"]
            embedded_profile = True
            profile_name = "release-embedded"
        else:
            profile_name = "release" if release_build else "debug"

        before_sizes = collect_artifact_sizes(repo_root, target=target, profile=profile_name, env=env)

        run_cmd(
            cargo_lib_build_cmd(build_mode=build_mode, build_args=build_args, build_shared=False),
            env=env,
            repo_root=repo_root,
            title="cargo build (embedded)",
            target=target,
            release_build=release_build,
            embedded_profile=embedded_profile,
        )
        print(f"info: Output: {cargo_target_directory(repo_root, env=env) / target / profile_name}")
        print_artifact_sizes(repo_root, target=target, profile=profile_name, env=env)
        return

    if build_python:
        build_args = ["--features", f"python{feature_suffix}", *(["--target", target] if target else [])]
        run_cmd(
            ["cargo", "build", *build_mode, *build_args],
            env=env,
            repo_root=repo_root,
            title="cargo build (python feature)",
            release_build=release_build,
        )
        _success(f"Build finished. Output is under: {cargo_target_directory(repo_root, env=env)}")
        print_artifact_sizes(
            repo_root,
            target=target,
            profile="release" if release_build else "debug",
            env=env,
        )
        return

    if build_wheel:
        run_cmd(
            ["maturin", "build", *build_mode, *(["--target", target] if target else []), *(["--features", ",".join(feature_parts)] if feature_parts else [])],
            env=env,
            repo_root=repo_root,
            title="maturin build (wheel)",
        )
        _success(f"Wheel build finished. Wheels are in: {cargo_target_directory(repo_root, env=env) / 'wheels'}")
        return

    if develop_wheel:
        run_cmd(
            ["maturin", "develop", *build_mode, *(["--target", target] if target else []), *(["--features", ",".join(feature_parts)] if feature_parts else [])],
            env=env,
            repo_root=repo_root,
            title="maturin develop (installs into env)",
        )
        _success("Develop install finished (installed into your current Python environment).")
        return

    if install_wheel:
        install_wheel_file(build_mode, env=env, repo_root=repo_root, target=target, feature_parts=feature_parts)
        return

    # default: plain cargo build
    if target:
        build_args = ["--target", target]
    if feature_parts:
        build_args.extend(["--features", ",".join(feature_parts)])

    run_cmd(
        cargo_lib_build_cmd(build_mode=build_mode, build_args=build_args, build_shared=build_shared),
        env=env,
        repo_root=repo_root,
        title="cargo build",
        target=target,
        release_build=release_build,
    )
    if target:
        prof = "release" if release_build else "debug"
        _success(f"Build finished. Output: {cargo_target_directory(repo_root, env=env) / target / prof}")
        print_artifact_sizes(repo_root, target=target, profile=prof, env=env)
    else:
        prof = "release" if release_build else "debug"
        _success(f"Build finished. Output: {cargo_target_directory(repo_root, env=env) / prof}")
        print_artifact_sizes(repo_root, target="", profile=prof, env=env)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        print("\n\nexiting...")
        exit(0)
    except Exception as e:
        _fail(f"Unexpected error: {e}")
        _fail("Run `./build.py --help` for usage and available options.")
        raise SystemExit(1) from e
