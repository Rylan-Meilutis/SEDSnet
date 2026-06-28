#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import ssl
from base64 import b64encode
from getpass import getpass
from pathlib import Path

# The line pattern in .gitignore we want to temporarily comment out.
# This is treated as a literal and turned into a whole-line regex.
PYI_IGNORE_LINE = "python-files/sedsnet/sedsnet.pyi"
PYI_IGNORE_REGEX = re.compile(rf"^{re.escape(PYI_IGNORE_LINE)}$")
RELEASE_CONFIG_FILE = ".sedsnet-release.toml"
PYPI_LEGACY_UPLOAD_URL = "https://upload.pypi.org/legacy/"


def print_help(error: str | None = None) -> None:
    out = sys.stderr if error else sys.stdout
    if error:
        print(f"error: {error}\n", file=out)

    print(
        """Usage:
  build.py [OPTIONS]

Options (can be combined where it makes sense):
  release                 Build in release mode.
  check                   Run `cargo clippy` for default, python, and embedded feature variants with `-D warnings`.
  test                    Run Rust tests, a stable Criterion benchmark smoke pass, and validate python +
  embedded build if cross C toolchain exists.
  full                    With `test`, also run long-duration Rust tests marked `#[ignore]`.
  embedded                Build for the embedded target (enables `embedded` feature).
  python                  Build with Python bindings (enables `python` feature).
  timesync                Build with time sync helpers (enables `timesync` feature).
  cryptography             Enable cryptography provider APIs (Rust trait helpers + optional C callbacks).
  maturin-build           Run `maturin build` with the .pyi .gitignore hack.
  maturin-develop         Run `maturin develop` with the .pyi .gitignore hack.
  maturin-install         Build wheel and install it with `uv pip install`.
  maturin-login           Validate and store PyPI/maturin publish credentials in .sedsnet-release.toml.
  target=<triple>         Set Rust compilation target (e.g. target=thumbv7em-none-eabihf).
  device_id=<id>          Set DEVICE_IDENTIFIER env var for the build.
  static_schema_path=<path>      Set SEDSNET_STATIC_SCHEMA_PATH for runtime registry seeding.
  static_ipc_schema_path=<path>  Set SEDSNET_STATIC_IPC_SCHEMA_PATH for runtime IPC overlay seeding.
  max_queue_budget=<n>    Set MAX_QUEUE_BUDGET for the shared router/relay queue budget.
  max_recent_rx_ids=<n>   Set MAX_RECENT_RX_IDS for the preallocated recent-ID cache.

New (compile-time env vars):
  max_stack_payload=<n>   Set MAX_STACK_PAYLOAD for define_stack_payload!(env="MAX_STACK_PAYLOAD", ...).
  env:KEY=VALUE           Set arbitrary environment variable(s) for the build (repeatable).
                          Example: env:MAX_QUEUE_BUDGET=65536 env:QUEUE_GROW_STEP=2.0
  env:SEDSNET_INSTALL_C_TOOLCHAIN_CMD="..."  Optional command used to auto-install
                          cross C toolchain when embedded checks need it.
  env:SEDSNET_EMBEDDED_CFLAGS_AUTO=0         Disable automatic size-oriented CFLAGS/defines
                          injection for embedded C dependencies.
  env:SEDSNET_TEST_RUNNER=auto|nextest|cargo Select Rust test runner for `build.py test`.
                          `auto` uses cargo-nextest when installed and falls back to cargo test.
                          `build.py test full` includes Rust tests marked `#[ignore]`, so future
                          soak tests are included automatically.

Special:
  -h, --help, help        Show this help message and exit.

Examples:
  build.py release
  build.py embedded release target=thumbv7em-none-eabihf
  build.py python
  build.py timesync
  build.py check
  build.py check release
  build.py test
  build.py test full
  build.py test release
  build.py maturin-build max_stack_payload=256
  build.py maturin-login
  build.py maturin-install max_recent_rx_ids=256 env:MAX_STACK_PAYLOAD=128
""",
        file=out,
        end="",
    )
    sys.exit(1 if error else 0)


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


def _toml_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'


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
            raise SystemExit("PyPI rejected the credentials; config was not written.") from e
        # Valid credentials should get a non-auth upload/form error because this validation
        # deliberately does not include a distribution file.
        return
    except urllib.error.URLError as e:
        raise SystemExit(f"Could not validate PyPI credentials: {e}") from e


def write_maturin_login_config(repo_root: Path) -> None:
    config_path = repo_root / RELEASE_CONFIG_FILE
    print(f"Writing PyPI credentials to ignored config: {config_path}")
    print("Use a PyPI API token. Username defaults to __token__.")

    username = os.environ.get("MATURIN_PYPI_USERNAME", "").strip()
    token = os.environ.get("MATURIN_PYPI_TOKEN", "").strip()

    if not username and sys.stdin.isatty():
        entered = input("PyPI username [__token__]: ").strip()
        username = entered or "__token__"
    elif not username:
        username = "__token__"

    if not token and sys.stdin.isatty():
        token = getpass("PyPI API token: ").strip()

    if not token:
        raise SystemExit(
            "No PyPI token provided. Set MATURIN_PYPI_TOKEN or run interactively."
        )

    print("Validating PyPI credentials before saving...")
    validate_pypi_credentials(username, token)

    body = "\n".join(
        [
            "# Local release credentials. This file is ignored by git.",
            "[pypi]",
            f"username = {_toml_string(username)}",
            f"token = {_toml_string(token)}",
            "",
        ]
    )
    config_path.write_text(body, encoding="utf-8")
    config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    _success(f"Saved PyPI credentials to {config_path}")


def shared_lib_name() -> str:
    if sys.platform == "darwin":
        return "libsedsnet.dylib"
    if os.name == "nt":
        return "sedsnet.dll"
    return "libsedsnet.so"


def print_artifact_sizes(repo_root: Path, *, target: str, profile: str) -> None:
    out_dir = repo_root / "target" / target / profile if target else repo_root / "target" / profile
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


def collect_artifact_sizes(repo_root: Path, *, target: str, profile: str) -> dict[str, int]:
    out_dir = repo_root / "target" / target / profile if target else repo_root / "target" / profile
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
    return " ".join(cmd)


def output_hint_for_cmd(
        cmd: list[str],
        *,
        repo_root: Path,
        target: str = "",
        release_build: bool = False,
        embedded_profile: bool = False,
) -> str | None:
    """
    Best-effort output location hint for common commands.
    """
    if not cmd:
        return None

    if cmd[:2] == ["cargo", "test"] or cmd[:3] == ["cargo", "nextest", "run"]:
        # cargo test builds test artifacts (and deps) under target/...
        return f"Build artifacts: {repo_root / 'target'}"

    if cmd[:2] == ["cargo", "bench"]:
        return f"Bench artifacts/results: {repo_root / 'target' / 'criterion'}"

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
                return f"Output: {repo_root / 'target' / tgt / prof}"
            return f"Output: {repo_root / 'target' / prof}"

        # Standard debug/release
        std = "release" if release_build else "debug"
        if embedded_profile:
            # Your embedded release uses --profile release-embedded
            # but if embedded_profile is True we already handled prof above.
            pass
        if tgt:
            return f"Output: {repo_root / 'target' / tgt / std}"
        return f"Output: {repo_root / 'target' / std}"

    if cmd and cmd[0] == "maturin" and len(cmd) >= 2:
        if cmd[1] == "build":
            return f"Wheels: {repo_root / 'target' / 'wheels'}"
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
    cargo_cmd = ["cargo", "test", "--features", feature_arg]
    if include_ignored:
        cargo_cmd.extend(["--", "--include-ignored"])
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
    if title:
        _banner(title)
    else:
        _banner("Running: " + " ".join(cmd))

    hint = output_hint_for_cmd(
        cmd,
        repo_root=repo_root,
        target=target,
        release_build=release_build,
        embedded_profile=embedded_profile,
    )
    if hint:
        print(f"info: {hint}")

    print("Running:", " ".join(cmd))
    t0 = time.monotonic()
    try:
        subprocess.run(cmd, check=True, env=env)
    except FileNotFoundError as e:
        _fail(f"Command not found: {e.filename}")
        _fail(f"While running: {_format_cmd(cmd)}")
        raise SystemExit(127) from e
    except PermissionError as e:
        _fail(f"Permission denied when running command: {e}")
        _fail(f"While running: {_format_cmd(cmd)}")
        raise SystemExit(1) from e
    except subprocess.CalledProcessError as e:
        dt = time.monotonic() - t0
        _fail(f"FAILED ({_fmt_secs(dt)}): {' '.join(cmd)}")
        # Keep the same exit code
        raise SystemExit(e.returncode) from e
    dt = time.monotonic() - t0
    _success(f"OK ({_fmt_secs(dt)}): {' '.join(cmd)}")


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
    print("info: running install command:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
        return True
    except FileNotFoundError as e:
        print(f"warning: install command not found: {e.filename}", file=sys.stderr)
        return False
    except subprocess.CalledProcessError as e:
        print(f"warning: install command failed ({e.returncode}): {' '.join(cmd)}", file=sys.stderr)
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


def apply_embedded_cflags_defaults(target: str, env: dict[str, str]) -> None:
    """
    For embedded cross builds with C deps (e.g. zstd-sys), apply size-oriented
    defaults unless the caller opts out.
    """
    if not target:
        return

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
        "info: applied embedded CFLAGS defaults for size (override with env:CFLAGS... "
        "or disable via env:SEDSNET_EMBEDDED_CFLAGS_AUTO=0)."
    )


def _comment_out_pyi_ignore(gitignore: Path) -> None:
    if not gitignore.exists():
        return

    text = gitignore.read_text(encoding="utf-8").splitlines(keepends=True)
    new_lines = []
    changed = False
    matched_lines = []

    for line in text:
        stripped = line.strip()

        if stripped.startswith("#"):
            new_lines.append(line)
            continue

        if PYI_IGNORE_REGEX.fullmatch(stripped):
            commented = "# " + line.lstrip()
            new_lines.append(commented)
            matched_lines.append(stripped)
            changed = True
        else:
            new_lines.append(line)

    if changed:
        print(f"info: Commented out in .gitignore: {matched_lines}")
        gitignore.write_text("".join(new_lines), encoding="utf-8")


def run_with_pyi_unignored(
        cmd: list[str],
        *,
        env: dict[str, str],
        repo_root: Path,
        title: str | None = None,
) -> None:
    gitignore = Path(".gitignore")
    backup = None

    if title:
        _banner(title)
    else:
        _banner("Running: " + " ".join(cmd))

    hint = output_hint_for_cmd(cmd, repo_root=repo_root)
    if hint:
        print(f"info: {hint}")

    t0 = time.monotonic()
    try:
        if gitignore.exists():
            backup = gitignore.with_name(".gitignore.maturin-backup")
            shutil.copy2(gitignore, backup)

            print(f"info: Temporarily commenting out pattern '{PYI_IGNORE_LINE}' in .gitignore")
            _comment_out_pyi_ignore(gitignore)

        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=True, env=env)
    except FileNotFoundError as e:
        _fail(f"Command not found: {e.filename}")
        _fail(f"While running: {_format_cmd(cmd)}")
        raise SystemExit(127) from e
    except PermissionError as e:
        _fail(f"Permission denied when running command: {e}")
        _fail(f"While running: {_format_cmd(cmd)}")
        raise SystemExit(1) from e

    except subprocess.CalledProcessError as e:
        dt = time.monotonic() - t0
        _fail(f"FAILED ({_fmt_secs(dt)}): {' '.join(cmd)}")
        raise SystemExit(e.returncode) from e

    finally:
        if backup and backup.exists():
            print("info: Restoring original .gitignore")
            shutil.move(backup, gitignore)

    dt = time.monotonic() - t0
    _success(f"OK ({_fmt_secs(dt)}): {' '.join(cmd)}")


def install_wheel_file(build_mode: list[str], *, env: dict[str, str], repo_root: Path) -> None:
    run_with_pyi_unignored(
        ["maturin", "build", *build_mode],
        env=env,
        repo_root=repo_root,
        title="maturin build (wheel)",
    )

    wheels_dir = repo_root / "target" / "wheels"
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
        print(f"info: env override: {k}={v}")


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


def main(argv: list[str]) -> None:
    repo_root = Path(__file__).parent.resolve()
    os.chdir(repo_root)

    build_mode: list[str] = []
    checks = False
    tests = False
    test_full = False
    build_embedded = False
    build_python = False
    build_timesync = False
    build_cryptography = False
    build_wheel = False
    develop_wheel = False
    release_build = False
    install_wheel = False
    maturin_login = False
    target = ""
    device_id = ""
    schema_path = ""
    ipc_schema_path = ""

    env_overrides: dict[str, str] = {}

    for arg in argv:
        if arg in ("-h", "--help", "help"):
            print_help()

        elif arg == "release":
            print("Building release version.")
            release_build = True

        elif arg == "test":
            tests = True

        elif arg == "full":
            test_full = True

        elif arg == "check":
            checks = True

        elif arg == "embedded":
            print("Building for Embedded target.")
            build_embedded = True

        elif arg == "python":
            print("Building Python bindings.")
            build_python = True

        elif arg == "timesync":
            print("Building with time sync helpers.")
            build_timesync = True

        elif arg == "cryptography":
            print("Building with cryptography provider APIs.")
            build_cryptography = True

        elif arg == "maturin-build":
            print("Building Python wheel.")
            build_wheel = True

        elif arg == "maturin-develop":
            print("Building and installing Python wheel in development mode.")
            develop_wheel = True

        elif arg == "maturin-install":
            print("Installing Python wheel.")
            install_wheel = True

        elif arg == "maturin-login":
            maturin_login = True

        elif arg.startswith("target="):
            target = arg.split("=", 1)[1]
            print(f"Target set to: {target}")

        elif arg.startswith("device_id="):
            device_id = arg.split("=", 1)[1]
            print(f"Device identifier set to: {device_id}")

        elif arg.startswith("static_schema_path=") or arg.startswith("schema_path="):
            schema_path = arg.split("=", 1)[1]
            if not schema_path:
                print_help("static_schema_path requires a value")
            env_overrides["SEDSNET_STATIC_SCHEMA_PATH"] = schema_path

        elif arg.startswith("static_ipc_schema_path=") or arg.startswith("ipc_schema_path="):
            ipc_schema_path = arg.split("=", 1)[1]
            if not ipc_schema_path:
                print_help("static_ipc_schema_path requires a value")
            env_overrides["SEDSNET_STATIC_IPC_SCHEMA_PATH"] = ipc_schema_path

        elif arg.startswith("max_stack_payload="):
            v = arg.split("=", 1)[1].strip()
            if not v:
                print_help("max_stack_payload requires a value")
            env_overrides["MAX_STACK_PAYLOAD"] = v

        elif arg.startswith("max_queue_budget="):
            v = arg.split("=", 1)[1].strip()
            if not v:
                print_help("max_queue_budget requires a value")
            env_overrides["MAX_QUEUE_BUDGET"] = v

        elif arg.startswith("max_queue_size="):
            v = arg.split("=", 1)[1].strip()
            if not v:
                print_help("max_queue_size requires a value")
            env_overrides["MAX_QUEUE_BUDGET"] = v

        elif arg.startswith("max_recent_rx_ids="):
            v = arg.split("=", 1)[1].strip()
            if not v:
                print_help("max_recent_rx_ids requires a value")
            env_overrides["MAX_RECENT_RX_IDS"] = v

        elif arg.startswith("env:"):
            rest = arg[4:]
            if "=" not in rest:
                print_help("env:KEY=VALUE requires '='")
            k, v = rest.split("=", 1)
            k = k.strip()
            v = v.strip()
            if not k:
                print_help("env:KEY=VALUE requires a non-empty KEY")
            env_overrides[k] = v

        else:
            print_help(f"Unknown option: {arg}")

    if test_full and not tests:
        print_help("full is only valid with test, e.g. `build.py test full`")

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
        feature_parts = []
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
        feature_parts = ["timesync"]
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
        total_steps = 7 if can_check_embedded else 6

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

        run_cmd(
            cargo_bench_smoke_cmd(),
            env=env,
            repo_root=repo_root,
            title=f"{next_step}/{total_steps} cargo bench (smoke)",
            release_build=True,
        )
        _success("Benchmark smoke pass finished.")
        next_step += 1

        run_cmd(
            ["cargo", "build", "--features", f"python{feature_suffix}", *build_mode],
            env=env,
            repo_root=repo_root,
            title=f"{next_step}/{total_steps} cargo build (python feature)",
            release_build=release_build,
        )
        _success(f"Python-feature build finished. Output is under: {repo_root / 'target'}")
        print_artifact_sizes(
            repo_root,
            target=target,
            profile="release" if release_build else "debug",
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

            print(f"info: Embedded output: {repo_root / 'target' / embedded_target / embedded_profile_name}")
            print_artifact_sizes(repo_root, target=embedded_target, profile=embedded_profile_name)
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
    feature_parts = []
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

        before_sizes = collect_artifact_sizes(repo_root, target=target, profile=profile_name)

        run_cmd(
            cargo_lib_build_cmd(build_mode=build_mode, build_args=build_args, build_shared=False),
            env=env,
            repo_root=repo_root,
            title="cargo build (embedded)",
            target=target,
            release_build=release_build,
            embedded_profile=embedded_profile,
        )
        print(f"info: Output: {repo_root / 'target' / target / profile_name}")
        print_artifact_sizes(repo_root, target=target, profile=profile_name)
        return

    if build_python:
        build_args = ["--features", f"python{feature_suffix}"]
        run_cmd(
            ["cargo", "build", *build_mode, *build_args],
            env=env,
            repo_root=repo_root,
            title="cargo build (python feature)",
            release_build=release_build,
        )
        _success(f"Build finished. Output is under: {repo_root / 'target'}")
        print_artifact_sizes(
            repo_root,
            target=target,
            profile="release" if release_build else "debug",
        )
        return

    if build_wheel:
        run_with_pyi_unignored(
            ["maturin", "build", *build_mode],
            env=env,
            repo_root=repo_root,
            title="maturin build (wheel)",
        )
        _success(f"Wheel build finished. Wheels are in: {repo_root / 'target' / 'wheels'}")
        return

    if develop_wheel:
        run_with_pyi_unignored(
            ["maturin", "develop", *build_mode],
            env=env,
            repo_root=repo_root,
            title="maturin develop (installs into env)",
        )
        _success("Develop install finished (installed into your current Python environment).")
        return

    if install_wheel:
        install_wheel_file(build_mode, env=env, repo_root=repo_root)
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
        _success(f"Build finished. Output: {repo_root / 'target' / target / prof}")
        print_artifact_sizes(repo_root, target=target, profile=prof)
    else:
        prof = "release" if release_build else "debug"
        _success(f"Build finished. Output: {repo_root / 'target' / prof}")
        print_artifact_sizes(repo_root, target="", profile=prof)


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
