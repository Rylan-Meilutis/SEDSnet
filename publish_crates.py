#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    print("error: Python 3.11+ is required for tomllib", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent
MACROS_MANIFEST = REPO_ROOT / "sedsnet_macros" / "Cargo.toml"
MAIN_MANIFEST = REPO_ROOT / "Cargo.toml"
PYPROJECT = REPO_ROOT / "pyproject.toml"
RELEASE_CONFIG = REPO_ROOT / ".sedsnet-release.toml"

DEFAULT_LINUX_DOCKER_TARGETS = [
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "armv7-unknown-linux-gnueabihf",
    "i686-unknown-linux-gnu",
]

DEFAULT_WINDOWS_DOCKER_TARGETS = [
    "x86_64-pc-windows-msvc",
]

DEFAULT_WINDOWS_DOCKER_IMAGE = "rust:bookworm"

MACOS_DOCKER_IMAGES = {
    "x86_64-apple-darwin": "registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/x86_64-apple-darwin:x86_64-apple-darwin",
    "aarch64-apple-darwin": "registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/aarch64-apple-darwin:aarch64-apple-darwin",
}

CARGO_NETWORK_ENV = {
    "CARGO_HTTP_MULTIPLEXING": "false",
    "CARGO_NET_RETRY": "10",
    "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
}

PUBLISH_DRY_RUN_OK = "dry_run_ok"
PUBLISH_PUBLISHED = "published"
PUBLISH_ALREADY_EXISTS = "already_exists"
PUBLISH_FAILED = "failed"


def run(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    display_cmd: list[str] | None = None,
) -> None:
    shown = display_cmd if display_cmd is not None else cmd
    print(f"\n$ {' '.join(shown)}", flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True)


def cargo_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(CARGO_NETWORK_ENV)
    return env


def docker_cargo_env_args() -> list[str]:
    args: list[str] = []
    for key, value in CARGO_NETWORK_ENV.items():
        args.extend(["-e", f"{key}={value}"])
    return args


def run_optional(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout_s: int | None = None,
    display_cmd: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    shown = display_cmd if display_cmd is not None else cmd
    print(f"\n$ {' '.join(shown)}", flush=True)
    try:
        return subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as e:
        output = e.output or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        output += f"\nerror: command timed out after {timeout_s}s\n"
        return subprocess.CompletedProcess(cmd, 124, output)


def capture(cmd: list[str], *, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(cmd, cwd=REPO_ROOT, env=env, text=True).strip()


def manifest_package(manifest: Path) -> tuple[str, str]:
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    pkg = data["package"]
    return str(pkg["name"]), str(pkg["version"])


def pyproject_package(pyproject: Path) -> tuple[str, str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    if "version" in project:
        return str(project["name"]), str(project["version"])
    if "version" in project.get("dynamic", []):
        _, cargo_version = manifest_package(MAIN_MANIFEST)
        return str(project["name"]), cargo_version
    print(
        "error: pyproject.toml must declare project.version or dynamic = [\"version\"].",
        file=sys.stderr,
    )
    sys.exit(1)


def load_pypi_credentials(token_env: str) -> tuple[str | None, str | None]:
    token = os.environ.get(token_env) or os.environ.get("MATURIN_PYPI_TOKEN")
    username = os.environ.get("MATURIN_PYPI_USERNAME") or "__token__"
    if token:
        return username, token
    if not RELEASE_CONFIG.exists():
        return None, None
    data = tomllib.loads(RELEASE_CONFIG.read_text(encoding="utf-8"))
    pypi = data.get("pypi", {})
    username = str(pypi.get("username", "__token__"))
    token_value = pypi.get("token")
    if not token_value:
        return None, None
    return username, str(token_value)


def ensure_pypi_credentials(token_env: str) -> tuple[str | None, str | None]:
    username, token = load_pypi_credentials(token_env)
    if token:
        return username, token
    if not sys.stdin.isatty():
        return None, None
    print(
        f"\nNo PyPI token found in {token_env}, MATURIN_PYPI_TOKEN, or {RELEASE_CONFIG}."
    )
    print("Starting `build.py maturin-login` to validate and save local credentials.")
    run(["python3", "build.py", "maturin-login"])
    return load_pypi_credentials(token_env)


def require_clean_tree(allow_dirty: bool) -> None:
    if allow_dirty:
        return
    status = capture(["git", "status", "--porcelain"])
    if status:
        print(
            "error: working tree is dirty. Commit/stash changes or pass --allow-dirty.\n"
            f"{status}",
            file=sys.stderr,
        )
        sys.exit(1)


def cargo_package(manifest: Path, *, allow_dirty: bool) -> None:
    cmd = ["cargo", "package", "--manifest-path", str(manifest)]
    if allow_dirty:
        cmd.append("--allow-dirty")
    run(cmd, env=cargo_env())


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(
            f"error: required tool `{name}` was not found on PATH. "
            f"Install it first, for example: python3 -m pip install {name}",
            file=sys.stderr,
        )
        sys.exit(1)


def require_python_module(name: str, install_hint: str | None = None) -> None:
    if importlib.util.find_spec(name) is not None:
        return
    hint = install_hint or name
    print(
        f"error: required Python module `{name}` was not found. "
        f"Install it first, for example: python3 -m pip install {hint}",
        file=sys.stderr,
    )
    sys.exit(1)


def cargo_publish(
    manifest: Path,
    *,
    publish: bool,
    allow_dirty: bool,
    token: str | None,
    ignore_errors: bool,
    timeout_s: int,
) -> str:
    crate_name, crate_version = manifest_package(manifest)
    if publish and crate_version_exists(crate_name, crate_version):
        print(f"\n{crate_name} v{crate_version} is already on crates.io; skipping upload.")
        return PUBLISH_ALREADY_EXISTS

    cmd = ["cargo", "publish", "--manifest-path", str(manifest)]
    if not publish:
        cmd.append("--dry-run")
    if allow_dirty:
        cmd.append("--allow-dirty")
    if token:
        cmd.extend(["--token", token])
    if not publish:
        run(cmd, env=cargo_env())
        return PUBLISH_DRY_RUN_OK

    result = run_optional(cmd, env=cargo_env(), timeout_s=timeout_s)
    print(result.stdout, end="")
    if result.returncode == 0:
        return PUBLISH_PUBLISHED
    if is_already_published_output(result.stdout):
        print(f"\n{crate_name} v{crate_version} was already published; continuing.")
        return PUBLISH_ALREADY_EXISTS
    if ignore_errors:
        print(
            f"\nwarning: cargo publish failed for {crate_name} v{crate_version}; "
            "continuing because --ignore-publish-errors was passed.",
            file=sys.stderr,
        )
        return PUBLISH_FAILED
    raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout)


def maturin_build() -> None:
    require_tool("maturin")
    run(["maturin", "build", "--release", "--compatibility", "pypi"], env=cargo_env())


def docker_maturin_build(
    *,
    image: str,
    targets: list[str],
    out_dir: str,
    use_zig: bool,
) -> None:
    require_tool("docker")
    for target in targets:
        maturin_cmd = [
            "maturin",
            "build",
            "--release",
            "--compatibility",
            "pypi",
            "--out",
            out_dir,
            "--target",
            target,
        ]
        if use_zig:
            maturin_cmd.append("--zig")

        shell_cmd = "cd /io && "
        if use_zig:
            shell_cmd += "python3 -m pip install ziglang && "
        shell_cmd += f"rustup target add {shlex.quote(target)} && "
        shell_cmd += " ".join(shlex.quote(part) for part in maturin_cmd)

        cmd = [
            "docker",
            "run",
            "--rm",
            *docker_cargo_env_args(),
            "-v",
            f"{REPO_ROOT}:/io",
            "--entrypoint",
            "bash",
            image,
            "-lc",
            shell_cmd,
        ]
        run(cmd)


def docker_maturin_sdist(*, image: str, out_dir: str) -> None:
    require_tool("docker")
    run(
        [
            "docker",
            "run",
            "--rm",
            *docker_cargo_env_args(),
            "-v",
            f"{REPO_ROOT}:/io",
            image,
            "sdist",
            "--out",
            out_dir,
        ]
    )


def docker_maturin_windows_build(
    *,
    image: str,
    targets: list[str],
    out_dir: str,
) -> None:
    require_tool("docker")
    for target in targets:
        maturin_cmd = [
            "maturin",
            "build",
            "--release",
            "--compatibility",
            "pypi",
            "--out",
            out_dir,
            "--target",
            target,
        ]
        shell_cmd = (
            "set -e; "
            "apt-get update >/dev/null; "
            "apt-get install -y clang lld llvm python3-pip curl ca-certificates >/dev/null; "
            "ln -sf $(command -v clang) /usr/local/bin/clang-cl; "
            "curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal >/tmp/rustup.log; "
            "source /usr/local/cargo/env; "
            "python3 -m pip install --break-system-packages maturin >/dev/null; "
            f"cd /io; rustup target add {shlex.quote(target)}; "
            + " ".join(shlex.quote(part) for part in maturin_cmd)
        )
        run(
            [
                "docker",
                "run",
                "--rm",
                *docker_cargo_env_args(),
                "-v",
                f"{REPO_ROOT}:/io",
                image,
                "bash",
                "-lc",
                shell_cmd,
            ]
        )


def local_maturin_macos_build(*, targets: list[str], out_dir: str) -> None:
    require_tool("maturin")
    require_tool("rustup")
    for target in targets:
        run(["rustup", "target", "add", target])
        run(
            [
                "maturin",
                "build",
                "--release",
                "--compatibility",
                "pypi",
                "--out",
                out_dir,
                "--target",
                target,
            ],
            env=cargo_env(),
        )


def macos_linker_prefix(target: str) -> str:
    if target == "x86_64-apple-darwin":
        return "x86_64-apple-darwin21.4"
    if target == "aarch64-apple-darwin":
        return "aarch64-apple-darwin21.4"
    raise SystemExit(f"No configured macOS linker prefix for target {target}")


def docker_maturin_macos_build(*, targets: list[str], out_dir: str) -> None:
    require_tool("docker")
    for target in targets:
        image = MACOS_DOCKER_IMAGES.get(target)
        if image is None:
            raise SystemExit(f"No configured macOS Docker image for target {target}")
        linker_prefix = macos_linker_prefix(target)
        rustflags = (
            "-C link-arg=-undefined "
            "-C link-arg=dynamic_lookup"
        )
        shell_cmd = (
            "set -e; "
            "export PATH=/opt/osxcross/bin:$HOME/.cargo/bin:/usr/local/cargo/bin:$PATH; "
            "apt-get update >/dev/null; "
            "apt-get install -y python3-pip curl ca-certificates >/dev/null; "
            "curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal >/tmp/rustup.log; "
            "source $HOME/.cargo/env; "
            "python3 -m pip install maturin >/dev/null; "
            f"cd /io; rustup target add {shlex.quote(target)}; "
            f"export CC_{target.replace('-', '_')}={shlex.quote(linker_prefix + '-clang')}; "
            f"export CXX_{target.replace('-', '_')}={shlex.quote(linker_prefix + '-clang++')}; "
            f"export AR_{target.replace('-', '_')}={shlex.quote(linker_prefix + '-ar')}; "
            f"export CARGO_TARGET_{target.replace('-', '_').upper()}_LINKER={shlex.quote(linker_prefix + '-clang')}; "
            f"export CARGO_TARGET_{target.replace('-', '_').upper()}_AR={shlex.quote(linker_prefix + '-ar')}; "
            f"export CARGO_TARGET_{target.replace('-', '_').upper()}_RUSTFLAGS={shlex.quote(rustflags)}; "
            "maturin build --release --compatibility pypi "
            f"--out {shlex.quote(out_dir)} --target {shlex.quote(target)}"
        )
        try:
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    *docker_cargo_env_args(),
                    "-v",
                    f"{REPO_ROOT}:/io",
                    image,
                    "bash",
                    "-lc",
                    shell_cmd,
                ]
            )
        except subprocess.CalledProcessError:
            if platform.system() != "Darwin":
                raise
            print(
                "\nmacOS Docker image was unavailable; falling back to local macOS maturin build "
                f"for {target}."
            )
            local_maturin_macos_build(targets=[target], out_dir=out_dir)


def pypi_artifacts_from_dir(out_dir: str) -> list[Path]:
    root = REPO_ROOT / out_dir
    artifacts = sorted([*root.glob("*.whl"), *root.glob("*.tar.gz")])
    return artifacts


def twine_upload(
    *,
    token_env: str,
    skip_existing: bool,
    username: str | None,
    token: str | None,
    artifacts: list[Path],
) -> None:
    require_python_module("twine")
    if not artifacts:
        raise SystemExit("No PyPI artifacts found to upload.")
    cmd = [sys.executable, "-m", "twine", "upload"]
    if skip_existing:
        cmd.append("--skip-existing")
    if token:
        cmd.extend(["--username", username or "__token__", "--password", token])
    cmd.extend(str(path) for path in artifacts)
    display_cmd = list(cmd)
    if token and "--password" in display_cmd:
        idx = display_cmd.index("--password")
        if idx + 1 < len(display_cmd):
            display_cmd[idx + 1] = "<redacted>"
    result = run_optional(cmd, display_cmd=display_cmd)
    print(result.stdout, end="")
    if result.returncode == 0:
        return
    if skip_existing and is_already_published_output(result.stdout):
        print("\nPyPI artifacts already exist; continuing.")
        return
    raise subprocess.CalledProcessError(result.returncode, cmd, output=result.stdout)


def build_local_pypi_artifacts(out_dir: str) -> list[Path]:
    require_tool("maturin")
    run(
        ["maturin", "build", "--release", "--compatibility", "pypi", "--out", out_dir],
        env=cargo_env(),
    )
    run(["maturin", "sdist", "--out", out_dir], env=cargo_env())
    return pypi_artifacts_from_dir(out_dir)


def cargo_search_output(crate_name: str) -> str:
    return capture(["cargo", "search", crate_name, "--limit", "10"], env=cargo_env())


def cargo_search(crate_name: str) -> bool:
    try:
        out = cargo_search_output(crate_name)
    except subprocess.CalledProcessError:
        return False
    needle = f"{crate_name} ="
    return any(line.startswith(needle) for line in out.splitlines())


def crate_version_exists(crate_name: str, version: str) -> bool:
    try:
        out = cargo_search_output(crate_name)
    except subprocess.CalledProcessError:
        return False
    pattern = re.compile(rf"^{re.escape(crate_name)}\s*=\s*\"{re.escape(version)}\"")
    return any(pattern.match(line) for line in out.splitlines())


def is_already_published_output(output: str) -> bool:
    lowered = output.lower()
    return (
        "already uploaded" in lowered
        or "already exists" in lowered
        or "crate version" in lowered and "is already uploaded" in lowered
        or "file already exists" in lowered
        or "400 bad request" in lowered and "already" in lowered
    )


def wait_for_index(crate_name: str, version: str, timeout_s: int, interval_s: int) -> bool:
    deadline = time.monotonic() + timeout_s
    print(f"\nWaiting for crates.io index to expose {crate_name} v{version}...")
    while time.monotonic() < deadline:
        if crate_version_exists(crate_name, version):
            print(f"crates.io index can see {crate_name} v{version}; continuing.")
            return True
        print(f"{crate_name} not visible yet; sleeping {interval_s}s...")
        time.sleep(interval_s)
    print(
        f"error: timed out waiting for {crate_name} in crates.io index. "
        "Retry the main crate publish after the index catches up.",
        file=sys.stderr,
    )
    return False


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build/package/publish SEDSnet crates in the required order. "
            "Default mode is a dry-run and will not upload anything."
        )
    )
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Actually upload crates to crates.io. Without this, cargo publish uses --dry-run.",
    )
    parser.add_argument(
        "--skip-crates",
        action="store_true",
        help="Skip all crates.io package/publish steps.",
    )
    parser.add_argument(
        "--pypi",
        action="store_true",
        help="Build the Python wheel with maturin build. This does not upload to PyPI.",
    )
    parser.add_argument(
        "--publish-pypi",
        action="store_true",
        help="Build/upload the Python package to PyPI with twine.",
    )
    parser.add_argument(
        "--docker-wheels",
        action="store_true",
        help="Build Linux Python wheels in Docker using the maturin manylinux image.",
    )
    parser.add_argument(
        "--docker-windows-wheels",
        action="store_true",
        help="Build Windows Python wheels in Docker using maturin's Windows cross support.",
    )
    parser.add_argument(
        "--docker-all-wheels",
        action="store_true",
        help="Build Linux, Windows, and macOS Docker wheels.",
    )
    parser.add_argument(
        "--docker-sdist",
        action="store_true",
        help="Build the Python source distribution in Docker.",
    )
    parser.add_argument(
        "--docker-macos-wheels",
        action="store_true",
        help="Build macOS Python wheels in Docker using the same osxcross images as SmartCopy.",
    )
    parser.add_argument(
        "--docker-macos-target",
        action="append",
        dest="docker_macos_targets",
        help="macOS Rust target triple for Docker wheel builds. Repeatable.",
    )
    parser.add_argument(
        "--docker-image",
        default="ghcr.io/pyo3/maturin:latest",
        help="Docker image used for --docker-wheels/--docker-sdist.",
    )
    parser.add_argument(
        "--docker-target",
        action="append",
        dest="docker_targets",
        help=(
            "Linux Rust target triple for Docker wheel builds. Repeatable. "
            "Defaults to x86_64/aarch64/armv7/i686 GNU Linux targets."
        ),
    )
    parser.add_argument(
        "--docker-windows-target",
        action="append",
        dest="docker_windows_targets",
        help=(
            "Windows Rust target triple for Docker wheel builds. Repeatable. "
            "Defaults to x86_64-pc-windows-msvc."
        ),
    )
    parser.add_argument(
        "--docker-windows-image",
        default=DEFAULT_WINDOWS_DOCKER_IMAGE,
        help="Docker image used for Windows cross wheel builds.",
    )
    parser.add_argument(
        "--docker-no-zig",
        action="store_true",
        help="Do not pass --zig to Docker maturin builds.",
    )
    parser.add_argument(
        "--wheel-out",
        default="dist",
        help="Wheel/sdist output directory for Docker builds. Defaults to dist.",
    )
    parser.add_argument(
        "--pypi-token-env",
        default="MATURIN_PYPI_TOKEN",
        help="Environment variable containing the PyPI API token. Defaults to MATURIN_PYPI_TOKEN.",
    )
    parser.add_argument(
        "--pypi-skip-existing",
        dest="pypi_skip_existing",
        action="store_true",
        default=True,
        help="Pass --skip-existing to twine upload. This is the default.",
    )
    parser.add_argument(
        "--pypi-no-skip-existing",
        dest="pypi_skip_existing",
        action="store_false",
        help="Fail PyPI publish when an artifact already exists.",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip the build.py test route.",
    )
    parser.add_argument(
        "--quick-tests",
        action="store_true",
        help="Run python3 build.py test instead of python3 build.py test full.",
    )
    parser.add_argument(
        "--skip-package",
        action="store_true",
        help="Skip cargo package checks before publish/dry-run.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow a dirty git tree and pass --allow-dirty to cargo package/publish.",
    )
    parser.add_argument(
        "--token-env",
        default="CARGO_REGISTRY_TOKEN",
        help="Environment variable containing the crates.io token. Defaults to CARGO_REGISTRY_TOKEN.",
    )
    parser.add_argument(
        "--skip-publish-without-token",
        action="store_true",
        help=(
            "When --publish is passed but the crates.io token env var is missing, run package "
            "checks and skip crates.io uploads instead of relying on a local cargo login token."
        ),
    )
    parser.add_argument(
        "--ignore-publish-errors",
        action="store_true",
        help="Treat crates.io upload failures as warnings after package checks have passed.",
    )
    parser.add_argument(
        "--publish-timeout",
        type=int,
        default=180,
        help="Seconds to allow each cargo publish upload attempt before timing out.",
    )
    parser.add_argument(
        "--index-timeout",
        type=int,
        default=300,
        help="Seconds to wait for sedsnet_macros to appear in the crates.io index after publishing.",
    )
    parser.add_argument(
        "--index-interval",
        type=int,
        default=15,
        help="Seconds between crates.io index checks.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    macro_name, macro_version = manifest_package(MACROS_MANIFEST)
    main_name, main_version = manifest_package(MAIN_MANIFEST)
    py_name, py_version = pyproject_package(PYPROJECT)
    token = os.environ.get(args.token_env)

    require_clean_tree(args.allow_dirty)

    print(f"Preparing {macro_name} v{macro_version} and {main_name} v{main_version}.")
    print(f"Python package metadata: {py_name} v{py_version}.")
    if args.skip_crates:
        print("Skipping crates.io steps.")
    elif args.publish:
        print("Publish mode: crates will be uploaded to crates.io.")
        if not token and args.skip_publish_without_token:
            print(
                f"warning: {args.token_env} is not set; package checks will run but crates.io "
                "uploads will be skipped."
            )
            args.publish = False
        elif not token:
            print(
                f"info: {args.token_env} is not set; cargo will use your saved cargo login token."
            )
    else:
        print("Dry-run mode: no crates will be uploaded. Pass --publish to upload.")

    if not args.skip_tests:
        test_cmd = ["python3", "build.py", "test"]
        if not args.quick_tests:
            test_cmd.append("full")
        run(test_cmd)

    if not args.skip_crates:
        if not args.skip_package:
            cargo_package(MACROS_MANIFEST, allow_dirty=args.allow_dirty)

        macro_publish_status = cargo_publish(
            MACROS_MANIFEST,
            publish=args.publish,
            allow_dirty=args.allow_dirty,
            token=token,
            ignore_errors=args.ignore_publish_errors,
            timeout_s=args.publish_timeout,
        )

        if args.publish and macro_publish_status == PUBLISH_PUBLISHED:
            index_ready = wait_for_index(
                macro_name,
                macro_version,
                timeout_s=args.index_timeout,
                interval_s=args.index_interval,
            )
            if not index_ready:
                if args.ignore_publish_errors:
                    print(
                        f"\nwarning: skipping {main_name} publish because {macro_name} "
                        "is not visible in the crates.io index yet.",
                        file=sys.stderr,
                    )
                    return 0
                return 1
        elif args.publish and macro_publish_status == PUBLISH_ALREADY_EXISTS:
            print(
                f"\n{macro_name} v{macro_version} is already published; "
                "skipping crates.io index wait."
            )
        elif args.publish:
            print(
                f"\nSkipping {main_name} publish because {macro_name} upload did not complete."
            )
            return 0
        else:
            if not cargo_search(macro_name):
                print(
                    "\nSkipping main crate dry-run publish because crates.io cannot resolve "
                    f"{macro_name} v{macro_version} until it is actually published."
                )
                print("Run this script with --publish to publish both crates in order.")
            else:
                print(
                    f"\n{macro_name} is already visible in crates.io; dry-running main crate too."
                )

        if args.publish or cargo_search(macro_name):
            if not args.skip_package:
                cargo_package(MAIN_MANIFEST, allow_dirty=args.allow_dirty)

            main_publish_status = cargo_publish(
                MAIN_MANIFEST,
                publish=args.publish,
                allow_dirty=args.allow_dirty,
                token=token,
                ignore_errors=args.ignore_publish_errors,
                timeout_s=args.publish_timeout,
            )

            if args.publish:
                if main_publish_status == PUBLISH_PUBLISHED:
                    print(
                        f"\nPublished {macro_name} v{macro_version} and "
                        f"{main_name} v{main_version}."
                    )
                elif main_publish_status == PUBLISH_ALREADY_EXISTS:
                    print(f"\n{main_name} v{main_version} is already published.")
                else:
                    print(
                        f"\n{main_name} v{main_version} was not uploaded; "
                        "continuing because --ignore-publish-errors was passed."
                    )

    if args.docker_all_wheels:
        args.docker_wheels = True
        args.docker_windows_wheels = True
        args.docker_macos_wheels = True

    built_pypi_artifacts = False

    if args.docker_wheels:
        targets = args.docker_targets or DEFAULT_LINUX_DOCKER_TARGETS
        print(f"\nBuilding Docker manylinux wheels into {args.wheel_out}:")
        for target in targets:
            print(f"  - {target}")
        docker_maturin_build(
            image=args.docker_image,
            targets=targets,
            out_dir=args.wheel_out,
            use_zig=not args.docker_no_zig,
        )
        built_pypi_artifacts = True

    if args.docker_windows_wheels:
        targets = args.docker_windows_targets or DEFAULT_WINDOWS_DOCKER_TARGETS
        print(f"\nBuilding Docker Windows wheels into {args.wheel_out}:")
        for target in targets:
            print(f"  - {target}")
        docker_maturin_windows_build(
            image=args.docker_windows_image,
            targets=targets,
            out_dir=args.wheel_out,
        )
        built_pypi_artifacts = True

    if args.docker_sdist:
        print(f"\nBuilding Docker source distribution into {args.wheel_out}.")
        docker_maturin_sdist(image=args.docker_image, out_dir=args.wheel_out)
        built_pypi_artifacts = True

    if args.docker_macos_wheels:
        targets = args.docker_macos_targets or list(MACOS_DOCKER_IMAGES)
        print(f"\nBuilding Docker macOS wheels into {args.wheel_out}:")
        for target in targets:
            print(f"  - {target}")
        docker_maturin_macos_build(targets=targets, out_dir=args.wheel_out)
        built_pypi_artifacts = True

    if args.pypi or args.publish_pypi:
        if args.publish_pypi:
            print(f"\nPyPI publish mode: {py_name} v{py_version} will be uploaded.")
            pypi_username, pypi_token = ensure_pypi_credentials(args.pypi_token_env)
            if not pypi_token:
                raise SystemExit(
                    "No PyPI credentials available. Run `python3 build.py maturin-login` first."
                )
            if built_pypi_artifacts:
                artifacts = pypi_artifacts_from_dir(args.wheel_out)
            else:
                with tempfile.TemporaryDirectory(prefix="sedsnet-pypi-") as tmp:
                    artifacts = build_local_pypi_artifacts(tmp)
                    twine_upload(
                        token_env=args.pypi_token_env,
                        skip_existing=args.pypi_skip_existing,
                        username=pypi_username,
                        token=pypi_token,
                        artifacts=artifacts,
                    )
                    print(f"\nPublished Python package {py_name} v{py_version}.")
                    return 0
            twine_upload(
                token_env=args.pypi_token_env,
                skip_existing=args.pypi_skip_existing,
                username=pypi_username,
                token=pypi_token,
                artifacts=artifacts,
            )
            print(f"\nPublished Python package {py_name} v{py_version}.")
        else:
            print(f"\nBuilding Python wheel for {py_name} v{py_version}.")
            maturin_build()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
