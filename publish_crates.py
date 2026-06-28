#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
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
    "i686-pc-windows-msvc",
    "x86_64-pc-windows-msvc",
]

MACOS_DOCKER_IMAGES = {
    "x86_64-apple-darwin": "registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/x86_64-apple-darwin:x86_64-apple-darwin",
    "aarch64-apple-darwin": "registry.gitlab.rylanswebsite.com/rylan-meilutis/macos-cargo-image/aarch64-apple-darwin:aarch64-apple-darwin",
}


def run(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    display_cmd: list[str] | None = None,
) -> None:
    shown = display_cmd if display_cmd is not None else cmd
    print(f"\n$ {' '.join(shown)}", flush=True)
    subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=True)


def capture(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, cwd=REPO_ROOT, text=True).strip()


def manifest_package(manifest: Path) -> tuple[str, str]:
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    pkg = data["package"]
    return str(pkg["name"]), str(pkg["version"])


def pyproject_package(pyproject: Path) -> tuple[str, str]:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    return str(project["name"]), str(project["version"])


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
    run(cmd)


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(
            f"error: required tool `{name}` was not found on PATH. "
            f"Install it first, for example: python3 -m pip install {name}",
            file=sys.stderr,
        )
        sys.exit(1)


def cargo_publish(
    manifest: Path,
    *,
    publish: bool,
    allow_dirty: bool,
    token: str | None,
) -> None:
    cmd = ["cargo", "publish", "--manifest-path", str(manifest)]
    if not publish:
        cmd.append("--dry-run")
    if allow_dirty:
        cmd.append("--allow-dirty")
    if token:
        cmd.extend(["--token", token])
    run(cmd)


def maturin_build() -> None:
    require_tool("maturin")
    run(["maturin", "build", "--release", "--compatibility", "pypi"])


def docker_maturin_build(
    *,
    image: str,
    targets: list[str],
    out_dir: str,
    use_zig: bool,
) -> None:
    require_tool("docker")
    for target in targets:
        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{REPO_ROOT}:/io",
            image,
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
            cmd.append("--zig")
        run(cmd)


def docker_maturin_sdist(*, image: str, out_dir: str) -> None:
    require_tool("docker")
    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{REPO_ROOT}:/io",
            image,
            "sdist",
            "--out",
            out_dir,
        ]
    )


def docker_maturin_macos_build(*, targets: list[str], out_dir: str) -> None:
    require_tool("docker")
    for target in targets:
        image = MACOS_DOCKER_IMAGES.get(target)
        if image is None:
            raise SystemExit(f"No configured macOS Docker image for target {target}")
        run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{REPO_ROOT}:/io",
                image,
                "bash",
                "-lc",
                "cd /io && (python3 -m pip install maturin || pip3 install maturin) && "
                f"maturin build --release --compatibility pypi --out {out_dir} --target {target}",
            ]
        )


def maturin_publish(
    *,
    token_env: str,
    skip_existing: bool,
    username: str | None,
    token: str | None,
) -> None:
    require_tool("maturin")
    cmd = ["maturin", "publish"]
    if token:
        cmd.extend(["--username", username or "__token__", "--password", token])
    if skip_existing:
        cmd.append("--skip-existing")
    display_cmd = list(cmd)
    if token and "--password" in display_cmd:
        idx = display_cmd.index("--password")
        if idx + 1 < len(display_cmd):
            display_cmd[idx + 1] = "<redacted>"
    run(cmd, display_cmd=display_cmd)


def cargo_search(crate_name: str) -> bool:
    try:
        out = capture(["cargo", "search", crate_name, "--limit", "5"])
    except subprocess.CalledProcessError:
        return False
    needle = f"{crate_name} ="
    return any(line.startswith(needle) for line in out.splitlines())


def wait_for_index(crate_name: str, version: str, timeout_s: int, interval_s: int) -> None:
    deadline = time.monotonic() + timeout_s
    print(f"\nWaiting for crates.io index to expose {crate_name} v{version}...")
    while time.monotonic() < deadline:
        if cargo_search(crate_name):
            print(f"crates.io index can see {crate_name}; continuing.")
            return
        print(f"{crate_name} not visible yet; sleeping {interval_s}s...")
        time.sleep(interval_s)
    print(
        f"error: timed out waiting for {crate_name} in crates.io index. "
        "Retry the main crate publish after the index catches up.",
        file=sys.stderr,
    )
    sys.exit(1)


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
        help="Upload the Python package to PyPI with maturin publish.",
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
        help="Windows Rust target triple for Docker wheel builds. Repeatable.",
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
        action="store_true",
        help="Pass --skip-existing to maturin publish.",
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
        if not token:
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

        cargo_publish(
            MACROS_MANIFEST,
            publish=args.publish,
            allow_dirty=args.allow_dirty,
            token=token,
        )

        if args.publish:
            wait_for_index(
                macro_name,
                macro_version,
                timeout_s=args.index_timeout,
                interval_s=args.index_interval,
            )
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

            cargo_publish(
                MAIN_MANIFEST,
                publish=args.publish,
                allow_dirty=args.allow_dirty,
                token=token,
            )

            if args.publish:
                print(
                    f"\nPublished {macro_name} v{macro_version} and {main_name} v{main_version}."
                )

    if args.docker_all_wheels:
        args.docker_wheels = True
        args.docker_windows_wheels = True
        args.docker_macos_wheels = True

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

    if args.docker_windows_wheels:
        targets = args.docker_windows_targets or DEFAULT_WINDOWS_DOCKER_TARGETS
        print(f"\nBuilding Docker Windows wheels into {args.wheel_out}:")
        for target in targets:
            print(f"  - {target}")
        docker_maturin_build(
            image=args.docker_image,
            targets=targets,
            out_dir=args.wheel_out,
            use_zig=False,
        )

    if args.docker_sdist:
        print(f"\nBuilding Docker source distribution into {args.wheel_out}.")
        docker_maturin_sdist(image=args.docker_image, out_dir=args.wheel_out)

    if args.docker_macos_wheels:
        targets = args.docker_macos_targets or list(MACOS_DOCKER_IMAGES)
        print(f"\nBuilding Docker macOS wheels into {args.wheel_out}:")
        for target in targets:
            print(f"  - {target}")
        docker_maturin_macos_build(targets=targets, out_dir=args.wheel_out)

    if args.pypi or args.publish_pypi:
        if args.publish_pypi:
            print(f"\nPyPI publish mode: {py_name} v{py_version} will be uploaded.")
            pypi_username, pypi_token = ensure_pypi_credentials(args.pypi_token_env)
            if not pypi_token:
                raise SystemExit(
                    "No PyPI credentials available. Run `python3 build.py maturin-login` first."
                )
            maturin_publish(
                token_env=args.pypi_token_env,
                skip_existing=args.pypi_skip_existing,
                username=pypi_username,
                token=pypi_token,
            )
            print(f"\nPublished Python package {py_name} v{py_version}.")
        else:
            print(f"\nBuilding Python wheel for {py_name} v{py_version}.")
            maturin_build()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
