#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def _cmd_text(cmd: List[str]) -> str:
    return " ".join(cmd)


def _hint_for_cmd(cmd: List[str], returncode: int) -> str | None:
    if not cmd or cmd[0] != "git":
        return None
    if cmd[:3] == ["git", "config", "--get"]:
        key = cmd[-1] if cmd else "<key>"
        return f"Set it with `git config {key} <value>` from the super-repo root."
    if cmd[:4] == ["git", "submodule", "update", "--init"]:
        return "Verify the submodule path exists in `.gitmodules`, then run `git submodule sync --recursive`."
    if cmd[:2] == ["git", "fetch"]:
        return "Check remote/branch names and auth. Try `git remote -v` and fetch manually."
    if cmd[:2] == ["git", "checkout"]:
        return "Ensure the branch exists upstream and your worktree has no conflicting local changes."
    if cmd[:3] == ["git", "merge", "--ff-only"]:
        return "Local branch diverged. Rebase/reset the submodule branch or resolve divergence manually."
    if cmd[:2] == ["git", "commit"]:
        return "Ensure git user.name/user.email are configured and there are staged changes."
    return f"Run `{_cmd_text(cmd)}` manually for full git output."


def run(cmd: List[str], *, capture: bool = False, cwd: Optional[Path] = None) -> str | None:
    """Run a command. Optionally capture stdout."""
    cmd_display = _cmd_text(cmd)
    run_cwd = str(cwd) if cwd is not None else None
    where = f" (cwd={cwd})" if cwd is not None else ""
    print("Running:", cmd_display)
    try:
        if capture:
            result = subprocess.run(
                cmd,
                check=True,
                text=True,
                capture_output=True,
                cwd=run_cwd,
            )
            return result.stdout.strip()
        subprocess.run(cmd, check=True, cwd=run_cwd)
        return None
    except FileNotFoundError as e:
        raise SystemExit(
            f"Required command '{e.filename}' was not found while running: {cmd_display}{where}. "
            "Install git and ensure it is on your PATH."
        ) from e
    except subprocess.CalledProcessError as e:
        hint = _hint_for_cmd(cmd, e.returncode)
        raise SystemExit(
            f"Command failed with exit code {e.returncode}: {cmd_display}{where}"
            + (f". Hint: {hint}" if hint else "")
        ) from e


def get_config(key: str) -> str:
    """Get a git config value or die with a friendly message."""
    value = run(["git", "config", "--get", key], capture=True)
    if not value:
        raise SystemExit(
            f"Empty git config key: {key}. "
            f"Set it with `git config {key} <value>`."
        )
    return value


def is_git_repo(path: Path) -> bool:
    """
    Detect whether `path` is a git repository (normal repo, submodule, or worktree).
    """
    if (path / ".git").is_dir():
        return True
    if (path / ".git").is_file():  # submodules / worktrees
        return True

    # Fallback: ask git directly
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=path,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError as e:
        raise SystemExit(
            "Required command 'git' was not found while checking repository state."
        ) from e


def main() -> None:
    # Script lives in <repo_root>/sedsnet/update_submodule.py
    script_dir = Path(__file__).parent.resolve()
    repo_root = script_dir.parent
    os.chdir(repo_root)

    prefix = "sedsnet"
    submodule_path = repo_root / prefix

    # --- Safety checks -----------------------------------------------------

    # Ensure path exists
    if not submodule_path.exists():
        raise SystemExit(
            f"Path '{prefix}' does not exist. "
            "Run this script from the expected super-repo layout containing that submodule path."
        )

    # Ensure it is a git repo (i.e., not a subtree)
    if not is_git_repo(submodule_path):
        raise SystemExit(
            f"'{prefix}' is NOT a git repository.\n"
            "This looks like a subtree or a plain directory.\n"
            "Refusing to run submodule update logic.\n"
            "Hint: Use `subtree_update_no_stash.py` if this checkout uses a subtree."
        )

    # Ensure it is actually registered as a submodule
    try:
        get_config(f"submodule.{prefix}.url")
    except SystemExit:
        raise SystemExit(
            f"'{prefix}' is a git repo, but NOT registered as a submodule.\n"
            "If this is a subtree, use the subtree updater instead.\n"
            f"Otherwise add/fix `submodule.{prefix}.url` and `submodule.{prefix}.branch` in git config."
        )

    # --- Normal submodule update logic ------------------------------------

    url = get_config(f"submodule.{prefix}.url")
    branch = get_config(f"submodule.{prefix}.branch")

    print(f"Updating submodule: {prefix}")
    print(f"  url:    {url}")
    print(f"  branch: {branch}")

    # Ensure the submodule is initialized
    run(["git", "submodule", "update", "--init", "--", prefix])

    # Fetch latest from origin
    run(["git", "fetch", "origin", branch], cwd=submodule_path)

    # Ensure correct branch
    existing = run(["git", "branch", "--list", branch], capture=True, cwd=submodule_path)
    if existing:
        run(["git", "checkout", branch], cwd=submodule_path)
    else:
        run(["git", "checkout", "-b", branch, f"origin/{branch}"], cwd=submodule_path)

    # Fast-forward only
    run(["git", "merge", "--ff-only", f"origin/{branch}"], cwd=submodule_path)

    # Stage submodule pointer
    run(["git", "add", prefix])

    # Commit only if changed
    try:
        diff_proc = subprocess.run(
            ["git", "diff", "--cached", "--quiet", "--", prefix]
        )
    except FileNotFoundError as e:
        raise SystemExit(
            "Required command 'git' was not found while checking staged changes. "
            "Install git and ensure it is on your PATH."
        ) from e
    if diff_proc.returncode == 0:
        print("Submodule is already at latest commit; nothing to commit.")
        return

    commit_msg = f"chore(submodule): Update submodule {prefix} to latest {branch}"
    run(["git", "commit", "-m", commit_msg])
    print("Done:", commit_msg)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nexiting...")
        exit(0)
    except Exception as e:
        print(f"Error: Unexpected failure: {e}", file=sys.stderr)
        raise SystemExit(1) from e
