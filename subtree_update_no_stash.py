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
    if cmd[:2] == ["git", "fetch"]:
        return "Check that remote `sedsnet-upstream` exists (`git remote -v`) and auth/network are valid."
    if cmd[:2] == ["git", "subtree"]:
        return "Confirm prefix/branch are correct and worktree is clean. Try the same git subtree command manually."
    return f"Run `{_cmd_text(cmd)}` manually for full git output."


def run(cmd: List[str], *, capture: bool = False) -> Optional[str]:
    """Run a command. Optionally capture stdout."""
    cmd_display = _cmd_text(cmd)
    print("Running:", cmd_display)
    try:
        if capture:
            result = subprocess.run(cmd, check=True, text=True, capture_output=True)
            return result.stdout.strip()
        subprocess.run(cmd, check=True)
        return None
    except FileNotFoundError as e:
        raise SystemExit(
            f"Required command '{e.filename}' was not found while running: {cmd_display}. "
            "Install git and ensure it is on your PATH."
        ) from e
    except subprocess.CalledProcessError as e:
        hint = _hint_for_cmd(cmd, e.returncode)
        raise SystemExit(
            f"Command failed with exit code {e.returncode}: {cmd_display}"
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


def get_config_default(key: str, default: str) -> str:
    try:
        return get_config(key)
    except SystemExit:
        return default


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def main() -> None:
    # Script should live in: <super_repo_root>/sedsnet/update_subtree.py
    subtree_prefix = Path(__file__).parent.resolve()
    super_repo_root = subtree_prefix.parent
    subtree_name = subtree_prefix.name  # "sedsnet"

    if is_git_repo(subtree_prefix):
        raise SystemExit(
            f"'{subtree_name}' looks like its own git repo (has .git). "
            "That is a submodule/standalone clone, not a subtree. "
            "Remove the nested .git directory and recommit, or fix your layout. "
            "If this is actually a submodule, run the submodule updater script instead."
        )

    os.chdir(super_repo_root)

    branch = get_config_default(f"subtree.{subtree_name}.branch", "main")
    squash_raw = get_config_default(f"subtree.{subtree_name}.squash", "false").strip().lower()
    squash = squash_raw in {"1", "true", "yes", "on"}

    # Commit message template (configurable)
    msg_default = f"chore(subtree): update {subtree_name} from upstream/{branch}"
    if squash:
        msg_default += " (squashed)"

    commit_msg = get_config_default(
        f"subtree.{subtree_name}.message",
        msg_default,
    )

    print(f"Updating subtree '{subtree_name}' (prefix '{subtree_name}') branch '{branch}'")
    print(f"Squash: {squash}")
    print(f"Commit message: {commit_msg}")

    # Stable local remote name
    remote_name = "sedsnet-upstream"

    # Fetch latest
    run(["git", "fetch", "--prune", remote_name])

    # Perform the subtree pull with commit message
    cmd = [
        "git",
        "subtree",
        "pull",
        "--prefix",
        subtree_name,
        remote_name,
        branch,
        "-m",
        commit_msg,
    ]
    if squash:
        cmd.append("--squash")

    try:
        pull_proc = subprocess.run(cmd, check=False, text=True, capture_output=True)
    except FileNotFoundError as e:
        raise SystemExit(
            "Required command 'git' was not found while running subtree pull. "
            "Install git and ensure it is on your PATH."
        ) from e
    if pull_proc.returncode != 0:
        output = f"{pull_proc.stdout}\n{pull_proc.stderr}".lower()
        if "already up to date" in output or "no new revisions were found" in output:
            print("Subtree pull did not apply changes (already up to date or no matching commits).")
            return
        raise SystemExit(
            f"Command failed with exit code {pull_proc.returncode}: {_cmd_text(cmd)}. "
            "Hint: Verify `sedsnet-upstream` remote/branch, ensure a clean worktree, and rerun."
        )

    print("Subtree updated successfully.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nexiting...")
        exit(0)
    except Exception as e:
        print(f"Error: Unexpected failure: {e}", file=sys.stderr)
        raise SystemExit(1) from e
