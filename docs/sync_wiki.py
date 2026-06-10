#!/usr/bin/env python3
"""Sync docs/wiki to GitHub and GitLab wiki repos.

Requires the wiki repos to exist (create the first wiki page in the UI first).
"""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple


def _cmd_text(cmd: list[str]) -> str:
    return " ".join(cmd)


def _hint_for_cmd(cmd: list[str], returncode: int) -> Optional[str]:
    if not cmd or cmd[0] != "git":
        return None
    if cmd[:2] == ["git", "clone"]:
        return "Check the repo URL, network access, and credentials/token permissions."
    if cmd[:2] == ["git", "fetch"]:
        return "Verify remote access and auth. Try `git remote -v` inside the repo."
    if cmd[:2] == ["git", "pull"]:
        return "Local branch may have diverged. Resolve locally, then retry with a clean fast-forward."
    if cmd[:2] == ["git", "push"]:
        return "Verify push permissions and authentication for the wiki repository."
    if cmd[:2] == ["git", "commit"]:
        return "Configure `git config user.name` and `git config user.email` if commit identity is missing."
    return f"Run `{_cmd_text(cmd)}` manually for full git output."


def run(cmd, cwd=None):
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except FileNotFoundError as e:
        raise SystemExit(
            f"Required command '{e.filename}' was not found while running: {_cmd_text(cmd)}. "
            "Install git and ensure it is on your PATH."
        ) from e
    except subprocess.CalledProcessError as e:
        hint = _hint_for_cmd(cmd, e.returncode)
        raise SystemExit(
            f"Command failed with exit code {e.returncode}: {_cmd_text(cmd)}"
            + (f". Hint: {hint}" if hint else "")
        ) from e


def git_output(cmd, cwd=None):
    try:
        return subprocess.check_output(cmd, cwd=cwd).decode("utf-8").strip()
    except FileNotFoundError as e:
        raise SystemExit(
            f"Required command '{e.filename}' was not found while running: {_cmd_text(cmd)}. "
            "Install git and ensure it is on your PATH."
        ) from e
    except subprocess.CalledProcessError as e:
        hint = _hint_for_cmd(cmd, e.returncode)
        raise SystemExit(
            f"Command failed with exit code {e.returncode}: {_cmd_text(cmd)}"
            + (f". Hint: {hint}" if hint else "")
        ) from e


def parse_git_remote_url(url: str) -> tuple[str, str, str]:
    """Return (host, owner_path, repo_name) from a git remote URL."""
    u = url.strip()

    # https://host/owner/repo(.git)
    m = re.match(r"^https?://([^/]+)/(.+?)/([^/]+?)(?:\.git)?/?$", u)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # ssh://git@host/owner/repo(.git)
    m = re.match(r"^ssh://git@([^/]+)/(.+?)/([^/]+?)(?:\.git)?/?$", u)
    if m:
        return m.group(1), m.group(2), m.group(3)

    # git@host:owner/repo(.git)
    m = re.match(r"^git@([^:]+):(.+?)/([^/]+?)(?:\.git)?/?$", u)
    if m:
        return m.group(1), m.group(2), m.group(3)

    raise SystemExit(
        f"Unsupported git remote URL format: {url}. "
        "Use --github-url/--gitlab-url explicitly, or set a standard HTTPS/SSH remote."
    )


def wiki_url(host: str, owner: str, repo: str) -> str:
    return f"https://{host}/{owner}/{repo}.wiki.git"


def derive_wiki_urls(
        remote: str,
        github_url: Optional[str],
        gitlab_url: Optional[str],
        gitlab_from_github: bool,
        gitlab_host: str,
) -> Tuple[Optional[str], Optional[str]]:
    if github_url and gitlab_url:
        return github_url, gitlab_url

    remote_url = git_output(["git", "remote", "get-url", remote])
    host, owner, repo = parse_git_remote_url(remote_url)
    host_l = host.lower()

    resolved_github = github_url
    resolved_gitlab = gitlab_url

    if resolved_github is None and "github.com" in host_l:
        resolved_github = wiki_url(host, owner, repo)

    if resolved_gitlab is None:
        if "gitlab" in host_l:
            resolved_gitlab = wiki_url(host, owner, repo)
        elif "github.com" in host_l and gitlab_from_github:
            resolved_gitlab = wiki_url(gitlab_host, owner, repo)

    return resolved_github, resolved_gitlab


def ensure_repo(url: str, repo_dir: Path):
    def _is_git_repo(path: Path) -> bool:
        try:
            subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=path,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    if not repo_dir.exists():
        run(["git", "clone", url, str(repo_dir)])
        return

    if not _is_git_repo(repo_dir):
        shutil.rmtree(repo_dir, ignore_errors=True)
        run(["git", "clone", url, str(repo_dir)])
        return

    run(["git", "fetch", "--all", "--prune"], cwd=repo_dir)
    branch = git_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir)
    run(["git", "pull", "--ff-only", "origin", branch], cwd=repo_dir)


def clear_repo_worktree(repo_dir: Path):
    try:
        for child in repo_dir.iterdir():
            if child.name == ".git":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    except OSError as e:
        raise SystemExit(
            f"Failed to clear repository worktree at {repo_dir}: {e}. "
            "Check file permissions and ensure files are not locked by another process."
        ) from e


def rewrite_links_for_target(
        text: str,
        target_host: str,
        target_owner: str,
        target_repo: str,
) -> str:
    target_host_l = target_host.lower()
    if "gitlab" not in target_host_l:
        return text

    def _rewrite_github_url(match: re.Match[str]) -> str:
        suffix = match.group("suffix")
        return f"https://{target_host}/{target_owner}/{target_repo}/{suffix}"

    return re.sub(
        r"https://github\.com/[^/]+/[^/]+/(?P<suffix>(?:blob|tree)/[^)\s]+)",
        _rewrite_github_url,
        text,
    )


def copy_source(
        source_dir: Path,
        repo_dir: Path,
        target_host: str,
        target_owner: str,
        target_repo: str,
):
    try:
        for item in source_dir.iterdir():
            dest = repo_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
            else:
                if item.suffix.lower() in {".md", ".txt"}:
                    dest.write_text(
                        rewrite_links_for_target(
                            item.read_text(encoding="utf-8"),
                            target_host,
                            target_owner,
                            target_repo,
                        ),
                        encoding="utf-8",
                    )
                else:
                    shutil.copy2(item, dest)
    except OSError as e:
        raise SystemExit(
            f"Failed to copy wiki files from {source_dir} to {repo_dir}: {e}. "
            "Check read/write permissions and available disk space."
        ) from e


def has_changes(repo_dir: Path) -> bool:
    status = git_output(["git", "status", "--porcelain"], cwd=repo_dir)
    return bool(status)


def commit_and_push(repo_dir: Path, message: str):
    run(["git", "add", "."], cwd=repo_dir)
    run(["git", "commit", "-m", message], cwd=repo_dir)
    run(["git", "push"], cwd=repo_dir)


def sync_one(name: str, url: str, source_dir: Path, workdir: Path, message: str):
    repo_dir = workdir / name
    ensure_repo(url, repo_dir)
    clear_repo_worktree(repo_dir)
    host, owner, repo = parse_git_remote_url(url)
    copy_source(source_dir, repo_dir, host, owner, repo)

    if has_changes(repo_dir):
        commit_and_push(repo_dir, message)
        print(f"[{name}] pushed")
    else:
        print(f"[{name}] no changes")


def main():
    parser = argparse.ArgumentParser(description="Sync docs/wiki to GitHub and GitLab wiki repos")
    parser.add_argument(
        "--source-dir",
        default=str(Path.cwd() / "docs" / "wiki"),
        help="Path to wiki source directory",
    )
    parser.add_argument(
        "--workdir",
        default="/tmp/sedsnet_wiki_sync",
        help="Directory for cloning wiki repos",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote name used to derive wiki URLs (default: origin)",
    )
    parser.add_argument(
        "--github-url",
        default=None,
        help="GitHub wiki repo URL (overrides remote-derived URL)",
    )
    parser.add_argument(
        "--gitlab-url",
        default=None,
        help="GitLab wiki repo URL (overrides remote-derived URL)",
    )
    parser.add_argument(
        "--gitlab-from-github",
        action="store_true",
        help="If remote host is GitHub, derive GitLab wiki URL using --gitlab-host and same owner/repo",
    )
    parser.add_argument(
        "--gitlab-host",
        default="gitlab.rylanswebsite.com",
        help="GitLab host used with --gitlab-from-github",
    )
    parser.add_argument(
        "--commit-message",
        default="Sync wiki from docs/wiki",
        help="Commit message for wiki sync",
    )
    args = parser.parse_args()

    source_dir = Path(args.source_dir).resolve()
    workdir = Path(args.workdir).resolve()

    if not source_dir.is_dir():
        raise SystemExit(
            f"Source dir not found: {source_dir}. "
            "Pass `--source-dir` pointing to your local `docs/wiki` directory."
        )

    try:
        workdir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise SystemExit(
            f"Failed to create workdir {workdir}: {e}. "
            "Choose a writable directory with `--workdir`."
        ) from e

    github_url, gitlab_url = derive_wiki_urls(
        remote=args.remote,
        github_url=args.github_url,
        gitlab_url=args.gitlab_url,
        gitlab_from_github=args.gitlab_from_github,
        gitlab_host=args.gitlab_host,
    )

    if not github_url and not gitlab_url:
        raise SystemExit(
            "Could not derive any wiki URLs from remote. "
            "Set --github-url/--gitlab-url explicitly, or use --gitlab-from-github."
        )

    if github_url:
        sync_one("github_wiki", github_url, source_dir, workdir, args.commit_message)
    else:
        print("[github_wiki] skipped (no URL resolved)")

    if gitlab_url:
        sync_one("gitlab_wiki", gitlab_url, source_dir, workdir, args.commit_message)
    else:
        print("[gitlab_wiki] skipped (no URL resolved)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        raise SystemExit(130)
    except Exception as e:
        print(f"Error: Unexpected failure while syncing wiki: {e}", file=sys.stderr)
        raise SystemExit(1) from e
