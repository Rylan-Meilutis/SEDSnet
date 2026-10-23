"""Resolve artifact locations using Cargo's configuration and environment."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def cargo_target_directory(repo_root: Path, *, env: dict[str, str] | None = None) -> Path:
    metadata = subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=repo_root,
        env=env,
        text=True,
    )
    return Path(json.loads(metadata)["target_directory"])


if __name__ == "__main__":
    print(cargo_target_directory(Path(sys.argv[1]), env=os.environ.copy()))
