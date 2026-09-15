import unittest
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class CiReleaseContracts(unittest.TestCase):
    def test_documented_release_matches_package_version(self) -> None:
        manifest = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text())
        version = manifest["package"]["version"]
        readme = (REPO_ROOT / "README.md").read_text()
        self.assertIn(f"Current stable release: **{version}**", readme)
        self.assertIn(f"consumers use the `v{version}` Git tag", readme)
        home = (REPO_ROOT / "docs/wiki/Home.md").read_text()
        self.assertIn(f"The current release is v{version}.", home)
        for name in ("README.md", "docs/wiki/Build-and-Configure.md", "docs/wiki/Usage-C-Cpp.md"):
            with self.subTest(document=name):
                self.assertIn(f"GIT_TAG v{version}", (REPO_ROOT / name).read_text())

    def test_github_ci_uses_publish_script_as_release_gate(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python3 publish_crates.py", workflow)

    def test_gitlab_tags_run_the_same_publish_gate(self) -> None:
        workflow = (REPO_ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        self.assertIn("$CI_COMMIT_TAG =~ /^v/", workflow)
        self.assertIn("python3 publish_crates.py", workflow)
        self.assertNotIn("python3 -m twine upload", workflow)


if __name__ == "__main__":
    unittest.main()
