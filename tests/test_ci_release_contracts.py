import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class CiReleaseContracts(unittest.TestCase):
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
