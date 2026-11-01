"""Exercise CI publication guards without contacting either package registry."""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def job(path, name, indent=0):
    lines = path.read_text().splitlines()
    at = lines.index(" " * indent + name + ":")
    end = next((n for n in range(at + 1, len(lines))
                if lines[n].strip() and not lines[n].startswith(" " * (indent + 1))
                and not lines[n].lstrip().startswith("#")), len(lines))
    return "\n".join(lines[at:end]) + "\n"


def gitlab_script(name):
    block = job(ROOT / ".gitlab-ci.yml", name)
    script = block.split("  script:\n", 1)[1]
    if script.startswith("    - |\n"):
        return textwrap.dedent(script[len("    - |\n"):])
    return "\n".join(line[len("    - "):] for line in script.splitlines()
                     if line.startswith("    - "))


class CiPublishGuards(unittest.TestCase):
    def run_gitlab(self, name, token_name=None, failure=0):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            stub = directory / "python3"
            stub.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SEDS_TEST_CALLS\"\n"
                            "case \"$*\" in *publish_crates.py*) exit \"$SEDS_TEST_EXIT\";; esac\nexit 0\n")
            stub.chmod(0o755)
            calls = directory / "calls"
            env = dict(os.environ)
            for key in ["CARGO_REGISTRY_TOKEN", "MATURIN_PYPI_TOKEN", "PYPI_API_TOKEN"]:
                env.pop(key, None)
            env.update(PATH=str(directory) + os.pathsep + env.get("PATH", ""),
                       SEDS_TEST_CALLS=str(calls), SEDS_TEST_EXIT=str(failure))
            if token_name:
                env[token_name] = "fixture-not-a-secret"
            result = subprocess.run(["bash", "-e", "-c", gitlab_script(name)], env=env, text=True, capture_output=True)
            return result, calls.read_text().splitlines() if calls.exists() else []

    def test_gitlab_missing_tokens_skip_successfully_without_running_publisher(self):
        for name in ["cargo-release", "pypi-release"]:
            with self.subTest(job=name):
                result, calls = self.run_gitlab(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [])
                self.assertIn("publication skipped", result.stdout)

    def test_gitlab_configured_uploads_run_and_real_errors_fail(self):
        for name, token in [("cargo-release", "CARGO_REGISTRY_TOKEN"),
                            ("pypi-release", "MATURIN_PYPI_TOKEN"),
                            ("pypi-release", "PYPI_API_TOKEN")]:
            for failure in [0, 23]:
                with self.subTest(job=name, token=token, failure=failure):
                    result, calls = self.run_gitlab(name, token, failure)
                    self.assertEqual(result.returncode, failure, result.stderr)
                    publish = [c for c in calls if c.startswith("publish_crates.py ")]
                    self.assertEqual(len(publish), 1)
                    self.assertNotIn("--ignore-publish-errors", publish[0])
                    self.assertIn("--publish-pypi" if name == "pypi-release" else "--publish", publish[0])

    def test_github_crates_job_explicitly_skips_only_missing_token(self):
        block = job(ROOT / ".github/workflows/release.yml", "cargo-release", 2)
        self.assertIn("CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}", block)
        self.assertIn("if: env.CARGO_REGISTRY_TOKEN == ''", block)
        publish = block.split("      - name: Publish crates\n", 1)[1]
        self.assertIn("if: env.CARGO_REGISTRY_TOKEN != ''", publish)
        self.assertIn("--skip-tests --skip-package --publish", publish)
        self.assertNotIn("--no-verify", publish)
        self.assertNotIn("--ignore-publish-errors", publish)

    def test_disk_savings_are_scoped_to_qualification_jobs(self):
        cases = [(".github/workflows/ci.yaml", "build_and_test", 2),
                 (".github/workflows/release.yml", "release-checks", 2),
                 (".gitlab-ci.yml", "rust-tests", 0)]
        for filename, name, indent in cases:
            with self.subTest(workflow=filename):
                path = ROOT / filename
                block = job(path, name, indent)
                for setting in ["CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG"]:
                    self.assertIn(setting + ': "0"', block)
                    self.assertEqual(path.read_text().count(setting + ":"), 1)
                self.assertIn("python3 publish_crates.py", block)
                self.assertNotIn("--skip-tests", block)
        for path in [ROOT / ".github/workflows/ci.yaml", ROOT / ".github/workflows/release.yml"]:
            self.assertIn("vars.SEDSNET_CODEC_SOAK_SECONDS || '600'", path.read_text())


if __name__ == "__main__":
    unittest.main()
