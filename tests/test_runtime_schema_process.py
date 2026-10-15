"""Exercise separate registries and real packets across std and empty embedded catalogs."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuntimeSchemaProcessTests(unittest.TestCase):
    def test_mixed_profiles_merge_runtime_only_schema_fragments(self):
        def build(extra, environment):
            result = subprocess.run(["cargo", "test", "--test", "runtime_schema_process",
                "--no-run", "--message-format=json", *extra], cwd=ROOT, env=environment,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr)
            for line in result.stdout.splitlines():
                item = json.loads(line)
                if item.get("reason") == "compiler-artifact" and item.get("executable"):
                    return item["executable"]
            self.fail("missing schema-process test executable")

        environment = os.environ.copy()
        hosted = build([], environment)
        with tempfile.TemporaryDirectory() as scratch:
            embedded_environment = environment.copy()
            embedded_environment["SEDSNET_EMBEDDED_SCHEMA_PATH"] = str(Path(scratch) / "no-schema.json")
            embedded = build(["--no-default-features", "--features", "embedded"], embedded_environment)
            selected_seed = Path(scratch) / "selected-seed.json"
            selected_seed.write_text(json.dumps({
                "endpoints": [{"rust": "SelectedSeed", "name": "BUNDLED_PROCESS_SEED"}],
                "types": []}))
            combined_environment = environment.copy()
            combined_environment["SEDSNET_EMBEDDED_SCHEMA_PATH"] = str(selected_seed)
            combined = build(["--features", "embedded"], combined_environment)
            for producer_a, producer_b in [(hosted, embedded), (embedded, hosted),
                                           (combined, embedded), (embedded, combined)]:
                with tempfile.TemporaryDirectory() as directory:
                    for executable, role in [(producer_a, "a"), (producer_b, "b"),
                        (hosted, "receive"), (embedded, "receive"), (combined, "receive")]:
                        child_environment = environment.copy()
                        child_environment.update(SEDSNET_PROCESS_SCHEMA_DIR=directory,
                            SEDSNET_PROCESS_SCHEMA_ROLE=role)
                        if executable == combined:
                            child_environment["SEDSNET_EXPECT_BUNDLED_ENDPOINT"] = "BUNDLED_PROCESS_SEED"
                        result = subprocess.run([executable, "--ignored", "--exact", "isolated_schema_node"],
                            cwd=ROOT, env=child_environment, text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
