import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location("sedsnet_build", Path(__file__).parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
class BuildCliTests(unittest.TestCase):
    def test_cargo_style_embedded_command(self):
        args = build.parse_args(["build", "--release", "--target", "thumbv7em-none-eabihf", "--features", "embedded,compact-packet-store", "--device-id", "RF", "--max-queue-budget", "8192", "--env", "RUSTFLAGS=-C target-cpu=cortex-m4"])
        self.assertTrue(args.release)
        self.assertEqual(args.features, ["embedded", "compact-packet-store"])
        self.assertEqual(args.env_overrides["MAX_QUEUE_BUDGET"], "8192")
        self.assertEqual(args.env_overrides["RUSTFLAGS"], "-C target-cpu=cortex-m4")
    def test_tests_and_repeated_features(self):
        args = build.parse_args(["test", "--full", "--features=timesync", "--features", "timesync fair-admission"])
        self.assertEqual(args.features, ["timesync", "fair-admission"])
        self.assertTrue(args.full)
    def test_standalone_native_cmake_configures(self):
        import shutil, subprocess, tempfile
        if not shutil.which("cmake"):
            self.skipTest("CMake is not installed")
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["cmake", "-S", str(Path(__file__).parents[1]), "-B", directory,
                "-DCMAKE_BUILD_TYPE=Release", "-DSEDSNET_DEVICE_IDENTIFIER=CLI_TEST",
                "-DSEDSNET_MAX_QUEUE_BUDGET=8192", "-DSEDSNET_ENV_QUEUE_GROW_STEP=1.25"],
                text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("build --release --device-id=CLI_TEST --max-queue-budget=8192", result.stdout)
            self.assertIn("--env QUEUE_GROW_STEP=1.25", result.stdout)

    def test_default_build(self):
        self.assertEqual(build.parse_args([]).command, "build")
        self.assertTrue(build.parse_args(["--release"]).release)
    def test_rejects_invalid_or_obsolete_options(self):
        for args in [["release"], ["embedded"], ["build", "--full"], ["--max-queue-budget", "0"], ["--env", "BAD KEY=x"], ["--features", "unknown"], ["--features", "embedded,python"]]:
            with self.subTest(args=args), self.assertRaises(SystemExit): build.parse_args(args)
if __name__ == "__main__": unittest.main()
