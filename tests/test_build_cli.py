import importlib.util
import unittest
import contextlib
import io
from unittest import mock
from pathlib import Path
spec = importlib.util.spec_from_file_location("sedsnet_build", Path(__file__).parents[1] / "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)
class BuildCliTests(unittest.TestCase):
    def test_all_runs_distinct_profiles_but_shared_checks_once(self):
        with mock.patch.object(build, 'has_embedded_c_toolchain', return_value=True), \
             mock.patch.object(build, 'ensure_rust_target_installed'), \
             mock.patch.object(build, 'apply_embedded_cflags_defaults'), \
             mock.patch.object(build, 'collect_artifact_sizes', return_value={}), \
             mock.patch.object(build, 'print_artifact_sizes'), \
             mock.patch.object(build, 'cargo_target_directory', return_value=Path('/tmp/fixture-target')), \
             mock.patch.object(build, 'cargo_nextest_available', return_value=False), \
             mock.patch.object(build, 'python_test_environment', side_effect=lambda *a: contextlib.nullcontext({})) as bindings, \
             mock.patch.object(build, 'run_cmd') as run, contextlib.redirect_stdout(io.StringIO()):
            build.main(['test', '--all', '--full', '--features', 'ingress-target-filter'])
        commands = [call.args[0] for call in run.call_args_list]
        native = [c for c in commands if c[:2] == ['cargo', 'test'] and '--no-default-features' not in c]
        self.assertEqual(len(native), 2)
        self.assertTrue(all('--include-ignored' in c for c in native))
        profiles = [set(c[c.index('--features') + 1].split(',')) for c in native]
        self.assertIn('cryptography', profiles[0])
        self.assertIn('ingress-target-filter', profiles[0])
        self.assertNotIn('compact-packet-compression', profiles[0])
        self.assertEqual(profiles[1] - profiles[0], {'compact-packet-compression', 'fair-admission'})
        self.assertEqual(sum(c[:2] == ['cargo', 'clippy'] for c in commands), 6)
        self.assertEqual(sum('embedded_memory_behavior_test' in c for c in commands), 2)
        self.assertEqual(sum('packet_packing_memory' in c for c in commands), 1)
        self.assertEqual(sum(c[:2] == ['cargo', 'bench'] for c in commands), 1)
        self.assertEqual(sum(c[:2] == ['cargo', 'build'] for c in commands), 2)
        self.assertEqual(bindings.call_count, 2)
        python = [c for c in commands if any(str(v).endswith('python_test_runner.py') for v in c)]
        self.assertEqual(len(python), 2)
        self.assertTrue(all('--require-bindings' in c for c in python))
        self.assertNotIn('--bindings-only', python[0])
        self.assertIn('--bindings-only', python[1])

    def test_matrix_selects_storage_profiles_and_keeps_common_features(self):
        profiles = build.qualification_profiles(['compact-packet-store', 'fair-admission', 'ingress-target-filter'])
        self.assertEqual(profiles, [['ingress-target-filter', 'cryptography'],
            ['ingress-target-filter', 'cryptography', 'compact-packet-compression', 'fair-admission']])

    def test_wheel_install_uses_selected_target_features_and_cargo_output(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / 'external artifacts'
            wheels = output / 'wheels'
            wheels.mkdir(parents=True)
            wheel = wheels / 'sedsnet-4.2.5-test.whl'
            wheel.write_bytes(b'fixture')
            env = {'CARGO_TARGET_DIR': str(output)}
            with patch.object(build, 'run_cmd') as run, patch.object(build, 'cargo_target_directory', return_value=output) as resolve:
                build.install_wheel_file(['--release'], env=env, repo_root=root, target='aarch64-apple-darwin', feature_parts=['timesync'])
            self.assertEqual(run.call_args_list[0].args[0], ['maturin', 'build', '--release', '--target', 'aarch64-apple-darwin', '--features', 'timesync'])
            self.assertEqual(run.call_args_list[1].args[0], ['uv', 'pip', 'install', str(wheel)])
            resolve.assert_called_once_with(root, env=env)

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

    def test_ingress_filter_cmake_feature_uses_supported_build_cli(self):
        import subprocess, tempfile
        args=build.parse_args(["build", "--features", "embedded,ingress-target-filter"])
        self.assertEqual(args.features, ["embedded", "ingress-target-filter"])
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.run(["cmake", "-S", str(Path(__file__).parents[1]), "-B", directory,
                "-DSEDSNET_INGRESS_TARGET_FILTER=ON"],text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn("--features ingress-target-filter", result.stdout)

    def test_requested_embedded_features_reach_the_actual_cargo_command(self):
        from unittest.mock import patch
        with patch.object(build, "ensure_rust_target_installed"), patch.object(build, "has_embedded_c_toolchain", return_value=True), patch.object(build, "collect_artifact_sizes", return_value={}), patch.object(build, "print_artifact_sizes"), patch.object(build, "run_cmd") as run:
            build.main(["build", "--release", "--target", "thumbv7em-none-eabihf", "--features", "embedded,ingress-target-filter,compact-packet-store,fair-admission"])
        command=run.call_args.args[0]
        features=command[command.index("--features")+1].split(",")
        self.assertEqual(set(features), {"embedded", "ingress-target-filter", "compact-packet-store", "fair-admission"})
        self.assertIn("--profile",command)
        self.assertIn("release-embedded",command)

    def test_default_build(self):
        self.assertEqual(build.parse_args([]).command, "build")
        self.assertTrue(build.parse_args(["--release"]).release)
    def test_rejects_invalid_or_obsolete_options(self):
        for args in [["release"], ["embedded"], ["build", "--full"], ['build', '--all'], ['test', '--fu'], ["--max-queue-budget", "0"], ["--env", "BAD KEY=x"], ["--features", "unknown"], ["--features", "embedded,python"]]:
            with self.subTest(args=args), self.assertRaises(SystemExit): build.parse_args(args)
if __name__ == "__main__": unittest.main()
