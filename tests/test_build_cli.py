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
        self.assertEqual(profiles[1] - profiles[0], {'compact-packet-compression', 'fair-admission', 'latest-value-egress'})
        self.assertEqual(sum(c[:2] == ['cargo', 'clippy'] for c in commands), 8)
        minimal = [c[c.index('--features') + 1] for c in commands
                   if c[:2] == ['cargo', 'clippy'] and '--no-default-features' in c
                   and c[c.index('--features') + 1] in {'std', 'std,latest-value-egress'}]
        self.assertEqual(minimal, ['std', 'std,latest-value-egress'])
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
        cross = [call for call in run.call_args_list
                 if call.args[0][:2] == ['cargo', 'check']]
        self.assertEqual(len(cross), 2)
        for call, profile in zip(cross, profiles):
            command = call.args[0]
            self.assertEqual(command[command.index('--target') + 1], 'i686-unknown-linux-gnu')
            self.assertEqual(set(command[command.index('--features') + 1].split(',')), profile | {'python'})
            self.assertEqual(call.kwargs['env']['PYO3_CROSS_PYTHON_VERSION'], '3.9')
            self.assertEqual(call.kwargs['env']['PYO3_CROSS'], '1')
            self.assertEqual(call.kwargs['env']['PYO3_NO_PYTHON'], '1')

    def test_matrix_selects_storage_profiles_and_keeps_common_features(self):
        profiles = build.qualification_profiles(['compact-packet-store', 'fair-admission', 'ingress-target-filter'])
        self.assertEqual(profiles, [['ingress-target-filter', 'cryptography'],
            ['ingress-target-filter', 'cryptography', 'compact-packet-compression', 'fair-admission', 'latest-value-egress']])

    def test_latest_feature_is_off_in_reference_and_on_in_compact_profile(self):
        profiles = build.qualification_profiles(['latest-value-egress'])
        self.assertNotIn('latest-value-egress', profiles[0])
        self.assertIn('latest-value-egress', profiles[1])
        self.assertNotIn('compact-packet-compression', profiles[0])
        self.assertIn('compact-packet-compression', profiles[1])
        args = build.parse_args(['build', '--features', 'latest-value-egress'])
        self.assertEqual(args.features, ['latest-value-egress'])

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

    def test_cmake_staticlib_selector_is_opt_in_and_validated(self):
        import subprocess, tempfile
        for value in [None, "staticlib", "cdylib"]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                command = ["cmake", "-S", str(Path(__file__).parents[1]), "-B", directory]
                if value is not None:
                    command.append("-DSEDSNET_CRATE_TYPE=" + value)
                result = subprocess.run(command, text=True, capture_output=True)
                output = result.stdout + result.stderr
                if value == "cdylib":
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SEDSNET_CRATE_TYPE must be empty or staticlib", output)
                else:
                    self.assertEqual(result.returncode, 0, output)
                    args_line = next(line for line in output.splitlines() if "sedsnet build args:" in line)
                    if value is None:
                        self.assertNotIn("--crate-type", args_line)
                    else:
                        self.assertIn("--crate-type staticlib", args_line)

    def test_staticlib_output_is_explicit_and_defaults_are_unchanged(self):
        for shared, expected in [(False, "rlib,staticlib"), (True, "rlib,staticlib,cdylib")]:
            command = build.cargo_lib_build_cmd(build_mode=[], build_args=[], build_shared=shared)
            self.assertEqual(command[command.index("--crate-type") + 1], expected)
            selected = build.cargo_lib_build_cmd(build_mode=[], build_args=[], build_shared=shared,
                                                crate_type="staticlib")
            self.assertEqual(selected[selected.index("--crate-type") + 1], "staticlib")
            self.assertNotIn("-Clto=fat", selected)
        self.assertIsNone(build.parse_args(["build"]).crate_type)
        for arguments in [["check", "--crate-type", "staticlib"],
                          ["test", "--crate-type", "staticlib"],
                          ["maturin-build", "--crate-type", "staticlib"],
                          ["build", "--features", "python", "--crate-type", "staticlib"],
                          ["build", "--crate-type", "cdylib"]]:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                build.parse_args(arguments)

    def test_staticlib_selector_reaches_host_and_embedded_cargo_invocations(self):
        for features in [[], ["--features", "embedded", "--target", "thumbv7em-none-eabihf"]]:
            with self.subTest(features=features), \
                 mock.patch.object(build, "ensure_rust_target_installed"), \
                 mock.patch.object(build, "has_embedded_c_toolchain", return_value=True), \
                 mock.patch.object(build, "collect_artifact_sizes", return_value={}), \
                 mock.patch.object(build, "print_artifact_sizes"), \
                 mock.patch.object(build, "run_cmd") as run, contextlib.redirect_stdout(io.StringIO()):
                build.main(["build", "--release", "--crate-type", "staticlib", *features])
            command = run.call_args.args[0]
            self.assertEqual(command[:3], ["cargo", "rustc", "--lib"])
            self.assertEqual(command[command.index("--crate-type") + 1], "staticlib")
            if features:
                self.assertEqual(command[command.index("--profile") + 1], "release-embedded")

    def test_default_build(self):
        self.assertEqual(build.parse_args([]).command, "build")
        self.assertTrue(build.parse_args(["--release"]).release)
    def test_rejects_invalid_or_obsolete_options(self):
        for args in [["release"], ["embedded"], ["build", "--full"], ['build', '--all'], ['test', '--fu'], ["--max-queue-budget", "0"], ["--env", "BAD KEY=x"], ["--features", "unknown"], ["--features", "embedded,python"]]:
            with self.subTest(args=args), self.assertRaises(SystemExit): build.parse_args(args)
if __name__ == "__main__": unittest.main()
