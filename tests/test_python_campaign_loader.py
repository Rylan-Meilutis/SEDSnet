"""Exercise test-only host extension staging without builds, installs or credentials."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import build
import python_test_runner


class PythonCampaignLoaderTests(unittest.TestCase):
    def test_additional_binding_profile_skips_only_named_shared_contracts(self):
        calls = []
        def case(module, label):
            cls = type('Fixture', (unittest.TestCase,), {
                '__module__': module, 'runTest': lambda self: calls.append(label)})
            return cls()
        suite = unittest.TestSuite([
            unittest.TestSuite([case('test_build_cli', 'shared')]),
            case('test_python_current_api', 'native'),
            case('test_future_module', 'unknown'),
        ])
        selected = python_test_runner.binding_suite(suite)
        self.assertEqual(selected.countTestCases(), 2)
        result = unittest.TestResult()
        selected.run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(calls, ['native', 'unknown'])

    def test_empty_additional_binding_profile_is_rejected(self):
        with mock.patch.object(python_test_runner.importlib, 'import_module'), \
             mock.patch.object(unittest.defaultTestLoader, 'discover', return_value=unittest.TestSuite()), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(python_test_runner.main(['--require-bindings', '--bindings-only']), 1)

    def test_private_copy_uses_cargo_output_and_host_abi_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'python-files/sedsnet').mkdir(parents=True)
            (root/'python-files/sedsnet/__init__.py').write_text('from .sedsnet import *\n')
            target = root/'external artifacts'
            library = target/'fake-host/debug/libsedsnet.so'
            library.parent.mkdir(parents=True)
            library.write_bytes(b'synthetic-native-library')
            with mock.patch.object(build.subprocess, 'check_output', return_value='host: fake-host\n'), \
                 mock.patch.object(build, 'cargo_target_directory', return_value=target), \
                 mock.patch.object(build, 'run_cmd') as run, \
                 mock.patch.object(build.sys, 'platform', 'linux'), \
                 mock.patch.object(build.sysconfig, 'get_config_var', return_value='.abi3.so'):
                with build.python_test_environment(root, {'PYTHONPATH':'old-path'}, 'python,timesync', [], 'test') as env:
                    staged = Path(env['PYTHONPATH'].split(build.os.pathsep)[0])
                    copied = staged/'sedsnet/sedsnet.abi3.so'
                    self.assertEqual(copied.read_bytes(), b'synthetic-native-library')
                    library.write_bytes(b'rebuilt-by-another-test')
                    self.assertEqual(copied.read_bytes(), b'synthetic-native-library')
                    self.assertEqual(env['PYO3_PYTHON'], build.sys.executable)
                    self.assertTrue(env['PYTHONPATH'].endswith('old-path'))
                self.assertFalse(staged.exists())
            command = run.call_args.args[0]
            self.assertIn('rustc', command)
            self.assertEqual(command[command.index('--target')+1], 'fake-host')
            self.assertEqual(command[command.index('--crate-type')+1], 'cdylib')

    def test_release_and_native_library_filename_selection(self):
        for platform, filename in [('darwin','libsedsnet.dylib'),('win32','sedsnet.dll')]:
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                (root/'python-files/sedsnet').mkdir(parents=True)
                (root/'python-files/sedsnet/__init__.py').write_text('')
                library=root/'target/fake-host/release'/filename
                library.parent.mkdir(parents=True)
                library.write_bytes(b'fake')
                with mock.patch.object(build.subprocess,'check_output',return_value='host: fake-host\n'), \
                     mock.patch.object(build,'cargo_target_directory',return_value=root/'target'), \
                     mock.patch.object(build,'run_cmd') as run, \
                     mock.patch.object(build.sys,'platform',platform), \
                     mock.patch.object(build.sysconfig,'get_config_var',return_value=None):
                    with build.python_test_environment(root,{},'python',['--release'],'test') as env:
                        self.assertTrue(Path(env['PYTHONPATH'],'sedsnet','sedsnet'+('.pyd' if platform=='win32' else '.so')).is_file())
                    self.assertIn('--release',run.call_args.args[0])
                    command = run.call_args.args[0]
                    child_env = run.call_args.kwargs['env']
                    if platform == 'darwin':
                        self.assertEqual(command[-5:], ['--', '-C', 'link-arg=-undefined', '-C', 'link-arg=dynamic_lookup'])
                        self.assertEqual(child_env['MACOSX_DEPLOYMENT_TARGET'], '11.0')
                    else:
                        self.assertNotIn('link-arg=dynamic_lookup', command)
                        self.assertNotIn('MACOSX_DEPLOYMENT_TARGET', child_env)

    def test_macos_extension_preserves_explicit_deployment_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'python-files/sedsnet').mkdir(parents=True)
            (root/'python-files/sedsnet/__init__.py').write_text('')
            library = root/'target/fake-host/debug/libsedsnet.dylib'
            library.parent.mkdir(parents=True)
            library.write_bytes(b'fake')
            original = {'MACOSX_DEPLOYMENT_TARGET': '13.0', 'RUSTFLAGS': '-C debuginfo=1'}
            with mock.patch.object(build.subprocess, 'check_output', return_value='host: fake-host\n'), \
                 mock.patch.object(build, 'cargo_target_directory', return_value=root/'target'), \
                 mock.patch.object(build, 'run_cmd') as run, \
                 mock.patch.object(build.sys, 'platform', 'darwin'), \
                 mock.patch.object(build.sysconfig, 'get_config_var', return_value='.so'):
                with build.python_test_environment(root, original, 'python', [], 'test'):
                    child_env = run.call_args.kwargs['env']
                    self.assertEqual(child_env['MACOSX_DEPLOYMENT_TARGET'], '13.0')
                    self.assertEqual(child_env['RUSTFLAGS'], original['RUSTFLAGS'])
            self.assertNotIn('PYO3_PYTHON', original)

    def test_missing_native_output_is_a_failure(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(build.subprocess,'check_output',return_value='host: fake-host\n'), \
             mock.patch.object(build,'cargo_target_directory',return_value=Path(directory)), \
             mock.patch.object(build,'run_cmd'):
            with self.assertRaises(SystemExit):
                with build.python_test_environment(Path(directory),{},'python',[],'test'):
                    self.fail('missing extension must not reach the tests')

    def run_nested(self, suite):
        with mock.patch.object(python_test_runner.importlib,'import_module'), \
             mock.patch.object(unittest.defaultTestLoader,'discover',return_value=suite), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return python_test_runner.main(['--require-bindings'])

    def test_full_campaign_fails_before_discovery_if_binding_is_unavailable(self):
        output=io.StringIO()
        with mock.patch.object(python_test_runner.importlib,'import_module',side_effect=ImportError('fake-secret-sentinel')), \
             mock.patch.object(unittest.defaultTestLoader,'discover') as discover, \
             contextlib.redirect_stderr(output):
            self.assertEqual(python_test_runner.main(['--require-bindings']),1)
        discover.assert_not_called()
        self.assertNotIn('fake-secret-sentinel',output.getvalue())

    def test_full_campaign_rejects_binding_skips(self):
        def unavailable(): raise unittest.SkipTest('sedsnet binding unavailable: synthetic fixture')
        self.assertEqual(self.run_nested(unittest.TestSuite([unittest.FunctionTestCase(unavailable)])),1)

    def test_full_campaign_runs_the_discovered_suite(self):
        self.assertEqual(self.run_nested(unittest.TestSuite([unittest.FunctionTestCase(lambda:None)])),0)
