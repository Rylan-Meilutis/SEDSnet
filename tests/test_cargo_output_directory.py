import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cargo_paths', ROOT / 'cargo_paths.py')
paths = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paths)


class CargoOutputDirectoryTests(unittest.TestCase):
    def test_matches_cargo_for_config_and_environment_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'src').mkdir()
            (root / 'src/lib.rs').write_text('pub fn fixture() {}\n')
            (root / 'Cargo.toml').write_text('[package]\nname="output_fixture"\nversion="0.1.0"\nedition="2021"\n[workspace]\n')
            (root / '.cargo').mkdir()
            config = root / '.cargo/config.toml'
            env = {k: v for k, v in os.environ.items() if k not in {'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR'}}
            cases = [('', None), ('configured-output', None), ('configured-output', 'relative-override'), ('configured-output', str(root / 'absolute override'))]
            for configured, override in cases:
                with self.subTest(configured=configured, override=override):
                    config.write_text('[build]\ntarget-dir=' + json.dumps(configured) + '\n' if configured else '')
                    selected = dict(env)
                    if override is not None:
                        selected['CARGO_TARGET_DIR'] = override
                    cargo = subprocess.check_output(['cargo', 'metadata', '--offline', '--no-deps', '--format-version', '1'], cwd=root, env=selected, text=True)
                    expected = Path(json.loads(cargo)['target_directory'])
                    self.assertEqual(paths.cargo_target_directory(root, env=selected), expected)
                    wanted = override or configured or 'target'
                    self.assertEqual(expected, (root / wanted).resolve())


    @unittest.skipUnless(shutil.which('cmake') and shutil.which('ninja'), 'CMake/Ninja required')
    def test_cmake_and_builder_agree_for_external_target_directories(self):
        with tempfile.TemporaryDirectory(prefix='seds cargo outputs ') as tmp:
            root = Path(tmp).resolve()
            source = root / 'crate'
            (source / 'src').mkdir(parents=True)
            (source / 'C-Headers').mkdir()
            (source / '.cargo').mkdir()
            (source / 'src/lib.rs').write_text('// fixture\n')
            (source / 'C-Headers/sedsnet.h').write_text('// fixture\n')
            (source / 'Cargo.toml').write_text('[package]\nname="output_fixture"\nversion="0.1.0"\nedition="2021"\n[workspace]\n')
            (source / '.cargo/config.toml').write_text('[build]\ntarget-dir="configured artifacts"\n')
            shutil.copy2(ROOT / 'CMakeLists.txt', source / 'CMakeLists.txt')
            shutil.copy2(ROOT / 'cargo_paths.py', source / 'cargo_paths.py')
            (source / 'build.py').write_text('from pathlib import Path\nimport sys, os\nfrom cargo_paths import cargo_target_directory\nfor index, value in enumerate(sys.argv):\n if value == "--env":\n  key, selected = sys.argv[index+1].split("=", 1)\n  os.environ[key] = selected\np=cargo_target_directory(Path.cwd())/"release/libsedsnet.a"\np.parent.mkdir(parents=True, exist_ok=True)\np.write_bytes(b"!<arch>\\n")\n')
            clean_env = {k: v for k, v in os.environ.items() if k not in {'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET_DIR'}}
            for index, (override, cached, expected) in enumerate([
                (None, None, 'configured artifacts'),
                ('environment artifacts', None, 'environment artifacts'),
                ('ignored artifacts', 'cache artifacts', 'cache artifacts'),
            ]):
                with self.subTest(override=override, cached=cached):
                    env = dict(clean_env)
                    if override is not None:
                        env['CARGO_TARGET_DIR'] = override
                    output = root / ('cmake-' + str(index))
                    command = ['cmake', '-S', str(source), '-B', str(output), '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DSEDSNET_FORCE_RELEASE=ON']
                    if cached is not None:
                        command.append('-DSEDSNET_ENV_CARGO_TARGET_DIR=' + cached)
                    for args in [command, ['cmake', '--build', str(output), '--target', 'sedsnet_build']]:
                        result = subprocess.run(args, env=env, text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue((source / expected / 'release/libsedsnet.a').is_file())
                    self.assertFalse((source / 'target').exists())


if __name__ == '__main__':
    unittest.main()
