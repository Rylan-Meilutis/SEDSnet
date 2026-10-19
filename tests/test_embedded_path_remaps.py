import importlib.util
from pathlib import Path
import unittest
from unittest import mock
spec=importlib.util.spec_from_file_location("seds_build",Path(__file__).parents[1]/"build.py")
build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
class EmbeddedPathRemapTests(unittest.TestCase):
    def test_preserves_explicit_flags_and_space_containing_paths(self):
        env={"RUSTFLAGS":"-C target-cpu=cortex-m33", "CARGO_HOME":"/tmp/a cargo home"}
        with mock.patch.object(build.subprocess,"check_output",return_value="/tmp/rust toolchain\n"):
            build.apply_embedded_path_remaps("thumbv8m.main-none-eabihf",env)
            flags=env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
            self.assertEqual(flags[-2:],["-C","target-cpu=cortex-m33"])
            self.assertIn("--remap-path-prefix=/tmp/a cargo home/registry/src=crates",flags)
            self.assertIn("--remap-path-prefix=/tmp/rust toolchain/lib/rustlib/src/rust/library=rust",flags)
            before=env.copy(); build.apply_embedded_path_remaps("thumbv8m.main-none-eabihf",env)
            self.assertEqual(before,env)
    def test_preserves_encoded_flags_and_custom_mapping(self):
        custom="--remap-path-prefix=/tool/lib/rustlib/src/rust/library=custom"
        env={"CARGO_ENCODED_RUSTFLAGS":custom+"\x1f--cfg\x1fvalue=\"with spaces\""}
        with mock.patch.object(build.subprocess,"check_output",return_value="/tool"):
            build.apply_embedded_path_remaps("thumbv7em-none-eabihf",env)
        self.assertTrue(env["CARGO_ENCODED_RUSTFLAGS"].endswith(custom+"\x1f--cfg\x1fvalue=\"with spaces\""))
    def test_keeps_cargo_config_host_build_and_opt_out_unchanged(self):
        for target,env in [("thumbv7em-none-eabihf",{}),("x86_64-unknown-linux-gnu",{"RUSTFLAGS":"-Copt-level=3"}),("thumbv7em-none-eabihf",{"RUSTFLAGS":"", "SEDSNET_EMBEDDED_PATH_REMAP_AUTO":"0"})]:
            before=env.copy()
            with mock.patch.object(build.subprocess,"check_output") as query:
                build.apply_embedded_path_remaps(target,env)
                query.assert_not_called()
            self.assertEqual(env,before)
    def test_registry_host_hash_is_omitted_and_specific_mapping_follows_root(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            registry=Path(temp)/"registry/src/index.example-deadbeef"
            registry.mkdir(parents=True)
            env={"RUSTFLAGS":"-Ctarget-cpu=cortex-m4","CARGO_HOME":temp}
            with mock.patch.object(build.subprocess,"check_output",return_value="/tool"):
                build.apply_embedded_path_remaps("thumbv7em-none-eabihf",env)
            flags=env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
            root=f"--remap-path-prefix={registry.parent}=crates"
            child=f"--remap-path-prefix={registry}=crates"
            self.assertGreater(flags.index(child),flags.index(root))
            self.assertIn("--remap-path-prefix=/tool/lib/rustlib/src/rust/library/alloc/src=alloc",flags)

    def test_missing_toolchain_retains_original_flags(self):
        env={"RUSTFLAGS":"-Copt-level=z"};before=env.copy()
        with mock.patch.object(build.subprocess,"check_output",side_effect=OSError):
            build.apply_embedded_path_remaps("thumbv7em-none-eabihf",env)
        self.assertEqual(env,before)

    def test_virtual_toolchain_sources_preserve_user_overrides(self):
        commit="a"*40
        custom=f"--remap-path-prefix=/rustc/{commit}/library/core/src=my-core"
        env={"RUSTFLAGS":custom}
        with mock.patch.object(build.subprocess,"check_output",side_effect=["/tool",f"commit-hash: {commit}\n"]):
            build.apply_embedded_path_remaps("thumbv8m.main-none-eabihf",env)
        flags=env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        self.assertIn(f"--remap-path-prefix=/rustc/{commit}/library/alloc/src=alloc",flags)
        self.assertEqual(flags[-1],custom)
        self.assertNotIn(f"--remap-path-prefix=/rustc/{commit}/library/core/src=core",flags)

    def test_unavailable_verbose_metadata_keeps_physical_mapping(self):
        env={"RUSTFLAGS":"-Copt-level=z"}
        with mock.patch.object(build.subprocess,"check_output",side_effect=["/tool",OSError()]):
            build.apply_embedded_path_remaps("thumbv8m.main-none-eabihf",env)
        self.assertIn("--remap-path-prefix=/tool/lib/rustlib/src/rust/library=rust",env["CARGO_ENCODED_RUSTFLAGS"])
