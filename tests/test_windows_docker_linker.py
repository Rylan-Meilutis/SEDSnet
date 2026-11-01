"""Release regression: old system LLD rejects Rust's Windows32 export aliases."""
import unittest
from unittest import mock

import publish_crates as publisher


class WindowsDockerLinkerTests(unittest.TestCase):
    def commands(self, targets):
        with mock.patch.object(publisher, "require_tool"), mock.patch.object(publisher, "run") as run:
            publisher.docker_maturin_windows_build(
                image="fixture-rust-image", targets=targets, out_dir="dist/release"
            )
        return [call.args[0] for call in run.call_args_list]

    def test_each_windows_build_uses_the_installed_rust_toolchains_linker(self):
        targets = ["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"]
        for command, target in zip(self.commands(targets), targets):
            with self.subTest(target=target):
                shell = command[-1]
                self.assertIn("sedsnet_rust_host=$(rustc -vV", shell)
                self.assertIn('/lib/rustlib/${sedsnet_rust_host}/bin/rust-lld', shell)
                self.assertIn('test -x "${sedsnet_rust_lld}"', shell)
                self.assertIn('ln -sf "${sedsnet_rust_lld}" /usr/local/bin/lld-link', shell)
                self.assertLess(shell.index("source /usr/local/cargo/env"), shell.index("sedsnet_rust_host="))
                self.assertLess(shell.index("/usr/local/bin/lld-link --version"), shell.index("maturin build"))
                self.assertIn("--target " + target, shell)
                self.assertIn("--out dist/release", shell)
                self.assertNotIn("lib/rustlib/x86_64-unknown-linux-gnu", shell)

    def test_windows32_selects_x86_sdk_without_changing_the_default_target(self):
        x64, x86 = self.commands(["x86_64-pc-windows-msvc", "i686-pc-windows-msvc"])
        self.assertNotIn("XWIN_ARCH=x86", x64)
        self.assertIn("XWIN_ARCH=x86", x86)
        self.assertEqual(publisher.DEFAULT_WINDOWS_DOCKER_TARGETS, ["x86_64-pc-windows-msvc"])


if __name__ == "__main__":
    unittest.main()
