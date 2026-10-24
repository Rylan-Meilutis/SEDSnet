"""Exercise actual Ninja dependency edges without downloading or rebuilding Rust."""
from pathlib import Path
import os
import json
import shutil
import subprocess
import tempfile
import unittest
CMAKE_TEMPLATE = Path(__file__).resolve().parents[1] / "CMakeLists.txt"

@unittest.skipUnless(shutil.which("cmake") and shutil.which("ninja"), "CMake/Ninja required")
class CMakeInputTests(unittest.TestCase):
    def test_schema_creation_edits_macro_edits_and_selected_schema_rebuild(self):
        with tempfile.TemporaryDirectory(prefix="seds inputs ") as temp:
            root=Path(temp); source=root/"crate"; output=root/"cmake build"; source.mkdir()
            (source/"CMakeLists.txt").write_text(CMAKE_TEMPLATE.read_text())
            shutil.copy2(CMAKE_TEMPLATE.parent/"cargo_paths.py", source/"cargo_paths.py")
            helper=source/"release_credentials.py"; helper.write_text("# credential helper v1\n")
            for directory in ["C-Headers", "src", "sedsnet_macros/src"]: (source/directory).mkdir(parents=True)
            (source/"C-Headers/sedsnet.h").write_text("// test header\n")
            (source/"Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
            (source/"src/lib.rs").write_text("// source\n")
            macro=source/"sedsnet_macros/src/lib.rs"; macro.write_text("// macro v1\n")
            (source/"build.py").write_text("from pathlib import Path\np=Path('target/release/libsedsnet.a');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'!<arch>\\n')\nc=Path('invocations');c.write_text(c.read_text()+'x' if c.exists() else 'x')\n")
            def run(args):
                result=subprocess.run(args,text=True,capture_output=True,env={**os.environ,"CARGO_TARGET_DIR":str(source/"target")})
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            def build(): run(["cmake","--build",str(output),"--target","sedsnet_build"])
            def count(): return len((source/"invocations").read_text())
            configure=["cmake","-S",str(source),"-B",str(output),"-G","Ninja","-DCMAKE_BUILD_TYPE=Release","-DSEDSNET_FORCE_RELEASE=ON"]
            run(configure); build(); self.assertEqual(count(),1)
            build(); self.assertEqual(count(),1,"unchanged builds should stay cached")
            schema=source/"telemetry_config.json"; schema.write_text('{"types": []}')
            build(); self.assertEqual(count(),2,"new default schema must invalidate compiled catalog")
            schema.write_text('{"types": [], "endpoints": []}')
            build(); self.assertEqual(count(),3,"schema-only edit must invoke Cargo")
            macro.write_text("// macro v2\n")
            build(); self.assertEqual(count(),4,"proc-macro edits must invoke Cargo")
            helper.write_text("# credential helper v2\n")
            build(); self.assertEqual(count(),5,"build helper edits must invoke Cargo")
            selected=root/"selected schema.json"; selected.write_text('{}')
            run(configure+["-DSEDSNET_SCHEMA_PATH="+str(selected)]); build(); before=count()
            selected.write_text('{"types": []}')
            build(); self.assertEqual(count(),before+1,"external schema override must invalidate library")

    @unittest.skipUnless(shutil.which("cc") and (shutil.which("c++") or shutil.which("g++")), "C/C++ compiler required")
    def test_noexecstack_is_assembler_only_while_link_protection_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="seds noexecstack ") as temp:
            root = Path(temp)
            sdk = root / "sdk"
            sdk.mkdir()
            (sdk / "CMakeLists.txt").write_text(CMAKE_TEMPLATE.read_text())
            shutil.copyfile(CMAKE_TEMPLATE.parent / "cargo_paths.py", sdk / "cargo_paths.py")
            (sdk / "C-Headers").mkdir()
            (sdk / "C-Headers/sedsnet.h").write_text("// fixture header\n")
            (sdk / "src").mkdir()
            (sdk / "src/lib.rs").write_text("// no Rust build in this fixture\n")
            (sdk / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
            (sdk / "build.py").write_text("raise RuntimeError('Rust must not run during generation')\n")
            for filename in ["probe.c", "probe.cpp", "probe.S"]:
                (root / filename).write_text("// compile-command fixture\n")
            (root / "CMakeLists.txt").write_text("""cmake_minimum_required(VERSION 3.22)
project(consumer LANGUAGES C CXX ASM)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(SEDSNET_EMBEDDED_BUILD ON CACHE BOOL "" FORCE)
add_subdirectory(sdk)
foreach(kind IN ITEMS c cpp S)
  add_library(probe_${kind} OBJECT probe.${kind})
  target_link_libraries(probe_${kind} PRIVATE sedsnet)
endforeach()
target_compile_options(probe_c PRIVATE -flto)
target_compile_options(probe_cpp PRIVATE -flto)
get_target_property(protection sedsnet INTERFACE_LINK_OPTIONS)
file(WRITE "${CMAKE_BINARY_DIR}/link-protection.txt" "${protection}")
""")
            build = root / "build"
            result = subprocess.run(["cmake", "-S", str(root), "-B", str(build), "-G", "Ninja"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = json.loads((build / "compile_commands.json").read_text())
            by_kind = {Path(command["file"]).suffix: command["command"] for command in commands}
            for kind in [".c", ".cpp"]:
                self.assertIn("-flto", by_kind[kind])
                self.assertNotIn("-Wa,--noexecstack", by_kind[kind])
            self.assertIn("-Wa,--noexecstack", by_kind[".S"])
            self.assertIn("-Wl,-z,noexecstack", (build / "link-protection.txt").read_text())
