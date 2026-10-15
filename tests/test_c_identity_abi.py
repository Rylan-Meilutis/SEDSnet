"""C identity widths must match Rust even with embedded short-enum flags."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class IdentityAbiTests(unittest.TestCase):
    def test_registry_ids_remain_u32_with_short_enums(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        source = r'''#include "sedsnet.h"
_Static_assert(sizeof(SedsDataType) == sizeof(uint32_t), "type identity ABI");
_Static_assert(sizeof(SedsDataEndpoint) == sizeof(uint32_t), "endpoint identity ABI");
_Static_assert(sizeof(SedsTypeRef) == sizeof(uint32_t), "type reference ABI");
static int distinguish(SedsDataType value) {
    switch (value) {
    case (SedsDataType)100U: return 1;
    case (SedsDataType)223048036U: return 2;
    default: return 0;
    }
}
int main(void) {
    SedsDataEndpoint endpoint = (SedsDataEndpoint)26587141U;
    return distinguish((SedsDataType)223048036U) == 2 &&
           endpoint == 26587141U ? 0 : 1;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_file = root / "identity.c"
            input_file.write_text(source)
            for flags in ([], ["-fshort-enums"]):
                output = root / ("short" if flags else "normal")
                subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    *flags, "-I", str(ROOT / "C-Headers"), str(input_file), "-o", str(output)], check=True)
                subprocess.run([str(output)], check=True)


if __name__ == "__main__":
    unittest.main()
