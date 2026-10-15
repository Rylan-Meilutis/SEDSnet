"""Callbacks may inspect their originating router without a wrapper deadlock."""
import subprocess
import sys
import unittest

try:
    import sedsnet
except ImportError:
    sedsnet = None


@unittest.skipIf(sedsnet is None, "installed Python binding required")
class CallbackReentryTests(unittest.TestCase):
    def test_callback_can_read_originating_router(self):
        source = """
import sedsnet
router = sedsnet.Router(hostname="python-callback-reentry")
seen = []
def accepted(packet):
    seen.append(router.sender_id)
router.add_side_packet("test-wire", accepted)
router.announce_discovery()
router.process_all_queues()
assert seen and all(name == "python-callback-reentry" for name in seen), seen
"""
        result = subprocess.run([sys.executable, "-c", source],
            text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
