"""Send router-owned ordinary data to an independently compiled codec-free receiver."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class PayloadCodecProcess(unittest.TestCase):
    def test_unknown_peer_router_data_is_decodable_by_codec_free_profile(self):
        def build(extra):
            result=subprocess.run(["cargo","test","--test","payload_codec_process","--no-run",
                "--message-format=json",*extra],cwd=ROOT,env=os.environ.copy(),text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            for line in result.stdout.splitlines():
                item=json.loads(line)
                if item.get("reason")=="compiler-artifact" and item.get("executable"):
                    return item["executable"]
            self.fail("missing process executable")
        hosted=build([])
        minimal=build(["--no-default-features","--features","discovery,timesync,serde,serde_json"])
        with tempfile.TemporaryDirectory()as directory:
            for executable,role in [(hosted,"produce"),(minimal,"receive")]:
                environment=os.environ.copy();environment.update(CODEC_PROCESS_DIR=directory,CODEC_PROCESS_ROLE=role)
                result=subprocess.run([executable,"--ignored","--exact","isolated_router_codec_node"],
                    cwd=ROOT,env=environment,text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
