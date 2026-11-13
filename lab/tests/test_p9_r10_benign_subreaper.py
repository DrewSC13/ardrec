"""Oraculos independientes del ensayo P9-R10. No prueban el motor Rust."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "p9_r10_benign_subreaper_demo.py"


def run_demo(extra_args=(), env=None):
    return subprocess.run([sys.executable, str(SCRIPT), *extra_args],
                          capture_output=True, text=True, timeout=12, env=env)


class TestBenignSubreaper(unittest.TestCase):
    def test_escaped_child_is_adopted_reaped_and_independently_absent(self):
        completed = run_demo()
        self.assertTrue(completed.stdout, completed.stderr)
        result = json.loads(completed.stdout)
        if completed.returncode == 3 and result["outcome"] == "UNSUPPORTED":
            self.skipTest("Host sin capacidad de subreaper/pidfd: resultado no sustituible por PASS")
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
        self.assertEqual(result["outcome"], "PASS_BENIGN_WITNESS")
        self.assertEqual(result["leader_returncode"], 0)
        self.assertTrue(result["adopted"])
        self.assertTrue(result["escaped_original_pgid"])
        self.assertNotEqual(result["witness_pgid"], result["leader_pgid"])
        self.assertTrue(result["termination_reaped"])
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(result["p8_operational"], "NO-GO")
        self.assertEqual(len(result["source_sha256"]), 64)
        # Oraculo separado: volver a consultar /proc ya fuera del supervisor.
        pid = result["witness_pid"]
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists():
            fields = stat.read_text(encoding="ascii").rsplit(") ", 1)[1].split()
            self.assertNotEqual(int(fields[19]), result["witness_start_ticks"],
                                "El testigo original continua vivo tras la supuesta limpieza")

    def test_capability_missing_fails_closed_without_process_launch(self):
        env = os.environ.copy()
        env["ARDREC_R10_FORCE_UNSUPPORTED"] = "1"
        completed = run_demo(env=env)
        self.assertEqual(completed.returncode, 3, completed.stderr + completed.stdout)
        result = json.loads(completed.stdout)
        self.assertEqual(result["outcome"], "UNSUPPORTED")
        self.assertFalse(result["cleanup_verified"])
        self.assertEqual(result["reason"], "forced_unsupported_for_negative_test")

    def test_no_user_supplied_command_accepted(self):
        completed = run_demo(("--exec", "/bin/sh"))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(completed.stdout, "")
        self.assertIn("unrecognized arguments", completed.stderr)


if __name__ == "__main__":
    unittest.main()
