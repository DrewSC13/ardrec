"""P9-P12: pruebas de ciclo real benigno, sin autorizar P8."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ardrec.benign_pipeline import BenignPipeline, GateError, VerificationError


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ardrec-p9-p12-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "db"
        self.pipe = BenignPipeline(self.root)

    def test_zero_exit_result_and_evidence(self):
        self.pipe.submit("one", "ok")
        record = self.pipe.execute("one")
        self.assertEqual(record["state"], "RECORDED_LIMITED")
        self.assertEqual(record["start_count"], 1)
        self.assertEqual(record["result"]["outcome"], "BENIGN_EXIT_ZERO")
        self.assertTrue(record["result"]["leader_reaped"])
        self.assertFalse(record["result"]["global_tree_cleanup_proven"])
        self.assertIsNotNone(record["result"]["leader_pid"])
        self.assertTrue(self.pipe.verify("one")["artifacts_verified"])
        self.assertEqual((self.pipe.artifacts / record["result"]["artifacts"]["stdout"]["name"]).read_text(),
                         "ARDREC_BENIGN_OK\n")

    def test_nonzero_is_not_success(self):
        self.pipe.submit("nonzero", "nonzero")
        result = self.pipe.execute("nonzero")["result"]
        self.assertEqual(result["leader_returncode"], 7)
        self.assertEqual(result["outcome"], "BENIGN_EXIT_NONZERO")
        self.assertTrue(self.pipe.verify("nonzero"))

    def test_bounded_capture_and_truncation_proof(self):
        self.pipe.submit("large", "noisy", output_cap=512)
        result = self.pipe.execute("large")["result"]
        stdout = result["bounded_capture"]["stdout"]
        self.assertEqual(stdout["stored_bytes"], 512)
        self.assertEqual(stdout["observed_bytes"], 131072)
        self.assertTrue(stdout["truncated"])
        self.assertTrue(stdout["eof_observed"])
        self.assertTrue(self.pipe.verify("large")["artifacts_verified"])

    def test_bounded_deadline_and_reaped_leader(self):
        self.pipe.submit("slow", "slow", deadline_ms=100)
        result = self.pipe.execute("slow")["result"]
        self.assertEqual(result["outcome"], "DEADLINE")
        self.assertTrue(result["deadline_exceeded"])
        self.assertTrue(result["leader_reaped"])
        self.assertFalse(result["global_tree_cleanup_proven"])
        self.assertTrue(self.pipe.verify("slow")["artifacts_verified"])

    def test_same_request_is_idempotent(self):
        first = self.pipe.submit("same", "ok")
        again = self.pipe.submit("same", "ok")
        self.assertEqual(first["fingerprint"], again["fingerprint"])
        result = self.pipe.execute("same")
        repeated = self.pipe.execute("same")
        self.assertEqual(result["state"], repeated["state"])
        self.assertEqual(repeated["start_count"], 1)
        self.assertEqual(self.pipe.verify("same")["event_count"], 5)

    def test_different_payload_same_id_rejected(self):
        self.pipe.submit("same", "ok")
        with self.assertRaisesRegex(GateError, "different_payload"):
            self.pipe.submit("same", "nonzero")
        self.assertEqual(self.pipe.read("same")["start_count"], 0)

    def test_arbitrary_commands_and_path_like_ids_rejected(self):
        for fixture in ("/bin/sh", "bash", "ssh", "ftp", "smbclient", "../../bin/date"):
            with self.subTest(fixture=fixture), self.assertRaises(GateError):
                self.pipe.submit("bad", fixture)
        for rid in ("", "../escape", "x/y", "a" * 65):
            with self.subTest(rid=rid), self.assertRaises(GateError):
                self.pipe.submit(rid, "ok")

    def test_invalid_budgets_rejected(self):
        for timeout, cap in ((0,512),(3001,512),(1000,0),(1000,65537),(True,512)):
            with self.subTest(timeout=timeout,cap=cap), self.assertRaises(GateError):
                self.pipe.submit("bad", "ok", deadline_ms=timeout, output_cap=cap)

    def test_recovery_of_uncertain_start_never_relaunches(self):
        self.pipe.submit("interrupted", "ok")
        self.pipe.accept("interrupted")
        self.assertIsNotNone(self.pipe._claim_start("interrupted"))
        self.assertEqual(self.pipe.recover(), ["interrupted"])
        self.assertEqual(self.pipe.recover(), [])
        result = self.pipe.execute("interrupted")
        self.assertEqual(result["state"], "RECOVERY_UNCERTAIN")
        self.assertEqual(result["start_count"], 1)
        self.assertTrue(self.pipe.verify("interrupted"))

    def test_real_process_exits_after_start_intent_before_launch(self):
        self.pipe.submit("hard_crash", "ok")
        env = os.environ.copy()
        env["ARDREC_DEV_FAILPOINT_AFTER_START_INTENT"] = "1"
        code = ("import sys;sys.path.insert(0,%r);"
                "from ardrec.benign_pipeline import BenignPipeline;"
                "BenignPipeline(%r).execute('hard_crash')" % (str(SRC), str(self.root)))
        child = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                               timeout=12)
        self.assertEqual(child.returncode, 77, child.stderr)
        self.assertEqual(self.pipe.read("hard_crash")["state"], "START_INTENT")
        second = BenignPipeline(self.root)
        self.assertEqual(second.recover(), ["hard_crash"])
        self.assertEqual(second.execute("hard_crash")["start_count"], 1)
        self.assertEqual(second.read("hard_crash")["state"], "RECOVERY_UNCERTAIN")

    def test_concurrent_requests_cannot_double_start(self):
        self.pipe.submit("parallel", "slow", deadline_ms=200)
        first = BenignPipeline(self.root)
        second = BenignPipeline(self.root)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(p.execute, "parallel") for p in (first,second)]
            for f in futures:
                f.result(timeout=15)
        record = self.pipe.read("parallel")
        self.assertEqual(record["start_count"], 1)
        self.assertIn(record["state"], ("RECORDED_LIMITED", "RECOVERY_UNCERTAIN"))
        self.assertTrue(self.pipe.verify("parallel"))

    def test_tampered_artifact_is_detected(self):
        self.pipe.submit("tamper", "ok")
        record = self.pipe.execute("tamper")
        path = self.pipe.artifacts / record["result"]["artifacts"]["stdout"]["name"]
        path.write_bytes(b"altered")
        with self.assertRaisesRegex(VerificationError, "artifact_integrity_mismatch"):
            self.pipe.verify("tamper")

    def test_tampered_event_is_detected(self):
        self.pipe.submit("event", "ok")
        with self.pipe._managed() as db:
            db.execute("UPDATE events SET action='ALTERED' WHERE request_id='event'")
        with self.assertRaises(VerificationError):
            self.pipe.verify("event")

    def test_database_result_tampering_is_detected(self):
        self.pipe.submit("changed", "ok")
        self.pipe.execute("changed")
        with self.pipe._managed() as db:
            original = json.loads(db.execute(
                "SELECT result_json FROM attempts WHERE id='changed'").fetchone()[0])
            original["leader_returncode"] = 99
            db.execute("UPDATE attempts SET result_json=? WHERE id='changed'",
                       (json.dumps(original),))
        with self.assertRaisesRegex(VerificationError, "result_record_mismatch"):
            self.pipe.verify("changed")

    def test_durable_acceptance_before_irrevocable_start(self):
        self.pipe.submit("accepted", "ok")
        self.assertEqual(self.pipe.accept("accepted")["state"], "ACCEPTED")
        self.assertEqual(self.pipe.read("accepted")["start_count"], 0)
        self.assertEqual(BenignPipeline(self.root).recover(), [])
        self.assertEqual(self.pipe.execute("accepted")["start_count"], 1)
        self.assertTrue(self.pipe.verify("accepted"))

    def test_closed_root_denies_world_writable_permissions(self):
        self.assertEqual(self.root.stat().st_mode & 0o077, 0)
        self.assertEqual(self.pipe.artifacts.stat().st_mode & 0o077, 0)
        self.pipe.submit("perms", "ok")
        result = self.pipe.execute("perms")["result"]
        file = self.pipe.artifacts / result["artifacts"]["stdout"]["name"]
        self.assertEqual(file.stat().st_mode & 0o077, 0)


    @unittest.skipUnless(sys.platform == "linux", "procfs fixture")
    def test_spawn_registration_exception_reaps_owned_leader(self):
        # Inyecta la falla DESPUES de Popen, ANTES de registrar PID duradero.
        observed = []

        def injected_failure(pid, ticks):
            observed.append((pid, ticks))
            raise OSError("forced_registration_failure")

        with self.assertRaisesRegex(OSError, "forced_registration_failure"):
            BenignPipeline._bounded_run("slow", 1000, 512, injected_failure)
        self.assertEqual(len(observed), 1)
        pid, ticks = observed[0]
        stat_file = Path(f"/proc/{pid}/stat")
        if stat_file.exists():
            fields = stat_file.read_text(encoding="ascii").rsplit(") ", 1)[1].split()
            self.assertNotEqual(int(fields[19]), ticks,
                                "El lider propio no fue recogido tras el error")


if __name__ == "__main__":
    unittest.main()
