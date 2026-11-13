"""R15: oráculos sin lanzar systemd en CI; caída coordinador es sintética."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from ardrec.benign_pipeline import BenignPipeline, GateError, VerificationError
from ardrec.benign_r14_stop_handoff import (
    DurableR14StopHandoff, R14_SCHEMA, R14_BASE_SHA, R12_READY_SCHEMA,
    MAX_REPORT_BYTES, PENDING_TIMEOUT_S,
)


def receipts():
    uid = os.getuid()
    unit = "ardrec-p9r12-012345abcdef.service"
    cg = "/user.slice/app.slice/" + unit
    worker = {"pid": 22001, "ppid": 1000, "pgid": 22001, "start_ticks": 600, "uid": uid, "state": "R"}
    witness = {"pid": 22002, "ppid": 22001, "pgid": 22002, "start_ticks": 620, "uid": uid, "state": "R"}
    ready = {"schema": R12_READY_SCHEMA, "unit": unit,
             "p8_operational": "NO-GO", "worker_uid": uid,
             "witness_escaped_pgid": True, "worker": worker, "witness": witness,
             "worker_cgroup": cg, "witness_cgroup": cg}
    report = {"schema": R14_SCHEMA, "base_sha": R14_BASE_SHA,
              "scope": "one_owned_benign_transient_user_service", "unit": unit,
              "cgroup_relative": cg, "worker": worker, "witness": witness,
              "result": "PASS_OWNED_ACTIVE_STOP", "p8_operational": "NO-GO",
              "general_tree_cleanup_proven": False, "live_group_verified": True,
              "prestop_is_active_rc": 0, "prestop_two_identities_alive": True,
              "targeted_stop_rc": 0, "stop_command_success": True,
              "two_identities_absent": True, "poststop_cgroup_absent_or_unpopulated": True,
              "systemd_run_wrapper_rc": 0,
              "effective_limits": {"pids.max": "16", "memory.max": "134217728", "cpu.max": "100000 100000"}}
    return report, ready


class DurableStopTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.b = DurableR14StopHandoff(self.folder / "db")

    def claim(self, rid="case"):
        self.b.submit(rid)
        self.assertTrue(self.b._claim(rid))
        return rid

    def receipt(self, rid, report=None, ready=None):
        d = self.b._directory(rid)
        report0, ready0 = receipts()
        if report is None: report = report0
        if ready is None: ready = ready0
        rp, rd = d / "r14_report.json", d / "ready.json"
        rp.write_text(json.dumps(report), encoding="utf-8")
        rd.write_text(json.dumps(ready), encoding="utf-8")
        os.chmod(rp, 0o600); os.chmod(rd, 0o600)
        return rp, rd

    def test_r14_source_is_pinned(self):
        self.assertEqual(self.b._r14_script().name, "p9_r14_active_stop_probe.py")

    def test_submit_is_idempotent_and_isolated_from_r13(self):
        a = self.b.submit("id")
        self.assertEqual(self.b.submit("id")["fingerprint"], a["fingerprint"])
        with self.assertRaises(GateError):
            self.b.pipe.submit("id", "r12_systemd", deadline_ms=30000, output_cap=65536)

    def test_legacy_execute_denies_r14(self):
        self.b.submit("id")
        with self.assertRaisesRegex(GateError, "r14_stop_requires_durable_bridge"):
            self.b.pipe.execute("id")
        self.assertEqual(self.b.pipe.read("id")["start_count"], 0)

    def test_legacy_recover_does_not_steal_r14(self):
        rid = self.claim()
        self.assertEqual(self.b.pipe.recover(), [])
        self.assertEqual(self.b.pipe.read(rid)["state"], "START_INTENT")

    def test_one_claim_under_race(self):
        self.b.submit("id")
        with ThreadPoolExecutor(max_workers=4) as pool:
            winners = list(pool.map(lambda _: self.b._claim("id"), range(4)))
        self.assertEqual(winners.count(True), 1)
        self.assertEqual(self.b.pipe.read("id")["start_count"], 1)

    def test_valid_scoped_receipts_reconcile_no_relaunch(self):
        rid = self.claim()
        self.receipt(rid)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("launch forbidden")):
            row = self.b.reconcile(rid)
        self.assertEqual(row["state"], "RECORDED_LIMITED")
        self.assertEqual(row["result"]["outcome"], "R14_ACTIVE_STOP_REPORTED_PASS")
        self.assertFalse(row["result"]["global_tree_cleanup_proven"])
        self.assertEqual(row["result"]["r14_targeted_stop_rc"], 0)
        self.assertEqual(row["result"]["p8_operational"], "NO-GO")
        self.assertTrue(self.b.verify(rid)["artifacts_verified"])

    def test_reconcile_idempotence(self):
        rid = self.claim()
        self.receipt(rid)
        first = self.b.reconcile(rid)
        second = self.b.reconcile(rid)
        self.assertEqual(first["start_count"], 1)
        self.assertEqual(second["start_count"], 1)
        self.assertEqual(self.b.verify(rid)["event_count"], 4)

    def test_pending_before_deadline(self):
        rid = self.claim()
        with self.b.pipe._managed() as db:
            created = db.execute("SELECT claimed_epoch FROM r14_claims WHERE id=?", (rid,)).fetchone()[0]
        self.assertEqual(self.b.reconcile(rid, now=created+PENDING_TIMEOUT_S-1)["state"], "START_INTENT")

    def test_missing_report_becomes_uncertain_no_retry(self):
        rid = self.claim()
        with self.b.pipe._managed() as db:
            created = db.execute("SELECT claimed_epoch FROM r14_claims WHERE id=?", (rid,)).fetchone()[0]
        with mock.patch("subprocess.Popen", side_effect=AssertionError("never retry")):
            a = self.b.reconcile(rid, now=created+PENDING_TIMEOUT_S+1)
            b = self.b.reconcile(rid, now=created+PENDING_TIMEOUT_S+20)
        self.assertEqual(a["state"], "RECOVERY_UNCERTAIN")
        self.assertEqual(b["start_count"], 1)
        self.assertTrue(self.b.verify(rid))

    def test_forged_stop_semantics_denied(self):
        a, b = receipts()
        alterations = (
            {"stop_command_success": False}, {"targeted_stop_rc": 5},
            {"prestop_is_active_rc": 3}, {"prestop_two_identities_alive": False},
            {"two_identities_absent": False}, {"poststop_cgroup_absent_or_unpopulated": False},
            {"live_group_verified": False}, {"systemd_run_wrapper_rc": 1},
            {"p8_operational": "GO"}, {"general_tree_cleanup_proven": True},
            {"unit": "other.service"}, {"base_sha": "0"*40},
            {"effective_limits": {"pids.max": "max"}},
            {"cgroup_relative": "/sys/fs/cgroup/tab.scope"},
        )
        for changes in alterations:
            with self.subTest(changes=changes):
                self.assertFalse(self.b._receipt_check({**a, **changes}, b))

    def test_wrong_ready_identity_denied(self):
        a, b = receipts()
        for changes in ({"unit": "fake.service"},
                        {"witness_cgroup": "/user.slice/unrelated"},
                        {"witness_escaped_pgid": False},
                        {"witness": {**b["witness"], "start_ticks": 999}}):
            with self.subTest(changes=changes):
                self.assertFalse(self.b._receipt_check(a, {**b, **changes}))

    def test_positive_report_requires_ready(self):
        a, _ = receipts()
        self.assertFalse(self.b._receipt_check(a, None))

    def test_negative_report_is_non_success(self):
        rid = self.claim()
        a, b = receipts(); a["result"] = "INCONCLUSIVE"
        self.receipt(rid, a, b)
        row = self.b.reconcile(rid)
        self.assertEqual(row["result"]["outcome"], "R14_ACTIVE_STOP_INCONCLUSIVE")
        self.assertFalse(row["result"]["global_tree_cleanup_proven"])
        self.assertTrue(self.b.verify(rid)["artifacts_verified"])

    def test_missing_ready_never_promotes_positive_report(self):
        rid = self.claim()
        rp, rd = self.receipt(rid)
        rd.unlink()
        self.assertEqual(self.b.reconcile(rid)["state"], "START_INTENT")

    def test_symlink_report_never_promotes(self):
        rid = self.claim()
        outside = self.folder / "outside.json"
        outside.write_text(json.dumps(receipts()[0]))
        (self.b._directory(rid)/"r14_report.json").symlink_to(outside)
        self.assertEqual(self.b.reconcile(rid)["state"], "START_INTENT")

    def test_symlink_ready_never_promotes(self):
        rid = self.claim()
        _, ready = self.receipt(rid)
        outside = self.folder / "untrusted-ready.json"
        outside.write_bytes(ready.read_bytes())
        ready.unlink(); ready.symlink_to(outside)
        self.assertEqual(self.b.reconcile(rid)["state"], "START_INTENT")

    def test_oversized_report_never_promotes(self):
        rid = self.claim()
        report_path,_ = self.receipt(rid)
        report_path.write_bytes(b'X' * (MAX_REPORT_BYTES + 1))
        self.assertEqual(self.b.reconcile(rid)["state"], "START_INTENT")

    def test_tampered_report_detected_after_record(self):
        rid = self.claim()
        p,_ = self.receipt(rid)
        self.b.reconcile(rid)
        report,_ = receipts()
        report["reason"] = "tampered"
        p.write_text(json.dumps(report))
        with self.assertRaisesRegex(VerificationError, "integrity_mismatch"):
            self.b.verify(rid)

    def test_tampered_ready_detected_after_record(self):
        rid = self.claim()
        _, ready = self.receipt(rid)
        self.b.reconcile(rid)
        a,b = receipts();b["extra"] = "tampered"
        ready.write_text(json.dumps(b))
        with self.assertRaisesRegex(VerificationError, "integrity_mismatch"):
            self.b.verify(rid)

    def test_tampered_artifact_detected(self):
        rid = self.claim()
        self.receipt(rid)
        record=self.b.reconcile(rid)
        name=record["result"]["artifacts"]["stderr"]["name"]
        (self.b.pipe.artifacts/name).write_bytes(b"changed")
        with self.assertRaises(VerificationError):
            self.b.verify(rid)

    def test_arbitrary_fixture_cannot_be_claimed(self):
        self.b.pipe.submit("other", "ok")
        with self.assertRaises(GateError):
            self.b._claim("other")
        self.assertEqual(self.b.pipe.read("other")["start_count"], 0)

    def test_only_fixed_r14_script_is_executed(self):
        class FakeChild:
            pid=29999
            def poll(self):return 0
            def wait(self,timeout=None):return 0
        with mock.patch("subprocess.Popen", return_value=FakeChild()) as popen:
            with mock.patch.object(self.b, "_observe_child"):
                self.b.start("test", wait=False)
        cmd=popen.call_args.args[0]
        self.assertEqual(cmd[:2],[sys.executable,"-I"])
        self.assertEqual(cmd[2],str(self.b._r14_script()))
        self.assertEqual(cmd[-2:],["--evidence-dir",str(self.b._directory("test"))])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(self.b.pipe.read("test")["start_count"],1)

    def test_crash_coordinator_synthetic_receipt_no_relaunch(self):
        mock_script = self.folder / "synthetic_r14.py"
        a,b = receipts()
        code = (
            "import json,os,pathlib,sys,time\n"
            "time.sleep(0.25)\n"
            "p=pathlib.Path(sys.argv[-1]);p.joinpath('r14_report.json').write_text("+repr(json.dumps(a))+ ")\n"
            "p.joinpath('ready.json').write_text("+repr(json.dumps(b))+ ")\n"
            "os.chmod(p/'r14_report.json',0o600);os.chmod(p/'ready.json',0o600)\n"
        )
        mock_script.write_text(code)
        child_code = (
            "import os,sys,pathlib;sys.path.insert(0," + repr(str(REPO/"src"))+ ");"
            "from ardrec.benign_r14_stop_handoff import DurableR14StopHandoff;"
            "DurableR14StopHandoff._r14_script=staticmethod(lambda: pathlib.Path("+repr(str(mock_script)) + "));"
            "b=DurableR14StopHandoff("+repr(str(self.b.pipe.root))+ ");"
            "r=b.start('crash',wait=False);"
            "assert r['state']=='START_INTENT' and r['start_count']==1;"
            "os._exit(77)"
        )
        proc=subprocess.run([sys.executable,"-c",child_code],capture_output=True,timeout=7)
        self.assertEqual(proc.returncode,77,proc.stderr)
        result=None
        with mock.patch("subprocess.Popen",side_effect=AssertionError("recovery must not launch")):
            for _ in range(100):
                result=self.b.reconcile("crash")
                if result["state"]!="START_INTENT":break
                time.sleep(.05)
        self.assertEqual(result["state"],"RECORDED_LIMITED")
        self.assertEqual(result["start_count"],1)
        self.assertTrue(self.b.verify("crash")["artifacts_verified"])

    def test_altered_source_is_rejected(self):
        with mock.patch("pathlib.Path.read_bytes",return_value=b"altered"):
            with self.assertRaises(GateError):
                self.b._r14_script()


if __name__=='__main__':
    unittest.main()
