"""P9-R13: pruebas fail-closed del enlace durable; no lanzan systemd en CI."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import subprocess
import time
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ardrec.benign_pipeline import BenignPipeline, GateError, VerificationError
from ardrec.benign_r12_handoff import (
    DurableR12Handoff, R12_SCHEMA, R12_MAIN_SHA,
    R12_UNIT_PATTERN, MAX_REPORT_BYTES, PENDING_TIMEOUT_S,
)


def report(*, result="PASS_BENIGN_TRANSIENT_UNIT"):
    unit = "ardrec-p9r12-012345abcdef.service"
    return {
        "schema": R12_SCHEMA,
        "main_sha": R12_MAIN_SHA,
        "unit": unit,
        "p8_operational": "NO-GO",
        "general_cleanup_certified": False,
        "result": result,
        "live_identity_confirmed": True,
        "live_group_proven": True,
        "poststop_absence_proven": True,
        "systemd_run_rc": 0,
        "targeted_stop_rc": 5,
        "cgroup_relative": "/user.slice/app.slice/" + unit,
        "observed_limits": {"pids.max": "16", "memory.max": "134217728", "cpu.max": "100000 100000"},
    }


class R13HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "state"
        self.b = DurableR12Handoff(self.root)

    def reserve(self, rid="case"):
        self.b.submit(rid)
        return rid

    def claim(self, rid="case"):
        self.reserve(rid)
        self.assertTrue(self.b._claim(rid))
        return rid

    def add_report(self, rid, value=None):
        path = self.b._directory(rid) / "report.json"
        path.write_text(json.dumps(report() if value is None else value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_r12_source_is_exactly_pinned(self):
        self.assertEqual(self.b._r12_script().name, "p9_r12_systemd_user_probe.py")

    def test_reservation_is_reproducible_and_idempotent(self):
        row = self.b.submit("same")
        self.assertEqual(self.b.submit("same")["fingerprint"], row["fingerprint"])
        self.assertEqual(row["state"], "RESERVED")

    def test_legacy_execute_denies_r12_after_reservation(self):
        rid = self.reserve()
        with self.assertRaisesRegex(GateError, "r12_requires_durable_bridge"):
            self.b.pipe.execute(rid)
        self.assertEqual(self.b.pipe.read(rid)["start_count"], 0)

    def test_legacy_recover_does_not_reconcile_r12(self):
        rid = self.claim()
        self.assertEqual(self.b.pipe.recover(), [])
        self.assertEqual(self.b.pipe.read(rid)["state"], "START_INTENT")

    def test_claim_is_exactly_once_under_race(self):
        self.reserve()
        with ThreadPoolExecutor(max_workers=4) as pool:
            claims = list(pool.map(lambda _: self.b._claim("case"), range(4)))
        self.assertEqual(claims.count(True), 1)
        self.assertEqual(self.b.pipe.read("case")["start_count"], 1)

    def test_valid_report_reconciles_without_launch(self):
        rid = self.claim()
        self.add_report(rid)
        with mock.patch("subprocess.Popen", side_effect=AssertionError("must not launch")):
            row = self.b.reconcile(rid)
        self.assertEqual(row["state"], "RECORDED_LIMITED")
        self.assertEqual(row["result"]["outcome"], "R12_OBSERVATION_REPORTED_PASS")
        self.assertFalse(row["result"]["global_tree_cleanup_proven"])
        self.assertEqual(row["result"]["r12_targeted_stop_rc"], 5)
        self.assertTrue(self.b.verify(rid)["artifacts_verified"])

    def test_reconcile_is_idempotent_and_does_not_double_start(self):
        rid = self.claim()
        self.add_report(rid)
        first = self.b.reconcile(rid)
        second = self.b.reconcile(rid)
        self.assertEqual(first["start_count"], 1)
        self.assertEqual(second["start_count"], 1)
        self.assertEqual(self.b.verify(rid)["event_count"], 4)

    def test_no_report_within_bound_stays_start_intent(self):
        rid = self.claim()
        with self.b.pipe._managed() as db:
            claimed = db.execute("SELECT claimed_epoch FROM r12_claims WHERE id=?", (rid,)).fetchone()[0]
        row = self.b.reconcile(rid, now=claimed + PENDING_TIMEOUT_S - 0.1)
        self.assertEqual(row["state"], "START_INTENT")

    def test_absent_report_after_deadline_is_uncertain_never_relaunched(self):
        rid = self.claim()
        with self.b.pipe._managed() as db:
            claimed = db.execute("SELECT claimed_epoch FROM r12_claims WHERE id=?", (rid,)).fetchone()[0]
        with mock.patch("subprocess.Popen", side_effect=AssertionError("must not launch")):
            row = self.b.reconcile(rid, now=claimed + PENDING_TIMEOUT_S + 1)
            again = self.b.reconcile(rid, now=claimed + PENDING_TIMEOUT_S + 10)
        self.assertEqual(row["state"], "RECOVERY_UNCERTAIN")
        self.assertEqual(again["start_count"], 1)
        self.assertTrue(self.b.verify(rid))

    def test_one_recovery_can_reconcile_multiple_receipts(self):
        self.claim("one"); self.claim("two")
        self.add_report("one")
        result = self.b.recover(now=0)
        self.assertEqual(result, {"one": "RECORDED_LIMITED", "two": "START_INTENT"})
        self.assertTrue(self.b.verify("one"))

    def test_no_forged_clean_status(self):
        for changes in (
            {"general_cleanup_certified": True},
            {"p8_operational": "GO"},
            {"live_group_proven": False},
            {"poststop_absence_proven": False},
            {"observed_limits": {"pids.max": "max"}},
            {"unit": "evil.service"},
            {"main_sha": "0" * 40},
            {"systemd_run_rc": 5},
        ):
            with self.subTest(changes=changes):
                d = report(); d.update(changes)
                self.assertFalse(self.b._receipt_check(d))

    def test_inconclusive_report_remains_non_success(self):
        rid = self.claim()
        self.add_report(rid, report(result="INCONCLUSIVE"))
        row = self.b.reconcile(rid)
        self.assertEqual(row["result"]["outcome"], "R12_OBSERVATION_INCONCLUSIVE")
        self.assertFalse(row["result"]["global_tree_cleanup_proven"])
        self.assertTrue(self.b.verify(rid))

    def test_symlink_report_never_finalizes(self):
        rid = self.claim()
        external = self.root / "untrusted.json"
        external.write_text(json.dumps(report()))
        (self.b._directory(rid) / "report.json").symlink_to(external)
        row = self.b.reconcile(rid)
        self.assertEqual(row["state"], "START_INTENT")

    def test_oversized_report_never_finalizes(self):
        rid = self.claim()
        p = self.add_report(rid)
        p.write_bytes(b"X" * (MAX_REPORT_BYTES + 1))
        row = self.b.reconcile(rid)
        self.assertEqual(row["state"], "START_INTENT")

    def test_tampered_receipt_detected_after_record(self):
        rid = self.claim()
        p = self.add_report(rid)
        self.b.reconcile(rid)
        p.write_text(json.dumps({**report(), "targeted_stop_rc": 0}))
        with self.assertRaisesRegex(VerificationError, "receipt_integrity"):
            self.b.verify(rid)

    def test_wrong_original_artifact_detected(self):
        rid = self.claim()
        self.add_report(rid)
        row = self.b.reconcile(rid)
        name = row["result"]["artifacts"]["stdout"]["name"]
        (self.b.pipe.artifacts / name).write_bytes(b"tampered")
        with self.assertRaises(VerificationError):
            self.b.verify(rid)

    def test_arbitrary_fixture_rejected_in_bridge(self):
        self.b.pipe.submit("other", "ok")
        with self.assertRaises(GateError):
            self.b._claim("other")
        self.assertEqual(self.b.pipe.read("other")["start_count"], 0)

    def test_only_fixed_r12_script_can_be_launched(self):
        rid = "mocked"
        class FakeChild:
            pid = 29999
            def poll(self): return 0
            def wait(self, timeout=None): return 0
        with mock.patch("subprocess.Popen", return_value=FakeChild()) as popen:
            with mock.patch.object(self.b, "_observe_child"):
                self.b.start(rid, wait=False)
        args = popen.call_args.args[0]
        self.assertEqual(args[:2], [sys.executable, "-I"])
        self.assertEqual(args[-2], "--evidence-dir")
        self.assertEqual(args[-1], str(self.b._directory(rid)))
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertFalse(popen.call_args.kwargs["shell"] if "shell" in popen.call_args.kwargs else False)
        self.assertEqual(self.b.pipe.read(rid)["start_count"], 1)

    def test_real_coordinator_crash_recovers_synthetic_receipt_without_relaunch(self):
        # Ensayo de proceso real, solo un reporte sintético, NO prueba systemd.
        script = Path(self.temp.name) / "mock_r12_worker.py"
        fake = report()
        script.write_text(
            "import json,os,pathlib,sys,time\n"
            "time.sleep(0.35)\n"
            "p=pathlib.Path(sys.argv[-1])/\"report.json\"\n"
            "t=p.with_name(\".atomic_tmp\")\n"
            "t.write_text(" + repr(json.dumps(fake)) + ")\n"
            "os.chmod(t,0o600)\n"
            "os.replace(t,p)\n",
            encoding="utf-8",
        )
        child_code = (
            "import os,sys,pathlib;sys.path.insert(0," + repr(str(ROOT / "src")) + ");"
            "from ardrec.benign_r12_handoff import DurableR12Handoff;"
            "DurableR12Handoff._r12_script=lambda self:pathlib.Path(" + repr(str(script)) + ");"
            "b=DurableR12Handoff(" + repr(str(self.root)) + ");"
            "r=b.start('crash',wait=False);"
            "assert r['state']=='START_INTENT' and r['start_count']==1;"
            "os._exit(77)"
        )
        proc = subprocess.run([sys.executable, "-c", child_code], timeout=7,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(proc.returncode, 77, proc.stderr)
        result = None
        with mock.patch("subprocess.Popen", side_effect=AssertionError("recovery must not launch")):
            for _ in range(90):
                result = self.b.reconcile("crash")
                if result["state"] != "START_INTENT":
                    break
                time.sleep(0.06)
        self.assertEqual(result["state"], "RECORDED_LIMITED")
        self.assertEqual(result["start_count"], 1)
        self.assertTrue(self.b.verify("crash")["artifacts_verified"])

    def test_source_rejects_any_changed_bytes(self):
        with mock.patch("pathlib.Path.read_bytes", return_value=b"altered"):
            with self.assertRaises(GateError):
                self.b._r12_script()


if __name__ == "__main__":
    unittest.main()
