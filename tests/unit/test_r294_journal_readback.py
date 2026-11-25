"""R294 synthetic journal readback regression."""
import hashlib
import io
import os
import sqlite3
import tempfile
import time
import unittest

from contextlib import closing, redirect_stdout
from pathlib import Path

from ardrec.experiments import prospective_attempt_journal as native
from ardrec.experiments import journal_readback as reader
from ardrec.experiments import study_cli


class JournalReadbackTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "journal.sqlite3"
        self.journal = native.Journal(self.path, create=True)

    def pin(self):
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def plan(self):
        now = int(time.time())
        return native.make_plan(
            plan_id="1" * 32,
            protocol="SSH",
            head="a" * 40,
            tree="b" * 40,
            coverage_sha256="c" * 64,
            runner_sha256="d" * 64,
            fixture_sha256="e" * 64,
            operator_uid=os.geteuid(),
            created_at=now-2,
            expires_at=now+120,
        )

    def evaluate(self):
        pin = self.pin()
        report = reader.evaluate(self.path, pin)
        self.assertEqual(self.pin(), pin)
        self.assertIs(report["operational_dispatch"], False)
        self.assertEqual(report["new_attempts"], 0)
        self.assertEqual(report["p8"], "NO-GO")
        return report

    def test_01_empty(self):
        self.assertEqual(self.evaluate()["plans"], 0)

    def test_02_planned_and_idempotent(self):
        self.journal.register(self.plan())
        first = self.evaluate()
        self.assertEqual(first["states"]["PLANNED"], 1)
        self.assertEqual(first, self.evaluate())

    def test_03_revoked(self):
        plan = self.plan()
        self.journal.register(plan)
        self.journal.revoke(plan["plan_id"])
        self.assertEqual(self.evaluate()["states"]["REVOKED"], 1)

    def test_04_wrong_pin(self):
        with self.assertRaisesRegex(ValueError, "SOURCE_PIN_MISMATCH"):
            reader.evaluate(self.path, "0" * 64)

    def test_05_sidecar_rejected(self):
        Path(str(self.path) + "-wal").touch()
        with self.assertRaisesRegex(ValueError, "JOURNAL_SIDECAR_PRESENT"):
            reader.evaluate(self.path, self.pin())

    def test_06_inconsistent_counter_rejected(self):
        self.journal.register(self.plan())
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE plans SET attempt_count=1")
            db.commit()

        with self.assertRaisesRegex(
            ValueError, "JOURNAL_RECONCILIATION_MISMATCH"
        ):
            self.evaluate()

    def test_07_cli(self):
        self.journal.register(self.plan())
        output = io.StringIO()
        with redirect_stdout(output):
            rc = study_cli.main([
                "--diario-historico", str(self.path),
                "--sha256", self.pin(),
                "--texto",
            ])
        self.assertEqual(rc, 0)
        self.assertIn("PLANS=1", output.getvalue())
        self.assertIn("CURRENT_AUTHORITY=ND", output.getvalue())

    def test_08_uncertain_reconciliation(self):
        snapshot = {
            "plan_id": "1"*32,
            "plan_sha256": "a"*64,
            "protocol": "FTP",
            "state": "UNCERTAIN",
            "attempt_count": 1,
            "receipt_sha256": None,
            "sha256": "b"*64,
            "events": [
                {"sequence": 1, "timestamp": 1,
                 "action": "REGISTERED", "detail": ""},
                {"sequence": 2, "timestamp": 2,
                 "action": "LOCAL_CONSENT_RECORDED", "detail": "a"*64},
                {"sequence": 3, "timestamp": 3,
                 "action": "ATTEMPT_RESERVED", "detail": "c"*64},
                {"sequence": 4, "timestamp": 4,
                 "action": "ATTEMPT_UNCERTAIN", "detail": ""},
            ],
        }
        row = reader.reconcile(snapshot)
        self.assertEqual(row["state"], "UNCERTAIN")
        self.assertEqual(row["attempt_count"], 1)
        self.assertEqual(row["current_authority"], "ND")


class HistoricalDispatchCompatibilityTests(unittest.TestCase):

    def fixture(self, claims=None, terminal="receipt"):
        events = [
            {
                "sequence": 1, "timestamp": 1,
                "action": "REGISTERED", "detail": "",
            },
            {
                "sequence": 2, "timestamp": 2,
                "action": "LOCAL_CONSENT_RECORDED",
                "detail": "a"*64,
            },
            {
                "sequence": 3, "timestamp": 3,
                "action": "ATTEMPT_RESERVED",
                "detail": "c"*64,
            },
        ]

        if claims is None:
            claims = ["c"*64]

        for claim in claims:
            events.append({
                "sequence": len(events)+1,
                "timestamp": len(events)+1,
                "action": "DISPATCH_CLAIMED",
                "detail": claim,
            })

        receipt = None
        state = "RESERVED"

        if terminal == "receipt":
            state = "RECEIPT_RECORDED_UNVERIFIED"
            receipt = "d"*64
            events.append({
                "sequence": len(events)+1,
                "timestamp": len(events)+1,
                "action": state,
                "detail": receipt,
            })

        elif terminal == "uncertain":
            state = "UNCERTAIN"
            events.append({
                "sequence": len(events)+1,
                "timestamp": len(events)+1,
                "action": "ATTEMPT_UNCERTAIN",
                "detail": "",
            })

        return {
            "plan_id": "1"*32,
            "plan_sha256": "a"*64,
            "protocol": "FTP",
            "state": state,
            "attempt_count": 1,
            "receipt_sha256": receipt,
            "sha256": "b"*64,
            "events": events,
        }

    def test_claim_preserves_counter_and_receipt(self):
        result = reader.reconcile(self.fixture())
        self.assertEqual(result["attempt_count"], 1)
        self.assertEqual(
            result["state"],
            "RECEIPT_RECORDED_UNVERIFIED",
        )
        self.assertFalse(
            result["receipt_technically_validated"]
        )
        self.assertEqual(result["current_authority"], "ND")

    def test_duplicate_claim_refused(self):
        with self.assertRaisesRegex(
            ValueError, "HISTORICAL_DISPATCH_DUPLICATE"
        ):
            reader.reconcile(
                self.fixture(["c"*64, "c"*64])
            )

    def test_wrong_reservation_binding_refused(self):
        with self.assertRaisesRegex(
            ValueError, "HISTORICAL_DISPATCH_BINDING_INVALID"
        ):
            reader.reconcile(self.fixture(["e"*64]))

    def test_claim_without_reservation_refused(self):
        snapshot = self.fixture()
        del snapshot["events"][2]
        with self.assertRaisesRegex(
            ValueError, "HISTORICAL_DISPATCH_STATE_INVALID"
        ):
            reader.reconcile(snapshot)

    def test_uncertain_after_claim_remains_uncertain(self):
        result = reader.reconcile(
            self.fixture(terminal="uncertain")
        )
        self.assertEqual(result["state"], "UNCERTAIN")
        self.assertEqual(result["attempt_count"], 1)
        self.assertEqual(result["current_authority"], "ND")
