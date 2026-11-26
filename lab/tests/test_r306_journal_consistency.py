"""R306: historical journal consistency, synthetic local metadata only."""
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from ardrec.experiments import journal_readback as reader
from ardrec.experiments import prospective_attempt_journal as native
from ardrec.experiments.prospective_local_dispatch import DispatchJournal


@unittest.skipIf(os.geteuid() == 0, "non-root journal contract")
class JournalConsistencyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "journal.sqlite3"
        self.journal = DispatchJournal(self.path, create=True)
        self.plan = native.make_plan(plan_id="1" * 32, protocol="FTP",
            head="a" * 40, tree="b" * 40, coverage_sha256="c" * 64,
            runner_sha256="d" * 64, fixture_sha256="e" * 64,
            operator_uid=os.geteuid(), created_at=100, expires_at=200)
        self.pid = self.plan["plan_id"]
        self.at(110, self.journal.register, self.plan)

    def at(self, now, fn, *args, **kwargs):
        with patch.object(native, "clock", return_value=now):
            return fn(*args, **kwargs)

    def authorize(self):
        self.at(120, self.journal.authorize, self.pid, native.consent_for(self.plan))

    def reserve(self, now=130):
        return self.at(now, self.journal.reserve, self.pid,
            head=self.plan["code_head"], tree=self.plan["code_tree"],
            runner_sha256=self.plan["runner_sha256"])

    def mutate(self, sql, args=()):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(sql, args)
            db.commit()

    def evaluate(self):
        raw = self.path.read_bytes()
        try:
            report = reader.evaluate(self.path, hashlib.sha256(raw).hexdigest())
            self.assertEqual(report["new_attempts"], 0)
            self.assertEqual(report["new_observations"], 0)
            self.assertEqual(report["a6"], "ND")
            self.assertIsNone(report["confirmed_rf"])
            self.assertEqual(report["p8"], "NO-GO")
            return report
        finally:
            self.assertEqual(self.path.read_bytes(), raw)

    def state(self, expected):
        self.assertEqual(self.evaluate()["states"][expected], 1)

    def test_planned_authorized_reserved_claimed_receipt(self):
        self.state("PLANNED")
        self.authorize()
        self.state("AUTHORIZED")
        token = self.reserve()
        self.state("RESERVED")
        self.at(140, self.journal.claim_dispatch, self.pid, token)
        self.state("RESERVED")
        self.at(150, self.journal.record_receipt, self.pid, token, "f" * 64)
        self.state("RECEIPT_RECORDED_UNVERIFIED")
        self.assertEqual(self.evaluate(), self.evaluate())

    def test_legacy_receipt_without_claim(self):
        self.authorize()
        token = self.reserve()
        self.at(150, self.journal.record_receipt, self.pid, token, "f" * 64)
        self.state("RECEIPT_RECORDED_UNVERIFIED")
        self.assertFalse(self.evaluate()["records"][0]["receipt_technically_validated"])

    def test_expiration_valid(self):
        self.authorize()
        with self.assertRaisesRegex(ValueError, "AUTHORIZATION_EXPIRED"):
            self.reserve(200)
        self.state("EXPIRED")

    def test_revocation_valid(self):
        self.authorize()
        self.at(130, self.journal.revoke, self.pid)
        self.state("REVOKED")

    def test_uncertain_valid(self):
        self.authorize()
        token = self.reserve()
        self.at(140, self.journal.mark_uncertain, self.pid, token)
        self.state("UNCERTAIN")

    def test_revoked_reserved_valid(self):
        self.authorize()
        self.reserve()
        self.at(140, self.journal.revoke, self.pid)
        self.state("UNCERTAIN")

    def test_reservation_hash_mismatch(self):
        self.authorize()
        self.reserve()
        self.mutate("UPDATE plans SET reservation_sha256=?", ("0" * 64,))
        with self.assertRaisesRegex(ValueError, "JOURNAL_MATERIALIZATION_MISMATCH"):
            self.evaluate()

    def test_authorization_time_mismatch(self):
        self.authorize()
        self.mutate("UPDATE plans SET authorized_at=121")
        with self.assertRaisesRegex(ValueError, "JOURNAL_MATERIALIZATION_MISMATCH"):
            self.evaluate()

    def test_reservation_time_mismatch(self):
        self.authorize()
        self.reserve()
        self.mutate("UPDATE plans SET reserved_at=131")
        with self.assertRaisesRegex(ValueError, "JOURNAL_MATERIALIZATION_MISMATCH"):
            self.evaluate()

    def test_revocation_time_mismatch(self):
        self.at(130, self.journal.revoke, self.pid)
        self.mutate("UPDATE plans SET revoked_at=NULL")
        with self.assertRaisesRegex(ValueError, "JOURNAL_MATERIALIZATION_MISMATCH"):
            self.evaluate()

    def test_early_expiration_rejected(self):
        self.authorize()
        with self.assertRaises(ValueError):
            self.reserve(200)
        self.mutate("UPDATE events SET timestamp=199 WHERE action='EXPIRED'")
        with self.assertRaisesRegex(ValueError, "EXPIRATION_TIME_INVALID"):
            self.evaluate()

    def test_reservation_outside_validity_rejected(self):
        self.authorize()
        self.reserve()
        self.mutate("UPDATE events SET timestamp=200 WHERE action='ATTEMPT_RESERVED'")
        self.mutate("UPDATE plans SET reserved_at=200")
        with self.assertRaisesRegex(ValueError, "EVENT_OUTSIDE_PLAN_VALIDITY"):
            self.evaluate()

    def test_unexpected_event_detail_rejected(self):
        self.mutate("UPDATE events SET detail='unexpected' WHERE action='REGISTERED'")
        with self.assertRaisesRegex(ValueError, "EVENT_DETAIL_INVALID"):
            self.evaluate()

    def test_receipt_before_reservation_rejected(self):
        self.authorize()
        token = self.reserve()
        self.at(150, self.journal.record_receipt, self.pid, token, "f" * 64)
        self.mutate("UPDATE events SET timestamp=129 WHERE action='RECEIPT_RECORDED_UNVERIFIED'")
        with self.assertRaisesRegex(ValueError, "RECEIPT_TIME_INVALID"):
            self.evaluate()

    def test_empty_reservation_must_not_exist(self):
        self.mutate("UPDATE plans SET reservation_sha256=?", ("0" * 64,))
        with self.assertRaisesRegex(ValueError, "JOURNAL_MATERIALIZATION_MISMATCH"):
            self.evaluate()

    def test_late_receipt_valid(self):
        self.authorize()
        token = self.reserve()
        self.at(220, self.journal.record_receipt, self.pid, token, "f" * 64)
        self.state("RECEIPT_RECORDED_UNVERIFIED")

    def test_dispatch_before_reservation_rejected(self):
        self.authorize()
        token = self.reserve()
        self.at(140, self.journal.claim_dispatch, self.pid, token)
        self.mutate("UPDATE events SET timestamp=129 WHERE action='DISPATCH_CLAIMED'")
        with self.assertRaisesRegex(ValueError, "DISPATCH_TIME_INVALID"):
            self.evaluate()

    def test_clock_regression_on_revocation_retained(self):
        self.authorize()
        self.at(115, self.journal.revoke, self.pid)
        report = self.evaluate()
        self.assertEqual(report["states"]["REVOKED"], 1)
        self.assertEqual(report["records"][0]["chronology_issues"], ["UTC_REGRESSION:3"])
