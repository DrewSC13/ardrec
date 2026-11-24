"""R205: disposable, offline transactional tests."""
import concurrent.futures
import os
import secrets
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from ardrec.experiments import prospective_attempt_journal as m
from ardrec.coordination import prospective_local_pilot as durable


HEAD = "a" * 40
TREE = "b" * 40
RUNNER = "c" * 64

IDENTITY = {
    "head": HEAD,
    "tree": TREE,
    "runner_sha256": RUNNER,
}


class JournalTests(unittest.TestCase):

    def setUp(self):

        self.temp = tempfile.TemporaryDirectory()

        self.addCleanup(self.temp.cleanup)

        self.path = (
            Path(self.temp.name) / "journal.sqlite3"
        )

        self.journal = m.Journal(
            self.path, create=True
        )

        self.plan = self.make_plan()

        self.pid = self.plan["plan_id"]

        self.journal.register(self.plan)

    def make_plan(self):

        now = m.clock()

        return m.make_plan(
            plan_id=secrets.token_hex(16),
            protocol="FTP",
            head=HEAD,
            tree=TREE,
            coverage_sha256="d" * 64,
            runner_sha256=RUNNER,
            fixture_sha256="e" * 64,
            operator_uid=os.geteuid(),
            created_at=now,
            expires_at=now + 300,
        )

    def authorize(self):

        self.journal.authorize(
            self.pid,
            m.consent_for(self.plan),
        )

    def reserve(self):

        return self.journal.reserve(
            self.pid,
            **IDENTITY,
        )

    def test_lifecycle_and_persistence(self):

        self.authorize()

        token = self.reserve()

        self.journal.record_receipt(
            self.pid, token, "f" * 64
        )

        reopened = m.Journal(self.path)

        state = reopened.snapshot(self.pid)

        self.assertEqual(
            state["state"],
            "RECEIPT_RECORDED_UNVERIFIED",
        )

        self.assertEqual(state["attempt_count"], 1)

        self.assertFalse(
            state["receipt_technically_validated"]
        )

        self.assertIsNone(state["confirmed_rf"])

        self.assertFalse(
            state["operational_a9_published"]
        )

        with self.assertRaises(m.Refusal):

            reopened.reserve(
                self.pid, **IDENTITY
            )

    def test_explicit_consent_required(self):

        with self.assertRaises(m.Refusal):

            self.journal.authorize(
                self.pid, "INVALID"
            )

        self.assertEqual(
            self.journal.snapshot(self.pid)["state"],
            "PLANNED",
        )

    def test_expiration(self):

        self.authorize()

        with patch.object(
            m,
            "clock",
            return_value=self.plan["expires_at"],
        ):

            with self.assertRaises(m.Refusal):

                self.reserve()

        state = self.journal.snapshot(self.pid)

        self.assertEqual(state["state"], "EXPIRED")
        self.assertEqual(state["attempt_count"], 0)

    def test_revocation_before_attempt(self):

        self.authorize()

        self.journal.revoke(self.pid)

        with self.assertRaises(m.Refusal):

            self.reserve()

        self.assertEqual(
            self.journal.snapshot(self.pid)["state"],
            "REVOKED",
        )

    def test_revocation_after_reservation(self):

        self.authorize()

        token = self.reserve()

        self.journal.revoke(self.pid)

        state = self.journal.snapshot(self.pid)

        self.assertEqual(state["state"], "UNCERTAIN")
        self.assertEqual(state["attempt_count"], 1)

        with self.assertRaises(m.Refusal):

            self.journal.record_receipt(
                self.pid, token, "f" * 64
            )

    def test_concurrent_reservation(self):

        self.authorize()

        def attempt():

            try:

                return m.Journal(
                    self.path
                ).reserve(
                    self.pid, **IDENTITY
                )

            except m.Refusal:

                return None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=8
        ) as pool:

            futures = [
                pool.submit(attempt)
                for _ in range(8)
            ]

            results = [
                item.result(timeout=10)
                for item in futures
            ]

        self.assertEqual(
            sum(value is not None for value in results),
            1,
        )

        self.assertEqual(
            self.journal.snapshot(
                self.pid
            )["attempt_count"],
            1,
        )

    def test_runtime_identity_mismatch(self):

        self.authorize()

        with self.assertRaises(m.Refusal):

            self.journal.reserve(
                self.pid,
                head="0" * 40,
                tree=TREE,
                runner_sha256=RUNNER,
            )

        self.assertEqual(
            self.journal.snapshot(
                self.pid
            )["attempt_count"],
            0,
        )

    def test_uncertain_attempt_no_retry(self):

        self.authorize()

        token = self.reserve()

        with self.assertRaises(m.Refusal):

            self.journal.record_receipt(
                self.pid,
                "0" * 64,
                "f" * 64,
            )

        self.journal.mark_uncertain(
            self.pid, token
        )

        reopened = m.Journal(self.path)

        with self.assertRaises(m.Refusal):

            reopened.reserve(
                self.pid, **IDENTITY
            )

        self.assertEqual(
            reopened.snapshot(self.pid)["state"],
            "UNCERTAIN",
        )

    def test_modified_scope_rejected(self):

        modified = dict(self.plan)

        modified.pop("sha256")
        modified["destination"] = "192.0.2.1"

        modified = durable.seal(modified)

        with self.assertRaises(m.Refusal):

            m.verify_plan(modified)


if __name__ == "__main__":
    unittest.main()
