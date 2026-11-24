"""Offline tests for dispatch claims and conservative analysis."""

import concurrent.futures
import os
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from ardrec.experiments import prospective_attempt_journal as j
from ardrec.experiments import prospective_local_dispatch as m
from ardrec.coordination import prospective_local_pilot as durable


class DispatchTests(unittest.TestCase):

    def setUp(self):

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.path = (
            Path(self.temp.name) / "journal.sqlite3"
        )

        self.database = m.DispatchJournal(
            self.path, create=True
        )

        now = j.clock()

        self.plan = j.make_plan(
            plan_id="a" * 32,
            protocol="FTP",
            head="b" * 40,
            tree="c" * 40,
            coverage_sha256="d" * 64,
            runner_sha256="e" * 64,
            fixture_sha256="f" * 64,
            operator_uid=os.geteuid(),
            created_at=now,
            expires_at=now + 300,
        )

        self.pid = self.plan["plan_id"]

        self.database.register(self.plan)

        self.database.authorize(
            self.pid,
            j.consent_for(self.plan),
        )

        self.token = self.database.reserve(
            self.pid,
            head="b" * 40,
            tree="c" * 40,
            runner_sha256="e" * 64,
        )

    def test_dispatch_claim_persisted(self):

        self.assertTrue(
            self.database.claim_dispatch(
                self.pid, self.token
            )
        )

        reopened = m.DispatchJournal(self.path)

        state = reopened.snapshot(self.pid)

        self.assertEqual(
            state["events"][-1]["action"],
            "DISPATCH_CLAIMED",
        )

        with self.assertRaises(j.Refusal):

            reopened.claim_dispatch(
                self.pid, self.token
            )

    def test_concurrent_dispatch_claim(self):

        def attempt():

            try:

                return m.DispatchJournal(
                    self.path
                ).claim_dispatch(
                    self.pid, self.token
                )

            except j.Refusal:

                return False

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=8
        ) as pool:

            futures = [
                pool.submit(attempt)
                for _ in range(8)
            ]

            results = [
                f.result(timeout=10)
                for f in futures
            ]

        self.assertEqual(sum(results), 1)

    def test_expired_claim_rejected(self):

        with patch.object(
            j,
            "clock",
            return_value=self.plan["expires_at"],
        ):

            with self.assertRaises(j.Refusal):

                self.database.claim_dispatch(
                    self.pid, self.token
                )

    def test_revoked_claim_rejected(self):

        self.database.revoke(self.pid)

        with self.assertRaises(j.Refusal):

            self.database.claim_dispatch(
                self.pid, self.token
            )

        self.assertEqual(
            self.database.snapshot(
                self.pid
            )["state"],
            "UNCERTAIN",
        )

    def test_analysis_is_counterfactual(self):

        source = durable.seal({
            "cases": [{
                "protocol": "FTP",
                "baseline_closed": False,
                "initial_risk_candidate": "1/6",
                "normalized_criticality_candidate": "0",
            }],
        })

        result = m.hypothetical_analysis(source)

        self.assertEqual(
            result["interval"],
            {
                "lower": "1/6",
                "upper": "7/18",
            },
        )

        self.assertIsNone(result["confirmed_rf"])

        self.assertFalse(
            result[
                "applicable_to_new_functional_configuration"
            ]
        )

        self.assertFalse(
            result["experimental_admission"]
        )


if __name__ == "__main__":
    unittest.main()
