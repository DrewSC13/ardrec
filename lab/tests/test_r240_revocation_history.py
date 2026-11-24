"""Synthetic signed history and rollback regression."""

import tempfile
import unittest

from pathlib import Path

import test_r237_signed_scope as fixtures

from ardrec.coordination import (
    r237_scope_review as scope,
    r240_revocation_history as history,
)


NOW = fixtures.NOW


class RevocationHistoryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        fixtures.SignedScopeTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.SignedScopeTests.tearDownClass()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()

        self.addCleanup(temporary.cleanup)

        self.directory = (
            Path(temporary.name) / "history"
        )

        self.fixture = fixtures.SignedScopeTests()
        self.fixture.setUp()

        self.trust_raw = scope.canonical(
            self.fixture.trust
        )

        self.genesis = history.initialize(
            self.directory,
            plan_sha256=self.fixture.plan["sha256"],
            trust_sha256=scope.sha(self.trust_raw),
            authorization_sha256=scope.sha(
                self.fixture.authorization
            ),
            minimum_sequence=5,
        )

        self.head = self.genesis

    def submit(self, **overrides):
        values = {
            "plan": self.fixture.plan,
            "trust_raw": self.trust_raw,
            "authorization_raw":
                self.fixture.authorization,
            "revocation_raw":
                self.fixture.revocation,
            "expected_genesis": self.genesis,
            "expected_head": self.head,
            "now": NOW,
        }

        values.update(overrides)

        return history.record(
            self.directory,
            **values,
        )

    def accept(self, **kwargs):
        report = self.submit(**kwargs)
        self.head = report["head_sha256"]

        return report

    def signed_status(
        self,
        sequence,
        *,
        revoked=False,
        issued_at=NOW,
        valid_until=NOW+30,
    ):
        self.fixture.rev.update({
            "sequence": sequence,
            "revoked": revoked,
            "reason": (
                "REVOKED" if revoked
                else "ACTIVE"
            ),
            "issued_at": issued_at,
            "valid_until": valid_until,
        })

        self.fixture.sign_revocation()

        return self.fixture.revocation

    def test_01_initial_signed_record(self):
        report = self.accept()

        self.assertEqual(report["entries"], 1)
        self.assertEqual(
            report["revocation_sequence"], 5
        )
        self.assertFalse(report["revoked"])

        self.assertTrue(
            (self.directory / "000001.json").is_file()
        )

    def test_02_idempotent_replay(self):
        first = self.accept()
        replay = self.accept()

        self.assertEqual(
            first["head_sha256"],
            replay["head_sha256"],
        )

        self.assertEqual(replay["entries"], 1)
        self.assertTrue(replay["replayed"])

    def test_03_monotonic_sequence(self):
        self.accept()
        self.signed_status(6)

        report = self.accept()

        self.assertEqual(report["entries"], 2)
        self.assertEqual(
            report["revocation_sequence"], 6
        )

    def test_04_signed_rollback_rejected(self):
        previous_raw = self.fixture.revocation

        self.accept()

        self.signed_status(6)
        self.accept()

        with self.assertRaisesRegex(
            ValueError, "REVOCATION_ROLLBACK"
        ):
            self.submit(
                revocation_raw=previous_raw
            )

    def test_05_same_sequence_equivocation(self):
        self.accept()

        self.signed_status(
            5,
            valid_until=NOW+40,
        )

        with self.assertRaisesRegex(
            ValueError,
            "REVOCATION_EQUIVOCATION",
        ):
            self.submit()

    def test_06_revocation_is_terminal(self):
        self.accept()

        self.signed_status(6, revoked=True)

        report = self.accept()

        self.assertTrue(report["revoked"])
        self.assertEqual(report["entries"], 2)

        self.signed_status(7)

        with self.assertRaisesRegex(
            ValueError, "REVOCATION_TERMINAL"
        ):
            self.submit()

    def test_07_original_review_still_denies(self):
        self.signed_status(5, revoked=True)

        with self.assertRaisesRegex(
            ValueError, "AUTHORIZATION_REVOKED"
        ):
            self.fixture.verify()

    def test_08_stale_expected_head(self):
        self.accept()

        with self.assertRaisesRegex(
            ValueError,
            "HISTORY_HEAD_PIN_MISMATCH",
        ):
            self.submit(
                expected_head=self.genesis
            )

    def test_09_truncated_history_detected(self):
        self.accept()
        self.signed_status(6)
        self.accept()

        # Only the synthetic test file is removed.
        (self.directory / "000002.json").unlink()

        with self.assertRaisesRegex(
            ValueError,
            "HISTORY_HEAD_PIN_MISMATCH",
        ):
            self.submit()

    def test_10_corrupt_history_detected(self):
        self.accept()

        path = self.directory / "000001.json"

        path.write_bytes(b"{}\n")

        with self.assertRaises(
            (ValueError, KeyError)
        ):
            self.submit()

    def test_11_invalid_signature_not_recorded(self):
        with self.assertRaises(ValueError):
            self.submit(
                revocation_raw=b"{}"
            )

        self.assertFalse(
            (self.directory / "000001.json").exists()
        )

    def test_12_expired_status_rejected(self):
        self.accept()

        with self.assertRaisesRegex(
            ValueError, "REVOCATION_NOT_CURRENT"
        ):
            self.submit(now=NOW+31)

    def test_13_genesis_pin_required(self):
        with self.assertRaisesRegex(
            ValueError, "GENESIS_PIN_MISMATCH"
        ):
            self.submit(
                expected_genesis="0"*64
            )

    def test_14_clock_regression_and_no_authority(self):
        first = self.accept(now=NOW+5)

        self.assertFalse(
            first["operational_authority"]
        )

        self.assertFalse(
            first["operational_dispatch"]
        )

        self.assertFalse(
            first["trusted_clock_attested"]
        )

        self.assertEqual(first["a6"], "ND")
        self.assertIsNone(first["confirmed_rf"])
        self.assertEqual(first["p8"], "NO-GO")

        self.signed_status(6)

        with self.assertRaisesRegex(
            ValueError,
            "OBSERVATION_TIME_ROLLBACK",
        ):
            self.submit(now=NOW+4)


if __name__ == "__main__":
    unittest.main()
