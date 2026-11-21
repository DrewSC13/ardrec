"""Tests of every recoverable F5B publication boundary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

import test_r117_f5b_transaction_integration as tx
import ardrec_r117_recovery_v1 as recovery


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tx.TransactionIntegrationTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        tx.TransactionIntegrationTests.tearDownClass()

    def setUp(self):
        self.fixture = tx.TransactionIntegrationTests(
            "test_01_positive_real_f5b_publication_in_temp"
        )
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.doCleanups()

    def check(self, *, now=None, **changes):
        options = {
            "head": tx.HEAD,
            "candidate_sha":
                tx.TransactionIntegrationTests.sha,
            "public":
                tx.TransactionIntegrationTests.public,
            "public_sha": tx.core.sha(
                tx.TransactionIntegrationTests.public
            ),
            "now": now or datetime.now(timezone.utc),
        }
        options.update(changes)

        return recovery.inspect(
            self.fixture.root,
            tx.TransactionIntegrationTests.candidate,
            **options,
        )

    def interrupted(self, point):
        with self.assertRaises(tx.SimulatedInterruption):
            self.fixture.run_transaction(point)

    def test_01_prepared(self):
        self.interrupted("PREPARED")
        value = self.check()
        self.assertEqual(
            value["phase"], "PREPARED_UNPUBLISHED"
        )

    def test_02_pilot_visible(self):
        self.interrupted("PILOT_PUBLISHED")
        value = self.check()
        self.assertEqual(
            value["phase"], "PILOT_ONLY_UNPUBLISHED"
        )

    def test_03_release_visible(self):
        self.interrupted("RELEASE_PUBLISHED")
        value = self.check()
        self.assertEqual(
            value["phase"], "RELEASE_VISIBLE_INCOMPLETE"
        )

    def test_04_completed(self):
        self.interrupted("COMPLETION_DURABLE")
        value = self.check()
        self.assertEqual(
            value["phase"], "COMPLETE_NOT_ACTIVATED"
        )

    def test_05_activated(self):
        self.fixture.run_transaction()
        value = self.check()
        self.assertEqual(
            value["phase"], "ACTIVATED_VERIFIED"
        )
        self.assertIs(value["boot_authorized"], False)

    def test_06_interruption_after_activation(self):
        self.interrupted("ACTIVATION_PUBLISHED")
        value = self.check()
        self.assertEqual(
            value["recommended_action"],
            "NO_REPLAY_REQUIRED",
        )

    def test_07_wrong_candidate_rejected(self):
        self.fixture.run_transaction()
        with self.assertRaises(recovery.core.Stop):
            self.check(candidate_sha="0" * 64)

    def test_08_tampered_manifest_rejected(self):
        self.fixture.run_transaction()
        target = (
            self.fixture.root /
            "r117-f4-ftp-pilot-root-v1" /
            "manifest.json"
        )
        target.write_bytes(b"{}\n")
        with self.assertRaisesRegex(recovery.Stop, 'PAYLOAD_BYTES_CHANGED_manifest.json'):
            self.check()

    def test_09_duplicate_transaction_rejected(self):
        self.fixture.run_transaction()
        duplicate = (
            self.fixture.root /
            (".r117-f5b-transaction-" + "f" * 24)
        )
        duplicate.mkdir(mode=0o700)
        with self.assertRaisesRegex(recovery.Stop, 'TRANSACTION_COUNT_NOT_ONE'):
            self.check()

    def test_10_expired_signature_still_checkable(self):
        self.fixture.run_transaction()
        later = (
            datetime.now(timezone.utc) +
            timedelta(minutes=20)
        )
        value = self.check(now=later)

        self.assertEqual(
            value["phase"], "ACTIVATED_VERIFIED"
        )
        self.assertIs(
            value["approval_fresh_for_new_install"],
            False,
        )

    def test_11_tampered_activation_rejected(self):
        self.fixture.run_transaction()
        target = (
            self.fixture.root /
            "r117-f5b-activation-v1.json"
        )
        target.write_bytes(b"{}\n")
        with self.assertRaisesRegex(recovery.Stop, 'ACTIVATION_NOT_AUTHENTIC'):
            self.check()

    def test_12_wrong_approval_public_key_rejected(self):
        self.fixture.run_transaction()
        with self.assertRaises(recovery.core.Stop):
            self.check(public_sha="0" * 64)


if __name__ == "__main__":
    unittest.main()
