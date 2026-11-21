"""Signed R117 release transaction tests in temporary directories."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import tempfile
import unittest

import ardrec_r117_f5b_release_transaction_v2 as m
import ardrec_r117_f5b_dual_authority_v1 as gate
import ardrec_r117_release_core_v1 as core
import test_r117_f5b_dual_authority_v1 as fixtures

PATCHES = Path(
    "/home/cicada/Development/GitHub/ardrec-patches"
)

HEAD = "1521f3af69e7875f6c79a60d7a905e5fbffdcba1"
CANDIDATE_SHA = (
    "fd75683758681684447d5f3c59c249d8077de914aa324b5c880a6fa23d03b11a"
)


class TransactionV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.DualAuthorityTests.setUpClass()
        cls.keys = fixtures.DualAuthorityTests()
        cls.candidate = (
            PATCHES /
            "R117_F5A_ROOT_CANDIDATE_1521f3af69e7.zip"
        ).read_bytes()
        cls.now = cls.keys.now

    @classmethod
    def tearDownClass(cls):
        fixtures.DualAuthorityTests.tearDownClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name) / "root"
        self.root.mkdir(mode=0o700)

    def arguments(
        self, *, purpose="INSTALL_SOURCE_ONLY",
        revoked=False,
    ):
        approval = self.keys.approval(
            head=HEAD,
            candidate_sha256=CANDIDATE_SHA,
            purpose=purpose,
        )

        revocation = self.keys.revocation(
            head=HEAD,
            candidate_sha256=CANDIDATE_SHA,
            revoked=revoked,
        )

        approval_public = self.keys.keys["approval"]["public"]
        revocation_public = self.keys.keys["revocation"]["public"]

        return (
            self.root,
            self.candidate,
            approval,
            self.keys.sign(
                "approval", core.PREFIX, approval
            ),
            approval_public,
            revocation,
            self.keys.sign(
                "revocation",
                gate.REVOCATION_PREFIX,
                revocation,
            ),
            revocation_public,
        )

    def install(self, *, checkpoint=None, **changes):
        args = self.arguments(**changes)

        return m.install(
            *args,
            head=HEAD,
            candidate_sha=CANDIDATE_SHA,
            approval_pin=hashlib.sha256(
                args[4]
            ).hexdigest(),
            revocation_pin=hashlib.sha256(
                args[7]
            ).hexdigest(),
            now=self.now,
            checkpoint=checkpoint,
        )

    def interrupt(self, target):
        def checkpoint(phase):
            if phase == target:
                raise RuntimeError(
                    "SIMULATED_INTERRUPTION_" + phase
                )
        return checkpoint

    def test_01_positive_source_only_publication(self):
        result = self.install()

        self.assertEqual(result["files_verified"], 39)
        self.assertIs(result["boot_authorized"], False)
        self.assertIs(result["network_authorized"], False)
        self.assertEqual(result["p8"], "NO-GO")

        self.assertTrue(
            (self.root / m.ACTIVATION_NAME).is_file()
        )

    def test_02_wrong_approval_before_writes(self):
        with self.assertRaises(
            (core.Stop, gate.Stop)
        ):
            self.install(
                purpose="BOOT_AND_NETWORK"
            )

        self.assertEqual(
            list(self.root.iterdir()), []
        )

    def test_03_revoked_before_writes(self):
        with self.assertRaises(
            (core.Stop, gate.Stop)
        ):
            self.install(revoked=True)

        self.assertEqual(
            list(self.root.iterdir()), []
        )

    def test_04_prepared_interruption(self):
        with self.assertRaisesRegex(
            RuntimeError, "PREPARED"
        ):
            self.install(
                checkpoint=self.interrupt("PREPARED")
            )

        self.assertFalse(
            (self.root / m.PILOT_NAME).exists()
        )
        self.assertFalse(
            (self.root / m.ACTIVATION_NAME).exists()
        )

    def test_05_pilot_published_interruption(self):
        with self.assertRaisesRegex(
            RuntimeError, "PILOT_PUBLISHED"
        ):
            self.install(
                checkpoint=self.interrupt(
                    "PILOT_PUBLISHED"
                )
            )

        self.assertTrue(
            (self.root / m.PILOT_NAME).is_dir()
        )
        self.assertFalse(
            (self.root / m.RELEASE_NAME).exists()
        )
        self.assertFalse(
            (self.root / m.ACTIVATION_NAME).exists()
        )

    def test_06_release_published_interruption(self):
        with self.assertRaisesRegex(
            RuntimeError, "RELEASE_PUBLISHED"
        ):
            self.install(
                checkpoint=self.interrupt(
                    "RELEASE_PUBLISHED"
                )
            )

        self.assertTrue(
            (self.root / m.PILOT_NAME).is_dir()
        )
        self.assertTrue(
            (self.root / m.RELEASE_NAME).is_dir()
        )
        self.assertFalse(
            (self.root / m.ACTIVATION_NAME).exists()
        )

    def test_07_durable_completion_interruption(self):
        with self.assertRaisesRegex(
            RuntimeError, "COMPLETION_DURABLE"
        ):
            self.install(
                checkpoint=self.interrupt(
                    "COMPLETION_DURABLE"
                )
            )

        self.assertFalse(
            (self.root / m.ACTIVATION_NAME).exists()
        )

        transactions = list(
            self.root.glob(
                ".r117-f5b-transaction-*"
            )
        )

        self.assertEqual(len(transactions), 1)
        self.assertTrue(
            (transactions[0] / "complete.json").is_file()
        )

    def test_08_interruption_after_activation(self):
        with self.assertRaisesRegex(
            RuntimeError, "ACTIVATION_PUBLISHED"
        ):
            self.install(
                checkpoint=self.interrupt(
                    "ACTIVATION_PUBLISHED"
                )
            )

        self.assertTrue(
            (self.root / m.ACTIVATION_NAME).is_file()
        )

    def test_09_no_reinstallation(self):
        self.install()

        with self.assertRaisesRegex(
            m.Stop, "RELEASE_ALREADY_PUBLISHED"
        ):
            self.install()

    def test_10_no_auto_recovery_after_crash(self):
        with self.assertRaises(RuntimeError):
            self.install(
                checkpoint=self.interrupt(
                    "PILOT_PUBLISHED"
                )
            )

        with self.assertRaisesRegex(
            m.Stop, "PREVIOUS_RELEASE_TRANSACTION"
        ):
            self.install()

    def test_11_candidate_identity_pinned(self):
        self.assertEqual(
            hashlib.sha256(
                self.candidate
            ).hexdigest(),
            CANDIDATE_SHA,
        )

    def test_12_checkpoint_inventory(self):
        self.assertEqual(len(m.CHECKPOINTS), 5)
        self.assertEqual(len(m.MARKERS), 3)


if __name__ == "__main__":
    unittest.main()
