"""R117 F5B: authentic V3 candidate, isolated Ed25519 and transaction tests.

All private keys are temporary test fixtures. No production authority
is opened. No privileged filesystem, VM or network action is permitted.
"""
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
import zipfile

import ardrec_r117_release_core_v1 as core
import ardrec_r117_f5b_dual_authority_v1 as gate
import ardrec_r117_f5b_release_transaction_v2 as txn
from r117_v3_candidate_fixture import candidate_bytes

HEAD = "197785a38bf166ec0b4c8d3ae17346d1fa217265"
SHA = (
    "5ef729690589497c787f34e99dba8fefea798459fc6c10a2d144a64a71cb2bf7"
)

PHASES = [
    "PREPARED",
    "PILOT_PUBLISHED",
    "RELEASE_PUBLISHED",
    "COMPLETION_DURABLE",
    "ACTIVATION_PUBLISHED",
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def run(command):
    subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
        timeout=30,
    )


def timestamp(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


class V3CandidateTransactionTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.candidate = candidate_bytes()

        if sha(cls.candidate) != SHA:
            raise RuntimeError("V3_CANDIDATE_SHA_CHANGED")

        cls.keys_folder = tempfile.TemporaryDirectory(
            prefix="ardrec-r117-v3-test-keys-"
        )

        cls.keys = {}

        for role in ("approval", "revocation"):
            folder = Path(cls.keys_folder.name)
            private = folder / f"{role}-private.pem"
            public = folder / f"{role}-public.pem"

            run([
                "/usr/bin/openssl", "genpkey",
                "-algorithm", "ED25519",
                "-out", str(private),
            ])

            private.chmod(0o600)

            run([
                "/usr/bin/openssl", "pkey",
                "-in", str(private),
                "-pubout", "-out", str(public),
            ])

            public.chmod(0o600)

            cls.keys[role] = {
                "private": private,
                "public": public.read_bytes(),
            }

        if (
            cls.keys["approval"]["public"] ==
            cls.keys["revocation"]["public"]
        ):
            raise RuntimeError("TEST_AUTHORITIES_NOT_DISTINCT")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "keys_folder"):
            cls.keys_folder.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(
            prefix="ardrec-r117-v3-transaction-"
        )

        self.workspace = Path(self.folder.name)
        self.root = self.workspace / "r117-test-root"
        self.root.mkdir(mode=0o700)

        self.now = datetime.now(timezone.utc).replace(
            microsecond=0
        )

    def tearDown(self):
        self.folder.cleanup()

    def sign(self, role, prefix, document):
        message = self.workspace / f"{role}.message"
        signature = self.workspace / f"{role}.sig"

        message.write_bytes(prefix + document)

        run([
            "/usr/bin/openssl", "pkeyutl",
            "-sign", "-rawin",
            "-inkey", str(self.keys[role]["private"]),
            "-in", str(message),
            "-out", str(signature),
        ])

        raw = signature.read_bytes()

        self.assertEqual(len(raw), 64)
        return raw

    def evidence(self, *, revoked=False, expired=False):
        approval = core.canonical({
            "schema": core.APPROVAL_SCHEMA,
            "head": HEAD,
            "candidate_sha256": SHA,
            "valid_from": timestamp(
                self.now - timedelta(seconds=15)
            ),
            "valid_until": timestamp(
                self.now + timedelta(seconds=240)
            ),
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "ARDREC_V3_CI_APPROVAL",
            "p8": "NO-GO",
        })

        if expired:
            issued = self.now - timedelta(seconds=70)
            until = self.now - timedelta(seconds=5)
        else:
            issued = self.now - timedelta(seconds=3)
            until = self.now + timedelta(seconds=75)

        revocation = core.canonical({
            "schema": gate.REVOCATION_SCHEMA,
            "head": HEAD,
            "candidate_sha256": SHA,
            "issued_at": timestamp(issued),
            "valid_until": timestamp(until),
            "revoked": revoked,
            "authority": "ARDREC_V3_CI_REVOCATION",
            "p8": "NO-GO",
        })

        return {
            "approval": approval,
            "approval_sig": self.sign(
                "approval", core.PREFIX, approval
            ),
            "revocation": revocation,
            "revocation_sig": self.sign(
                "revocation",
                gate.REVOCATION_PREFIX,
                revocation,
            ),
        }

    def admission(self, documents):
        return gate.verify_release(
            self.candidate,
            documents["approval"],
            documents["approval_sig"],
            self.keys["approval"]["public"],
            documents["revocation"],
            documents["revocation_sig"],
            self.keys["revocation"]["public"],
            now=datetime.now(timezone.utc),
            head=HEAD,
            candidate_sha=SHA,
            approval_pin=sha(
                self.keys["approval"]["public"]
            ),
            revocation_pin=sha(
                self.keys["revocation"]["public"]
            ),
            historical=False,
        )

    def install(self, documents, checkpoint=None):
        return txn.install(
            self.root,
            self.candidate,
            documents["approval"],
            documents["approval_sig"],
            self.keys["approval"]["public"],
            documents["revocation"],
            documents["revocation_sig"],
            self.keys["revocation"]["public"],
            head=HEAD,
            candidate_sha=SHA,
            approval_pin=sha(
                self.keys["approval"]["public"]
            ),
            revocation_pin=sha(
                self.keys["revocation"]["public"]
            ),
            now=datetime.now(timezone.utc),
            checkpoint=checkpoint,
        )

    def test_01_real_v3_positive_admission(self):
        documents = self.evidence()
        report = self.admission(documents)

        self.assertEqual(report["head"], HEAD)
        self.assertEqual(report["candidate_sha256"], SHA)
        self.assertEqual(report["file_count_verified"], 39)
        self.assertEqual(report["source_count_verified"], 36)
        self.assertTrue(report["separate_authorities"])
        self.assertFalse(report["revoked"])
        self.assertFalse(report["boot_authorized"])
        self.assertFalse(report["network_authorized"])
        self.assertEqual(report["p8"], "NO-GO")

    def test_02_complete_isolated_transaction(self):
        documents = self.evidence()
        phases = []

        result = self.install(
            documents,
            checkpoint=lambda phase: phases.append(phase),
        )

        self.assertEqual(phases, PHASES)
        self.assertEqual(result["head"], HEAD)
        self.assertEqual(result["files_verified"], 39)
        self.assertFalse(result["boot_authorized"])
        self.assertFalse(result["network_authorized"])

        with zipfile.ZipFile(
            BytesIO(self.candidate)
        ) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), 39)

            for name in names:
                installed = (
                    self.root / txn.PILOT_NAME / name
                )
                self.assertEqual(
                    installed.read_bytes(),
                    archive.read(name),
                    name,
                )

        activation = (
            self.root / txn.ACTIVATION_NAME
        )
        self.assertTrue(activation.is_file())

        journal = self.root / result["transaction"]

        self.assertEqual(
            {
                entry.name
                for entry in journal.iterdir()
            },
            {
                "intent.json",
                "prepared.once",
                "pilot-visible.once",
                "release-visible.once",
                "complete.json",
            },
        )

    def test_03_no_reinstallation(self):
        documents = self.evidence()

        self.install(documents)

        activation = (
            self.root / txn.ACTIVATION_NAME
        )
        original = activation.read_bytes()

        with self.assertRaisesRegex(
            Exception, "RELEASE_ALREADY_PUBLISHED"
        ):
            self.install(documents)

        self.assertEqual(
            activation.read_bytes(), original
        )

    def test_04_revoked_rejected_before_writes(self):
        documents = self.evidence(revoked=True)

        with self.assertRaisesRegex(
            Exception, "REVOCATION_SCOPE_INVALID"
        ):
            self.install(documents)

        self.assertEqual(
            list(self.root.iterdir()), []
        )

    def test_05_signature_tampering_rejected(self):
        documents = self.evidence()

        altered = bytearray(
            documents["approval_sig"]
        )
        altered[0] ^= 1

        documents["approval_sig"] = bytes(altered)

        with self.assertRaisesRegex(
            Exception, "APPROVAL_SIGNATURE_INVALID"
        ):
            self.install(documents)

        self.assertEqual(
            list(self.root.iterdir()), []
        )

    def test_06_interrupted_transaction_is_not_retried(self):
        documents = self.evidence()

        def interrupt(phase):
            if phase == "PILOT_PUBLISHED":
                raise RuntimeError(
                    "SIMULATED_INTERRUPTION_TEST_ONLY"
                )

        with self.assertRaisesRegex(
            RuntimeError,
            "SIMULATED_INTERRUPTION_TEST_ONLY",
        ):
            self.install(
                documents,
                checkpoint=interrupt,
            )

        self.assertFalse(
            (self.root / txn.ACTIVATION_NAME).exists()
        )

        with self.assertRaisesRegex(
            Exception, "PREVIOUS_RELEASE_TRANSACTION_PRESENT"
        ):
            self.install(documents)


if __name__ == "__main__":
    unittest.main()
