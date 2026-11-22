"""R130-B17-R6B1: pruebas Ed25519 y staging sin root."""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from ardrec.coordination import (
    r130_b17_r6_signed_stage as m,
)
from ardrec.coordination import (
    r130_b17_r6_install_contract as intake,
)

ROOT = Path(__file__).resolve().parents[2]

NOW = datetime(
    2026, 11, 22, 3, 0, 5,
    tzinfo=timezone.utc,
)


def openssl(*args):
    result = subprocess.run(
        [
            "/usr/bin/openssl",
            *map(str, args),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
    )

    if result.returncode:
        raise RuntimeError(
            "TEST_OPENSSL_FAILED:"
            + result.stderr.decode(
                errors="replace"
            )[:200]
        )

    return result.stdout


class SignedInstallReview(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="ardrec-r130-keys-test-only-"
        )

        cls.base = Path(cls.temporary.name)
        cls.public = {}

        for role in (
            "installation",
            "revocation",
        ):
            private = cls.base / (role + ".key")
            public = cls.base / (role + ".pub")

            openssl(
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                private,
            )

            openssl(
                "pkey",
                "-in",
                private,
                "-pubout",
                "-out",
                public,
            )

            cls.public[role] = public.read_text(
                encoding="ascii"
            )

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.entries = {
            "root-controller.py.source-only":
                (
                    ROOT
                    / "scripts/ardrec_p14_r126_root_session_guard.py"
                ).read_bytes(),

            "root-executor.py.source-only":
                (
                    ROOT
                    / "scripts/ardrec_p14_r128_root_v2_executor.py"
                ).read_bytes(),

            "manifest-b4.draft.json":
                intake.canon(intake.EXPECTED_B4),

            "manifest-b9.draft.json":
                intake.canon(intake.EXPECTED_B9),

            "source-provenance.json":
                intake.canon(intake.EXPECTED_PROVENANCE),
        }

        self.trust = {
            "schema": m.TRUST_SCHEMA,

            "installation_signer": {
                "key_id": "r130.test.installation",
                "public_key_pem":
                    self.public["installation"],
            },

            "revocation_signer": {
                "key_id": "r130.test.revocation",
                "public_key_pem":
                    self.public["revocation"],
            },
        }

        self.statement = {
            "schema": m.APPROVAL_SCHEMA,
            "install_id": "r130.test.install01",
            "source_head": intake.HEAD,
            "source_tree": intake.TREE,
            "archive_sha256": intake.ARCHIVE_SHA,
            "b4_sha256": intake.B4_SHA,
            "b9_sha256": intake.B9_SHA,
            "targets": m.TARGETS,
            "boot_id":
                "00000000-0000-4000-8000-000000000000",
            "valid_from":
                "2026-11-22T03:00:00Z",
            "valid_until":
                "2026-11-22T03:04:00Z",
            "purpose":
                "INSTALL_SOURCE_ONLY_WITHOUT_ACTIVATION",
            "one_time": True,
            "automatic_network": False,
            "p8": "NO-GO",
        }

        self.approval = self.sign(
            self.statement,
            "installation",
            m.APPROVAL_PREFIX,
        )

        self.rev_statement = {
            "schema": m.REV_SCHEMA,
            "install_id":
                self.statement["install_id"],
            "approval_sha256":
                m.digest(m.canon(self.approval)),
            "issued_at":
                "2026-11-22T03:00:00Z",
            "valid_until":
                "2026-11-22T03:00:40Z",
            "revoked": False,
            "reason_code": "CURRENT_CLEAR",
        }

        self.revocation = self.sign(
            self.rev_statement,
            "revocation",
            m.REV_PREFIX,
        )

    def sign(self, statement, role, prefix):
        with tempfile.TemporaryDirectory(
            prefix="ardrec-r130-sign-test-only-"
        ) as folder:

            base = Path(folder)
            message = base / "message.bin"
            signature = base / "signature.bin"

            message.write_bytes(
                prefix + m.canon(statement)
            )

            openssl(
                "pkeyutl",
                "-sign",
                "-inkey",
                self.base / (role + ".key"),
                "-rawin",
                "-in",
                message,
                "-out",
                signature,
            )

            raw = signature.read_bytes()

        return {
            "statement":
                copy.deepcopy(statement),

            "signer_key_id":
                "r130.test." + role,

            "signature_b64":
                base64.b64encode(raw).decode("ascii"),
        }

    def review(self):
        return m.review(
            self.entries,
            self.approval,
            self.revocation,
            self.trust,
            now=NOW,
        )

    def denied(self, code):
        with self.assertRaisesRegex(
            m.Stop,
            code,
        ):
            self.review()

    def test_01_valid_signatures_without_root_authority(self):
        report = self.review()

        self.assertEqual(
            report["signature_verification"],
            "PASS",
        )

        self.assertFalse(
            report["root_install_authorized"]
        )

        self.assertFalse(
            report["independent_root_trust_anchored"]
        )

    def test_02_signature_tamper(self):
        self.approval["signature_b64"] = (
            base64.b64encode(
                bytes(64)
            ).decode("ascii")
        )

        self.denied(
            "SIGNATURE_NOT_VERIFIED"
        )

    def test_03_revoked(self):
        self.rev_statement["revoked"] = True

        self.revocation = self.sign(
            self.rev_statement,
            "revocation",
            m.REV_PREFIX,
        )

        self.denied(
            "REVOCATION_NOT_BOUND_OR_REVOKED"
        )

    def test_04_stale_revocation(self):
        self.rev_statement["issued_at"] = (
            "2026-11-22T02:59:00Z"
        )

        self.revocation = self.sign(
            self.rev_statement,
            "revocation",
            m.REV_PREFIX,
        )

        self.denied(
            "REVOCATION_NOT_FRESH"
        )

    def test_05_wrong_commit(self):
        self.statement["source_head"] = (
            "0" * 40
        )

        self.approval = self.sign(
            self.statement,
            "installation",
            m.APPROVAL_PREFIX,
        )

        self.denied(
            "INSTALL_SCOPE_MISMATCH"
        )

    def test_06_wrong_archive(self):
        self.statement["archive_sha256"] = (
            "0" * 64
        )

        self.approval = self.sign(
            self.statement,
            "installation",
            m.APPROVAL_PREFIX,
        )

        self.denied(
            "INSTALL_SCOPE_MISMATCH"
        )

    def test_07_wrong_destination(self):
        self.statement["targets"] = [
            "/tmp/other"
        ]

        self.approval = self.sign(
            self.statement,
            "installation",
            m.APPROVAL_PREFIX,
        )

        self.denied(
            "INSTALL_SCOPE_MISMATCH"
        )

    def test_08_reused_signer(self):
        self.trust["revocation_signer"] = (
            copy.deepcopy(
                self.trust["installation_signer"]
            )
        )

        self.denied(
            "SIGNERS_NOT_DISTINCT"
        )

    def test_09_changed_approval_binding(self):
        self.rev_statement["approval_sha256"] = (
            "0" * 64
        )

        self.revocation = self.sign(
            self.rev_statement,
            "revocation",
            m.REV_PREFIX,
        )

        self.denied(
            "REVOCATION_NOT_BOUND_OR_REVOKED"
        )

    def test_10_expired_install_approval(self):
        self.statement["valid_until"] = (
            "2026-11-22T03:00:04Z"
        )

        self.approval = self.sign(
            self.statement,
            "installation",
            m.APPROVAL_PREFIX,
        )

        self.denied(
            "INSTALL_APPROVAL_NOT_CURRENT"
        )

    def test_11_private_atomic_candidate(self):
        with tempfile.TemporaryDirectory(
            prefix="ardrec-r130-stage-"
        ) as folder:

            result = m.user_stage(
                self.entries,
                self.approval,
                self.revocation,
                self.trust,
                now=NOW,
                parent=Path(folder),
            )

            final = Path(result["path"])

            self.assertTrue(
                final.is_dir()
            )

            self.assertFalse(
                result["root_install"]
            )

            self.assertEqual(
                result["p8"],
                "NO-GO",
            )

            self.assertEqual(
                {
                    p.name
                    for p in final.iterdir()
                },
                {
                    "root-controller.py.source-only",
                    "root-executor.py.source-only",
                    "offline-review.json",
                },
            )

            for path in final.iterdir():
                self.assertEqual(
                    path.stat().st_mode & 0o777,
                    0o600,
                )

    def test_12_injected_failure_no_publication(self):
        with tempfile.TemporaryDirectory(
            prefix="ardrec-r130-crash-"
        ) as folder:

            parent = Path(folder)

            with self.assertRaisesRegex(
                m.Stop,
                "INJECTED_STOP_PENDING_PRESERVED",
            ):
                m.user_stage(
                    self.entries,
                    self.approval,
                    self.revocation,
                    self.trust,
                    now=NOW,
                    parent=parent,
                    fail_after_first=True,
                )

            children = list(
                parent.iterdir()
            )

            self.assertEqual(
                len(children),
                1,
            )

            self.assertTrue(
                children[0].name.startswith(
                    ".r130-incomplete-"
                )
            )

    def test_13_parent_permissions(self):
        with tempfile.TemporaryDirectory(
            prefix="ardrec-r130-parent-"
        ) as folder:

            parent = Path(folder)
            parent.chmod(0o755)

            with self.assertRaisesRegex(
                m.Stop,
                "PRIVATE_PARENT_REQUIRED",
            ):
                m.user_stage(
                    self.entries,
                    self.approval,
                    self.revocation,
                    self.trust,
                    now=NOW,
                    parent=parent,
                )

    def test_14_source_tamper(self):
        self.entries[
            "root-controller.py.source-only"
        ] += b"drift"

        with self.assertRaisesRegex(
            intake.Stop,
            "SOURCE_B4_SHA_MISMATCH",
        ):
            self.review()

    def test_15_capabilities(self):
        capabilities = m.capabilities()

        self.assertTrue(
            capabilities["verifies_real_ed25519"]
        )

        self.assertFalse(
            capabilities["can_install_root"]
        )

        self.assertFalse(
            capabilities["can_enable_network"]
        )

        self.assertEqual(
            capabilities["p8"],
            "NO-GO",
        )
