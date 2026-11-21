"""Bootstrap R117: test-only keys and unprivileged atomic staging."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ardrec_r117_bootstrap_agent_v1 as m

REPO = Path(__file__).resolve().parents[2]
PATCHES = Path("/home/cicada/Development/GitHub/ardrec-patches")


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agent = (
            PATCHES /
            ("R117_ROOT_AGENT_SOURCE_" + m.HEAD[:12] + ".zip")
        ).read_bytes()
        cls.candidate = (
            PATCHES /
            ("R117_F5A_ROOT_CANDIDATE_" + m.HEAD[:12] + ".zip")
        ).read_bytes()
        cls.files = m.bundles(cls.agent, cls.candidate)
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        private = cls.directory / "temporary-private.pem"
        public = cls.directory / "temporary-public.pem"

        subprocess.run(
            ["/usr/bin/openssl", "genpkey",
             "-algorithm", "ED25519", "-out", str(private)],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["/usr/bin/openssl", "pkey",
             "-in", str(private), "-pubout",
             "-out", str(public)],
            check=True, capture_output=True,
        )

        cls.private = private
        cls.public = public.read_bytes()
        cls.now = datetime.now(timezone.utc)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name) / "stage"
        self.root.mkdir(mode=0o700)

    def contract(self, **changes):
        value = {
            "schema": m.CONTRACT_SCHEMA,
            "head": m.HEAD,
            "candidate_sha256": m.CANDIDATE_SHA,
            "agent_sha256": m.AGENT_SHA,
            "bootstrap_public_sha256": m.sha(self.public),
            "approval_public_sha256": m.PINS["approval"],
            "revocation_public_sha256": m.PINS["revocation"],
            "valid_from": (
                self.now - timedelta(seconds=30)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": (
                self.now + timedelta(minutes=5)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "purpose": "STAGE_ROOT_AGENT_ONLY",
            "boot_authorized": False,
            "network_authorized": False,
            "p8": "NO-GO",
        }
        value.update(changes)
        return m.canonical(value)

    def sign(self, raw):
        message = self.directory / "test-message.bin"
        signature = self.directory / "test-signature.bin"
        message.write_bytes(m.CONTRACT_PREFIX + raw)
        subprocess.run(
            ["/usr/bin/openssl", "pkeyutl",
             "-sign", "-rawin", "-inkey", str(self.private),
             "-in", str(message), "-out", str(signature)],
            check=True, capture_output=True,
        )
        return signature.read_bytes()

    def signed_check(self, raw, signature=None, now=None):
        sig = self.sign(raw) if signature is None else signature
        with patch.dict(
            m.PINS, {"bootstrap": m.sha(self.public)}
        ):
            return m.verify_contract(
                raw, sig, self.public,
                self.agent, self.candidate,
                now=now or self.now,
            )

    def test_01_archive_verified(self):
        self.assertEqual(len(self.files), 5)

    def test_02_corrupt_agent_rejected(self):
        with self.assertRaisesRegex(m.Stop, "AGENT_SHA256"):
            m.bundles(self.agent + b"x", self.candidate)

    def test_03_corrupt_candidate_rejected(self):
        with self.assertRaisesRegex(m.Stop, "CANDIDATE_SHA256"):
            m.bundles(self.agent, self.candidate + b"x")

    def test_04_valid_ed25519_contract(self):
        raw = self.contract()
        self.assertEqual(
            self.signed_check(raw),
            self.files,
        )

    def test_05_modified_contract_rejected(self):
        raw = self.contract()
        sig = self.sign(raw)
        altered = self.contract(
            purpose="START_GUEST_AND_NETWORK"
        )
        with self.assertRaisesRegex(m.Stop, "CONTRACT_SCOPE"):
            self.signed_check(altered, sig)

    def test_06_expired_contract_rejected(self):
        raw = self.contract()
        with self.assertRaisesRegex(m.Stop, "EXPIRED"):
            self.signed_check(
                raw, now=self.now + timedelta(minutes=7)
            )

    def test_07_tampered_signature_rejected(self):
        raw = self.contract()
        signature = bytearray(self.sign(raw))
        signature[0] ^= 1
        with self.assertRaisesRegex(
            m.Stop, "ED25519_VERIFICATION_FAILED"
        ):
            self.signed_check(raw, bytes(signature))

    def test_08_wrong_trust_pin_rejected(self):
        raw = self.contract()
        with self.assertRaisesRegex(m.Stop, "CONTRACT_SCOPE"):
            self.signed_check(
                raw.replace(
                    m.sha(self.public).encode(),
                    b"0" * 64,
                )
            )

    def test_09_atomic_stage_positive(self):
        result = m.stage_agent(self.root, self.files)
        self.assertTrue(result["agent_installed"])
        self.assertTrue(m.audit_agent(self.root, self.files))
        self.assertFalse(result["boot_authorized"])

    def test_10_before_publication_fails_closed(self):
        def interruption(phase):
            if phase == "STAGED":
                raise RuntimeError("INTERRUPTED")

        with self.assertRaisesRegex(RuntimeError, "INTERRUPTED"):
            m.stage_agent(
                self.root, self.files,
                checkpoint=interruption,
            )

        self.assertFalse(
            (self.root / m.DESTINATION).exists()
        )

    def test_11_after_publication_detected(self):
        def interruption(phase):
            if phase == "PUBLISHED":
                raise RuntimeError("INTERRUPTED")

        with self.assertRaisesRegex(RuntimeError, "INTERRUPTED"):
            m.stage_agent(
                self.root, self.files,
                checkpoint=interruption,
            )

        self.assertTrue(
            m.audit_agent(self.root, self.files)
        )

    def test_12_no_overwrite(self):
        m.stage_agent(self.root, self.files)
        with self.assertRaisesRegex(m.Stop, "ALREADY_PRESENT"):
            m.stage_agent(self.root, self.files)

    def test_13_pending_stage_blocks_retry(self):
        def interruption(phase):
            if phase == "STAGED":
                raise RuntimeError("INTERRUPTED")

        with self.assertRaises(RuntimeError):
            m.stage_agent(
                self.root, self.files,
                checkpoint=interruption,
            )

        with self.assertRaisesRegex(m.Stop, "UNRESOLVED"):
            m.stage_agent(self.root, self.files)

    def test_14_symlink_destination_rejected(self):
        (self.root / m.DESTINATION).symlink_to(
            Path(self.tempdir.name)
        )
        with self.assertRaisesRegex(m.Stop, "ALREADY_PRESENT"):
            m.stage_agent(self.root, self.files)


    def test_15_root_required(self):
        if os.geteuid() != 0:
            with self.assertRaisesRegex(m.Stop, "ROOT_REQUIRED"):
                m._root_context()

    def test_16_checkout_execution_rejected(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                m.Stop, "EXECUTOR_NOT_ROOT_STAGED"
            ):
                m._root_context()

    def test_17_root_failure_precedes_signature_check(self):
        with patch.object(
            m, "verify_contract"
        ) as verify:
            with self.assertRaises(m.Stop):
                m.root_stage(
                    Path("/nonexistent-agent"),
                    Path("/nonexistent-candidate"),
                    Path("/nonexistent-contract"),
                    Path("/nonexistent-signature"),
                )
            verify.assert_not_called()

    def test_18_invalid_signature_prevents_publication(self):
        with (
            patch.object(
                m, "_root_context",
                return_value=(self.root, self.public),
            ),
            patch.object(m, "_guard_host"),
            patch.object(
                m, "_input_bytes",
                side_effect=[
                    self.agent, self.candidate,
                    b"invalid-contract", b"invalid-signature"
                ],
            ),
            patch.object(
                m, "verify_contract",
                side_effect=m.Stop("SIGNATURE_REJECTED"),
            ),
            patch.object(m, "stage_agent") as stage,
        ):
            with self.assertRaisesRegex(
                m.Stop, "SIGNATURE_REJECTED"
            ):
                m.root_stage(
                    Path("agent"), Path("candidate"),
                    Path("contract"), Path("signature"),
                )
            stage.assert_not_called()

    def test_19_verified_contract_precedes_publication(self):
        calls = []

        def verify(*args, **kwargs):
            calls.append("VERIFY")
            return self.files

        def stage(root, files):
            calls.append("STAGE")
            return {
                "agent_installed": True,
                "file_count": 5,
                "head": m.HEAD,
                "boot_authorized": False,
                "network_authorized": False,
                "p8": "NO-GO",
            }

        with (
            patch.object(
                m, "_root_context",
                return_value=(self.root, self.public),
            ),
            patch.object(m, "_guard_host"),
            patch.object(
                m, "_input_bytes",
                side_effect=[
                    self.agent, self.candidate,
                    b"contract", b"signature"
                ],
            ),
            patch.object(
                m, "verify_contract",
                side_effect=verify,
            ),
            patch.object(
                m, "stage_agent",
                side_effect=stage,
            ),
            patch.object(
                m, "audit_agent",
                return_value=True,
            ),
        ):
            result = m.root_stage(
                Path("agent"), Path("candidate"),
                Path("contract"), Path("signature"),
            )

        self.assertEqual(calls, ["VERIFY", "STAGE"])
        self.assertIs(result["boot_authorized"], False)


if __name__ == "__main__":
    unittest.main()
