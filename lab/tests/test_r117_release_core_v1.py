"""Release core: positive and negative tests; no privileged actions."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

core = load(
    ROOT / "scripts/ardrec_r117_release_core_v1.py",
    "r117_install_core",
)
builder = load(
    ROOT / "scripts/ardrec_p14_r117_f5_root_candidate.py",
    "r117_candidate_builder",
)

HEAD = "a" * 40
NOW = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


class ReleaseCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = builder.candidate(HEAD, repo=ROOT)
        cls.candidate_sha = core.sha(cls.candidate)
        cls.tmp = tempfile.TemporaryDirectory()
        directory = Path(cls.tmp.name)

        cls.private = directory / "test-private.pem"
        cls.public = directory / "test-public.pem"

        subprocess.run(
            [
                "/usr/bin/openssl", "genpkey",
                "-algorithm", "ED25519",
                "-out", str(cls.private),
            ],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl", "pkey",
                "-in", str(cls.private),
                "-pubout", "-out", str(cls.public),
            ],
            check=True, capture_output=True,
        )
        cls.public_raw = cls.public.read_bytes()
        cls.public_sha = core.sha(cls.public_raw)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def approval(self, **changes):
        value = {
            "schema": core.APPROVAL_SCHEMA,
            "head": HEAD,
            "candidate_sha256": self.candidate_sha,
            "valid_from":
                NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until":
                (NOW + timedelta(minutes=5)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "CI_EPHEMERAL_TEST_ONLY",
            "p8": "NO-GO",
        }
        value.update(changes)
        return core.canonical(value)

    def sign(self, raw):
        directory = Path(self.tmp.name)
        statement = directory / "statement.bin"
        signature = directory / "signature.bin"
        statement.write_bytes(core.PREFIX + raw)

        subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl",
                "-sign", "-rawin",
                "-inkey", str(self.private),
                "-in", str(statement),
                "-out", str(signature),
            ],
            check=True, capture_output=True,
        )
        return signature.read_bytes()

    def verify(self, raw, signature=None, **overrides):
        signature = (
            self.sign(raw) if signature is None else signature
        )
        options = {
            "head": HEAD,
            "candidate_sha": self.candidate_sha,
            "public_sha": self.public_sha,
            "now": NOW,
        }
        options.update(overrides)

        return core.verify_signed_candidate(
            self.candidate, raw, signature,
            self.public_raw, **options
        )

    def test_01_archive_39_verified(self):
        result = core.verify_candidate(
            self.candidate,
            head=HEAD,
            expected_sha=self.candidate_sha,
        )
        self.assertEqual(result["file_count"], 39)
        self.assertEqual(result["source_count"], 36)

    def test_02_wrong_archive_digest_denied(self):
        with self.assertRaises(core.Stop):
            core.verify_candidate(
                self.candidate,
                head=HEAD,
                expected_sha="0" * 64,
            )

    def test_03_wrong_head_denied(self):
        with self.assertRaises(core.Stop):
            core.verify_candidate(
                self.candidate,
                head="b" * 40,
                expected_sha=self.candidate_sha,
            )

    def test_04_truncated_zip_denied(self):
        with self.assertRaises(core.Stop):
            core.verify_candidate(
                self.candidate[:-40],
                head=HEAD,
                expected_sha=core.sha(self.candidate[:-40]),
            )

    def test_05_valid_ed25519_signature(self):
        report = self.verify(self.approval())
        self.assertEqual(report["approval_signature"], "VALID")
        self.assertIs(report["root_install_executed"], False)

    def test_06_signature_tamper_denied(self):
        raw = self.approval()
        signature = bytearray(self.sign(raw))
        signature[0] ^= 1
        with self.assertRaises(core.Stop):
            self.verify(raw, bytes(signature))

    def test_07_approval_tamper_denied(self):
        raw = self.approval()
        signature = self.sign(raw)
        modified = self.approval(
            authority="DIFFERENT_REVIEWER"
        )
        with self.assertRaises(core.Stop):
            self.verify(modified, signature)

    def test_08_expired_approval_denied(self):
        raw = self.approval()
        with self.assertRaises(core.Stop):
            self.verify(
                raw, now=NOW + timedelta(minutes=6)
            )

    def test_09_wrong_public_pin_denied(self):
        with self.assertRaises(core.Stop):
            self.verify(
                self.approval(),
                public_sha="0" * 64,
            )

    def test_10_boot_authorization_denied(self):
        raw = self.approval(purpose="BOOT_AND_NETWORK")
        with self.assertRaises(core.Stop):
            self.verify(raw)

    def test_11_duplicate_json_fields_denied(self):
        with self.assertRaises(core.Stop):
            core.document(b'{"a":1,"a":2}\n')

    def test_12_no_privileged_entrypoint(self):
        self.assertFalse(hasattr(core, "apply"))
        self.assertFalse(hasattr(core, "boot"))


if __name__ == "__main__":
    unittest.main()
