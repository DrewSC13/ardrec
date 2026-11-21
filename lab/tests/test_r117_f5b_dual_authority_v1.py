"""Offline dual-signature and immutable-candidate regression."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest

import ardrec_r117_f5b_dual_authority_v1 as gate
import ardrec_r117_release_core_v1 as core

PATCHES = Path("/home/cicada/Development/GitHub/ardrec-patches")


class DualAuthorityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.candidate = (
            PATCHES /
            "R117_F5A_ROOT_CANDIDATE_ba7a184406a0.zip"
        ).read_bytes()

        cls.folder = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.folder.name)

        cls.keys = {}

        for role in ("approval", "revocation"):
            private = cls.directory / (role + "-private.pem")
            public = cls.directory / (role + "-public.pem")

            subprocess.run(
                [
                    "/usr/bin/openssl", "genpkey",
                    "-algorithm", "ED25519",
                    "-out", str(private),
                ],
                check=True, capture_output=True,
            )

            subprocess.run(
                [
                    "/usr/bin/openssl", "pkey",
                    "-in", str(private),
                    "-pubout", "-out", str(public),
                ],
                check=True, capture_output=True,
            )

            cls.keys[role] = {
                "private": private,
                "public": public.read_bytes(),
            }

        cls.now = datetime.now(timezone.utc).replace(
            microsecond=0
        )

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def timestamp(self, value):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def approval(self, *, start=None, duration=300, **changes):
        start = start or (self.now - timedelta(seconds=15))

        value = {
            "schema": core.APPROVAL_SCHEMA,
            "head": gate.HEAD,
            "candidate_sha256": gate.CANDIDATE_SHA,
            "valid_from": self.timestamp(start),
            "valid_until": self.timestamp(
                start + timedelta(seconds=duration)
            ),
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "CI_TEST_APPROVAL",
            "p8": "NO-GO",
        }
        value.update(changes)
        return core.canonical(value)

    def revocation(self, *, start=None, duration=60, **changes):
        start = start or (self.now - timedelta(seconds=5))

        value = {
            "schema": gate.REVOCATION_SCHEMA,
            "head": gate.HEAD,
            "candidate_sha256": gate.CANDIDATE_SHA,
            "issued_at": self.timestamp(start),
            "valid_until": self.timestamp(
                start + timedelta(seconds=duration)
            ),
            "revoked": False,
            "authority": "CI_TEST_REVOCATION",
            "p8": "NO-GO",
        }
        value.update(changes)
        return core.canonical(value)

    def sign(self, role, prefix, statement):
        message = self.directory / (role + "-message.bin")
        signature = self.directory / (role + "-signature.bin")

        message.write_bytes(prefix + statement)

        subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl",
                "-sign", "-rawin",
                "-inkey", str(self.keys[role]["private"]),
                "-in", str(message),
                "-out", str(signature),
            ],
            check=True, capture_output=True,
        )

        return signature.read_bytes()

    def check(
        self, *, approval=None, revocation=None,
        approval_signature=None, revocation_signature=None,
        approval_role="approval", revocation_role="revocation",
        now=None, historical=False, candidate=None,
    ):
        approval = approval if approval is not None else self.approval()
        revocation = (
            revocation if revocation is not None
            else self.revocation()
        )

        a_signature = (
            approval_signature
            if approval_signature is not None
            else self.sign(
                approval_role, core.PREFIX, approval
            )
        )
        r_signature = (
            revocation_signature
            if revocation_signature is not None
            else self.sign(
                revocation_role, gate.REVOCATION_PREFIX,
                revocation,
            )
        )

        a_public = self.keys[approval_role]["public"]
        r_public = self.keys[revocation_role]["public"]

        return gate.verify_release(
            candidate if candidate is not None else self.candidate,
            approval,
            a_signature,
            a_public,
            revocation,
            r_signature,
            r_public,
            now=now or self.now,
            approval_pin=core.sha(a_public),
            revocation_pin=core.sha(r_public),
            historical=historical,
        )

    def test_01_two_real_signatures_valid(self):
        result = self.check()
        self.assertEqual(result["file_count_verified"], 39)
        self.assertEqual(result["source_count_verified"], 36)
        self.assertTrue(result["separate_authorities"])
        self.assertIs(
            result["new_installation_allowed_by_this_module"],
            False,
        )

    def test_02_wrong_candidate_denied(self):
        with self.assertRaisesRegex(
            core.Stop, "CANDIDATE_HASH_CHANGED"
        ):
            self.check(candidate=self.candidate + b"x")

    def test_03_invalid_approval_signature(self):
        raw = self.approval()
        signature = bytearray(
            self.sign("approval", core.PREFIX, raw)
        )
        signature[0] ^= 1

        with self.assertRaisesRegex(
            core.Stop, "APPROVAL_SIGNATURE_INVALID"
        ):
            self.check(
                approval=raw,
                approval_signature=bytes(signature),
            )

    def test_04_invalid_revocation_signature(self):
        raw = self.revocation()
        signature = bytearray(
            self.sign(
                "revocation", gate.REVOCATION_PREFIX, raw
            )
        )
        signature[0] ^= 1

        with self.assertRaisesRegex(
            core.Stop, "APPROVAL_SIGNATURE_INVALID"
        ):
            self.check(
                revocation=raw,
                revocation_signature=bytes(signature),
            )

    def test_05_revoked_release_denied(self):
        with self.assertRaisesRegex(
            gate.Stop, "REVOCATION_SCOPE_INVALID"
        ):
            self.check(
                revocation=self.revocation(revoked=True)
            )

    def test_06_expired_revocation_denied(self):
        old = self.now - timedelta(minutes=3)

        with self.assertRaisesRegex(
            gate.Stop, "REVOCATION_ASSERTION_EXPIRED"
        ):
            self.check(
                revocation=self.revocation(start=old)
            )

    def test_07_extended_revocation_denied(self):
        with self.assertRaisesRegex(
            gate.Stop, "REVOCATION_ASSERTION_EXPIRED"
        ):
            self.check(
                revocation=self.revocation(duration=91)
            )

    def test_08_expired_approval_denied_for_install(self):
        old = self.now - timedelta(minutes=12)

        with self.assertRaisesRegex(
            core.Stop, "APPROVAL_WINDOW_INVALID"
        ):
            self.check(
                approval=self.approval(start=old)
            )

    def test_09_historical_approval_with_fresh_revocation(self):
        old = self.now - timedelta(minutes=12)
        value = self.check(
            approval=self.approval(start=old),
            historical=True,
        )

        self.assertEqual(
            value["approval_mode"], "HISTORICAL_SIGNATURE"
        )
        self.assertIs(value["boot_authorized"], False)

    def test_10_same_key_in_both_roles_rejected(self):
        with self.assertRaisesRegex(
            gate.Stop, "KEYS_NOT_INDEPENDENT"
        ):
            self.check(
                revocation_role="approval",
            )

    def test_11_boot_purpose_denied(self):
        with self.assertRaisesRegex(
            core.Stop, "APPROVAL_SCOPE_INVALID"
        ):
            self.check(
                approval=self.approval(
                    purpose="BOOT_AND_NETWORK"
                )
            )

    def test_12_wrong_revocation_head_denied(self):
        with self.assertRaisesRegex(
            gate.Stop, "REVOCATION_SCOPE_INVALID"
        ):
            self.check(
                revocation=self.revocation(
                    head="0" * 40
                )
            )

    def test_13_source_receipt_from_candidate(self):
        from io import BytesIO
        import zipfile

        with zipfile.ZipFile(
            BytesIO(self.candidate)
        ) as bundle:
            members = {
                name: bundle.read(name)
                for name in bundle.namelist()
            }

        receipt = core.document(
            gate.release_receipt(members)
        )

        self.assertEqual(
            set(receipt["source_sha256"]),
            set(gate.F4),
        )
        self.assertIs(receipt["authorized_to_boot"], False)

    def test_14_historical_still_requires_fresh_revocation(self):
        old = self.now - timedelta(minutes=12)

        with self.assertRaisesRegex(
            gate.Stop, "REVOCATION_ASSERTION_EXPIRED"
        ):
            self.check(
                approval=self.approval(start=old),
                revocation=self.revocation(
                    start=self.now - timedelta(minutes=2)
                ),
                historical=True,
            )


if __name__ == "__main__":
    unittest.main()
