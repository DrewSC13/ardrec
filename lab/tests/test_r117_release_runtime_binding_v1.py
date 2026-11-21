"""Verify F4 installed bytes and explicit dual-signature identity."""
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch
import hashlib
import json
import unittest

from ardrec.coordination import r117_f4_root_release as f4
import test_r117_f5b_dual_authority_v1 as dual_fixtures
import ardrec_r117_f5b_dual_authority_v1 as dual


REPO = Path(__file__).resolve().parents[2]


class RuntimeBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create isolated Ed25519 fixtures without importing
        # the other TestCase into this module's test discovery.
        dual_fixtures.DualAuthorityTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        dual_fixtures.DualAuthorityTests.tearDownClass()

    def fixture(self, tamper=False):
        head = "a" * 40
        files = {
            source: (REPO / source).read_bytes()
            for source in f4.SRC
        }

        pilot = json.dumps({
            "schema": f4.PILOT_SCHEMA,
            "head": head,
            "p8": "NO-GO",
            "a6": "ND",
            "network_automatic": False,
        }, sort_keys=True).encode()

        receipt = json.dumps({
            "schema": f4.RELEASE_SCHEMA,
            "head": head,
            "source_sha256": {
                source: hashlib.sha256(raw).hexdigest()
                for source, raw in files.items()
            },
            "pilot_manifest_sha256":
                hashlib.sha256(pilot).hexdigest(),
            "pilot_schema": f4.PILOT_SCHEMA,
            "p8": "NO-GO",
            "authorized_to_boot": False,
        }, sort_keys=True).encode()

        touched = []

        def reader(path):
            touched.append(path)

            if path == f4.RECEIPT:
                return receipt
            if path == f4.PILOT_MANIFEST:
                return pilot

            root = Path(
                "/var/lib/ardrec/r117-f4-ftp-pilot-root-v1"
            ) / "runtime/ardrec/coordination"

            for source, raw in files.items():
                if path == root / Path(source).name:
                    if tamper and source == f4.SRC[0]:
                        return raw + b"# alteration"
                    return raw

            raise AssertionError("UNEXPECTED_READ_" + str(path))

        return head, reader, touched

    def test_01_accepts_installed_source_bytes(self):
        head, reader, touched = self.fixture()

        with patch.object(
            f4, "_closed_transaction", return_value=True
        ) as closure:
            outcome = f4.require_attested_release(
                head,
                repo=Path("/nonexistent-untrusted-checkout"),
                reader=reader,
            )

        closure.assert_called_once()
        self.assertEqual(outcome["p8"], "NO-GO")
        self.assertEqual(len(touched), 5)
        self.assertTrue(all(
            str(path).startswith("/var/lib/ardrec/")
            for path in touched
        ))

    def test_02_rejects_tampered_installed_source(self):
        head, reader, _ = self.fixture(tamper=True)

        with patch.object(
            f4, "_closed_transaction"
        ) as closure:
            with self.assertRaisesRegex(
                f4.Stop, "RELEASE_SOURCE_DRIFT"
            ):
                f4.require_attested_release(
                    head, reader=reader
                )
            closure.assert_not_called()

    def test_03_rejects_bad_dynamic_identity(self):
        with self.assertRaisesRegex(
            dual.Stop, "SIGNED_CANDIDATE_IDENTITY_INVALID"
        ):
            dual.verify_release(
                b"x", b"x", b"x", b"x",
                b"x", b"x", b"x",
                now=datetime.now(timezone.utc),
                head="not-a-commit",
                candidate_sha="0" * 64,
            )

    def test_04_explicit_identity_accepted(self):
        fixture = dual_fixtures.DualAuthorityTests()
        fixture.setUp()

        approval = fixture.approval()
        revocation = fixture.revocation()

        a_public = fixture.keys["approval"]["public"]
        r_public = fixture.keys["revocation"]["public"]

        result = dual.verify_release(
            fixture.candidate,
            approval,
            fixture.sign(
                "approval",
                __import__(
                    "ardrec_r117_release_core_v1"
                ).PREFIX,
                approval,
            ),
            a_public,
            revocation,
            fixture.sign(
                "revocation",
                dual.REVOCATION_PREFIX,
                revocation,
            ),
            r_public,
            now=fixture.now,
            head=dual.HEAD,
            candidate_sha=dual.CANDIDATE_SHA,
            approval_pin=hashlib.sha256(
                a_public
            ).hexdigest(),
            revocation_pin=hashlib.sha256(
                r_public
            ).hexdigest(),
        )

        self.assertEqual(result["head"], dual.HEAD)
        self.assertEqual(
            result["candidate_sha256"],
            dual.CANDIDATE_SHA,
        )
        self.assertIs(result["boot_authorized"], False)


if __name__ == "__main__":
    unittest.main()
