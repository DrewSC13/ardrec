"""ARDREC R117: independent V3 authority binding."""
from pathlib import Path
import hashlib
import json
import unittest

from ardrec.coordination import r117_f4_root_release as f4

REPO = Path(__file__).resolve().parents[2]
DOCUMENT = (
    REPO / "lab/operational-controller/"
    "r117-f5b-authorities-v3.json"
)


class AuthoritiesV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(DOCUMENT.read_bytes())

    def test_01_approval_pin(self):
        self.assertEqual(
            f4.APPROVAL_PIN,
            self.doc["approval_public_sha256"]
        )

    def test_02_revocation_pin(self):
        self.assertEqual(
            f4.REVOCATION_PIN,
            self.doc["revocation_public_sha256"]
        )

    def test_03_independent_keys(self):
        self.assertNotEqual(
            f4.APPROVAL_PIN, f4.REVOCATION_PIN
        )

    def test_04_new_root_trust_paths(self):
        self.assertEqual(
            str(f4.TRUST),
            self.doc["approval_public_path"]
        )
        self.assertEqual(
            str(f4.REVOCATION_TRUST),
            self.doc["revocation_public_path"]
        )
        self.assertIn(
            "r117-authorities-v3",
            str(f4.TRUST)
        )

    def test_05_source_manifest(self):
        source = (
            REPO / "src/ardrec/coordination/"
            "r117_f4_root_release.py"
        )
        dispatch = json.loads((
            REPO / "lab/operational-controller/"
            "r117-f4-dispatch-sources-v1.json"
        ).read_bytes())

        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            dispatch["source_sha256"][
                "src/ardrec/coordination/r117_f4_root_release.py"
            ]
        )

    def test_06_source_only_authority(self):
        self.assertEqual(
            self.doc["schema"],
            "ARDREC-R117-F5B-AUTHORITIES-v3"
        )
        self.assertFalse(
            self.doc["private_keys_in_repository"]
        )
        self.assertFalse(
            self.doc["boot_authorized"]
        )
        self.assertFalse(
            self.doc["network_authorized"]
        )
        self.assertEqual(self.doc["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
