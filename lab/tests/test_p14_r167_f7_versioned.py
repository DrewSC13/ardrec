"""R167: regression of versioned SSH plan reader; no physical operations."""
import hashlib
import unittest
from pathlib import Path
from unittest.mock import patch

from ardrec.coordination import r167_f7_controlled_boot as f

REPO = Path("/home/cicada/Development/GitHub/ardrec")

class R167F7Versioned(unittest.TestCase):

    def test_posix_path_reaches_custody_validation(self):
        path = f.ROOT / "plan-regression"
        with patch.object(
            f, "_private",
            side_effect=RuntimeError("CUSTODY_REACHED")
        ):
            with self.assertRaisesRegex(RuntimeError, "CUSTODY_REACHED"):
                f._read_plan(path)

    def test_string_path_rejected(self):
        with self.assertRaisesRegex(f.Stop, "INVALID_PLAN_PATH"):
            f._read_plan(str(f.ROOT / "plan-invalid"))

    def test_physical_boot_blocked_until_release(self):
        with self.assertRaisesRegex(
            f.Stop, "R167_RELEASE_NOT_ATTESTED_SOURCE_ONLY"
        ):
            f._boot_ssh(None, None, None, None)

    def test_original_pin_unchanged(self):
        original = (
            REPO /
            "src/ardrec/coordination/r115_f7_controlled_boot.py"
        )
        self.assertEqual(
            hashlib.sha256(original.read_bytes()).hexdigest(),
            "361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af"
        )

    def test_new_version_and_trust_are_distinct(self):
        self.assertEqual(
            f.SCHEMA, "ARDREC-R167-F7-ONE-BOOT-DENY-v1"
        )
        self.assertEqual(
            f.PERMIT_TRUST.name, "r167-f7-boot-trust-v1.json"
        )
        self.assertEqual(
            f.PERMIT_REVOCATION.name,
            "r167-f7-boot-revocation-v1.json"
        )
