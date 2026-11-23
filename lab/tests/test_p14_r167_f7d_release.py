"""R167-F7D: release admission and non-destructive boot regressions."""
import hashlib
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from ardrec.coordination import (
    r167_f7d_controlled_boot as f,
    r167_f7d_release_gate as release,
)

REPO = Path("/home/cicada/Development/GitHub/ardrec")

class VersionedReleaseTests(unittest.TestCase):

    def test_source_manifest_pins_are_exact(self):
        self.assertEqual(
            len(release.source_admission()), 4
        )

    def test_versioned_namespace_is_independent(self):
        self.assertEqual(
            f.SCHEMA, "ARDREC-R167-F7D-ONE-BOOT-DENY-v1"
        )
        self.assertEqual(
            f.PERMIT_TRUST.name,
            "r167-f7d-boot-trust-v1.json"
        )
        self.assertEqual(
            f.PERMIT_REVOCATION.name,
            "r167-f7d-boot-revocation-v1.json"
        )

    def test_posixpath_reaches_private_validation(self):
        candidate = f.ROOT / "plan-regression"
        with patch.object(
            f, "_private",
            side_effect=RuntimeError("CUSTODY_REACHED")
        ):
            with self.assertRaisesRegex(
                RuntimeError, "CUSTODY_REACHED"
            ):
                f._read_plan(candidate)

    def test_string_plan_path_is_rejected(self):
        with self.assertRaisesRegex(f.Stop, "INVALID_PLAN_PATH"):
            f._read_plan(str(f.ROOT / "plan-invalid"))

    def test_absent_release_fails_closed(self):
        with patch.object(
            release,
            "APPROVAL",
            Path("/nonexistent/r167-f7d/release.json"),
        ):
            with self.assertRaisesRegex(
                release.Stop, "RELEASE_APPROVAL_UNAVAILABLE"
            ):
                release.require(
                    {"role": "ssh"},
                    now=datetime.now(timezone.utc),
                )

    def test_release_checks_precede_irreversible_claim(self):
        code = (
            REPO /
            "src/ardrec/coordination/r167_f7d_controlled_boot.py"
        ).read_text()

        first = "release.require(plan, now=now)"
        second = "release.require(plan, now=clock())"
        claim = "f2.exclusive(folder/'boot.once'"

        self.assertEqual(code.count(first), 1)
        self.assertEqual(code.count(second), 1)
        self.assertLess(
            code.index(first), code.index("fresh=f5.capture")
        )
        self.assertLess(
            code.index(second), code.index(claim)
        )
        self.assertNotIn(
            "need(False, 'R167_RELEASE_NOT_ATTESTED_SOURCE_ONLY')",
            code,
        )

    def test_historical_f7_is_unchanged(self):
        path = (
            REPO /
            "src/ardrec/coordination/r115_f7_controlled_boot.py"
        )
        self.assertEqual(
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af",
        )


class ReleaseTrustIsolationTests(unittest.TestCase):

    def test_release_has_separate_root_trust(self):
        self.assertEqual(
            release.RELEASE_TRUST,
            Path("/etc/ardrec/r167-f7d-release-trust-v1.json"),
        )
        self.assertNotEqual(
            release.RELEASE_TRUST,
            Path("/etc/ardrec/r115-ftp-t01-trust-v1.json"),
        )

    def test_unallowlisted_policy_is_rejected(self):
        with self.assertRaisesRegex(
            release.Stop, "ROOT_POLICY_NOT_ALLOWLISTED"
        ):
            release.root_policy(
                Path("/tmp/untrusted-release-policy.json")
            )

    def test_release_refuses_scope_key_reuse_by_design(self):
        import inspect
        code = inspect.getsource(release.require)
        self.assertIn(
            "RELEASE_TRUST_REUSES_SCOPE_AUTHORITY", code
        )
        self.assertIn(
            "root_policy(RELEASE_TRUST)", code
        )
