"""R117 F5B root preflight regression, without privilege."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ardrec_r117_f5b_root_preflight_v2 as m


class RootPreflightTests(unittest.TestCase):

    def deny(self):
        return {
            "deny": "MATCH",
            "p8": "NO-GO",
            "host_writes": 0,
            "states": {
                "ssh": "OFF",
                "runner": "OFF",
                "ftp": "OFF",
                "smb": "OFF",
            },
            "policy": {
                "active_count": 0,
                "absent_count": 6,
                "allow_traffic": False,
            },
        }

    def test_01_exact_candidate(self):
        files = m.verify_candidate(
            m.archive_bytes(m.CANDIDATE_ZIP)
        )
        self.assertEqual(len(files), 39)

    def test_02_exact_agent(self):
        files = m.verify_agent(
            m.archive_bytes(m.AGENT_ZIP)
        )
        self.assertEqual(set(files), m.AGENT_NAMES)

    def test_03_candidate_modified(self):
        raw = m.archive_bytes(m.CANDIDATE_ZIP)
        with self.assertRaisesRegex(
            m.Stop, "CANDIDATE_SHA_CHANGED"
        ):
            m.verify_candidate(raw + b"x")

    def test_04_agent_modified(self):
        raw = m.archive_bytes(m.AGENT_ZIP)
        with self.assertRaisesRegex(
            m.Stop, "AGENT_SHA_CHANGED"
        ):
            m.verify_agent(raw + b"x")

    def test_05_physical_deny_valid(self):
        self.assertIsNone(
            m.check_deny(self.deny())
        )

    def test_06_physical_deny_rejects_traffic(self):
        doc = self.deny()
        doc["policy"]["allow_traffic"] = True

        with self.assertRaisesRegex(
            m.Stop, "PHYSICAL_DENY_CHANGED"
        ):
            m.check_deny(doc)

    def test_07_physical_deny_rejects_active(self):
        doc = self.deny()
        doc["policy"]["active_count"] = 1

        with self.assertRaisesRegex(
            m.Stop, "PHYSICAL_DENY_CHANGED"
        ):
            m.check_deny(doc)

    def test_08_empty_root_has_no_release(self):
        with tempfile.TemporaryDirectory() as temp:
            m.check_unpublished(Path(temp))

    def test_09_existing_transaction_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".r117-f5b-transaction-abc").mkdir()

            with self.assertRaisesRegex(
                m.Stop, "PREVIOUS_RELEASE_TRANSACTION"
            ):
                m.check_unpublished(root)

    def test_10_existing_pilot_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / m.PILOT.name).mkdir()

            with self.assertRaisesRegex(
                m.Stop, "RELEASE_ALREADY_PRESENT"
            ):
                m.check_unpublished(root)

    def test_11_root_command_not_callable_from_checkout(self):
        with patch.object(m.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(
                m.Stop, "EXECUTOR_NOT_INSTALLED_IN_ROOT"
            ):
                m.inspect_root()

    def test_12_no_apply_entrypoint(self):
        import argparse
        self.assertFalse(
            hasattr(m, "apply")
        )
        self.assertEqual(m.HEAD, (
            "1521f3af69e7875f6c79a60d7a905e5fbffdcba1"
        ))


if __name__ == "__main__":
    unittest.main()
