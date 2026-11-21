"""R117 F5B executor V3 binding and negative tests."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import ardrec_r117_f5b_release_executor_v3 as m
from r117_v3_candidate_fixture import candidate_bytes

REPO = Path(__file__).resolve().parents[2]

class ExecutorV3Tests(unittest.TestCase):
    def test_01_candidate_head(self):
        self.assertEqual(
            m.HEAD,
            "197785a38bf166ec0b4c8d3ae17346d1fa217265"
        )

    def test_02_candidate_sha(self):
        self.assertEqual(
            hashlib.sha256(candidate_bytes()).hexdigest(),
            m.CANDIDATE_SHA
        )

    def test_03_approval_identity(self):
        self.assertEqual(
            m.APPROVAL_PIN,
            "304c3409f9d074f2ab68881622de9129ab41ee1e1652e8a0ee102211637159d8"
        )

    def test_04_revocation_identity(self):
        self.assertEqual(
            m.REVOCATION_PIN,
            "4c32a558cf5b4c6032234ee91a457f203a8dd3472141a29906d6fb0b775a3509"
        )

    def test_05_separate_root_authorities(self):
        self.assertNotEqual(m.APPROVAL_PIN, m.REVOCATION_PIN)
        self.assertIn("authorities-v3", str(m.TRUST_APPROVAL))
        self.assertIn("authorities-v3", str(m.TRUST_REVOCATION))

    def test_06_versioned_receipts(self):
        self.assertIn("ledger-v3", str(m.APPROVAL_LEDGER))
        self.assertIn("events-v3", str(m.EVENT_LOG))

    def test_07_unprivileged_rejected(self):
        with patch.object(m.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(m.Stop, "ROOT_REQUIRED"):
                m.check_package()

    def test_08_no_old_candidate(self):
        source = (
            REPO / "scripts/ardrec_r117_f5b_release_executor_v3.py"
        ).read_text()
        self.assertNotIn(
            "R117_F5A_ROOT_CANDIDATE_1521f3af69e7.zip",
            source
        )
        self.assertIn("V3_CANDIDATE_BYTES_CHANGED", source)

if __name__ == "__main__":
    unittest.main()
