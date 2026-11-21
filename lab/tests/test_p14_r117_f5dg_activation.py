"""R117-F5D-G source-only regression of atomic activation.

No test in this file performs a root installation or a VM start.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from ardrec.coordination import r117_f4_root_release as f4

REPO = Path(__file__).resolve().parents[2]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()

class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.head = "a" * 40
        self.transaction = ".r117-f5b-transaction-" + "b" * 24
        self.receipt = b"receipt\\n"
        self.pilot = b"pilot\\n"
        self.approval = b"approval\\n"
        self.complete_raw = b"complete\\n"
        self.intent = {
            "candidate_sha256": "c" * 64,
            "approval_sha256": sha(self.approval),
        }
        self.complete = {
            "pilot_manifest_sha256": sha(self.pilot),
            "receipt_sha256": sha(self.receipt),
        }
        self.activation = {
            "schema": f4.ACTIVATION_SCHEMA,
            "head": self.head,
            "transaction": self.transaction,
            "candidate_sha256": "c" * 64,
            "approval_sha256": sha(self.approval),
            "pilot_manifest_sha256": sha(self.pilot),
            "receipt_sha256": sha(self.receipt),
            "complete_sha256": sha(self.complete_raw),
            "boot_authorized": False,
            "network_authorized": False,
            "p8": "NO-GO",
        }

    def check(self, value=None):
        return f4._verify_activation(
            canonical(self.activation if value is None else value),
            self.head, self.transaction,
            self.intent, self.complete,
            self.receipt, self.pilot,
            self.approval, self.complete_raw,
        )

    def reject(self, field, value):
        obj = dict(self.activation)
        obj[field] = value
        with self.assertRaises(f4.Stop):
            self.check(obj)

    def test_01_structural_activation_valid(self):
        self.assertEqual(self.check()["p8"], "NO-GO")

    def test_02_missing_field_rejected(self):
        obj = dict(self.activation)
        del obj["complete_sha256"]
        with self.assertRaises(f4.Stop):
            self.check(obj)

    def test_03_wrong_schema_rejected(self):
        self.reject("schema", "OTHER")

    def test_04_wrong_head_rejected(self):
        self.reject("head", "d" * 40)

    def test_05_wrong_transaction_rejected(self):
        self.reject("transaction", ".r117-f5b-transaction-" + "d" * 24)

    def test_06_wrong_candidate_rejected(self):
        self.reject("candidate_sha256", "d" * 64)

    def test_07_wrong_approval_rejected(self):
        self.reject("approval_sha256", "d" * 64)

    def test_08_wrong_pilot_manifest_rejected(self):
        self.reject("pilot_manifest_sha256", "d" * 64)

    def test_09_wrong_receipt_rejected(self):
        self.reject("receipt_sha256", "d" * 64)

    def test_10_wrong_completion_rejected(self):
        self.reject("complete_sha256", "d" * 64)

    def test_11_boot_permission_rejected(self):
        self.reject("boot_authorized", True)

    def test_12_network_permission_rejected(self):
        self.reject("network_authorized", True)

    def test_13_expanded_p8_rejected(self):
        self.reject("p8", "GO")

    def test_14_publication_after_completion(self):
        source = (
            REPO / "scripts/ardrec_p14_r117_f5b_root_stage.py"
        ).read_text()
        self.assertLess(
            source.index('            txn / "complete.json"'),
            source.index('        activation_sha = _publish_activation('),
        )
        self.assertIn(
            'os.rename(pending, ACTIVATION)', source
        )

    def test_15_apply_remains_blocked(self):
        source = (
            REPO / "scripts/ardrec_p14_r117_f5b_root_stage.py"
        ).read_text()
        self.assertIn(
            "need(False, 'F5B_APPLY_BLOCKED_PENDING_ATOMIC_RELEASE_AND_BOOT_GATE')",
            source,
        )

if __name__ == "__main__":
    unittest.main()
