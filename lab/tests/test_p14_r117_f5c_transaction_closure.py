"""R117-F5C structural closure tests with synthetic snapshots.

The synthetic signature never constitutes an authorization.
"""
from io import BytesIO
from pathlib import Path
import copy
import importlib.util
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / (
    "scripts/ardrec_p14_r117_f5c_transaction_closure.py"
)
spec = importlib.util.spec_from_file_location(
    "r117_f5c_closure", SCRIPT
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class ClosureTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.head = "a" * 40
        cls.a, cls.b = m.modules(REPO)
        cls.candidate = cls.a.candidate(
            cls.head, repo=REPO
        )

        with zipfile.ZipFile(
            BytesIO(cls.candidate)
        ) as archive:
            cls.pilot = {
                name: archive.read(name)
                for name in archive.namelist()
            }

        approval = {
            "schema": cls.b.APPROVAL_SCHEMA,
            "head": cls.head,
            "candidate_sha256":
                cls.a.sha(cls.candidate),
            "valid_from": "2026-11-20T20:00:00Z",
            "valid_until": "2026-11-20T20:05:00Z",
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "synthetic-test-fixture",
            "p8": "NO-GO",
        }
        approval_raw = cls.a.canonical(approval)

        receipt = cls.b.release_receipt(
            cls.a, cls.head,
            cls.pilot["manifest.json"], repo=REPO
        )
        receipt_raw = cls.a.canonical(receipt)

        cls.release = {
            "receipt.json": receipt_raw,
            "approval.json": approval_raw,
            # Structural shape only: NOT a valid signature.
            "approval.sig": b"\x00" * 64,
        }

        intent = {
            "schema": m.INTENT_SCHEMA,
            "head": cls.head,
            "candidate_sha256":
                cls.a.sha(cls.candidate),
            "approval_sha256":
                cls.a.sha(approval_raw),
            "status": "SOURCE_INSTALL_ATTEMPT",
            "p8": "NO-GO",
        }

        complete = {
            "schema": m.COMPLETE_SCHEMA,
            "head": cls.head,
            "pilot_manifest_sha256":
                cls.a.sha(cls.pilot["manifest.json"]),
            "receipt_sha256":
                cls.a.sha(receipt_raw),
            "approved_install": True,
            "boot_permit_issued": False,
            "network_connections": 0,
            "vm_starts": 0,
            "p8": "NO-GO",
        }

        cls.journal = {
            **m.JOURNAL_MARKERS,
            "intent.json": cls.a.canonical(intent),
            "complete.json": cls.a.canonical(complete),
        }

    def snapshot(self):
        return (
            dict(self.pilot),
            dict(self.release),
            dict(self.journal),
        )

    def check(self, pilot, release, journal,
              head=None):
        return m.validate(
            head or self.head,
            self.candidate,
            pilot, release, journal, repo=REPO
        )

    def rejected(self, pilot, release, journal,
                 head=None):
        with self.assertRaises(m.Stop):
            self.check(
                pilot, release, journal, head=head
            )

    def test_complete_snapshot_is_structurally_consistent(self):
        result = self.check(*self.snapshot())
        self.assertEqual(
            result["structural_closure"], "CONSISTENT"
        )
        self.assertEqual(result["file_count"], 39)
        self.assertIs(result["ed25519_verified"], False)
        self.assertIs(result["boot_authorized"], False)

    def test_missing_completion_rejected(self):
        p, r, j = self.snapshot()
        del j["complete.json"]
        self.rejected(p, r, j)

    def test_missing_prepared_marker_rejected(self):
        p, r, j = self.snapshot()
        del j["prepared.once"]
        self.rejected(p, r, j)

    def test_missing_pilot_visible_marker_rejected(self):
        p, r, j = self.snapshot()
        del j["pilot-visible.once"]
        self.rejected(p, r, j)

    def test_missing_release_visible_marker_rejected(self):
        p, r, j = self.snapshot()
        del j["release-visible.once"]
        self.rejected(p, r, j)

    def test_changed_pilot_source_rejected(self):
        p, r, j = self.snapshot()
        p["root-pilot.py"] += b"# tampered\n"
        self.rejected(p, r, j)

    def test_changed_release_receipt_rejected(self):
        p, r, j = self.snapshot()
        r["receipt.json"] += b" "
        self.rejected(p, r, j)

    def test_changed_approval_rejected(self):
        p, r, j = self.snapshot()
        r["approval.json"] += b" "
        self.rejected(p, r, j)

    def test_wrong_intent_candidate_rejected(self):
        p, r, j = self.snapshot()
        doc = self.a.strict_json(j["intent.json"])
        doc["candidate_sha256"] = "b" * 64
        j["intent.json"] = self.a.canonical(doc)
        self.rejected(p, r, j)

    def test_wrong_completion_manifest_rejected(self):
        p, r, j = self.snapshot()
        doc = self.a.strict_json(j["complete.json"])
        doc["pilot_manifest_sha256"] = "b" * 64
        j["complete.json"] = self.a.canonical(doc)
        self.rejected(p, r, j)

    def test_forged_boot_permit_rejected(self):
        p, r, j = self.snapshot()
        doc = self.a.strict_json(j["complete.json"])
        doc["boot_permit_issued"] = True
        j["complete.json"] = self.a.canonical(doc)
        self.rejected(p, r, j)

    def test_extra_journal_entry_rejected(self):
        p, r, j = self.snapshot()
        j["another-transaction.json"] = b"{}\n"
        self.rejected(p, r, j)

    def test_duplicate_intent_json_rejected(self):
        p, r, j = self.snapshot()
        j["intent.json"] = b'{"head":"a","head":"b"}\n'
        self.rejected(p, r, j)

    def test_invalid_signature_shape_rejected(self):
        p, r, j = self.snapshot()
        r["approval.sig"] = b"\x00" * 63
        self.rejected(p, r, j)

    def test_wrong_head_rejected(self):
        p, r, j = self.snapshot()
        self.rejected(p, r, j, head="b" * 40)

    def test_missing_release_member_rejected(self):
        p, r, j = self.snapshot()
        del r["approval.json"]
        self.rejected(p, r, j)

if __name__ == "__main__":
    unittest.main()
