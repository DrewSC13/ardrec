"""Pruebas F5B offline; nunca ejercen --apply ni root."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/ardrec_p14_r117_f5b_root_stage.py"

spec = importlib.util.spec_from_file_location("f5b", SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class F5BTests(unittest.TestCase):

    def approval(self, now=None):
        now = now or datetime(2026, 11, 20, 20, 0, tzinfo=timezone.utc)
        return {
            "schema": m.APPROVAL_SCHEMA,
            "head": "a" * 40,
            "candidate_sha256": "b" * 64,
            "valid_from": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "valid_until": (
                now + timedelta(minutes=5)
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "purpose": "INSTALL_SOURCE_ONLY",
            "authority": "external-reviewer",
            "p8": "NO-GO",
        }

    def test_candidate_source_pins(self):
        builder = m.offline_builder()
        raw, doc = m.expected_bundle(builder, "a" * 40)
        self.assertEqual(len(doc["source_sha256"]), 36)
        self.assertGreater(len(raw), 0)

    def test_release_receipt_shape(self):
        builder = m.offline_builder()
        raw, doc = m.expected_bundle(builder, "a" * 40)
        receipt = m.release_receipt(
            builder, "a" * 40, m.canonical(doc)
        )
        self.assertEqual(set(receipt), {
            "schema", "head", "source_sha256",
            "pilot_manifest_sha256", "pilot_schema",
            "p8", "authorized_to_boot"
        })
        self.assertIs(receipt["authorized_to_boot"], False)

    def test_approval_valid_window(self):
        now = datetime(2026, 11, 20, 20, 0, 0,
                       tzinfo=timezone.utc)
        doc = self.approval(now)
        self.assertEqual(
            m.approval_fields(
                doc, "a" * 40, "b" * 64, now
            ), doc
        )

    def test_approval_wrong_head_rejected(self):
        now = datetime(2026, 11, 20, 20, 0, 0,
                       tzinfo=timezone.utc)
        with self.assertRaises(m.Stop):
            m.approval_fields(
                self.approval(now), "c" * 40,
                "b" * 64, now
            )

    def test_approval_wrong_archive_rejected(self):
        now = datetime(2026, 11, 20, 20, 0, 0,
                       tzinfo=timezone.utc)
        with self.assertRaises(m.Stop):
            m.approval_fields(
                self.approval(now), "a" * 40,
                "c" * 64, now
            )

    def test_expired_approval_rejected(self):
        now = datetime(2026, 11, 20, 20, 0, 0,
                       tzinfo=timezone.utc)
        with self.assertRaises(m.Stop):
            m.approval_fields(
                self.approval(now), "a" * 40,
                "b" * 64, now + timedelta(minutes=6)
            )

    def test_expansive_approval_rejected(self):
        now = datetime(2026, 11, 20, 20, 0, 0,
                       tzinfo=timezone.utc)
        doc = self.approval(now)
        doc["purpose"] = "BOOT_AND_NETWORK"
        with self.assertRaises(m.Stop):
            m.approval_fields(doc, "a" * 40,
                              "b" * 64, now)

    def test_duplicate_json_rejected(self):
        with self.assertRaises(m.Stop):
            m.document(b'{"head":"a","head":"b"}\n')

if __name__ == "__main__":
    unittest.main()
