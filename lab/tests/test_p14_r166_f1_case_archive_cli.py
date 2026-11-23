"""R166-F1: regression CLI sobre fixtures preexistentes B10/B11; NO laboratorio."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "lab/tests")]

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r166_case_archive_cli as m
import test_p14_r129_b10_receipt_gate as fixture_b10
import test_p14_r129_b11_independent_a6 as fixture_b11


@unittest.skipIf(os.geteuid() == 0, "requires unprivileged F13 receipts")
class CaseArchiveCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_b11.IndependentA6B11.setUpClass()

    def setUp(self):
        x = fixture_b10.ReceiptB10("test_01_f13_prespent")
        x.setUp()
        self.addCleanup(x.doCleanups)
        self.x = x
        temp = tempfile.TemporaryDirectory(prefix="ardrec-r166-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.origin = self.root / "exported"
        self.origin.mkdir(mode=0o700)
        self.archive = self.root / "archive"
        self.manifest = self.root / "manifest.json"
        self._write_sources()

    def _write(self, name, payload, parent=None):
        folder = parent or self.origin
        p = folder / (name + ".json")
        p.write_bytes(f1.canonical(payload))
        p.chmod(0o600)
        return p

    def _write_sources(self):
        for name in m.DOCS:
            self._write(name, getattr(self.x, name))

    def _seal(self, signed_time=None):
        doc = m.build_manifest(origin=self.origin, journal=self.x.journal,
                               review_at_utc=signed_time)
        m._create_exclusive(self.manifest, f1.canonical(doc))
        return doc

    def test_01_normal_cli_entry_seal_replay_archive_reopen(self):
        from ardrec.__main__ import main
        # Sin subproceso de red ni instalador; entra por python -m ardrec.
        self.assertEqual(main(["caso", "sellar", "--origen", str(self.origin),
                               "--journal", str(self.x.journal), "--manifiesto",
                               str(self.manifest), "--texto"]), 0)
        self.assertEqual(main(["caso", "revisar", "--manifiesto",
                               str(self.manifest), "--texto"]), 0)
        self.assertEqual(main(["caso", "incorporar", "--manifiesto",
                               str(self.manifest), "--archivo", str(self.archive),
                               "--texto"]), 0)
        self.assertEqual(main(["caso", "reabrir", "--manifiesto",
                               str(self.manifest), "--archivo", str(self.archive),
                               "--texto"]), 0)

    def test_02_idempotence_same_originals(self):
        self._seal()
        first, status = m.process(manifest=self.manifest, archive=self.archive,
                                  action="incorporar")
        again, again_status = m.process(manifest=self.manifest,
                                       archive=self.archive, action="incorporar")
        self.assertEqual(status, "DOCUMENTARY_RECORD_WRITTEN")
        self.assertEqual(again_status, "ALREADY_INCORPORATED")
        self.assertEqual(first, again)
        self.assertEqual({p.name for p in self.archive.iterdir()},
                         {".record.lock", "record.json"})

    def test_03_full_content_hash_tamper_denied(self):
        self._seal()
        self._write("guest", {**self.x.guest, "response_hex": "00"})
        with self.assertRaisesRegex(m.Stop, "SOURCE_SHA256_MISMATCH_guest"):
            m.process(manifest=self.manifest, archive=self.archive,
                      action="incorporar")
        self.assertFalse(self.archive.exists())

    def test_04_reopen_fail_closed_on_original_mutation(self):
        self._seal()
        m.process(manifest=self.manifest, archive=self.archive,
                  action="incorporar")
        self._write("receipt", {**self.x.receipt, "a6": "VERDADERO"})
        with self.assertRaisesRegex(m.Stop, "SOURCE_SHA256_MISMATCH_receipt"):
            m.process(manifest=self.manifest, archive=self.archive,
                      action="reabrir")

    def test_05_conflicting_case_record_CAS_denied(self):
        self._seal()
        old, _ = m.process(manifest=self.manifest, archive=self.archive,
                           action="incorporar")
        self.x.receipt.update({"result": "NO_GO_ATTEMPT_CONSUMED",
                               "error": "fixture failure",
                               "guest_result_sha256": None,
                               "denies_restored_and_verified": False})
        for name in ("guest", "qga"):
            (self.origin / (name + ".json")).unlink()
        self._write("receipt", self.x.receipt)
        other = m.build_manifest(origin=self.origin, journal=self.x.journal)
        other_file = self.root / "alternate.json"
        m._create_exclusive(other_file, f1.canonical(other))
        with self.assertRaisesRegex(m.Stop, "ARCHIVE_CAS_CONFLICT"):
            m.process(manifest=other_file, archive=self.archive,
                      action="incorporar")
        self.assertEqual(m._read_record(self.archive), old)

    def test_06_orphan_pending_safe_retry(self):
        self._seal()
        self.archive.mkdir(mode=0o700)
        abandoned = self.archive / ".pending-previous-interruption"
        abandoned.write_bytes(b"unconfirmed\n")
        abandoned.chmod(0o600)
        m.process(manifest=self.manifest, archive=self.archive,
                  action="incorporar")
        self.assertEqual(abandoned.read_bytes(), b"unconfirmed\n")
        record, state = m.process(manifest=self.manifest,
                                  archive=self.archive, action="reabrir")
        self.assertEqual(state, "ARCHIVE_REOPEN_VERIFIED_FROM_ORIGINALS")
        self.assertFalse(record["native_a9_committed"])

    def test_07_second_process_can_reopen_without_network(self):
        self._seal()
        m.process(manifest=self.manifest, archive=self.archive,
                  action="incorporar")
        proc = subprocess.run([sys.executable, "-m", "ardrec", "caso",
                               "reabrir", "--manifiesto", str(self.manifest),
                               "--archivo", str(self.archive), "--texto"],
                              cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
                              capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ARCHIVE_REOPEN_VERIFIED_FROM_ORIGINALS", proc.stdout)
        self.assertIn("RF_CONFIRMADO=ND", proc.stdout)

    def test_08_existing_manifest_conflict_fails(self):
        doc = self._seal()
        self.assertFalse(m._create_exclusive(self.manifest, f1.canonical(doc)))
        other = {**doc, "review_at_utc": "2026-01-01T00:00:00Z"}
        with self.assertRaisesRegex(m.Stop, "EXISTING_RECORD_CONFLICT"):
            m._create_exclusive(self.manifest, f1.canonical(other))

    def test_09_symlink_export_denied(self):
        self._seal()
        f = self.origin / "receipt.json"
        f.unlink()
        f.symlink_to(self.origin / "intent.json")
        with self.assertRaisesRegex(m.Stop, "PRIVATE_FILE_OWNER_MODE"):
            m.process(manifest=self.manifest, archive=None, action="revisar")

    def test_10_signed_historical_verification_is_not_live(self):
        original = fixture_b11.IndependentA6B11("test_01_real_ed25519_three_roles")
        original.setUp()
        self.addCleanup(original.doCleanups)
        # El segundo fixture B11 coincide con su propio F13, no con B10 de setUp.
        for name in m.DOCS:
            self._write(name, getattr(original.x, name))
        signed = self.origin / "signed"
        signed.mkdir(mode=0o700)
        for name in m.SIGNED:
            self._write(name, getattr(original, name), signed)
        manifest = m.build_manifest(origin=self.origin,
                                    journal=original.x.journal,
                                    review_at_utc="2026-11-21T22:00:00Z")
        self.assertEqual(m.evaluate_manifest(manifest)["a6"], "ND")
        self.assertTrue(m.evaluate_manifest(manifest)["a6_documentary_signatures_verified"])
        self.assertIsNone(m.evaluate_manifest(manifest)["a9_generation"])

    def test_11_unsigned_with_arbitrary_review_time_denied(self):
        with self.assertRaisesRegex(m.Stop, "UNSIGNED_REVIEW_CLOCK_FORBIDDEN"):
            m.build_manifest(origin=self.origin, journal=self.x.journal,
                             review_at_utc="2026-11-21T22:00:00Z")

    def test_12_untrusted_json_extra_fields_denied(self):
        self._seal()
        raw = json.loads(self.manifest.read_bytes())
        raw["claimed_physical_a6"] = True
        self.manifest.write_bytes(f1.canonical(raw))
        with self.assertRaisesRegex(m.Stop, "MANIFEST_SCHEMA_INVALID"):
            m.process(manifest=self.manifest, archive=None, action="revisar")

    def test_13_no_socket_or_native_A9(self):
        self._seal()
        with (patch("socket.socket", side_effect=AssertionError("NO SOCKET")),
              patch("ardrec.persistence.DurableStore.open",
                    side_effect=AssertionError("NO A9 OPEN")),
              patch("ardrec.persistence.DurableStore.create",
                    side_effect=AssertionError("NO A9 CREATE"))):
            m.process(manifest=self.manifest, archive=self.archive,
                      action="incorporar")


if __name__ == "__main__":
    unittest.main()
