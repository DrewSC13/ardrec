"""F17 release integrity, regression guard and fail-closed acceptance tests."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'scripts'))
import ardrec_p14_r115_f17_merge_gate as gate


class TestR115F17Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ardrec-r115-f17-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source_lock = json.loads((REPO / gate.LOCK).read_text())
        files = list(source_lock['source_sha256']) + [gate.LOCK, gate.CATALOG, gate.CI, gate.DOC]
        for rel in files:
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / rel, dest)
        self.source = sorted(source_lock['source_sha256'])[0]

    def _lock(self):
        return json.loads((self.root / gate.LOCK).read_text())

    def _write_lock(self, lock):
        (self.root / gate.LOCK).write_text(json.dumps(lock), encoding='utf-8')

    def _reject(self, reason):
        with self.assertRaises(gate.GateFailure) as ctx:
            gate.evaluate(self.root)
        self.assertIn(reason, str(ctx.exception))

    def test_audit_passes_without_operational_go(self):
        result = gate.evaluate(self.root)
        self.assertEqual(result['source_integrity'], 'PASS_58')
        self.assertEqual(result['p8'], 'NO-GO')
        self.assertEqual(result['a6'], 'ND')
        self.assertFalse(result['p7_pilot_completed'])
        self.assertEqual(result['host_mutations'], 0)

    def test_missing_source_is_rejected(self):
        (self.root / self.source).unlink()
        self._reject('FILE_MISSING')

    def test_modified_source_is_rejected(self):
        with (self.root / self.source).open('ab') as f:
            f.write(b'\nnot an authorized modification\n')
        self._reject('SOURCE_DRIFT')

    def test_symlink_source_is_rejected(self):
        original = self.root / self.source
        original.unlink()
        original.symlink_to(self.root / gate.CATALOG)
        self._reject('SYMLINK_FORBIDDEN')

    def test_catalog_sha_drift_is_rejected(self):
        with (self.root / gate.CATALOG).open('ab') as f:
            f.write(b'\n')
        self._reject('CATALOG_PIN_MISMATCH')

    def test_catalog_enabled_even_with_updated_pin_is_rejected(self):
        path = self.root / gate.CATALOG
        cat = json.loads(path.read_text())
        cat['execution_enabled'] = True
        raw = json.dumps(cat).encode()
        path.write_bytes(raw)
        lock = self._lock()
        lock['catalog_sha256'] = hashlib.sha256(raw).hexdigest()
        self._write_lock(lock)
        self._reject('CATALOG_NO_GO_INVARIANT_FAILED')

    def test_source_count_changed_is_rejected(self):
        lock = self._lock()
        lock['source_count'] = 57
        self._write_lock(lock)
        self._reject('LOCK_SOURCE_COUNT_MISMATCH')

    def test_attempt_to_mark_p8_go_is_rejected(self):
        lock = self._lock()
        lock['p8'] = 'GO'
        self._write_lock(lock)
        self._reject('UNSAFE_LOCK_STATE')

    def test_attempt_to_mark_physical_a5_is_rejected(self):
        lock = self._lock()
        lock['a5_physical'] = 'CONFIRMED'
        self._write_lock(lock)
        self._reject('UNSAFE_LOCK_STATE')

    def test_duplicate_manifest_key_is_rejected(self):
        path = self.root / gate.LOCK
        raw = path.read_text()
        raw = raw.replace('"schema":', '"schema": "forged", "schema":', 1)
        path.write_text(raw)
        self._reject('INVALID_JSON')

    def test_ci_registration_is_required(self):
        (self.root / gate.CI).write_text('name: ci\n')
        self._reject('R115_CI_GATE_NOT_REGISTERED')

    def test_r116_risks_document_is_required(self):
        (self.root / gate.DOC).write_text('No references to deferred work\n')
        self._reject('CLOSURE_RISK_DISCLOSURE_MISSING')


if __name__ == '__main__':
    unittest.main()
