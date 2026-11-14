"""R37: oráculo independiente para admisión documental; sin acceso a VM."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.evidence.defensive_import import (
    SCHEMA, DefensiveImportError, admit_defensive_observation,
    read_observation, validate_admission, validate_unique_observations,
)

CONTENT = b'PasswordAuthentication no\nPermitRootLogin no\n'
TIME = '2026-11-14T20:00:00Z'

def receipt():
    return {
        'schema': SCHEMA, 'record_id': 'DEV-SSH-0001',
        'session_id': 'DEV_TUTOR_001', 'service_id': 'SSH_DEV',
        'case_id': 'CASE_REFERENCE', 'source_kind': 'SYNTHETIC_FIXTURE',
        'method_id': 'SSH_EFFECTIVE_CONFIG_READONLY',
        'captured_at_utc': '2026-11-14T19:59:00Z',
        'configuration_sha256': 'a' * 64,
        # Independiente del código de importación: SHA-256 estándar sobre bytes literales
        'support_sha256': hashlib.sha256(CONTENT).hexdigest(),
        'support_bytes': 45,
        'observed_claim': 'INCONCLUSIVE',
    }

class DefensiveImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.support = self.root / 'support.txt'
        self.support.write_bytes(CONTENT)
        self.doc = receipt()

    def _run(self):
        raw = json.dumps(self.doc, sort_keys=True, separators=(',', ':')).encode()
        return admit_defensive_observation(self.doc, raw, self.support,
                                           as_of_utc=TIME)

    def test_independent_bytes_oracle(self):
        self.assertEqual(len(CONTENT), 45)
        self.assertEqual(self.doc['support_sha256'], hashlib.sha256(CONTENT).hexdigest())
        out = self._run()
        self.assertTrue(validate_admission(out))
        self.assertEqual(out['admission'], 'ACCEPTED_FOR_DOCUMENTARY_REVIEW')
        self.assertEqual(out['classification'], 'ND')
        self.assertFalse(out['technical_truth_accredited'])
        self.assertFalse(out['provenance_independently_attested'])
        self.assertIsNone(out['confirmed_rf'])
        self.assertEqual(out, self._run())

    def test_tampered_support_rejected(self):
        self.support.write_bytes(CONTENT[:-1] + b'X')
        with self.assertRaisesRegex(DefensiveImportError, 'support_digest_mismatch'):
            self._run()

    def test_absent_support_rejected(self):
        self.support.unlink()
        with self.assertRaisesRegex(DefensiveImportError, 'source_read_failed'):
            self._run()

    def test_out_of_scope_rejected(self):
        self.doc['service_id'] = 'FTP_DEV'
        with self.assertRaisesRegex(DefensiveImportError, 'observation_binding_mismatch'):
            self._run()

    def test_unapproved_method_rejected(self):
        self.doc['method_id'] = 'SSH_ACTIVE_EXPLOIT'
        with self.assertRaisesRegex(DefensiveImportError, 'method_not_allowed'):
            self._run()

    def test_old_observation_rejected(self):
        self.doc['captured_at_utc'] = '2026-11-12T19:59:00Z'
        with self.assertRaisesRegex(DefensiveImportError, 'capture_stale_relative_to_as_of'):
            self._run()

    def test_future_observation_rejected(self):
        self.doc['captured_at_utc'] = '2026-11-14T20:01:00Z'
        with self.assertRaisesRegex(DefensiveImportError, 'capture_in_future_relative_to_as_of'):
            self._run()

    def test_duplicate_json_keys_rejected(self):
        path = self.root / 'receipt.json'
        path.write_text('{"a":1,"a":2}', encoding='utf-8')
        with self.assertRaises(DefensiveImportError):
            read_observation(path)

    def test_duplicate_record_rejected(self):
        with self.assertRaisesRegex(DefensiveImportError, 'duplicate_record_id'):
            validate_unique_observations([self.doc, copy.deepcopy(self.doc)])

    def test_conflicting_result_rejected(self):
        other = copy.deepcopy(self.doc)
        other['record_id'] = 'DEV-SSH-0002'
        other['observed_claim'] = 'DIFF'
        with self.assertRaisesRegex(DefensiveImportError, 'conflicting_observations_require_review'):
            validate_unique_observations([self.doc, other])

    def test_report_mutation_rejected(self):
        result = self._run()
        result['technical_truth_accredited'] = True
        with self.assertRaises(DefensiveImportError):
            validate_admission(result)

    def test_symlink_support_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.support)
        raw = json.dumps(self.doc, sort_keys=True, separators=(',', ':')).encode()
        with self.assertRaisesRegex(DefensiveImportError, 'source_path_invalid'):
            admit_defensive_observation(self.doc, raw, alias, as_of_utc=TIME)

if __name__ == '__main__':
    unittest.main()
