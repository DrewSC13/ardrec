"""P8-R7: shared synthetic diagnostic fixtures; never authorizes execution."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from copy import deepcopy

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec import p8_diagnostic as P


class P8DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / 'tests/fixtures/p8-diagnostic-v1.json').read_text())

    def test_shared_vectors_exact_codes(self):
        self.assertEqual(self.fixture['schema_version'], '1.0')
        self.assertEqual(self.fixture['contract'], 'P8-R7')
        cases = self.fixture['cases']
        self.assertGreaterEqual(len(cases), 100)
        self.assertEqual(len(set(c['name'] for c in cases)), len(cases))
        for c in cases:
            with self.subTest(name=c['name']):
                result = P.evaluate_text(c['payload'])
                self.assertEqual(result['reason_code'], c['reason_code'])
                self.assertEqual(result['decision'], P.DENIAL)
                self.assertFalse(result['authorized'])
                self.assertFalse(result['dispatch_allowed'])
                self.assertEqual(set(result), {
                    'schema_version','message_type','decision','reason_code',
                    'authorized','dispatch_allowed'})

    def test_all_29_profiles(self):
        self.assertEqual(len(P.KNOWN_PROFILES), 29)
        fixtures = {c['name'] for c in self.fixture['cases']}
        self.assertEqual({f'profile_{i}' for i in P.KNOWN_PROFILES} & fixtures,
                         {f'profile_{i}' for i in P.KNOWN_PROFILES})

    def test_documented_contract_and_cross_language_codes(self):
        import hashlib
        import re
        contract = json.loads((ROOT / 'lab/p8-diagnostic-contract-v1/contract.json').read_text())
        trace = json.loads((ROOT / 'docs/traceability/p8-diagnostic-r7.json').read_text())
        self.assertEqual(contract['base_commit'], 'bd3500bfc7310abdbaf9bb1e57042e1c526f25d7')
        self.assertEqual(contract['shared_fixture_cases'], len(self.fixture['cases']))
        self.assertEqual(contract['frozen_profile_slots'], 29)
        self.assertFalse(contract['dispatch_allowed'])
        self.assertFalse(contract['operational_authorization'])
        self.assertEqual(contract['open_findings'], ['AL-06', 'AL-07'])
        self.assertEqual(contract['open_development_obligations'], 7)
        self.assertEqual(trace['status'], 'SOURCE_ONLY_UNMERGED')
        self.assertFalse(trace['restrictions']['dispatch_allowed'])
        rust = (ROOT / 'crates/ardrec-executor/src/p8_diagnostic.rs').read_text()
        seen = set(re.findall(r'P8_R7_[A-Z_]+', rust)) - {'P8_R7_DIAGNOSTIC_PROPOSAL', 'P8_R7_DENIAL_RESULT'}
        self.assertEqual(set(contract['deny_reason_codes']), seen)
        self.assertEqual({c['reason_code'] for c in self.fixture['cases']}, seen)
        for rel, key in [
            ('lab/verify_p8_lifecycle.py', 'upstream_r6_validator_git_blob'),
            ('lab/p8-lifecycle-v1/contract.json', 'upstream_r6_contract_git_blob'),
        ]:
            path = ROOT / rel
            if path.is_file():
                content = path.read_bytes()
                blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
                self.assertEqual(blob, contract[key])

    def test_unchanged_input(self):
        x = self.fixture['cases'][0]['payload']
        y = deepcopy(x)
        P.evaluate_text(x)
        self.assertEqual(x, y)

    def test_duplicate_full_schema(self):
        valid = self.fixture['cases'][0]['payload']
        duplicate = valid[:-1] + ',"profile_id":"SSH-T02-BASE"}'
        self.assertEqual(P.evaluate_text(duplicate)['reason_code'], 'P8_R7_INVALID_SCHEMA')

    def test_non_utf8_and_surrogate(self):
        self.assertEqual(P.evaluate_bytes(b'\xff')['reason_code'], 'P8_R7_INVALID_SCHEMA')
        self.assertEqual(P.evaluate_text('\ud800')['reason_code'], 'P8_R7_INVALID_SCHEMA')

    def test_byte_limits_and_types(self):
        for raw in [b'', b' ' * 4097, None, 42, bytearray(b'{}')]:
            with self.subTest(raw=repr(raw)[:40]):
                self.assertEqual(P.evaluate_bytes(raw)['reason_code'], 'P8_R7_INVALID_SCHEMA')

    def test_nonfinite_values_rejected(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            self.assertEqual(P.evaluate_bytes(raw)['reason_code'], 'P8_R7_INVALID_SCHEMA')

    def test_source_no_operational_imports(self):
        source = (ROOT / 'src/ardrec/p8_diagnostic.py').read_text()
        for forbidden in ('subprocess', 'Popen', 'socket.', 'os.system', 'os.exec', 'os.spawn',
                          'open(', 'eval(', 'exec('):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
