"""R88: integración real de módulos originales, solo fixture local DEV."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r88_vertical import (
    rust_deny_probe, run_vertical_once, verify_vertical, VerticalError, FILE,
)
from ardrec.persistence.codec import parse

FIXTURE = ROOT/'lab/p14-r26-session-v1/scenario.json'
DIAG = ROOT/'tests/fixtures/p8-diagnostic-v1.json'


@unittest.skipIf(os.geteuid() == 0, 'Store prohíbe root; ejecutar con usuario ordinario')
class R88OriginalModuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ardrec-r88-original-')
        cls.dir = Path(cls.temp.name)
        cls.durable = cls.dir/'durable'
        cls.benign = cls.dir/'benign'
        cls.fixture = read_fixed_scenario(FIXTURE)
        cls.probe = cls.dir/'deny_probe.py'
        cls.probe.write_text(f'#!{sys.executable}\n'
            'import json,sys\n'
            'from ardrec.p8_diagnostic import evaluate_bytes\n'
            'print(json.dumps(evaluate_bytes(sys.stdin.buffer.read())))\n')
        cls.probe.chmod(0o700)
        cls.pin = hashlib.sha256(cls.probe.read_bytes()).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_01_rust_contract_parity_fixture_mock_only(self):
        x = rust_deny_probe(self.probe, self.pin, DIAG)
        self.assertEqual(x['reason_code'], 'P8_R7_UNVERIFIED_AUTHORITY')
        self.assertEqual(x['identity_relation'], 'UNBOUND_DIAGNOSTIC')

    def test_02_modified_binary_rejected_before_any_write(self):
        with self.assertRaisesRegex(VerticalError, 'probe_binary_pin_mismatch'):
            run_vertical_once(self.dir/'tamper-durable',self.dir/'tamper-benign',self.fixture,
                              self.probe,'0'*64,DIAG)
        self.assertFalse((self.dir/'tamper-benign').exists())
        self.assertFalse((self.dir/'tamper-durable').exists())

    def test_03_real_original_R69_R70_R71_R38_one_start(self):
        r = run_vertical_once(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
        self.assertEqual(r['status'],'PASS_ONE_LOCAL_BENIGN_INTEGRATED')
        self.assertEqual(r['rust_gate'],'DENY_ONLY')
        self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertEqual(r['a5_new_starts'],1)
        self.assertEqual(r['record_id'],'DEV_TUTOR_001')
        self.assertEqual(len(r['r38_sha256']),64)
        doc = parse((self.benign/FILE).read_bytes())
        self.assertEqual(doc['shadow']['a7_hypothetical_rf'],'5/12')
        self.assertIsNone(doc['shadow']['a7_confirmed_rf'])
        self.assertFalse(doc['shadow']['a9_new_generation_published'])
        self.assertFalse(doc['operational_dispatch'])
        self.assertEqual(doc['physical_executions'],0)

    def test_04_reopen_never_calls_A5_again(self):
        original = (self.benign/FILE).read_bytes()
        r = run_vertical_once(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
        self.assertEqual(r['status'],'PASS_ORIGINAL_MODULES_REPLAY_NO_A5')
        self.assertEqual(r['a5_new_starts'],0)
        self.assertEqual(original,(self.benign/FILE).read_bytes())

    def test_05_verify_only_no_execution_and_external_pin(self):
        document = parse((self.benign/FILE).read_bytes())
        r = verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG,
                            expected_sha256=document['sha256'])
        self.assertEqual(r['a5_new_starts'],0)
        with self.assertRaisesRegex(VerticalError, 'external_vertical_pin_mismatch'):
            verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG,
                            expected_sha256='0'*64)

    def test_06_original_journal_corruption_rejected(self):
        artifact = next((self.benign/'artifacts').glob('*.stdout'))
        original=artifact.read_bytes()
        artifact.write_bytes(b'FORGED')
        try:
            with self.assertRaises((RuntimeError,ValueError,OSError)):
                verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
        finally:
            artifact.write_bytes(original)
        self.assertEqual(verify_vertical(self.durable,self.benign,self.fixture,
                       self.probe,self.pin,DIAG)['a5_new_starts'],0)

    def test_07_false_authorization_or_risk_rejected(self):
        p=self.benign/FILE
        original=p.read_bytes()
        for field,value in [('p8_operational','GO'),('rf_confirmed','5/12'),
                            ('physical_executions',1)]:
            data=json.loads(original)
            data[field]=value
            # Self-rehashing unauthenticated data cannot bypass semantic guard.
            from ardrec.persistence.codec import canonical,digest
            data['sha256']=digest(canonical({k:v for k,v in data.items() if k!='sha256'}))
            p.write_bytes(canonical(data))
            try:
                with self.assertRaises((VerticalError,ValueError)):
                    verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
            finally:p.write_bytes(original)

    def test_08_wrong_identity_rejected(self):
        altered=copy.deepcopy(self.fixture)
        altered['session_id']='DIFFERENT'
        with self.assertRaises((VerticalError,ValueError)):
            verify_vertical(self.durable,self.benign,altered,self.probe,self.pin,DIAG)

    def test_09_root_overlap_rejected(self):
        with self.assertRaises(ValueError):
            run_vertical_once(self.durable,self.durable,self.fixture,
                              self.probe,self.pin,DIAG)

    def test_10_source_head_persists(self):
        previous=verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
        later=verify_vertical(self.durable,self.benign,self.fixture,self.probe,self.pin,DIAG)
        self.assertEqual(previous['r70_head_sha256'],later['r70_head_sha256'])
        self.assertEqual(previous['r38_sha256'],later['r38_sha256'])


if __name__=='__main__':
    unittest.main()
