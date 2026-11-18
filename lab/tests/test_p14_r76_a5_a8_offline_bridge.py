"""R76: prueba 25 familias, R75 fuente exacta y A5-A8 conservador offline."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import ardrec_p14_r76_a5_a8_offline_bridge as r76
from ardrec.persistence.codec import canonical, digest

@unittest.skipIf(os.geteuid()==0,'R76/R75 prohíben root')
class R76Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='ardrec-r76-')
        cls.root=Path(cls.tmp.name)/'r75'
        cls.base=r76.r75.create(cls.root)
        cls.doc=r76.build(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_01_exact_25_families(self):
        d=self.doc
        self.assertEqual(d['service_family_counts'],{'SSH_DEV':8,'FTP_DEV':8,'SMB_DEV':9})
        self.assertEqual(len(d['candidates']),25)
        self.assertEqual(d['family_count'],25)
        self.assertEqual(len({x['a7_case_id'] for x in d['candidates']}),25)

    def test_02_no_promotion(self):
        d=self.doc
        self.assertEqual(d['a6_classification'],'ND')
        self.assertFalse(d['a6_technical_truth_accredited'])
        self.assertIsNone(d['a7_confirmed_rf'])
        self.assertEqual(d['physical_a5_starts_accredited'],0)
        self.assertEqual(d['a8_applied_transitions'],0)
        self.assertEqual(d['a9_new_generations'],0)
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertFalse(d['operational_dispatch'])

    def test_03_synthetic_claims_are_not_technical_truth(self):
        claims=[x for x in self.doc['candidates'] if x['declared_outcome']!='NO_START']
        self.assertEqual({x['declared_outcome'] for x in claims},
            {'OBSERVADO_POSITIVO','OBSERVADO_NEGATIVO','INCONCLUSO'})
        self.assertEqual(len(claims),3)
        for x in claims:
            self.assertEqual(x['a5_candidate']['a6_classification'],'ND')
            self.assertFalse(x['a5_candidate']['a5_physical_start_accredited'])
            self.assertFalse(x['a5_candidate']['a6_technical_truth_accredited'])
            self.assertEqual(x['claim_source'],'FIXED_SYNTHETIC_UNTRUSTED')

    def test_04_no_start_has_zero_support(self):
        rows=[x for x in self.doc['candidates'] if x['declared_outcome']=='NO_START']
        self.assertEqual(len(rows),22)
        for x in rows:
            self.assertEqual(x['support_bytes'],0)
            self.assertEqual(x['a5_candidate']['status'],'DECLARED_NO_START_NO_A5')

    def test_05_a7_full_unresolved_and_a8_stop(self):
        b=self.doc['conservative_bridge']
        self.assertTrue(r76.verify_unit_bridge(b))
        self.assertEqual(b['unit_count'],25)
        self.assertEqual(b['documentary_admission_count'],0)
        for d in b['decisions']:
            self.assertIsNone(d['confirmed_rf'])
            self.assertEqual(d['a6_classification'],'ND')
            self.assertEqual(d['a7_interval_source'],'MATHEMATICAL_ONLY_FULL_UNRESOLVED')
            self.assertEqual(d['a8_recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
            self.assertIsNone(d['a8_applied_transition'])

    def test_06_r75_link_and_sha_repeat(self):
        self.assertEqual(self.doc['r75_r70_head_sha256'],self.base['source_links']['r70_head_sha256'])
        with patch('subprocess.run',side_effect=AssertionError('R76 must not spawn subprocess')):
            self.assertEqual(canonical(r76.build(self.root)),canonical(self.doc))
            self.assertTrue(r76.verify(self.doc,self.root))

    def test_07_rehash_fake_go_rejected(self):
        bad=copy.deepcopy(self.doc)
        bad['p8_operational']='GO'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(r76.R76Error):r76.verify(bad,self.root)

    def test_08_rehash_fake_rf_rejected(self):
        bad=copy.deepcopy(self.doc)
        bad['a7_confirmed_rf']='1/2'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(r76.R76Error):r76.verify(bad,self.root)

    def test_09_rehash_false_technical_truth_rejected(self):
        bad=copy.deepcopy(self.doc)
        bad['candidates'][0]['a5_candidate']['a6_technical_truth_accredited']=True
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(r76.R76Error):r76.verify(bad,self.root)

    def test_10_candidate_duplicate_rejected(self):
        bad=copy.deepcopy(self.doc)
        bad['candidates'][1]=copy.deepcopy(bad['candidates'][0])
        with self.assertRaises(r76.R76Error):r76.verify(bad,self.root)

    def test_11_r75_tampering_rejected_before_bridge(self):
        path=self.root/'reports'/'54_units.json'
        original=path.read_bytes()
        try:
            path.write_bytes(original+b'\n')
            with self.assertRaises(ValueError):r76.build(self.root)
        finally:path.write_bytes(original)

    def test_12_cli_determinism(self):
        command=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r76_a5_a8_offline_bridge.py'),
                 '--receipt-dir',str(self.root),'--json']
        p=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=25)
        self.assertEqual(p.returncode,0,p.stderr.decode())
        self.assertEqual(p.stdout,canonical(self.doc)+b'\n')
        q=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=25)
        self.assertEqual(p.stdout,q.stdout)

    def test_13_verify_json_file_no_exec(self):
        path=Path(self.tmp.name)/'result.json'
        path.write_bytes(canonical(self.doc)+b'\n');path.chmod(0o600)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r76_a5_a8_offline_bridge.py'),
             '--receipt-dir',str(self.root),'--verify-json',str(path)]
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=25)
        self.assertEqual(p.returncode,0,p.stderr.decode())
        self.assertIn(b'PASS_VERIFIED_NO_EXECUTION',p.stdout)

    def test_14_insecure_json_file_rejected(self):
        path=Path(self.tmp.name)/'too_public.json'
        path.write_bytes(canonical(self.doc)+b'\n');path.chmod(0o644)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r76_a5_a8_offline_bridge.py'),
             '--receipt-dir',str(self.root),'--verify-json',str(path)]
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,timeout=25)
        self.assertEqual(p.returncode,23)

    def test_15_synthetic_receipt_has_no_effect_on_r75(self):
        source=canonical(self.base)
        self.assertEqual(canonical(r76.r75.verify(self.root)),source)
        self.assertFalse((self.root/'r76.json').exists())

    def test_16_source_has_no_execution_apis(self):
        raw=(ROOT/'scripts/ardrec_p14_r76_a5_a8_offline_bridge.py').read_text()
        for token in ('subprocess.run(', 'os.system(', 'shell=True', 'systemctl ',
                      'virsh ', 'sudo ', 'nft ', 'gh pr merge', 'requests.get('):
            with self.subTest(token=token):self.assertNotIn(token,raw)

if __name__=='__main__':unittest.main()
