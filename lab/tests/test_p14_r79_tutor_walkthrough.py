"""R79: demostración académico-matemática A1–A10 sin ejecución ni acreditación."""
from __future__ import annotations

import copy
import json
import os
from fractions import Fraction
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
sys.path.insert(0, str(REPO/'scripts'))
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r78_a7_whatif_sensitivity as r78
import ardrec_p14_r79_tutor_walkthrough as r79
from ardrec.persistence.codec import canonical, digest

@unittest.skipIf(os.geteuid()==0, 'R79: only nonroot test user')
class R79TutorWalkthrough(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='ardrec-r79-')
        cls.root=Path(cls.temp.name)/'r75'
        cls.manifest=r75.create(cls.root)
        cls.r76=r76.build(cls.root)
        cls.r78=r78.build(cls.root,cls.r76)
        cls.r79=r79.build(cls.root,cls.r76,cls.r78)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_01_sources_recomputed(self):
        self.assertTrue(r75.verify(self.root))
        self.assertTrue(r76.verify(self.r76,self.root))
        self.assertTrue(r78.verify(self.r78,self.root,self.r76))
        self.assertTrue(r79.verify(self.r79,self.root,self.r76,self.r78))

    def test_02_exact_ten_stages(self):
        self.assertEqual([x['algorithm'] for x in self.r79['stages']],
                         [f'A{i}' for i in range(1,11)])
        self.assertEqual(self.r79['stage_count'],10)
        self.assertTrue(all(x['experimental_validation']=='NOT_RUN'
                            for x in self.r79['stages']))

    def test_03_25_families_with_counts(self):
        self.assertEqual(self.r79['r78_mathematical_family_count'],25)
        self.assertEqual(self.r79['family_counts'],
                         {'SSH_DEV':8,'FTP_DEV':8,'SMB_DEV':9})
        self.assertEqual(len(set(x['family_id'] for x in self.r79['families'])),25)

    def test_04_exact_rational_intervals(self):
        for row in self.r79['families']:
            with self.subTest(family=row['family_id']):
                lo,mid,hi=(Fraction(row[k]) for k in (
                    'hypothetical_rf_E0','hypothetical_rf_Ehalf','hypothetical_rf_E1'))
                self.assertTrue(lo<=mid<=hi)
                self.assertEqual(row['unresolved_interval'],[str(lo),str(hi)])
                self.assertIsNone(row['confirmed_rf'])

    def test_05_cross_stage_source_proofs(self):
        self.assertEqual(self.r79['source_links']['r75_gen1_head_sha256'],
                         self.r76['r75_r70_head_sha256'])
        self.assertEqual(self.r79['source_links']['r76_report_sha256'],self.r76['sha256'])
        self.assertEqual(self.r79['source_links']['r78_report_sha256'],self.r78['sha256'])
        self.assertEqual(self.r79['r75_local_benign_starts'],1)
        self.assertEqual(self.r79['r75_synthetic_units'],54)
        self.assertEqual(self.r79['r76_unverified_claims'],3)
        self.assertEqual(self.r79['r76_declared_nonstarts'],22)

    def test_06_no_authority_promoted(self):
        self.assertEqual(self.r79['a6_classification'],'ND')
        self.assertIsNone(self.r79['a7_confirmed_rf'])
        self.assertEqual(self.r79['a8_applied_transitions'],0)
        self.assertEqual(self.r79['a9_new_generations'],0)
        self.assertEqual(self.r79['physical_executions'],0)
        self.assertFalse(self.r79['operational_dispatch'])
        self.assertEqual(self.r79['p8_operational'],'NO-GO')
        self.assertFalse(self.r79['r77_external_registry_pin_provided'])
        self.assertFalse(self.r79['r77_external_independent_witness_attested'])
        self.assertEqual(self.r79['experimental_validation'],'NOT_RUN')

    def test_07_replay_exact(self):
        twice=r79.build(self.root,self.r76,self.r78)
        self.assertEqual(canonical(twice),canonical(self.r79))
        self.assertEqual(twice['sha256'],self.r79['sha256'])

    def test_08_verify_without_subprocess(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_CHILD_PROCESS')):
            self.assertTrue(r79.verify(self.r79,self.root,self.r76,self.r78))

    def test_09_forged_p8_and_risk_rejected_even_when_rehashed(self):
        for field,value in (('p8_operational','GO'),('a7_confirmed_rf','5/12'),
                            ('physical_executions',1),('a9_new_generations',1)):
            with self.subTest(field=field):
                bad=copy.deepcopy(self.r79)
                bad[field]=value
                bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
                with self.assertRaisesRegex(r79.R79Error,'NOT_REPRODUCIBLE'):
                    r79.verify(bad,self.root,self.r76,self.r78)

    def test_10_fake_interval_rejected(self):
        bad=copy.deepcopy(self.r79)
        bad['families'][0]['hypothetical_rf_Ehalf']='99'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(r79.R79Error):
            r79.verify(bad,self.root,self.r76,self.r78)

    def test_11_forged_r78_source_rejected(self):
        bad=copy.deepcopy(self.r78)
        bad['r77_external_pin_provided']=True
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r79.build(self.root,self.r76,bad)

    def test_12_forged_r76_source_rejected(self):
        bad=copy.deepcopy(self.r76)
        bad['a6_classification']='VERDADERO'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r79.build(self.root,bad,self.r78)

    def test_13_modified_r75_receipt_rejected(self):
        file=self.root/'reports'/'54_units.json'
        before=file.read_bytes()
        try:
            file.write_bytes(before+b'\n')
            with self.assertRaises(ValueError):
                r79.build(self.root,self.r76,self.r78)
        finally:
            file.write_bytes(before)

    def test_14_text_has_10_stages_and_all_families(self):
        shown=r79.render_text(self.r79)
        self.assertIn('NO EXPERIMENTO',shown)
        self.assertIn('RF_CONFIRMADO=NULL',shown)
        for i in range(1,11):self.assertIn(f'A{i}',shown)
        for f in self.r79['families']:self.assertIn(f['family_id'],shown)

    def test_15_cli_json_text_verify(self):
        parent=Path(self.temp.name)
        inputs={
            'r76.json':self.r76,
            'r78.json':self.r78,
            'r79.json':self.r79,
        }
        for name,doc in inputs.items():
            f=parent/name
            f.write_bytes(canonical(doc)+b'\n')
            f.chmod(0o600)
        cmd=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r79_tutor_walkthrough.py'),
             '--receipt-dir',str(self.root),'--r76-report',str(parent/'r76.json'),
             '--r78-report',str(parent/'r78.json')]
        for mode in (['--json'],['--texto'],['--verify-json',str(parent/'r79.json')]):
            with self.subTest(mode=mode[0]):
                out=subprocess.run(cmd+mode,cwd=REPO,capture_output=True,timeout=70)
                self.assertEqual(out.returncode,0,out.stderr.decode())
                if mode[0]=='--json':self.assertEqual(out.stdout,canonical(self.r79)+b'\n')
                elif mode[0]=='--texto':self.assertIn(b'R79=PASS_DERIVED_READONLY',out.stdout)
                else:self.assertIn(b'PASS_VERIFIED_NO_EXECUTION',out.stdout)

    def test_16_public_source_file_rejected(self):
        root=Path(self.temp.name)
        file=root/'r76_untrusted.json'
        file.write_bytes(canonical(self.r76)+b'\n')
        file.chmod(0o644)
        with self.assertRaises(ValueError):r79.r77.read_canonical(file)

    def test_17_no_operational_calls(self):
        source=(REPO/'scripts/ardrec_p14_r79_tutor_walkthrough.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'shell=True',
                          'systemctl ', 'virsh ', 'sudo ', 'nft ', 'gh pr merge'):
            self.assertNotIn(forbidden,source)

    def test_18_manifest_crypto_is_not_technical_attestation(self):
        self.assertIn('SYNTHETIC',self.r79['source_kind'])
        self.assertEqual(self.r79['system_functional_acceptance'],'PENDING')
        self.assertEqual(self.r79['r77_external_registry_pin_provided'],False)
        self.assertEqual(self.r79['r77_external_independent_witness_attested'],False)

if __name__=='__main__':unittest.main()
