"""R78: mathematical counterfactual A7 remains distinct from technical truth."""
from __future__ import annotations

import copy
from fractions import Fraction
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts'))
sys.path.insert(0,str(REPO/'src'))
import ardrec_p14_r78_a7_whatif_sensitivity as r78
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r75_integrated_demo as r75
from ardrec.analytics.exact_preview import canonical, digest

@unittest.skipIf(os.geteuid() == 0, 'R78 nonroot only')
class Counterfactual(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ardrec-r78-')
        cls.root = Path(cls.temp.name) / 'receipt'
        cls.manifest = r75.create(cls.root)
        cls.r76 = r76.build(cls.root)
        cls.report = r78.build(cls.root,cls.r76)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_01_r75_r76_integrity(self):
        self.assertEqual(self.report['r75_manifest_sha256'],self.r76['r75_manifest_sha256'])
        self.assertEqual(self.report['r76_sha256'],self.r76['sha256'])
        self.assertTrue(r76.verify(self.r76,self.root))

    def test_02_families_and_scenarios(self):
        self.assertEqual(self.report['family_count'],25)
        self.assertEqual(len(self.report['cases']),25)
        self.assertEqual(len(set(x['family_id'] for x in self.report['cases'])),25)
        self.assertEqual(set(self.report['r58d_synthetic_scenario_sha256']),{'E_0','E_HALF','E_1'})
        self.assertEqual(self.report['service_family_counts'],{'SSH_DEV':8,'FTP_DEV':8,'SMB_DEV':9})

    def test_03_exact_interval_boundary_consistency(self):
        for x in self.report['cases']:
            with self.subTest(family=x['family_id']):
                lo=Fraction(x['whatif_E_0_rf'])
                mid=Fraction(x['whatif_E_half_rf'])
                hi=Fraction(x['whatif_E_1_rf'])
                self.assertLessEqual(lo,mid)
                self.assertLessEqual(mid,hi)
                self.assertEqual(x['rf_unresolved_lower'],x['whatif_E_0_rf'])
                self.assertEqual(x['rf_unresolved_upper'],x['whatif_E_1_rf'])

    def test_04_no_evidence_promotion(self):
        self.assertEqual(self.report['a6_classification'],'ND')
        self.assertIsNone(self.report['a7_confirmed_rf'])
        self.assertFalse(self.report['r77_external_pin_provided'])
        self.assertEqual(self.report['a8_applied_transitions'],0)
        self.assertEqual(self.report['a9_new_generations'],0)
        self.assertEqual(self.report['physical_executions'],0)
        self.assertFalse(self.report['operational_dispatch'])
        self.assertEqual(self.report['p8_operational'],'NO-GO')
        for x in self.report['cases']:
            self.assertEqual(x['a6'],'ND')
            self.assertFalse(x['technical_truth_accredited'])
            self.assertIsNone(x['a7_confirmed_rf'])
            self.assertIsNone(x['a8_applied_transition'])
            self.assertFalse(x['whatif_point_is_technical_evidence'])

    def test_05_recompute_identical(self):
        self.assertEqual(canonical(self.report),canonical(r78.build(self.root,self.r76)))
        self.assertTrue(r78.verify(self.report,self.root,self.r76))

    def test_06_verifier_never_executes_a5(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('process forbidden')):
            self.assertTrue(r78.verify(self.report,self.root,self.r76))

    def test_07_rehashed_go_rejected(self):
        change=copy.deepcopy(self.report)
        change['p8_operational']='GO'; change['sha256']=digest({k:v for k,v in change.items() if k!='sha256'})
        with self.assertRaisesRegex(r78.R78Error,'NOT_REPRODUCIBLE'):
            r78.verify(change,self.root,self.r76)

    def test_08_rehashed_confirmed_risk_rejected(self):
        change=copy.deepcopy(self.report)
        change['a7_confirmed_rf']='1/2'; change['sha256']=digest({k:v for k,v in change.items() if k!='sha256'})
        with self.assertRaises(r78.R78Error):r78.verify(change,self.root,self.r76)

    def test_09_rehashed_case_simulation_rejected(self):
        change=copy.deepcopy(self.report)
        change['cases'][0]['whatif_E_half_rf']='0'
        change['sha256']=digest({k:v for k,v in change.items() if k!='sha256'})
        with self.assertRaises(r78.R78Error):r78.verify(change,self.root,self.r76)

    def test_10_forged_r76_source_rejected(self):
        change=copy.deepcopy(self.r76)
        change['p8_operational']='GO'
        change['sha256']=digest({k:v for k,v in change.items() if k!='sha256'})
        with self.assertRaises(ValueError):r78.build(self.root,change)

    def test_11_tampered_r75_refused(self):
        file=self.root/'reports'/'54_units.json'; old=file.read_bytes()
        try:
            file.write_bytes(old+b'\n')
            with self.assertRaises(ValueError):r78.build(self.root,self.r76)
        finally:file.write_bytes(old)

    def test_12_input_permutation_stability(self):
        # R76 input itself must retain exact ordering and digest; no silent remapping.
        altered=copy.deepcopy(self.r76)
        altered['candidates'].reverse()
        with self.assertRaises(ValueError):r78.build(self.root,altered)

    def test_13_cli_json_text_and_verify(self):
        parent=Path(self.temp.name)
        r76_path=parent/'r76.json'; result_path=parent/'r78.json'
        r76_path.write_bytes(canonical(self.r76)+b'\n')
        result_path.write_bytes(canonical(self.report)+b'\n')
        r76_path.chmod(0o600);result_path.chmod(0o600)
        cmd=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r78_a7_whatif_sensitivity.py'),
             '--receipt-dir',str(self.root),'--r76-report',str(r76_path)]
        out=subprocess.run(cmd+['--json'],cwd=REPO,capture_output=True,timeout=50)
        self.assertEqual(out.returncode,0,out.stderr.decode())
        self.assertEqual(out.stdout,canonical(self.report)+b'\n')
        out=subprocess.run(cmd+['--texto'],cwd=REPO,capture_output=True,timeout=50)
        self.assertEqual(out.returncode,0,out.stderr.decode())
        self.assertIn(b'25_OF_25_PASS',out.stdout)
        out=subprocess.run(cmd+['--verify-json',str(result_path)],cwd=REPO,capture_output=True,timeout=50)
        self.assertEqual(out.returncode,0,out.stderr.decode())
        self.assertIn(b'PASS_VERIFIED_NO_EXECUTION',out.stdout)

    def test_14_reject_untrusted_report_permissions(self):
        parent=Path(self.temp.name)
        public=parent/'bad.json';public.write_bytes(canonical(self.r76)+b'\n')
        public.chmod(0o644)
        with self.assertRaises(ValueError):
            r78.r77.read_canonical(public)

    def test_15_invalid_missing_fields_rejected(self):
        with self.assertRaises(ValueError):r78.build(self.root,{})

    def test_16_domain_separation(self):
        self.assertEqual(r78.SOURCE,'SYNTHETIC_MATHEMATICAL_WHAT_IF_NOT_TECHNICAL_EVIDENCE')
        self.assertEqual(self.report['scenario_evidence_source'],'SYNTHETIC_FIXED_MATHEMATICAL_ONLY')

    def test_17_no_operational_commands_in_entrypoint(self):
        code=(REPO/'scripts/ardrec_p14_r78_a7_whatif_sensitivity.py').read_text()
        for term in ('subprocess.run(', 'os.system(', 'shell=True', 'systemctl ', 'virsh ', 'sudo ', 'nft ', 'gh pr merge'):
            self.assertNotIn(term,code)

if __name__=='__main__':unittest.main()
