"""R85: adversarial DEV gate stress tests; fail-closed, synthetic only."""
from __future__ import annotations
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO/'scripts'))
sys.path.insert(0,str(REPO/'lab/tests'))
from ardrec.persistence.codec import canonical,digest
import test_p14_r84_dev_acceptance_gate as fixtures
import ardrec_p14_r84_dev_acceptance_gate as r84
import ardrec_p14_r85_dev_adversarial_campaign as r85

@unittest.skipIf(os.geteuid()==0,'Tests require unprivileged user')
class R85AdversarialDevCampaign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=fixtures.make_inputs()
        cls.baseline=r84.evaluate(*cls.inputs)
        cls.report=r85.campaign(cls.baseline,cls.inputs)

    def test_01_exact_156_fail_closed_probes(self):
        self.assertEqual(self.report['fault_count'],156)
        self.assertEqual(self.report['faults_rejected'],156)
        self.assertEqual(self.report['faults_undetected'],0)

    def test_02_coverage_categories(self):
        self.assertEqual(self.report['fault_groups'],r85.EXPECTED)
        self.assertEqual(sum(self.report['fault_groups'].values()),156)

    def test_03_every_fault_has_guard(self):
        self.assertEqual(len(self.report['faults']),156)
        self.assertTrue(all(x['guard'] and x['result']=='REJECTED_BY_R84'
                            for x in self.report['faults']))

    def test_04_source_baseline_was_not_modified(self):
        self.assertEqual(self.baseline,r84.evaluate(*self.inputs))
        self.assertEqual(self.report['r84_report_sha256'],self.baseline['sha256'])

    def test_05_reproducible(self):
        again=r85.campaign(self.baseline,self.inputs)
        self.assertEqual(canonical(self.report),canonical(again))

    def test_06_family_coverage(self):
        for group in ('A5_BINDING','A6_FALSE_ADMISSION','A7_FALSE_RF','A7_OUT_OF_RANGE'):
            actual={x['target'] for x in self.report['faults'] if x['group']==group}
            expected={x['family_id'] for x in self.baseline['cases']}
            self.assertEqual(actual,expected)

    def test_07_a8_29_model_variants(self):
        rows=[x for x in self.report['faults'] if x['group']=='A8_FALSE_APPROVAL']
        self.assertEqual(len(rows),29)
        self.assertTrue(all(type(x['model_variant']) is int for x in rows))

    def test_08_no_authority_promotion(self):
        d=self.report
        self.assertEqual(d['a6_classification'],'ND')
        self.assertIsNone(d['a7_confirmed_rf'])
        self.assertEqual(d['a8_operational_transitions'],0)
        self.assertFalse(d['operational_dispatch'])
        self.assertEqual(d['physical_executions'],0)
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertEqual(d['system_functional_acceptance'],'PENDING')
        self.assertEqual(d['experimental_validation'],'NOT_RUN')

    def test_09_not_full_functional_acceptance(self):
        self.assertEqual(self.report['software_criteria_pass_dev_only'],13)
        self.assertEqual(self.report['external_criteria_pending'],6)
        self.assertEqual(self.report['operational_cross_population_joins'],0)

    def test_10_reject_forged_r84_baseline(self):
        bad=copy.deepcopy(self.baseline)
        bad['p8_operational']='GO'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(r85.R85Error):r85.campaign(bad,self.inputs)

    def test_11_reject_changed_criterion(self):
        bad=copy.deepcopy(self.baseline)
        bad['criteria'][0]['result']='PASS_EXPERIMENTAL'
        with self.assertRaises(r85.R85Error):r85.campaign(bad,self.inputs)

    def test_12_reject_incomplete_fault_plan(self):
        with patch.object(r85,'_tasks',return_value=iter(())):
            with self.assertRaisesRegex(r85.R85Error,'INCOMPLETE_FAULT'):
                r85.campaign(self.baseline,self.inputs)

    def test_13_surviving_mutation_is_fatal(self):
        with patch.object(r85,'_mutate',side_effect=lambda docs,task:(docs[0].__setitem__('unvalidated_extension','FORGED'),r85._rehash(docs[0]))):
            with self.assertRaisesRegex(r85.R85Error,'UNDETECTED_MUTATION'):
                # Force a mutation invisible to R84's core gate to verify that
                # the harness detects a surviving logical perturbation.
                r85.campaign(self.baseline,self.inputs)

    def test_14_vacuous_mutation_is_fatal(self):
        with patch.object(r85,'_mutate',return_value=None):
            with self.assertRaisesRegex(r85.R85Error,'VACUOUS_MUTATION'):
                r85.campaign(self.baseline,self.inputs)

    def test_15_receipt_replay(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r85-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r85,'compute',return_value=self.report):
                self.assertEqual(r85.create(target,Path('/x'),Path('/y'),Path('/z'),Path('/w')),self.report)
                self.assertEqual(r85.verify(target,Path('/x'),Path('/y'),Path('/z'),Path('/w')),self.report)
                with self.assertRaises((ValueError,OSError)):
                    r85.create(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))

    def test_16_mutated_receipt_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r85-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r85,'compute',return_value=self.report):
                r85.create(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))
                p=target/'MANIFEST.json'
                p.write_bytes(p.read_bytes().replace(b'NO-GO',b'GO   '))
                with self.assertRaises(ValueError):
                    r85.verify(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))

    def test_17_unsafe_file_permissions_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r85-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r85,'compute',return_value=self.report):
                r85.create(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))
                (target/'MANIFEST.json').chmod(0o644)
                with self.assertRaises(ValueError):
                    r85.verify(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))

    def test_18_unexpected_receipt_file_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r85-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r85,'compute',return_value=self.report):
                r85.create(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))
                (target/'extra.txt').write_text('FORGED')
                with self.assertRaisesRegex(r85.R85Error,'FILESET'):
                    r85.verify(target,Path('/x'),Path('/y'),Path('/z'),Path('/w'))

    def test_19_no_host_or_subprocess_calls(self):
        source=(REPO/'scripts/ardrec_p14_r85_dev_adversarial_campaign.py').read_text()
        for bad in ('subprocess.run(', 'os.system(', 'socket.connect(', 'shell=True',
                    'virsh ', 'systemctl ', 'sudo ', 'nft ', 'gh pr merge'):
            self.assertNotIn(bad,source)

    def test_20_sha_canonical(self):
        self.assertEqual(self.report['sha256'],digest(canonical({k:v for k,v in self.report.items() if k!='sha256'})))

if __name__=='__main__':unittest.main()
