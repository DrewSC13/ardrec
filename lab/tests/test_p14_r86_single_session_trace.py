"""R86 DEV A1-A10 event chains per typed assessment, all non-operational."""
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
import test_p14_r84_dev_acceptance_gate as fixtures
import ardrec_p14_r84_dev_acceptance_gate as r84
import ardrec_p14_r85_dev_adversarial_campaign as r85
import ardrec_p14_r86_single_session_trace as r86
from ardrec.persistence.codec import canonical,digest

@unittest.skipIf(os.geteuid()==0,'Run as a nonroot user')
class R86SingleSessionTrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs=fixtures.make_inputs()
        cls.matrix=r84.evaluate(*cls.inputs)
        cls.campaign=r85.campaign(cls.matrix,cls.inputs)
        cls.r76=cls.inputs[1]
        cls.session=copy.deepcopy(cls.inputs[2])
        cls.session.update({'r75_gen1_head':'e'*64,'presentation_count':8})
        cls.r79={'sha256':cls.session['r79_sha256'],'stage_count':10,
                 'stages':[{'algorithm':'A'+str(i)} for i in range(1,11)],
                 'a6_classification':'ND','a7_confirmed_rf':None,'p8_operational':'NO-GO'}
        cls.report=r86.project(cls.matrix,cls.campaign,cls.r76,cls.session,cls.r79)

    def test_01_counts(self):
        self.assertEqual((self.report['case_count'],self.report['stage_events']),(25,250))
    def test_02_one_session(self):
        self.assertEqual(self.report['session_count'],1)
        self.assertEqual({x['session_id'] for x in self.report['cases']},{'DEV_TUTOR_001'})
    def test_03_stage_order(self):
        for c in self.report['cases']:
            self.assertEqual([e['algorithm'] for e in c['events']],list(r86.STAGES))
    def test_04_linked_events(self):
        self.assertTrue(r86.validate_ledger(self.report))
        for row in self.report['cases']:
            self.assertEqual(row['events'][0]['prev_sha256'],row['seed_sha256'])
            self.assertEqual(row['events'][-1]['event_sha256'],row['head_sha256'])
    def test_05_no_start_or_unverified(self):
        actual={e['result'] for c in self.report['cases'] for e in c['events'] if e['algorithm']=='A5'}
        self.assertEqual(actual,{'NOT_STARTED','UNVERIFIED_DECLARATION'})
    def test_06_no_false_evidence(self):
        self.assertTrue(all(c['events'][5]['detail']['classification']=='ND' for c in self.report['cases']))
    def test_07_mathematical_interval(self):
        self.assertEqual({tuple(c['events'][6]['detail']['interval']) for c in self.report['cases']},{('1/4','7/12')})
    def test_08_no_operational_transitions(self):
        self.assertTrue(all(c['events'][7]['result']=='HOLD_NO_AUTHORITY' for c in self.report['cases']))
        self.assertTrue(all(c['events'][7]['detail']['applied_transition'] is None for c in self.report['cases']))
    def test_09_separate_models(self):
        self.assertEqual(self.report['r82_model_cases_separate'],29)
        self.assertEqual(self.report['operational_cross_population_joins'],0)
    def test_10_failure_campaign_link(self):
        self.assertEqual(self.report['negative_faults_rejected'],156)
        self.assertEqual(self.report['source_links']['r85_sha256'],self.campaign['sha256'])
    def test_11_criteria_are_not_experimental(self):
        self.assertEqual(self.report['software_dev_criteria'],13)
        self.assertEqual(self.report['external_criteria_pending'],6)
        self.assertEqual(self.report['system_functional_acceptance'],'PENDING')
        self.assertEqual(self.report['experimental_validation'],'NOT_RUN')
    def test_12_deterministic(self):
        self.assertEqual(canonical(r86.project(self.matrix,self.campaign,self.r76,self.session,self.r79)),canonical(self.report))
    def test_13_cross_session_rejected(self):
        doc=copy.deepcopy(self.r76)
        doc['candidates'][0]['a5_intent']['session_id']='OTHER_DEV_SESSION'
        with self.assertRaises(r86.R86Error):r86.project(self.matrix,self.campaign,doc,self.session,self.r79)
    def test_14_attempt_binding_rejected(self):
        doc=copy.deepcopy(self.r76)
        doc['candidates'][0]['a5_intent']['attempt_id']='FAKE'
        with self.assertRaises(r86.R86Error):r86.project(self.matrix,self.campaign,doc,self.session,self.r79)
    def test_15_duplicate_case_rejected(self):
        doc=copy.deepcopy(self.report)
        doc['cases'][1]=copy.deepcopy(doc['cases'][0])
        with self.assertRaises(r86.R86Error):r86.validate_ledger(doc)
    def test_16_swapped_stage_rejected(self):
        doc=copy.deepcopy(self.report)
        row=doc['cases'][0]
        row['events'][3],row['events'][4]=row['events'][4],row['events'][3]
        with self.assertRaises(r86.R86Error):r86.validate_ledger(doc)
    def test_17_forged_risk_even_if_rehashed_rejected(self):
        doc=copy.deepcopy(self.report)
        evt=doc['cases'][0]['events'][6]
        evt['detail']['confirmed_rf']='5/12'
        evt['event_sha256']=digest(canonical({k:v for k,v in evt.items() if k!='event_sha256'}))
        with self.assertRaises(r86.R86Error):r86.validate_ledger(doc)
    def test_18_dangling_event_rejected(self):
        doc=copy.deepcopy(self.report)
        doc['cases'][0]['events'][4]['prev_sha256']='0'*64
        with self.assertRaises(r86.R86Error):r86.validate_ledger(doc)
    def test_19_rehashed_go_rejected(self):
        doc=copy.deepcopy(self.report);doc['p8_operational']='GO'
        doc['sha256']=digest(canonical({k:v for k,v in doc.items() if k!='sha256'}))
        with self.assertRaises(r86.R86Error):r86.validate_ledger(doc)
    def test_20_changed_campaign_rejected(self):
        bad=copy.deepcopy(self.campaign);bad['faults_rejected']=155
        with self.assertRaises(r86.R86Error):r86.project(self.matrix,bad,self.r76,self.session,self.r79)
    def test_21_private_receipt_replay_and_tamper(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r86-') as d:
            dest=Path(d)/'receipt'
            with patch.object(r86,'compute',return_value=self.report):
                self.assertEqual(r86.create(dest,*([Path('/x')]*5)),self.report)
                self.assertEqual(r86.verify(dest,*([Path('/x')]*5)),self.report)
                with self.assertRaises((ValueError,OSError)):r86.create(dest,*([Path('/x')]*5))
                f=dest/'MANIFEST.json'
                f.write_bytes(f.read_bytes().replace(b'NO-GO',b'GO   '))
                with self.assertRaises(ValueError):r86.verify(dest,*([Path('/x')]*5))
    def test_22_permission_and_extra_file_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r86-') as d:
            dest=Path(d)/'receipt'
            with patch.object(r86,'compute',return_value=self.report):
                r86.create(dest,*([Path('/x')]*5))
                file=dest/'MANIFEST.json';file.chmod(0o644)
                with self.assertRaises(ValueError):r86.verify(dest,*([Path('/x')]*5))
                file.chmod(0o600)
                (dest/'injected.txt').write_text('bad')
                with self.assertRaises(r86.R86Error):r86.verify(dest,*([Path('/x')]*5))
    def test_23_no_dispatch_in_module(self):
        s=(REPO/'scripts/ardrec_p14_r86_single_session_trace.py').read_text()
        for marker in ('subprocess.run(', 'socket.connect(', 'os.system(', 'virsh ', 'systemctl ', 'sudo ', 'nft '):
            self.assertNotIn(marker,s)
    def test_24_unchanged_sources(self):
        before=(canonical(self.matrix),canonical(self.campaign),canonical(self.r76),canonical(self.session),canonical(self.r79))
        r86.project(self.matrix,self.campaign,self.r76,self.session,self.r79)
        after=(canonical(self.matrix),canonical(self.campaign),canonical(self.r76),canonical(self.session),canonical(self.r79))
        self.assertEqual(before,after)

if __name__=='__main__':unittest.main()
