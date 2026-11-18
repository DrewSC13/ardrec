"""R87 golden acceptance: deterministic oracle, explicit DEV vs experimental boundary."""
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
import ardrec_p14_r87_dev_acceptance as r87
from ardrec.persistence.codec import canonical,digest

@unittest.skipIf(os.geteuid()==0,'Requires nonroot')
class R87GoldenAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inputs=fixtures.make_inputs()
        cls.matrix=r84.evaluate(*inputs)
        cls.campaign=r85.campaign(cls.matrix,inputs)
        session=copy.deepcopy(inputs[2])
        session.update({'r75_gen1_head':'e'*64,'presentation_count':8})
        r79={'sha256':session['r79_sha256'],'stage_count':10,
             'stages':[{'algorithm':'A'+str(i)} for i in range(1,11)],
             'a6_classification':'ND','a7_confirmed_rf':None,'p8_operational':'NO-GO'}
        cls.ledger=r86.project(cls.matrix,cls.campaign,inputs[1],session,r79)
        cls.result=r87.assess(cls.ledger,cls.matrix,cls.campaign)

    def test_01_all_golden_contracts(self):
        self.assertEqual(self.result['dev_check_count'],18)
        self.assertEqual([x['id'] for x in self.result['dev_checks']],list(r87.CHECKS))
        self.assertTrue(all(x['status']=='PASS_SOFTWARE_DEV_ONLY' for x in self.result['dev_checks']))
    def test_02_unique_session(self):
        self.assertEqual(self.result['session_id'],self.ledger['single_session_id'])
    def test_03_25_assessments(self):
        self.assertEqual(len(self.result['cases']),25)
        self.assertEqual(len({x['attempt_id'] for x in self.result['cases']}),25)
    def test_04_all_250_events(self):
        self.assertEqual(self.result['stage_events_verified'],250)
        self.assertTrue(all(x['events_verified']==10 for x in self.result['cases']))
    def test_05_outcomes(self):
        self.assertEqual(sum(x['a5_review_state']=='UNVERIFIED_DECLARATION' for x in self.result['cases']),3)
        self.assertEqual(sum(x['a5_review_state']=='NOT_STARTED' for x in self.result['cases']),22)
    def test_06_risk_25_exact(self):
        self.assertEqual({tuple(x['a7_hypothetical']) for x in self.result['cases']},
                         {('1/4','5/12','7/12')})
        self.assertEqual(self.result['a7_exact_unresolved'],25)
    def test_07_model_denial_separated(self):
        self.assertEqual(self.result['a8_model_denials_separate'],29)
        self.assertEqual(self.result['authoritative_cross_population_joins'],0)
    def test_08_criteria_promotion_blocked(self):
        self.assertEqual(len(self.result['r84_software_criteria']),13)
        self.assertEqual(len(self.result['r84_external_pending']),6)
        self.assertEqual(self.result['system_functional_acceptance'],'PENDING')
        self.assertEqual(self.result['experimental_validation'],'NOT_RUN')
    def test_09_security_frozen(self):
        self.assertEqual(self.result['a6'],'ND')
        self.assertIsNone(self.result['confirmed_rf'])
        self.assertFalse(self.result['operational_dispatch'])
        self.assertEqual(self.result['physical_executions'],0)
        self.assertEqual(self.result['p8_operational'],'NO-GO')
    def test_10_source_links(self):
        self.assertEqual(self.result['source_links']['r86_sha256'],self.ledger['sha256'])
        self.assertEqual(self.result['source_links']['r84_sha256'],self.matrix['sha256'])
        self.assertEqual(self.result['source_links']['r85_sha256'],self.campaign['sha256'])
    def test_11_repeat_exact(self):
        self.assertEqual(canonical(r87.assess(self.ledger,self.matrix,self.campaign)),canonical(self.result))
    def test_12_integrity_of_report(self):
        self.assertEqual(self.result['sha256'],digest(canonical({k:v for k,v in self.result.items() if k!='sha256'})))
    def test_13_rehashed_go_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['p8_operational']='GO'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_14_rehashed_risk_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['cases'][0]['events'][6]['detail']['confirmed_rf']='5/12'
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_15_missing_stage_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['cases'][0]['events'].pop()
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_16_false_a1_stage_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['cases'][0]['events'][0]['result']='OPERATIONAL_GEN1'
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_17_wrong_a7_golden_fraction_rejected(self):
        bad=copy.deepcopy(self.ledger)
        bad['cases'][0]['events'][6]['detail']['hypothetical_e_half']='3/8'
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_18_mismatched_source_rejected(self):
        bad=copy.deepcopy(self.matrix);bad['cases'][0]['attempt_id']='FORGED'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r87.assess(self.ledger,bad,self.campaign)
    def test_19_promote_external_criterion_rejected(self):
        bad=copy.deepcopy(self.matrix);bad['criteria'][13]['result']='PASS_EXPERIMENT'
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r87.assess(self.ledger,bad,self.campaign)
    def test_20_surviving_fault_false(self):
        bad=copy.deepcopy(self.campaign);bad['faults_undetected']=1
        bad['sha256']=digest(canonical({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(ValueError):r87.assess(self.ledger,self.matrix,bad)
    def test_21_missing_case_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['cases'].pop()
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_22_duplicate_case_rejected(self):
        bad=copy.deepcopy(self.ledger);bad['cases'][1]=bad['cases'][0]
        with self.assertRaises(ValueError):r87.assess(bad,self.matrix,self.campaign)
    def test_23_readonly_private_replay(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r87-') as d:
            root=Path(d)/'receipt'
            with patch.object(r87,'compute',return_value=self.result):
                self.assertEqual(r87.create(root,*([Path('/fake')]*6)),self.result)
                self.assertEqual(r87.verify(root,*([Path('/fake')]*6)),self.result)
                with self.assertRaises(ValueError):r87.create(root,*([Path('/fake')]*6))
    def test_24_tampered_receipt_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r87-') as d:
            root=Path(d)/'receipt'
            with patch.object(r87,'compute',return_value=self.result):
                r87.create(root,*([Path('/fake')]*6))
                p=root/'MANIFEST.json';p.write_bytes(p.read_bytes()+b' ')
                with self.assertRaises(ValueError):r87.verify(root,*([Path('/fake')]*6))
    def test_25_unexpected_file_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r87-') as d:
            root=Path(d)/'receipt'
            with patch.object(r87,'compute',return_value=self.result):
                r87.create(root,*([Path('/fake')]*6))
                (root/'surprise.txt').write_text('forged')
                with self.assertRaises(ValueError):r87.verify(root,*([Path('/fake')]*6))
    def test_26_world_readable_rejected(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r87-') as d:
            root=Path(d)/'receipt'
            with patch.object(r87,'compute',return_value=self.result):
                r87.create(root,*([Path('/fake')]*6))
                (root/'MANIFEST.json').chmod(0o644)
                with self.assertRaises(ValueError):r87.verify(root,*([Path('/fake')]*6))
    def test_27_no_external_exec(self):
        s=(REPO/'scripts/ardrec_p14_r87_dev_acceptance.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'socket.connect(', 'systemctl ',
                          'virsh ', 'sudo ', 'nft ', 'gh pr merge','shell=True'):
            self.assertNotIn(forbidden,s)
    def test_28_original_inputs_unchanged(self):
        src=[canonical(x) for x in (self.ledger,self.matrix,self.campaign)]
        r87.assess(self.ledger,self.matrix,self.campaign)
        self.assertEqual(src,[canonical(x) for x in (self.ledger,self.matrix,self.campaign)])

if __name__=='__main__':unittest.main()
