"""R84: conservative DEV-only A5-A8 acceptance matrix and fail-closed replay."""
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
import test_p14_r83_cross_population_integrity as fixtures
import ardrec_p14_r83_cross_population_integrity as r83
import ardrec_p14_r84_dev_acceptance_gate as r84
from ardrec.persistence.codec import canonical,digest


def make_inputs():
    software,model,r76,r79,gate=copy.deepcopy(fixtures.samples())
    software['r76_sha256']=r76['sha256']
    model['r58_denied_operational_requests']=gate['request_count']
    r76.update(synthetic_unverified_claim_count=3,synthetic_declared_nonstart_count=22,
               operational_dispatch=False)
    for idx,c in enumerate(r76['candidates']):
        intent={
            'session_id':'DEV_TUTOR_001', 'service_id':c['service_id'],
            'family_id':c['family_id'],
            'derived_case_id':c['family_id']+'-S01-01',
            'assessment_index':0,'attempt_id':'ATT_R84_'+c['family_id'],
            'configuration_sha256':'f'*64,'method_id':'METHOD_DEV',
            'sha256':f'{idx+1:064x}',
        }
        outcome=('OBSERVADO_POSITIVO' if idx==0 else
                 'OBSERVADO_NEGATIVO' if idx==1 else
                 'INCONCLUSO' if idx==2 else 'NO_START')
        c['declared_outcome']=outcome
        c['derived_case_id']=intent['derived_case_id']
        c['a5_intent']=intent
        c['a5_candidate']={
            'intent':copy.deepcopy(intent),
            'receipt':{'intent_sha256':intent['sha256'],'declared_outcome':outcome},
            'a5_physical_start_accredited':False,
            'a5_case_binding_independently_attested':False,
            'a6_classification':'ND','a6_technical_truth_accredited':False,
            'a7_confirmed_rf':None,'p8_operational':'NO-GO',
            'operational_dispatch':False,
        }
    r83_report=r83.reconcile(software,model,r76,r79,gate)
    return r83_report,r76,software,model

@unittest.skipIf(os.geteuid()==0,'Run R84 tests as nonroot')
class R84DevAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input=make_inputs()
        cls.report=r84.evaluate(*cls.input)

    def test_01_exact_counts(self):
        self.assertEqual(self.report['case_count'],25)
        self.assertEqual(self.report['model_variant_denials'],29)
        self.assertEqual(self.report['unverified_declarations'],3)
        self.assertEqual(self.report['no_start_count'],22)

    def test_02_exact_per_protocol(self):
        self.assertEqual({s:sum(x['service_id']==s for x in self.report['cases'])
                          for s in r84.CASE_COUNTS},r84.CASE_COUNTS)

    def test_03_criteria_matrix(self):
        r=self.report
        self.assertEqual(r['software_contract_count'],13)
        self.assertEqual(r['independent_acceptance_pending_count'],6)
        self.assertEqual([x['criterion'] for x in r['criteria']],
                         list(r84.SOFTWARE)+list(r84.EXPERIMENTAL))
        self.assertTrue(all(x['result']=='PASS_DEV_CONTRACT_ONLY'
                            for x in r['criteria'][:13]))
        self.assertTrue(all(x['result']=='PENDING_EXTERNAL_ATTESTATION'
                            for x in r['criteria'][13:]))

    def test_04_stage_order(self):
        self.assertEqual(self.report['a1_a10_stages'],[f'A{i}' for i in range(1,11)])

    def test_05_typed_identity(self):
        ids={(x['service_id'],x['derived_case_id'],x['assessment_index'],x['attempt_id'])
             for x in self.report['cases']}
        self.assertEqual(len(ids),25)
        self.assertTrue(all(x['intent_sha256'] for x in self.report['cases']))

    def test_06_conservative_a6(self):
        self.assertTrue(all(x['a6_admission']=='NOT_ADMITTED' and
                            x['a6_classification']=='ND' and
                            x['independent_technical_evidence'] is False
                            for x in self.report['cases']))

    def test_07_exact_math(self):
        self.assertEqual({tuple(x['a7_uncertainty_interval'])
                          for x in self.report['cases']},{('1/4','7/12')})
        self.assertTrue(all(x['a7_hypothetical_midpoint']=='5/12' and
                            x['a7_confirmed_rf'] is None
                            for x in self.report['cases']))

    def test_08_a8_no_mutations(self):
        self.assertTrue(all(x['a8_decision']=='HOLD_NO_AUTHORITY' and
                            x['a8_operational_transition'] is None and
                            x['same_assessment_as_model'] is False
                            for x in self.report['cases']))
        self.assertEqual(sum(x['a8_model_variants_denied'] for x in self.report['cases']),29)

    def test_09_no_false_acceptance(self):
        r=self.report
        self.assertEqual(r['system_functional_acceptance'],'PENDING')
        self.assertEqual(r['experimental_validation'],'NOT_RUN')
        self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertIsNone(r['a7_confirmed_rf'])
        self.assertEqual(r['physical_executions'],0)

    def test_10_replay_exact(self):
        self.assertEqual(canonical(r84.evaluate(*self.input)),canonical(self.report))

    def fail_if(self,n,update):
        things=copy.deepcopy(self.input)
        update(things[n])
        with self.assertRaises((ValueError,KeyError,TypeError)):
            r84.evaluate(*things)

    def test_11_reject_forged_r83_go(self):
        self.fail_if(0,lambda x:x.__setitem__('p8_operational','GO'))

    def test_12_reject_rehashed_crosswalk_go(self):
        def alter(x):
            x['p8_operational']='GO'
            x['sha256']=digest(canonical({k:v for k,v in x.items() if k!='sha256'}))
        self.fail_if(0,alter)

    def test_13_reject_rehashed_authoritative_join(self):
        def alter(x):
            x['cross_population_authoritative_join_count']=1
            x['sha256']=digest(canonical({k:v for k,v in x.items() if k!='sha256'}))
        self.fail_if(0,alter)

    def test_14_reject_r81_mismatch(self):
        self.fail_if(2,lambda x:x.__setitem__('sha256','0'*64))

    def test_15_reject_r82_operational_transition(self):
        self.fail_if(3,lambda x:x.__setitem__('operational_transitions_applied',1))

    def test_16_reject_duplicate_intent(self):
        self.fail_if(1,lambda x:x['candidates'][1]['a5_intent'].__setitem__(
            'attempt_id',x['candidates'][0]['a5_intent']['attempt_id']))
        # More direct duplicate identity can share the same full case.
        self.fail_if(1,lambda x:x['candidates'][1].update(
            a5_intent=copy.deepcopy(x['candidates'][0]['a5_intent'])))

    def test_17_reject_fake_a6_evidence(self):
        self.fail_if(1,lambda x:x['candidates'][0]['a5_candidate'].__setitem__(
            'a6_technical_truth_accredited',True))

    def test_18_reject_fake_confirmed_rf(self):
        self.fail_if(1,lambda x:x['candidates'][0]['a5_candidate'].__setitem__(
            'a7_confirmed_rf','5/12'))

    def test_19_reject_interval_outside_unit_domain(self):
        def alter(x):
            x['families'][0]['r79_hypothetical_Ehalf']='9/8'
            x['sha256']=digest(canonical({k:v for k,v in x.items() if k!='sha256'}))
        self.fail_if(0,alter)

    def test_20_reject_extra_model_approvals(self):
        def alter(x):
            x['families'][0]['model_cases'][0]['denied']=False
            x['sha256']=digest(canonical({k:v for k,v in x.items() if k!='sha256'}))
        self.fail_if(0,alter)

    def test_21_receipt_replay_and_no_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r84-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r84,'compute',return_value=self.report):
                self.assertEqual(r84.create(target,Path('/x'),Path('/y'),Path('/z')),self.report)
                self.assertEqual(r84.verify(target,Path('/x'),Path('/y'),Path('/z')),self.report)
                with self.assertRaises((OSError,ValueError)):
                    r84.create(target,Path('/x'),Path('/y'),Path('/z'))

    def test_22_reject_modified_receipt(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r84-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r84,'compute',return_value=self.report):
                r84.create(target,Path('/x'),Path('/y'),Path('/z'))
                path=target/'MANIFEST.json'
                path.write_bytes(path.read_bytes().replace(b'NO-GO',b'GOGOG'))
                with self.assertRaises(ValueError):
                    r84.verify(target,Path('/x'),Path('/y'),Path('/z'))

    def test_23_reject_unsafe_permissions(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r84-') as tmp:
            target=Path(tmp)/'receipt'
            with patch.object(r84,'compute',return_value=self.report):
                r84.create(target,Path('/x'),Path('/y'),Path('/z'))
                (target/'MANIFEST.json').chmod(0o644)
                with self.assertRaises(ValueError):
                    r84.verify(target,Path('/x'),Path('/y'),Path('/z'))

    def test_24_no_process_network_or_host_calls(self):
        source=(REPO/'scripts/ardrec_p14_r84_dev_acceptance_gate.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'shell=True',
                          'virsh ', 'systemctl ', 'sudo ', 'nft ',
                          'socket.connect(', 'gh pr merge'):
            self.assertNotIn(forbidden,source)

    def test_25_source_set_includes_all_4(self):
        self.assertEqual(set(self.report['source_links']),
                         {'r83_sha256','r81_sha256','r82_sha256','r76_sha256'})

if __name__=='__main__':unittest.main()
