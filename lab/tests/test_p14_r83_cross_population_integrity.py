"""R83: 25-family/29-model-case coverage crosswalk, explicit no-authority identity."""
from __future__ import annotations
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO/'scripts'))
import ardrec_p14_r83_cross_population_integrity as r83
from ardrec.persistence.codec import canonical


def samples():
    keys = [(service, f'{protocol}-T{number:02d}')
            for service,protocol,n in (('SSH_DEV','SSH',8),('FTP_DEV','FTP',8),('SMB_DEV','SMB',9))
            for number in range(1,n+1)]
    candidates=[]; families=[]; cases=[]
    for service,family in keys:
        case='CASE_'+family.replace('-','_')+'_S01_01'
        candidates.append({'service_id':service,'family_id':family,
                           'a7_case_id':case,'a6_classification':'ND',
                           'physical_start_accredited':False,
                           'a5_intent':{'assessment_index':0}})
        families.append({'service_id':service,'family_id':family,'case_id':case,
                         'a6':'ND','confirmed_rf':None,'operational_authority':False,
                         'hypothetical_rf_E0':'1/4','hypothetical_rf_Ehalf':'5/12',
                         'hypothetical_rf_E1':'7/12'})
        extras=1 if service in ('FTP_DEV','SMB_DEV') and family.endswith(('T01','T02')) else 0
        for variant in range(1+extras):
            cases.append({'service_id':service,'family_id':family,
                          'session_id':'DEV_TUTOR_001',
                          'derived_case_id':family+'-S01-01-V'+str(variant),
                          'assessment_index':0,'case_id_a7':case+'_V'+str(variant),
                          'variant':'variant_'+str(variant),
                          'logical_candidate':variant==0,
                          'review_outcome':'DENIED','state_committed':None,
                          'independent_authority_attested':False,
                          'signed_approval_attested':False,
                          'transition_commit_attested':False,
                          'current_phase':'PREPARADO'})
    cases.sort(key=lambda x:(x['service_id'],x['family_id'],x['case_id_a7']))
    assert len(cases)==29
    software={'sha256':'a'*64,'software_dev_smoke':'PASS',
              'stage_count':10,'synthetic_units':54,'family_count':25,
              'local_benign_starts':1,'a6':'ND','confirmed_rf':None,
              'a8_applied_transitions':0,'a9_new_generations':0,
              'physical_executions':0,'p8_operational':'NO-GO',
              'system_functional_acceptance':'PENDING',
              'experimental_validation':'NOT_RUN',
              'r79_sha256':'c'*64,'r76_sha256':'d'*64}
    model={'sha256':'b'*64,'r81_software_smoke_sha256':'a'*64,
           'r81_synthetic_units':54,'r81_family_count':25,'r58_model_cases':29,
           'populations_are_distinct':True,
           'model_t1_count':2,'model_t8_pause_count':1,'model_t9_resume_count':1,
           'model_t10_stop_count':1,'atomic_rollback_checks':2,
           'idempotent_replay_checks':2,'terminal_reentry_rejected':True,
           'operational_transitions_applied':0,'operational_state_mutated':False,
           'technical_truth_accredited':False,'confirmed_rf':None,'a6':'ND',
           'physical_executions':0,'p8_operational':'NO-GO',
           'system_functional_acceptance':'PENDING','experimental_validation':'NOT_RUN',
           'r58_gate_sha256':'e'*64,
           'model_cases':[cases[0]['case_id_a7'],cases[1]['case_id_a7']]}
    r76={'sha256':'d'*64,'family_count':25,'a6_classification':'ND',
         'a7_confirmed_rf':None,'physical_a5_starts_accredited':0,
         'p8_operational':'NO-GO','candidates':candidates}
    r79={'sha256':'c'*64,'stage_count':10,
         'stages':[{'algorithm':f'A{i}'} for i in range(1,11)],
         'r75_synthetic_units':54,'r78_mathematical_family_count':25,
         'family_counts':r83.FAMILY_COUNTS,'a6_classification':'ND',
         'a7_confirmed_rf':None,'a8_applied_transitions':0,
         'p8_operational':'NO-GO','families':families}
    gate={'sha256':'e'*64,'case_count':29,'family_count':25,
          'all_requests_denied':True,'transitions_applied':0,
          'state_machine_mutated':False,'independent_authority_attested':False,
          'signed_approval_attested':False,'transition_commit_attested':False,
          'confirmed_final_risk':None,'p8_operational':'NO-GO',
          'cases':cases,'request_count':8}
    return software,model,r76,r79,gate

@unittest.skipIf(os.geteuid()==0,'R83: exercise as nonroot')
class PopulationIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=samples()
        cls.report=r83.reconcile(*cls.original)
    def test_01_exact_coverage(self):
        self.assertEqual(self.report['family_catalog_coverage'],25)
        self.assertEqual(self.report['model_coverage'],29)
        self.assertEqual(len(self.report['families']),25)
    def test_02_protocol_extras(self):
        rows=self.report['families']
        self.assertEqual({p:sum(x['model_variant_count'] for x in rows if x['service_id']==p)
                          for p in r83.MODEL_COUNTS},r83.MODEL_COUNTS)
    def test_03_denied_and_no_authoritative_join(self):
        self.assertEqual(self.report['cross_population_authoritative_join_count'],0)
        self.assertTrue(all(not r['same_assessment_attested'] for r in self.report['families']))
        self.assertTrue(all(v['denied'] for r in self.report['families'] for v in r['model_cases']))
    def test_04_all_algorithms(self):
        self.assertEqual(self.report['a1_a10_stages'],[f'A{i}' for i in range(1,11)])
    def test_05_no_escalated_risk_or_authority(self):
        r=self.report
        self.assertEqual(r['a6'],'ND')
        self.assertIsNone(r['confirmed_rf'])
        self.assertEqual(r['operational_transitions_applied'],0)
        self.assertFalse(r['technical_truth_accredited'])
        self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertEqual(r['experimental_validation'],'NOT_RUN')
    def test_06_replay_pure(self):
        self.assertEqual(r83.reconcile(*self.original),self.report)
        self.assertEqual(canonical(r83.reconcile(*self.original)),canonical(self.report))
    def reject(self,idx,change):
        inputs=copy.deepcopy(self.original)
        change(inputs[idx])
        with self.assertRaises((r83.R83Error,ValueError,KeyError)):
            r83.reconcile(*inputs)
    def test_07_reject_r81_authority(self):
        for k,v in [('p8_operational','GO'),('confirmed_rf','5/12'),
                    ('physical_executions',1),('system_functional_acceptance','PASS')]:
            with self.subTest(k=k):self.reject(0,lambda d:d.__setitem__(k,v))
    def test_08_reject_r82_authority(self):
        for k,v in [('operational_transitions_applied',1),
                    ('technical_truth_accredited',True),('p8_operational','GO'),
                    ('terminal_reentry_rejected',False)]:
            with self.subTest(k=k):self.reject(1,lambda d:d.__setitem__(k,v))
    def test_09_reject_r81_r82_pin_mismatch(self):
        self.reject(1,lambda d:d.__setitem__('r81_software_smoke_sha256','0'*64))
    def test_10_reject_changed_analytic_source(self):
        self.reject(3,lambda d:d.__setitem__('sha256','f'*64))
    def test_11_reject_missing_family(self):
        self.reject(3,lambda d:d['families'].pop())
    def test_12_reject_duplicate_model_identity(self):
        self.reject(4,lambda d:d['cases'][1].update({k:d['cases'][0][k]
                    for k in ('service_id','session_id','derived_case_id','assessment_index')}))
    def test_13_reject_gate_approval(self):
        self.reject(4,lambda d:d['cases'][0].__setitem__('review_outcome','APPROVED'))
    def test_14_reject_gate_hash_drift(self):
        self.reject(4,lambda d:d.__setitem__('sha256','f'*64))
    def test_15_reject_missing_model_variant(self):
        self.reject(4,lambda d:d['cases'].pop())
    def test_16_reject_unauthorized_r76_claim(self):
        self.reject(2,lambda d:d['candidates'][0].__setitem__('a6_classification','VERDADERO'))
    def test_17_reject_out_of_scope_model_case(self):
        self.reject(4,lambda d:d['cases'][0].__setitem__('family_id','UNKNOWN-T99'))
    def test_18_no_operational_calls(self):
        source=(REPO/'scripts/ardrec_p14_r83_cross_population_integrity.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'shell=True','virsh ',
                          'systemctl ', 'sudo ', 'nft ', 'socket.connect(', 'gh pr merge'):
            self.assertNotIn(forbidden,source)
    def test_19_private_receipt_idempotence(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r83-') as tmp:
            dest=Path(tmp)/'report'
            with patch.object(r83,'compute',return_value=self.report):
                self.assertEqual(r83.create(dest,Path('/unused'),Path('/unused')),self.report)
                self.assertEqual(r83.verify(dest,Path('/unused'),Path('/unused')),self.report)
                with self.assertRaises(ValueError):r83.create(dest,Path('/unused'),Path('/unused'))
    def test_20_reject_forged_report_even_when_persisted(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r83-') as tmp:
            dest=Path(tmp)/'report'
            with patch.object(r83,'compute',return_value=self.report):
                r83.create(dest,Path('/unused'),Path('/unused'))
                file=dest/'MANIFEST.json'
                original=file.read_bytes()
                try:
                    file.write_bytes(original.replace(b'NO-GO',b'GOGOG'))
                    with self.assertRaises(ValueError):r83.verify(dest,Path('/unused'),Path('/unused'))
                finally:file.write_bytes(original)
    def test_21_no_publicly_readable_manifest(self):
        with tempfile.TemporaryDirectory(prefix='ardrec-r83-') as tmp:
            dest=Path(tmp)/'report'
            with patch.object(r83,'compute',return_value=self.report):
                r83.create(dest,Path('/unused'),Path('/unused'))
                file=dest/'MANIFEST.json'
                file.chmod(0o644)
                with self.assertRaises(ValueError):r83.verify(dest,Path('/unused'),Path('/unused'))
    def test_22_zero_external_record_authority(self):
        self.assertTrue(all(r['cross_population_join']=='CATALOG_FAMILY_ONLY'
                     for r in self.report['families']))
        self.assertEqual(sum(len(r['model_cases']) for r in self.report['families']),29)

if __name__=='__main__':unittest.main()
