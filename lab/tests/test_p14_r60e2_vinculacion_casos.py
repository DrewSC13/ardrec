"""R60-E2 offline: comprehensive fail-closed per-case model joining tests."""
from __future__ import annotations
import copy
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[2] / 'scripts/ardrec_p14_r60e2_vinculacion_casos.py'
spec=importlib.util.spec_from_file_location('r60e2',PATH)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
SHA=lambda c: c*64


def fixture():
    samples=[]
    for service,protocol,count in (('SSH_DEV','SSH',8),('FTP_DEV','FTP',10),('SMB_DEV','SMB',11)):
        for idx in range(count):
            # 25 unique families with 4 additional legitimate variant model rows.
            if protocol=='FTP':
                families=['FTP-T01','FTP-T02','FTP-T02','FTP-T03','FTP-T04','FTP-T05','FTP-T06','FTP-T07','FTP-T08','FTP-T08']
                variants={1:'CONTROL',2:'DATA',8:'READ',9:'WRITE'}
            elif protocol=='SMB':
                families=['SMB-T01','SMB-T02','SMB-T03','SMB-T03','SMB-T04','SMB-T05','SMB-T06','SMB-T07','SMB-T08','SMB-T09','SMB-T09']
                variants={2:'SIGNING',3:'ENCRYPTION',9:'READ',10:'WRITE'}
            else:
                families=[f'SSH-T{i:02d}' for i in range(1,9)]
                variants={}
            fid=families[idx]
            samples.append({'service_id':service,'session_id':'DEV_TUTOR_001',
                  'derived_case_id':f'{fid}-S01-{idx+1:02}',
                  'assessment_index':0,'family_id':fid,'variant':variants.get(idx),
                  'case_id_a7':'CASE_'+SHA('A')[:48], 'a6_classification':'ND',
                  'technical_truth_accredited':False,'confirmed_rf':None,
                  'published_generation':None,'applied_transition':None,
                  'a7_rf_lower':'1/4','a7_rf_upper':'1',
                  'a8_recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
                  'hypothetical_result_class':'INCONCLUSO'})
    for i,row in enumerate(samples):row['case_id_a7']='CASE_'+format(i+1,'048X')
    selected={x:samples[0][x] for x in ('service_id','session_id','derived_case_id','assessment_index')}
    rrows=[]
    for row in samples:
        rrows.append({**row,'a4_selected_simulated':m.case_key(row)==m.case_key(selected),
                      'a5_history_is_synthetic':False,
                      'a6_hypothetical_result':'INCONCLUSO'})
    prior={'schema':'ardrec-r60e1r2-e0-log-reconciliation-v1',
           'p8_operational':'NO-GO','host_mutations':0,'vm_start_requests':0,'nft_writes':0,
           'integration':{'model_demo_case_count':29,'model_case_capacity':54,
               'remaining_capacity_not_demonstrated':25,'families_in_demos':25,
               'ten_stage_trace_present':True,'per_case_cross_contract_identity_attested':False,
               'p8_operational':'NO-GO',
               'source_summaries':{'R58K':{'case_count':29,'families':25,'sha256':SHA('a')},
                                   'R58V':{'case_count':29,'families':25,'sha256':SHA('b')},
                                   'R58O':{'case_count':29,'families':25,'stage_count':10,
                                           'case_binding_attested':False,
                                           'sha256':SHA('c'),'stage_head_sha256':SHA('d')}}}}
    review={'unified':{'sha256':SHA('a'),'source_catalog_sha256':SHA('1'),
                       'decisions':samples},
            'session_id':'DEV_TUTOR_001','source_catalog_sha256':SHA('1'),
            'source_thesis_sha256':SHA('2'),'unit_count':29,'covered_family_count':25,
            'count_by_service':{'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11},
            'a4_operational_selection':None,'a6_classification':'ND',
            'technical_truth_accredited':False,'confirmed_final_risk':None,
            'applied_state_transition':None,'published_generation':None,
            'operational_dispatch':False,'p8_operational':'NO-GO',
            'a5':{'actual_attempts_started':0,'actual_attempt_reservations':0},
            'a4_selected_identity':selected,'decisions':rrows,'sha256':SHA('3')}
    scenario={'session_id':'DEV_TUTOR_001','services':[
        {'id':'SSH_DEV','protocol':'SSH','fact':'VERDADERO'},
        {'id':'FTP_DEV','protocol':'FTP','fact':'AUSENTE'},
        {'id':'SMB_DEV','protocol':'SMB','fact':'FALSO'}]}
    return prior,review,scenario

class Checks(unittest.TestCase):
    def good(self,p=None,r=None,s=None):
        a,b,c=fixture()
        return m.build_ledger(a if p is None else p,b if r is None else r,
                              c if s is None else s,session_sha256=SHA('f'))
    def assert_rejected(self,edit,target='review'):
        p,r,s=fixture()
        val={'prior':p,'review':r,'scenario':s}[target]
        edit(val)
        with self.assertRaises(m.Blocked):
            m.build_ledger(p,r,s,session_sha256=SHA('f'))
    def test_01_valid(self):
        d=self.good()
        self.assertEqual(len(d['case_rows']),29)
        self.assertEqual(d['covered_family_count'],25)
        self.assertEqual(d['ten_stage_count'],10)
        self.assertEqual(sum(x['a4_selected_simulated'] for x in d['case_rows']),1)
    def test_02_deterministic(self): self.assertEqual(self.good(),self.good())
    def test_03_29_not_54(self):
        d=self.good();self.assertEqual(d['missing_authentic_case_definitions'],25)
    def test_04_model_truth_false(self):
        d=self.good();self.assertFalse(d['a1_a3_to_a4_a8_operational_identity_attested'])
    def test_05_a5_no_start(self): self.assertEqual(self.good()['a5_physical_attempts'],0)
    def test_06_a6_nd(self): self.assertEqual(self.good()['a6_classification'],'ND')
    def test_07_a9_not_published(self): self.assertIsNone(self.good()['a9_published_generation'])
    def test_08_p8_nogo(self): self.assertEqual(self.good()['p8_operational'],'NO-GO')
    def test_09_no_vm(self): self.assertEqual(self.good()['vm_start_requests'],0)
    def test_10_hash(self):
        d=self.good();self.assertEqual(d['sha256'],m.digest(m.canonical({k:v for k,v in d.items() if k!='sha256'})))
    def test_11_prior_wrong_mode(self):self.assert_rejected(lambda p:p.update(schema='evil'),'prior')
    def test_12_prior_p8_go(self):self.assert_rejected(lambda p:p.update(p8_operational='GO'),'prior')
    def test_13_prior_cases_54(self):self.assert_rejected(lambda p:p['integration'].update(model_demo_case_count=54),'prior')
    def test_14_prior_family_drift(self):self.assert_rejected(lambda p:p['integration'].update(families_in_demos=24),'prior')
    def test_15_prior_authority(self):self.assert_rejected(lambda p:p['integration'].update(per_case_cross_contract_identity_attested=True),'prior')
    def test_16_prior_mutated_host(self):self.assert_rejected(lambda p:p.update(host_mutations=1),'prior')
    def test_17_prior_vm_start(self):self.assert_rejected(lambda p:p.update(vm_start_requests=1),'prior')
    def test_18_prior_nft_write(self):self.assert_rejected(lambda p:p.update(nft_writes=1),'prior')
    def test_19_prior_source_sha(self):self.assert_rejected(lambda p:p['integration']['source_summaries']['R58K'].update(sha256=SHA('0')),'prior')
    def test_20_prior_v_case_count(self):self.assert_rejected(lambda p:p['integration']['source_summaries']['R58V'].update(case_count=54),'prior')
    def test_21_prior_o_stage_count(self):self.assert_rejected(lambda p:p['integration']['source_summaries']['R58O'].update(stage_count=11),'prior')
    def test_22_prior_o_claim(self):self.assert_rejected(lambda p:p['integration']['source_summaries']['R58O'].update(case_binding_attested=True),'prior')
    def test_23_wrong_review_sha(self):self.assert_rejected(lambda r:r['unified'].update(sha256=SHA('2')))
    def test_24_review_missing(self):self.assert_rejected(lambda r:r['decisions'].pop())
    def test_25_review_extra(self):self.assert_rejected(lambda r:r['decisions'].append(copy.deepcopy(r['decisions'][0])))
    def test_26_k_missing(self):self.assert_rejected(lambda r:r['unified']['decisions'].pop())
    def test_27_k_duplicate(self):self.assert_rejected(lambda r:r['unified']['decisions'][1].update(derived_case_id=r['unified']['decisions'][0]['derived_case_id'],service_id=r['unified']['decisions'][0]['service_id']))
    def test_28_l_duplicate(self):self.assert_rejected(lambda r:r['decisions'][1].update(derived_case_id=r['decisions'][0]['derived_case_id'],service_id=r['decisions'][0]['service_id']))
    def test_29_family_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(family_id='SMB-T01'))
    def test_30_variant_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(variant='BAD'))
    def test_31_a7_case_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(case_id_a7='CASE_OTHER'))
    def test_32_a7_lower_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(a7_rf_lower='0'))
    def test_33_a7_upper_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(a7_rf_upper='0'))
    def test_34_a8_wrong(self):self.assert_rejected(lambda r:r['decisions'][0].update(a8_recommendation='CONTINUAR'))
    def test_35_k_a6_positive(self):self.assert_rejected(lambda r:r['unified']['decisions'][0].update(a6_classification='POSITIVO_VALIDO'))
    def test_36_l_a6_positive(self):self.assert_rejected(lambda r:r['decisions'][0].update(a6_classification='POSITIVO_VALIDO'))
    def test_37_false_rf(self):self.assert_rejected(lambda r:r['decisions'][0].update(confirmed_rf='1/4'))
    def test_38_false_a9(self):self.assert_rejected(lambda r:r['decisions'][0].update(published_generation='G1'))
    def test_39_false_transition(self):self.assert_rejected(lambda r:r['decisions'][0].update(applied_transition='ACTIVO'))
    def test_40_wrong_selected(self):self.assert_rejected(lambda r:r['decisions'][0].update(a4_selected_simulated=False))
    def test_41_multiple_selected(self):self.assert_rejected(lambda r:r['decisions'][1].update(a4_selected_simulated=True))
    def test_42_false_a5(self):self.assert_rejected(lambda r:r['a5'].update(actual_attempts_started=1))
    def test_43_false_a4(self):self.assert_rejected(lambda r:r.update(a4_operational_selection='FTP-T01'))
    def test_44_false_dispatch(self):self.assert_rejected(lambda r:r.update(operational_dispatch=True))
    def test_45_wrong_service(self):self.assert_rejected(lambda s:s['services'][0].update(id='FTP_DEV'),'scenario')
    def test_46_wrong_protocol(self):self.assert_rejected(lambda s:s['services'][0].update(protocol='SMB'),'scenario')
    def test_47_wrong_session(self):self.assert_rejected(lambda s:s.update(session_id='A_NEW_SESSION'),'scenario')
    def test_48_dup_key(self):
        with self.assertRaises(m.Blocked):m.strict_json(b'{"a":1,"a":2}')
    def test_49_nan(self):
        with self.assertRaises(m.Blocked):m.strict_json(b'{"a":NaN}')
    def test_50_bool_index(self):self.assert_rejected(lambda r:r['decisions'][0].update(assessment_index=True))
    def test_51_no_model_p8(self):self.assert_rejected(lambda r:r.update(p8_operational='GO'))
    def test_52_fake_technical_truth(self):self.assert_rejected(lambda r:r.update(technical_truth_accredited=True))
    def test_53_review_families_24(self):self.assert_rejected(lambda r:r.update(covered_family_count=24))
    def test_54_prior_summaries_extra(self):self.assert_rejected(lambda p:p['integration']['source_summaries'].update(evil={}),'prior')
    def test_55_a6_hypothesis_mismatch(self):self.assert_rejected(lambda r:r['decisions'][0].update(a6_hypothetical_result='POSITIVO_VALIDO'))
    def test_56_false_history(self):self.assert_rejected(lambda r:r['decisions'][0].update(a5_history_is_synthetic='yes'))
    def test_57_sha_session_invalid(self):
        p,r,s=fixture()
        with self.assertRaises(m.Blocked):m.build_ledger(p,r,s,session_sha256='abc')
    def test_58_case_count_by_service(self):self.assertEqual(self.good()['case_count_by_service'],{'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11})
    def test_59_stages_order(self):self.assertEqual([x['algorithm'] for x in self.good()['ten_stage_ledger']],[f'A{i}' for i in range(1,11)])
    def test_60_case_id_unique(self):self.assertEqual(len({x['a7_case_id'] for x in self.good()['case_rows']}),29)

if __name__=='__main__':
    unittest.main(verbosity=1)
