"""R58-Q: A3 guard input vs dual R27 A4 selection, without real transitions."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from ardrec.coordination import r58q_transition_guard_bridge as q
from ardrec.analytics.exact_preview import digest

SCENARIO = {
    'format': 'ardrec-p14-r26-fixed-three-service-scenario-v1',
    'session_id': 'DEV_TUTOR_001',
    'services': [
        {'id': s, 'protocol': p, 'fact': v,
         'initial_risk': '1/4', 'normalized_criticality': '1/2'}
        for s, p, v in (
            ('SSH_DEV','SSH','VERDADERO'),
            ('FTP_DEV','FTP','AUSENTE'),
            ('SMB_DEV','SMB','FALSO'))
    ],
}


def case_fixture(applicable=True):
    rows = []
    ctrl = []
    envelopes = []
    for sid, num, truth in (
        ('SSH_DEV',8,'VERDADERO'),
        ('FTP_DEV',10,'ND'),
        ('SMB_DEV',11,'FALSO'),
    ):
        for n in range(num):
            fid = f'{sid[:3]}-T{n+1:02}'
            ident = dict(service_id=sid,session_id='DEV_TUTOR_001',
                         derived_case_id=f'{fid}-S01-01',assessment_index=0)
            cid='CASE_'+format(len(rows)+1,'048X')
            guard_blockers=[
                *(['GUARDA_ND','TABLA_NO_ACREDITADA'] if truth=='ND'
                  else ['GUARDA_FALSA','TABLA_NO_ACREDITADA'] if truth=='FALSO' else []),
                'AUTORIDAD_OPERACIONAL_NO_ACREDITADA']
            row={**ident,'family_id':fid,'variant':None,'case_id_a7':cid,
                 'a4_precedence':(n%4)+1,'a4_guard_simulated':'VERDADERO',
                 'a4_applicable_simulated':applicable,
                 'a4_eligible_simulated':applicable,
                 'a6_classification':'ND','technical_truth_accredited':False,
                 'confirmed_rf':None,'applied_transition':None,
                 'published_generation':None}
            rows.append(row)
            ctrl.append({**ident,'family_id':fid,'variant':None,'case_id_a7':cid,
                         'precedence':row['a4_precedence'],
                         'control_id_a3':'CTRL_'+cid[5:],'a3_phase':'PREPARADO',
                         'a3_table_status':truth,'a3_guard_truth':truth,
                         'a3_blockers':guard_blockers,
                         'a4_guard_simulated':'VERDADERO',
                         'a4_eligible_simulated':applicable,
                         'operational_eligibility_attested':False,
                         'technical_truth_accredited':False})
            envelopes.append({'service_id':sid,'unit':{
                k:ident[k] for k in ('session_id','derived_case_id','assessment_index')},
                'risk':{'initial_risk':'1/4','normalized_criticality':'1/2',
                        'replacement_risk':'1/4'}})
    r = {'sha256':'b'*64,'session_id':'DEV_TUTOR_001',
         'source_catalog_sha256':'c'*64,'source_thesis_sha256':'d'*64,
         'decisions':rows,'unified':{'inputs':envelopes},
         'unit_count':len(rows),'covered_family_count':25,
         'weights':['1/3','1/3','1/3'],
         'a4_selected_identity':rows[8],
         'a5':{'actual_attempts_started':0,'actual_attempt_reservations':0},
         'a6_classification':'ND','technical_truth_accredited':False,
         'operational_dispatch':False,'p8_operational':'NO-GO',
         'confirmed_final_risk':None,'published_generation':None,
         'applied_state_transition':None}
    p={'sha256':'e'*64,'session_id':'DEV_TUTOR_001',
       'r58l_review_sha256':r['sha256'],
       'source_catalog_sha256':r['source_catalog_sha256'],
       'source_thesis_sha256':r['source_thesis_sha256'],
       'control_reference_count':len(ctrl),'control_cases':ctrl,
       'family_count':25,'case_count_by_service':{'FTP_DEV':10,'SMB_DEV':11,'SSH_DEV':8},
       'a3_guard_truth_counts':{'VERDADERO':8,'ND':10,'FALSO':11},
       'a3_a4_guard_mismatch_count':21,
       'a3_typed_case_references_constructed':True,
       'a3_case_guard_is_operational_authority':False,
       'a1_a3_to_family_case_authority_attested':False,
       'a6_classification':'ND','technical_truth_accredited':False,
       'operational_dispatch':False,'p8_operational':'NO-GO',
       'confirmed_final_risk':None,'published_generation':None,
       'applied_transition':None}
    return r,p


class TransitionBridgeTests(unittest.TestCase):
    def setUp(self):
        self.scenario=deepcopy(SCENARIO)
        self.review,self.a3=case_fixture()
        s=patch.object(q,'normalize_scenario',side_effect=lambda s: s)
        s.start();self.addCleanup(s.stop)
        for attr in ('verify_a4_a5_review','verify_family_a3_projection'):
            p=patch.object(q,attr,return_value=True)
            p.start();self.addCleanup(p.stop)

    def build(self):
        return q.build_a3_a4_transition_audit(self.scenario,self.review,self.a3)

    def test_29_cases_and_25_families(self):
        r=self.build()
        self.assertEqual((r['unit_count'],r['family_count']),(29,25))

    def test_prepared_has_no_actual_eligible_case(self):
        r=self.build()
        self.assertEqual(r['a4_actual_prepared_selection']['eligible_count'],0)
        self.assertIsNone(r['a4_actual_prepared_selection']['selected'])

    def test_counterfactual_exact_eight(self):
        r=self.build()
        self.assertEqual(r['a4_counterfactual_pending_selection']['eligible_count'],8)
        self.assertEqual(r['hypothetical_phase_counts'],{'PREPARADO':21,'PENDIENTE':8})

    def test_counterfactual_winner_is_ssh(self):
        self.assertEqual(self.build()['a4_counterfactual_pending_selection']['selected']['service_id'],'SSH_DEV')

    def test_original_r58l_winner_retained_as_assumption(self):
        self.assertEqual(self.build()['a4_original_assumed_selection']['service_id'],'FTP_DEV')

    def test_21_original_a3_a4_mismatches(self):
        self.assertEqual(self.build()['a3_a4_original_guard_mismatch_count'],21)

    def test_all_truth_counts(self):
        self.assertEqual(self.build()['a3_guard_truth_counts'],{'VERDADERO':8,'FALSO':11,'ND':10})

    def test_no_real_transition_or_pending(self):
        r=self.build()
        self.assertEqual(r['prepared_to_pending_transitions_applied'],0)
        self.assertEqual(r['confirmed_pending_case_count'],0)
        self.assertIsNone(r['applied_state_transition'])

    def test_no_operational_authority(self):
        r=self.build()
        self.assertIs(r['a3_to_a4_operational_authority_attested'],False)
        self.assertIs(r['operational_dispatch'],False)
        self.assertEqual(r['p8_operational'],'NO-GO')

    def test_no_a6_promotion(self):
        r=self.build()
        self.assertEqual(r['a6_classification'],'ND')
        self.assertIs(r['technical_truth_accredited'],False)
        self.assertIsNone(r['confirmed_final_risk'])
        self.assertIsNone(r['published_generation'])

    def test_no_actual_start(self):
        self.assertEqual(self.build()['a5_operational_attempts_started'],0)

    def test_report_reproducible(self):
        self.assertEqual(self.build(),self.build())
        self.assertTrue(q.verify_a3_a4_transition_audit(self.build(),self.scenario,self.review,self.a3))

    def test_permutation_invariant(self):
        prior=self.build()
        self.review['decisions'].reverse()
        self.review['unified']['inputs'].reverse()
        self.a3['control_cases'].reverse()
        self.assertEqual(prior,self.build())

    def test_no_false_pending_for_nd(self):
        self.assertTrue(all(row['counterfactual_phase']=='PREPARADO'
                            for row in self.build()['control_cases'] if row['service_id']=='FTP_DEV'))

    def test_no_false_pending_for_false(self):
        self.assertTrue(all(row['counterfactual_phase']=='PREPARADO'
                            for row in self.build()['control_cases'] if row['service_id']=='SMB_DEV'))

    def test_true_but_inapplicable_is_blocked(self):
        self.review['decisions'][0]['a4_applicable_simulated']=False
        self.a3['control_cases'][0]['a4_eligible_simulated']=False
        self.review['decisions'][0]['a4_eligible_simulated']=False
        self.assertEqual(self.build()['a4_counterfactual_pending_selection']['eligible_count'],7)

    def test_unknown_extra_blocker_blocks(self):
        self.a3['control_cases'][0]['a3_blockers'].append('DEPENDENCIAS_NO_CONFIRMADAS')
        self.assertEqual(self.build()['a4_counterfactual_pending_selection']['eligible_count'],7)

    def test_no_history_effect_on_r58l_inputs(self):
        initial=deepcopy(self.review)
        self.build()
        self.assertEqual(self.review,initial)

    def test_separate_report_from_a3_inputs(self):
        old=deepcopy(self.a3)
        self.build()
        self.assertEqual(self.a3,old)

    def test_source_pins(self):
        r=self.build()
        self.assertEqual(r['source_catalog_sha256'],'c'*64)
        self.assertEqual(r['source_thesis_sha256'],'d'*64)

    def test_all_control_ids_unique(self):
        values=[r['control_id_a3'] for r in self.build()['control_cases']]
        self.assertEqual(len(values),len(set(values)))

    def test_no_confirmed_phase_change_per_case(self):
        self.assertTrue(all(r['confirmed_transition'] is None and not r['current_confirmed_phase_change']
                            for r in self.build()['control_cases']))

    def test_no_case_authority_per_case(self):
        self.assertTrue(all(r['case_authority_attested'] is False
                            for r in self.build()['control_cases']))

    def test_report_tamper_even_with_rehash_refused(self):
        r=self.build();r['prepared_to_pending_transitions_applied']=1
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(q.TransitionBridgeError):
            q.verify_a3_a4_transition_audit(r,self.scenario,self.review,self.a3)

    def test_report_tamper_original_selection_refused(self):
        r=self.build();r['a4_actual_prepared_selection']['selected']={'service_id':'SSH_DEV'}
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(q.TransitionBridgeError):
            q.verify_a3_a4_transition_audit(r,self.scenario,self.review,self.a3)

    def test_report_wrong_digest_refused(self):
        r=self.build();r['sha256']='0'*64
        with self.assertRaises(q.TransitionBridgeError):
            q.verify_a3_a4_transition_audit(r,self.scenario,self.review,self.a3)

    def test_a3_wrong_session_refused(self):
        self.a3['session_id']='ANOTHER'
        with self.assertRaisesRegex(q.TransitionBridgeError,'SOURCE_IDENTITY'):
            self.build()

    def test_review_wrong_session_refused(self):
        self.review['session_id']='ANOTHER'
        with self.assertRaisesRegex(q.TransitionBridgeError,'SOURCE_IDENTITY'):
            self.build()

    def test_a3_wrong_review_digest_refused(self):
        self.a3['r58l_review_sha256']='0'*64
        with self.assertRaisesRegex(q.TransitionBridgeError,'SOURCE_IDENTITY'):
            self.build()

    def test_catalog_mismatch_refused(self):
        self.a3['source_catalog_sha256']='0'*64
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_thesis_mismatch_refused(self):
        self.a3['source_thesis_sha256']='0'*64
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_case_count_mismatch_refused(self):
        self.a3['control_reference_count']=28
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_missing_a3_case_refused(self):
        self.a3['control_cases'].pop()
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_duplicate_a3_case_refused(self):
        self.a3['control_cases'][1]=deepcopy(self.a3['control_cases'][0])
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_duplicate_risk_envelope_refused(self):
        self.review['unified']['inputs'][1]=deepcopy(self.review['unified']['inputs'][0])
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_missing_risk_envelope_refused(self):
        self.review['unified']['inputs'].pop()
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_case_id_swap_refused(self):
        self.a3['control_cases'][0]['case_id_a7']='CASE_'+'F'*48
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_family_swap_refused(self):
        self.a3['control_cases'][0]['family_id']='SMB-T03'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_variant_swap_refused(self):
        self.a3['control_cases'][0]['variant']='READ'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_precedence_swap_refused(self):
        self.a3['control_cases'][0]['precedence']=1023
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a4_guard_swap_refused(self):
        self.a3['control_cases'][0]['a4_guard_simulated']='FALSO'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a4_eligibility_mismatch_refused(self):
        self.a3['control_cases'][0]['a4_eligible_simulated']=False
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_false_control_authority_refused(self):
        self.a3['control_cases'][0]['operational_eligibility_attested']=True
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_false_report_authority_refused(self):
        self.a3['a1_a3_to_family_case_authority_attested']=True
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a5_actual_start_refused(self):
        self.review['a5']['actual_attempts_started']=1
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a5_reservation_refused(self):
        self.review['a5']['actual_attempt_reservations']=1
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a6_truth_promotion_refused(self):
        self.review['technical_truth_accredited']=True
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_a6_risk_promotion_refused(self):
        self.review['confirmed_final_risk']='0'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_p8_operational_refused(self):
        self.review['p8_operational']='GO'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_no_dispatch_refused(self):
        self.a3['operational_dispatch']=True
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_phase_mismatch_refused(self):
        self.a3['control_cases'][0]['a3_phase']='PENDIENTE'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_guard_domain_mismatch_refused(self):
        self.a3['control_cases'][0]['a3_guard_truth']='TRUE'
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_wrong_auth_blocker_refused(self):
        self.a3['control_cases'][0]['a3_blockers']=[]
        with self.assertRaises(q.TransitionBridgeError):
            self.build()

    def test_user_boolean_trivalent_refused(self):
        self.a3['control_cases'][0]['a3_guard_truth']=True
        with self.assertRaises(q.TransitionBridgeError):
            self.build()


if __name__ == '__main__':
    unittest.main()
