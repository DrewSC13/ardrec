"""R58-R: immutable declared-only A3/A4 proposal, fail-closed replay tests."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
from ardrec.analytics.exact_preview import digest, canonical
from ardrec.coordination import r58r_durable_transition_proposal as r


def synthetic_sources():
    scenario = {'session_id':'DEV_TUTOR_001'}
    review = {'sha256': 'b'*64, 'source_catalog_sha256': 'c'*64,
              'source_thesis_sha256': 'd'*64}
    a3 = {'sha256':'e'*64}
    rows = []
    for service, count, guard in (('SSH_DEV',8,'VERDADERO'),
                                  ('FTP_DEV',10,'ND'),
                                  ('SMB_DEV',11,'FALSO')):
        for n in range(count):
            ready = guard == 'VERDADERO'
            rows.append({
                'service_id':service, 'session_id':'DEV_TUTOR_001',
                'derived_case_id': f'{service[:3]}-T{n+1:02}-S01-01',
                'assessment_index':0,
                'family_id':f'{service[:3]}-T{n+1:02}',
                'variant':None,
                'case_id_a7':'CASE_'+format(len(rows)+1,'048X'),
                'control_id_a3':'CTRL_'+format(len(rows)+1,'048X'),
                'a3_guard_truth':guard,'a3_table_status':guard,
                'a3_blockers':['AUTORIDAD_OPERACIONAL_NO_ACREDITADA'] if ready
                    else ['GUARDA_ND','AUTORIDAD_OPERACIONAL_NO_ACREDITADA']
                    if guard=='ND' else ['GUARDA_FALSA','AUTORIDAD_OPERACIONAL_NO_ACREDITADA'],
                'a4_applicable_simulated':True,
                'a3_phase_confirmed_by_fixture':'PREPARADO',
                'logical_pending_counterfactual':ready,
                'counterfactual_phase':'PENDIENTE' if ready else 'PREPARADO',
                'confirmed_transition':None,
                'current_confirmed_phase_change':False,
                'case_authority_attested':False,
            })
    trace = {
        'schema':'ardrec-r58q-prepared-pending-a3-a4-counterfactual-v1',
        'mode':'DUAL_A4_RANKING_NO_STATE_CHANGE',
        'session_id':'DEV_TUTOR_001',
        'source_catalog_sha256':'c'*64,
        'source_thesis_sha256':'d'*64,
        'r58l_review_sha256':'b'*64,
        'r58p_a3_projection_sha256':'e'*64,
        'transition_context_sha256':'f'*64,
        'unit_count':29,'family_count':25,
        'control_cases': rows,
        'a4_actual_prepared_selection':{
            'eligible_count':0,'selected':None,
            'operational_dispatch':False,'selection_is_operational':False},
        'a4_counterfactual_pending_selection':{
            'eligible_count':8,'selected':{'service_id':'SSH_DEV',
                                         'case_id':rows[0]['case_id_a7']},
            'operational_dispatch':False,'selection_is_operational':False,
            'p8_operational':'NO-GO'},
        'hypothetical_phase_counts':{'PREPARADO':21,'PENDIENTE':8},
        'prepared_to_pending_transitions_applied':0,
        'confirmed_pending_case_count':0,
        'a3_to_a4_operational_authority_attested':False,
        'a5_operational_attempts_started':0,
        'a6_classification':'ND',
        'technical_truth_accredited':False,
        'confirmed_final_risk':None,
        'applied_state_transition':None,
        'published_generation':None,
        'vm_checks_executed':False,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
    }
    trace['sha256'] = digest(trace)
    return scenario, review, a3, trace


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.scenario,self.review,self.a3,self.trace=synthetic_sources()
        p=patch.object(r,'verify_a3_a4_transition_audit',return_value=True)
        p.start();self.addCleanup(p.stop)
        tmp=tempfile.TemporaryDirectory(prefix='r58r-test-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve()

    def build(self):
        return r.build_proposal(self.trace,self.scenario,self.review,self.a3)

    def persist(self):
        return r.persist_proposal(self.root,self.trace,self.scenario,self.review,self.a3)

    def verify(self):
        return r.verify_persisted_proposal(self.root,self.trace,self.scenario,self.review,self.a3)

    def rehash(self):
        self.trace['sha256']=digest({k:v for k,v in self.trace.items() if k!='sha256'})

    def test_receipt_schema(self):
        doc=self.build()
        self.assertEqual(set(doc),r.RECEIPT_FIELDS)
        self.assertEqual(doc['schema'],r.SCHEMA)

    def test_all_cases_and_25_families(self):
        doc=self.build()
        self.assertEqual((doc['case_count'],doc['family_count']),(29,25))

    def test_current_prepared_and_no_actual_selection(self):
        doc=self.build()
        self.assertEqual(doc['current_prepared_count'],29)
        self.assertEqual(doc['a4_current_eligible_count'],0)
        self.assertIsNone(doc['current_selected_case'])

    def test_counterfactual_eight_only(self):
        doc=self.build()
        self.assertEqual(doc['counterfactual_pending_count'],8)
        self.assertEqual(doc['a4_counterfactual_eligible_count'],8)

    def test_source_hashes_bound(self):
        doc=self.build()
        self.assertEqual(doc['r58q_trace_sha256'],self.trace['sha256'])
        self.assertEqual(doc['r58p_a3_projection_sha256'],'e'*64)
        self.assertEqual(doc['source_catalog_sha256'],'c'*64)

    def test_current_case_phases_never_changed(self):
        self.assertEqual({v['current_phase'] for v in self.build()['cases']},
                         {'PREPARADO'})

    def test_eight_only_have_pending_proposal(self):
        doc=self.build()
        candidates=[x for x in doc['cases'] if x['counterfactual_phase']=='PENDIENTE']
        self.assertEqual(len(candidates),8)
        self.assertEqual({x['service_id'] for x in candidates},{'SSH_DEV'})

    def test_no_transition_authority(self):
        doc=self.build()
        self.assertFalse(any(x['transition_authorized'] for x in doc['cases']))
        self.assertEqual(doc['transitions_applied'],0)
        self.assertEqual(doc['confirmed_pending_case_count'],0)

    def test_no_a5_a6_a9_p8_authority(self):
        doc=self.build()
        self.assertIsNone(doc['confirmed_final_risk'])
        self.assertIsNone(doc['applied_state_transition'])
        self.assertIsNone(doc['published_generation'])
        self.assertIs(doc['technical_truth_accredited'],False)
        self.assertIs(doc['operational_dispatch'],False)
        self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_receipt_deterministic(self):
        self.assertEqual(self.build(),self.build())

    def test_source_order_invariant(self):
        baseline=self.build()
        self.trace['control_cases'].reverse()
        self.rehash()
        revised=self.build()
        self.assertEqual(baseline['cases'],revised['cases'])
        self.assertNotEqual(baseline['sha256'],revised['sha256'])

    def test_inputs_not_mutated(self):
        before=deepcopy(self.trace)
        self.build()
        self.assertEqual(self.trace,before)

    def test_proposal_verify(self):
        self.assertTrue(r.verify_proposal(self.build(),self.trace,self.scenario,self.review,self.a3))

    def test_tampered_proposal_rejected_even_with_forged_hash(self):
        doc=self.build()
        doc['transitions_applied']=1
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(r.ProposalError):
            r.verify_proposal(doc,self.trace,self.scenario,self.review,self.a3)

    def test_extra_receipt_key_rejected(self):
        doc=self.build(); doc['new']=True
        with self.assertRaises(r.ProposalError):
            r.verify_proposal(doc,self.trace,self.scenario,self.review,self.a3)

    def test_first_persist_created(self):
        x=self.persist()
        self.assertEqual(x['persist_status'],'CREATED')
        self.assertFalse(x['state_machine_mutated'])

    def test_replay_identical(self):
        self.persist()
        self.assertEqual(self.persist()['persist_status'],'REPLAY_IDENTICAL')

    def test_one_receipt_per_session(self):
        self.persist();self.persist()
        self.assertEqual(len(list(self.root.iterdir())),1)

    def test_file_permissions_private(self):
        name=self.persist()['receipt_filename']
        self.assertEqual(stat.S_IMODE((self.root/name).stat().st_mode),0o600)

    def test_persisted_verified(self):
        self.persist()
        self.assertEqual(self.verify()['verification'],
                         'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION')

    def test_persisted_no_authority(self):
        self.persist()
        doc=self.verify()
        self.assertEqual(doc['transitions_applied'],0)
        self.assertFalse(doc['state_machine_mutated'])
        self.assertFalse(doc['technical_truth_accredited'])

    def test_source_changed_replay_conflict(self):
        self.persist()
        self.trace['transition_context_sha256']='0'*64
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.persist()

    def test_source_changed_verify_conflict(self):
        self.persist()
        self.trace['transition_context_sha256']='0'*64
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_existing_corrupted_receipt_refused(self):
        name=self.persist()['receipt_filename']
        (self.root/name).write_bytes(b'{}\n')
        with self.assertRaises(r.ProposalError):
            self.persist()

    def test_noncanonical_json_refused(self):
        name=self.persist()['receipt_filename']
        path=self.root/name
        path.write_bytes(b' ' + path.read_bytes())
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_deleted_file_refused(self):
        name=self.persist()['receipt_filename']
        (self.root/name).unlink()
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_symlink_to_receipt_refused(self):
        name=self.persist()['receipt_filename']
        path=self.root/name
        backup=self.root/'other.json'
        path.rename(backup)
        path.symlink_to(backup)
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_hardlinked_receipt_refused(self):
        name=self.persist()['receipt_filename']
        os.link(self.root/name,self.root/'extra-link')
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_permissive_receipt_file_refused(self):
        name=self.persist()['receipt_filename']
        (self.root/name).chmod(0o644)
        with self.assertRaises(r.ProposalError):
            self.verify()

    def test_permissive_root_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(r.ProposalError):
            self.persist()

    def test_relative_root_refused(self):
        with self.assertRaises(r.ProposalError):
            r.persist_proposal(Path('.'),self.trace,self.scenario,self.review,self.a3)

    def test_root_symlink_refused(self):
        alias=self.root.parent/(self.root.name+'-alias')
        alias.symlink_to(self.root,target_is_directory=True)
        self.addCleanup(lambda: alias.unlink(missing_ok=True))
        with self.assertRaises(r.ProposalError):
            r.persist_proposal(alias,self.trace,self.scenario,self.review,self.a3)

    def test_bad_session_id_refused(self):
        self.scenario['session_id']='../bad'
        self.trace['session_id']='../bad'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_trace_integrity_rejected(self):
        self.trace['sha256']='0'*64
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_duplicate_case_identity_rejected(self):
        self.trace['control_cases'][1]=deepcopy(self.trace['control_cases'][0])
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_current_phase_rejected(self):
        self.trace['control_cases'][0]['a3_phase_confirmed_by_fixture']='PENDIENTE'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_case_transition_rejected(self):
        self.trace['control_cases'][0]['confirmed_transition']='PENDIENTE'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_case_authority_rejected(self):
        self.trace['control_cases'][0]['case_authority_attested']=True
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_missing_authority_blocker_rejected(self):
        self.trace['control_cases'][0]['a3_blockers']=[]
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_nd_promoted_pending_rejected(self):
        self.trace['control_cases'][8]['counterfactual_phase']='PENDIENTE'
        self.trace['control_cases'][8]['logical_pending_counterfactual']=True
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_a4_actual_selected_rejected(self):
        self.trace['a4_actual_prepared_selection']['selected']={'service_id':'FTP_DEV'}
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_changed_hypothetical_count_rejected(self):
        self.trace['a4_counterfactual_pending_selection']['eligible_count']=9
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_a5_start_rejected(self):
        self.trace['a5_operational_attempts_started']=1
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_p8_authority_rejected(self):
        self.trace['p8_operational']='GO'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_technical_truth_rejected(self):
        self.trace['technical_truth_accredited']=True
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_false_a9_generation_rejected(self):
        self.trace['published_generation']='GEN_1'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_original_catalog_pins_rejected_when_changed(self):
        self.trace['source_catalog_sha256']='0'*64
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_oversize_unit_count_rejected(self):
        self.trace['unit_count']=55
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()

    def test_noncanonical_case_truth_is_refused(self):
        self.trace['control_cases'][0]['counterfactual_phase']='ACTIVO'
        self.rehash()
        with self.assertRaises(r.ProposalError):
            self.build()


class RealCheckoutIntegration(unittest.TestCase):
    def test_real_pinned_catalog_carries_no_authority(self):
        catalog=REPO/'lab/operational-catalog-v1/catalog.json'
        scenario_path=REPO/'lab/p14-r26-session-v1/scenario.json'
        if not catalog.is_file() or not scenario_path.is_file():
            self.skipTest('FULL_AUTHENTIC_CHECKOUT_REQUIRED')
        from ardrec.coordination.demo_session import read_fixed_scenario
        from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
        from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
        from ardrec.coordination.r58q_transition_guard_bridge import build_a3_a4_transition_audit
        from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries
        scenario=read_fixed_scenario(scenario_path)
        review=build_a4_a5_review(synthetic_entries())
        a3=build_family_a3_projection(scenario,review)
        trace=build_a3_a4_transition_audit(scenario,review,a3)
        doc=r.build_proposal(trace,scenario,review,a3)
        self.assertEqual((doc['case_count'],doc['family_count']),(29,25))
        self.assertEqual(doc['counterfactual_pending_count'],8)
        self.assertEqual(doc['transitions_applied'],0)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve()
            result=r.persist_proposal(root,trace,scenario,review,a3)
            self.assertEqual(result['persist_status'],'CREATED')
            verified=r.verify_persisted_proposal(root,trace,scenario,review,a3)
            self.assertEqual(verified['verification'],
                             'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION')


if __name__ == '__main__':
    unittest.main()
