"""R58-S deny-only decisions; includes negative persistence and integrity tests."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from ardrec.analytics.exact_preview import digest, canonical
from ardrec.coordination import r58s_transition_deny_gate as s


def fixture():
    cases = []
    for sid, count, truth in [('SSH_DEV',2,'VERDADERO'),('FTP_DEV',1,'ND'),('SMB_DEV',1,'FALSO')]:
        for n in range(count):
            hypothetical = truth == 'VERDADERO'
            cases.append({
                'service_id':sid,'session_id':'DEV_TUTOR_001',
                'derived_case_id':f'{sid}_T{n+1:02}', 'assessment_index':0,
                'family_id':sid[:3]+'-T01', 'variant':None,
                'case_id_a7':'CASE_'+format(len(cases)+1,'048X'),
                'control_id_a3':'CTRL_'+format(len(cases)+1,'048X'),
                'a3_guard_truth':truth,
                'a3_blockers':(['AUTORIDAD_OPERACIONAL_NO_ACREDITADA'] if hypothetical
                               else ['GUARDA_ND' if truth=='ND' else 'GUARDA_FALSA',
                                     'AUTORIDAD_OPERACIONAL_NO_ACREDITADA']),
                'current_phase':'PREPARADO',
                'counterfactual_phase':'PENDIENTE' if hypothetical else 'PREPARADO',
                'decision':'HYPOTHETICAL_PENDING_NO_AUTHORITY' if hypothetical
                           else 'STAY_PREPARED_NOT_APPLIED',
                'transition_authorized':False,
            })
    proposal={
        'schema':'ardrec-r58r-immutable-declared-transition-proposal-v1',
        'mode':'IMMUTABLE_LOCAL_PROPOSAL_NOT_MACHINE_STATE',
        'session_id':'DEV_TUTOR_001',
        'r58q_trace_sha256':'1'*64,'source_catalog_sha256':'2'*64,
        'source_thesis_sha256':'3'*64,
        'case_count':4,'family_count':3,
        'current_prepared_count':4,'counterfactual_pending_count':2,
        'a4_current_eligible_count':0,'current_selected_case':None,
        'a4_counterfactual_eligible_count':2,
        'transitions_applied':0,'confirmed_pending_case_count':0,
        'technical_truth_accredited':False,
        'applied_state_transition':None,'published_generation':None,
        'operational_dispatch':False,'p8_operational':'NO-GO',
        'cases':cases,
    }
    proposal['sha256']=digest(proposal)
    trace={'sha256':'1'*64, 'session_id':'DEV_TUTOR_001'}
    review={'source_catalog_sha256':'2'*64,'source_thesis_sha256':'3'*64}
    scenario={'session_id':'DEV_TUTOR_001'}
    return proposal,trace,review,scenario


class DenyOnlyGateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='r58s-test-')
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.proposal_root=root/'proposal'
        self.gate_root=root/'gate'
        self.proposal_root.mkdir(mode=0o700)
        self.gate_root.mkdir(mode=0o700)
        self.proposal,self.trace,self.review,self.scenario=fixture()
        self.a3={}
        def build(*unused):
            return deepcopy(self.proposal)
        def verified(*unused):
            return {
                'verification':'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION',
                'receipt_sha256':self.proposal['sha256'],
                'transitions_applied':0,'state_machine_mutated':False,
                'operational_dispatch':False,'p8_operational':'NO-GO',
            }
        p=patch.object(s,'build_proposal',side_effect=build)
        p.start();self.addCleanup(p.stop)
        p=patch.object(s,'verify_persisted_proposal',side_effect=verified)
        p.start();self.addCleanup(p.stop)

    def build(self):
        return s.build_deny_gate(self.proposal_root,self.trace,self.scenario,
                                 self.review,self.a3)

    def persist(self):
        return s.persist_deny_gate(self.gate_root,self.proposal_root,
                                   self.trace,self.scenario,self.review,self.a3)

    def verify(self):
        return s.verify_persisted_deny_gate(self.gate_root,self.proposal_root,
                                            self.trace,self.scenario,self.review,self.a3)

    def test_expected_coverage(self):
        r=self.build();self.assertEqual((r['case_count'],r['family_count']),(4,3))

    def test_two_logical_requests(self):
        self.assertEqual(self.build()['request_count'],2)

    def test_two_not_eligible(self):
        self.assertEqual(self.build()['not_eligible_count'],2)

    def test_all_requests_denied(self):
        self.assertIs(self.build()['all_requests_denied'],True)

    def test_reason_split(self):
        self.assertEqual(self.build()['denials_by_reason'],{
            'CASE_NOT_A3_LOGICALLY_ELIGIBLE':2,
            'INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED':2})

    def test_case_denials(self):
        self.assertEqual({r['review_outcome'] for r in self.build()['cases']},{'DENIED'})

    def test_no_approval(self):
        r=self.build();self.assertFalse(r['signed_approval_attested']);self.assertFalse(r['independent_authority_attested'])

    def test_no_transition_commit(self):
        self.assertIs(self.build()['transition_commit_attested'],False)

    def test_no_state_machine_mutation(self):
        self.assertFalse(self.build()['state_machine_mutated'])

    def test_no_actual_pending(self):
        self.assertEqual(self.build()['confirmed_pending_case_count'],0)

    def test_zero_applied_transition(self):
        self.assertEqual(self.build()['transitions_applied'],0)

    def test_no_dispatch(self):
        self.assertFalse(self.build()['operational_dispatch'])

    def test_no_risk_promotion(self):
        self.assertIsNone(self.build()['confirmed_final_risk'])

    def test_no_generation(self):
        self.assertIsNone(self.build()['published_generation'])

    def test_no_a6_evidence(self):
        self.assertEqual(self.build()['a6_classification'],'ND')

    def test_p8_no_go(self):
        self.assertEqual(self.build()['p8_operational'],'NO-GO')

    def test_source_hash_linked(self):
        self.assertEqual(self.build()['r58r_proposal_sha256'],self.proposal['sha256'])

    def test_report_deterministic(self):
        self.assertEqual(self.build(),self.build())

    def test_verify_report(self):
        self.assertTrue(s.verify_deny_gate(self.build(),self.proposal_root,
                         self.trace,self.scenario,self.review,self.a3))

    def test_source_permutation_without_rehash_rejected(self):
        self.proposal['cases'].reverse()
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_created(self):
        self.assertEqual(self.persist()['persist_status'],'CREATED')

    def test_replay_identical(self):
        self.persist();self.assertEqual(self.persist()['persist_status'],'REPLAY_IDENTICAL')

    def test_persisted_verified(self):
        self.persist();self.assertEqual(self.verify()['verification'],
             'PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION')

    def test_one_receipt_created(self):
        self.persist();self.persist();self.assertEqual(len(list(self.gate_root.iterdir())),1)

    def test_private_mode(self):
        name=self.persist()['filename'];self.assertEqual(stat.S_IMODE((self.gate_root/name).stat().st_mode),0o600)

    def test_no_proposal_directory_mutation(self):
        self.persist();self.assertEqual(list(self.proposal_root.iterdir()),[])

    def test_persisted_result_deny_only(self):
        self.persist();v=self.verify();self.assertFalse(v['operational_dispatch']);self.assertEqual(v['transitions_applied'],0)

    def test_tampered_hash_rejected(self):
        r=self.build();r['case_count']=999
        with self.assertRaises(s.TransitionGateError):
            s.verify_deny_gate(r,self.proposal_root,self.trace,self.scenario,self.review,self.a3)

    def test_tampered_rehashed_rejected(self):
        r=self.build();r['all_requests_denied']=False
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(s.TransitionGateError):
            s.verify_deny_gate(r,self.proposal_root,self.trace,self.scenario,self.review,self.a3)

    def test_tampered_case_rehashed_rejected(self):
        r=self.build();r['cases'][0]['review_outcome']='APPROVED'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(s.TransitionGateError):
            s.verify_deny_gate(r,self.proposal_root,self.trace,self.scenario,self.review,self.a3)

    def test_source_digest_changed_rejected(self):
        self.proposal['sha256']='4'*64
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_trace_changed_rejected(self):
        self.trace['sha256']='a'*64
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_catalog_changed_rejected(self):
        self.review['source_catalog_sha256']='a'*64
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_thesis_changed_rejected(self):
        self.review['source_thesis_sha256']='a'*64
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_false_approved_proposal_rejected(self):
        self.proposal['cases'][0]['transition_authorized']=True
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_false_state_rejected(self):
        self.proposal['cases'][0]['current_phase']='PENDIENTE'
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_false_guard_pending_rejected(self):
        self.proposal['cases'][-1]['counterfactual_phase']='PENDIENTE'
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_pending_with_nd_rejected(self):
        self.proposal['cases'][2]['counterfactual_phase']='PENDIENTE'
        self.proposal['cases'][2]['decision']='HYPOTHETICAL_PENDING_NO_AUTHORITY'
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_pending_with_unexpected_blocker_rejected(self):
        self.proposal['cases'][0]['a3_blockers'].append('NEW_BLOCKER')
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_duplicate_case_identity_rejected(self):
        self.proposal['cases'][1]['derived_case_id']=self.proposal['cases'][0]['derived_case_id']
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_nonzero_transition_rejected(self):
        self.proposal['transitions_applied']=1
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_claimed_publication_rejected(self):
        self.proposal['published_generation']='G1'
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_claimed_technical_truth_rejected(self):
        self.proposal['technical_truth_accredited']=True
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_unsupported_p8_rejected(self):
        self.proposal['p8_operational']='GO'
        with self.assertRaises(s.TransitionGateError):self.build()

    def test_corrupt_persisted_file_rejected(self):
        path=self.gate_root/self.persist()['filename']
        path.write_bytes(b'{"edited":true}\n')
        with self.assertRaises(s.TransitionGateError):self.verify()

    def test_replay_conflict_rejected(self):
        path=self.gate_root/self.persist()['filename']
        path.write_bytes(b'changed')
        with self.assertRaises(s.TransitionGateError):self.persist()

    def test_symlink_receipt_rejected(self):
        name=s._name('DEV_TUTOR_001')
        (self.gate_root/name).symlink_to(self.proposal_root)
        with self.assertRaises(s.TransitionGateError):self.persist()

    def test_root_must_be_private(self):
        self.gate_root.chmod(0o755)
        with self.assertRaises(Exception):self.persist()

    def test_source_root_must_be_private(self):
        self.proposal_root.chmod(0o755)
        with self.assertRaises(Exception):self.persist()

    def test_distinct_roots_required(self):
        with self.assertRaises(s.TransitionGateError):
            s.persist_deny_gate(self.proposal_root,self.proposal_root,
                                self.trace,self.scenario,self.review,self.a3)

    def test_relative_root_rejected(self):
        with self.assertRaises(Exception):
            s.persist_deny_gate(Path('relative'),self.proposal_root,
                                self.trace,self.scenario,self.review,self.a3)

    def test_file_world_readable_rejected(self):
        path=self.gate_root/self.persist()['filename'];path.chmod(0o644)
        with self.assertRaises(Exception):self.verify()

    def test_extra_field_report_rejected(self):
        r=self.build();r['untrusted']='y'
        with self.assertRaises(s.TransitionGateError):
            s.verify_deny_gate(r,self.proposal_root,self.trace,self.scenario,self.review,self.a3)

    def test_modified_proposal_after_persist_rejected(self):
        self.persist()
        self.proposal['cases'][0]['derived_case_id']='CHANGED'
        with self.assertRaises(s.TransitionGateError):self.verify()

    def test_missing_file_rejected(self):
        with self.assertRaises(Exception):self.verify()

    def test_identity_bound_in_every_case(self):
        cases=self.build()['cases']
        self.assertEqual(len({(d['service_id'],d['derived_case_id']) for d in cases}),4)

    def test_no_committed_state_every_case(self):
        self.assertTrue(all(d['state_committed'] is None for d in self.build()['cases']))

    def test_gate_rows_have_strict_shape(self):
        self.assertTrue(all(set(d)==s.CASE_KEYS for d in self.build()['cases']))

    def test_source_unmodified(self):
        old=deepcopy(self.proposal)
        self.build()
        self.assertEqual(old,self.proposal)


if __name__ == '__main__':
    unittest.main()
