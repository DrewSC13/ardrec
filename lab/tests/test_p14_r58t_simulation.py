"""R58-T atomic SQLite counterfactual T1: adversarial integrity and replay tests."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from ardrec.analytics.exact_preview import digest
from ardrec.coordination import r58t_counterfactual_state_store as t


def fake_gate():
    rows=[]
    for service, count, logical in [('SSH_DEV',8,True),('FTP_DEV',10,False),('SMB_DEV',11,False)]:
        for n in range(count):
            token = 'CASE_'+format(len(rows)+1,'048X')
            rows.append({
                'service_id':service,'session_id':'DEV_TUTOR_001',
                'derived_case_id':f'{service[:3]}-T{n+1:02}-S01-01',
                'assessment_index':0,'case_id_a7':token,
                'current_phase':'PREPARADO','counterfactual_phase':'PENDIENTE' if logical else 'PREPARADO',
                'review_outcome':'DENIED','state_committed':None,
                'logical_candidate':logical,'a3_guard_truth':'VERDADERO' if logical else 'ND',
                'deny_reason':t.DENIED if logical else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE',
                'independent_authority_attested':False,'signed_approval_attested':False,
                'transition_commit_attested':False,
            })
    gate = {'schema':'ardrec-r58s-a3-a4-deny-only-transition-gate-v1',
            'session_id':'DEV_TUTOR_001', 'case_count':29,'family_count':25,
            'cases':rows,'request_count':8,'logical_candidates_count':8,'not_eligible_count':21,
            'all_requests_denied':True,'transitions_applied':0,'confirmed_pending_case_count':0,
            'independent_authority_attested':False,'signed_approval_attested':False,
            'transition_commit_attested':False,'state_machine_mutated':False,
            'a6_classification':'ND','technical_truth_accredited':False,
            'published_generation':None,'operational_dispatch':False,'p8_operational':'NO-GO'}
    gate['sha256']=digest(gate)
    return gate


class CounterfactualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='r58t-unit-')
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.sim,self.gate_root,self.proposal = (root/name for name in ('sim','gate','proposal'))
        for path in (self.sim,self.gate_root,self.proposal):path.mkdir(mode=0o700)
        self.gate=fake_gate()
        p=patch.object(t,'build_deny_gate',side_effect=lambda *a:self.gate)
        p.start();self.addCleanup(p.stop)
        q=patch.object(t,'verify_persisted_deny_gate',side_effect=lambda *a:{
            'verification':'PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION',
            'receipt_sha256':self.gate['sha256'], 'transitions_applied':0,
            'state_machine_mutated':False, 'operational_dispatch':False, 'p8_operational':'NO-GO'})
        q.start();self.addCleanup(q.stop)
        self.params=(self.sim,self.gate_root,self.proposal,{}, {}, {}, {})
        self.good=self.gate['cases'][0]['case_id_a7']
        self.good2=self.gate['cases'][1]['case_id_a7']
        self.bad=self.gate['cases'][8]['case_id_a7']

    def init(self):return t.initialize_simulator(*self.params)
    def read(self):return t.inspect_simulator(*self.params)
    def move(self,case=None,req='SIM_UNIT_A',**kw):
        return t.simulate_t1(*self.params,case_id_a7=case or self.good,request_id=req,**kw)
    def db(self):return t._db_path(self.sim,self.gate)
    def sql(self,statement,values=()):
        c=sqlite3.connect(self.db())
        try:c.execute(statement,values);c.commit()
        finally:c.close()

    def test_01_initial_create(self):
        r=self.init();self.assertEqual(r['persist_status'],'CREATED')
        self.assertEqual((r['case_count'],r['simulated_pending_count']),(29,0))
    def test_02_repeated_initialization(self):
        self.init();self.assertEqual(self.init()['persist_status'],'REPLAY_IDENTICAL')
    def test_03_all_cases_prepared_initially(self):
        self.init();self.assertEqual(self.read()['simulated_prepared_count'],29)
    def test_04_first_t1(self):
        self.init();r=self.move();self.assertEqual(r['persist_status'],'COMMITTED_IN_SANDBOX_ONLY')
    def test_05_one_pending(self):
        self.init();self.move();self.assertEqual(self.read()['simulated_pending_count'],1)
    def test_06_replay_identical(self):
        self.init();self.move();self.assertEqual(self.move()['persist_status'],'REPLAY_IDENTICAL')
    def test_07_second_t1(self):
        self.init();self.move();self.move(self.good2,'SIM_UNIT_B');self.assertEqual(self.read()['simulated_t1_count'],2)
    def test_08_replay_request_different_case_rejected(self):
        self.init();self.move()
        with self.assertRaisesRegex(t.SimulatorError,'REQUEST_REPLAY_CONFLICT'):self.move(self.good2,'SIM_UNIT_A')
    def test_09_replay_same_case_new_request_rejected(self):
        self.init();self.move()
        with self.assertRaisesRegex(t.SimulatorError,'ALREADY_TRANSITIONED'):self.move(req='SIM_NEW')
    def test_10_ftp_rejected(self):
        self.init()
        with self.assertRaisesRegex(t.SimulatorError,'NOT_LOGICALLY_ELIGIBLE'):self.move(self.bad)
    def test_11_case_unknown(self):
        self.init()
        with self.assertRaisesRegex(t.SimulatorError,'UNKNOWN'):self.move('CASE_'+'A'*48)
    def test_12_invalid_request_lowercase(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(req='sim_invalid')
    def test_13_invalid_request_empty(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(req='')
    def test_14_invalid_request_long(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(req='SIM_'+'A'*80)
    def test_15_invalid_case_id(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move('CASE_SHORT')
    def test_16_revision_other_than_zero(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(expected_revision=1)
    def test_17_revision_bool_not_integer(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(expected_revision=False)
    def test_18_fault_before_commit_rolls_back(self):
        self.init()
        with self.assertRaisesRegex(t.SimulatorError,'INJECTED_ROLLBACK'):self.move(fault_before_commit=True)
        self.assertEqual(self.read()['simulated_pending_count'],0)
    def test_19_fault_recovery_can_retry(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(fault_before_commit=True)
        self.assertEqual(self.move()['simulated_pending_count'],1)
    def test_20_read_recovery_from_new_connection(self):
        self.init();self.move();self.assertEqual(self.read()['simulated_t1_count'],1)
    def test_21_hash_head_not_zero_after_commit(self):
        self.init();self.move();self.assertNotEqual(self.read()['last_event_sha256'],t.ZERO_SHA)
    def test_22_hash_head_zero_initially(self):
        self.init();self.assertEqual(self.read()['last_event_sha256'],t.ZERO_SHA)
    def test_23_tamper_event_sha(self):
        self.init();self.move();self.sql('UPDATE events SET sha=?',('a'*64,))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_24_tamper_event_prev(self):
        self.init();self.move();self.sql('UPDATE events SET prev_sha=?',('b'*64,))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_25_tamper_case_revision(self):
        self.init();self.move();self.sql('UPDATE cases SET revision=0 WHERE phase=?',('PENDIENTE',))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_26_tamper_case_phase(self):
        self.init();self.move();self.sql('UPDATE cases SET phase=? WHERE phase=?',('PREPARADO','PENDIENTE'))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_27_tamper_gate_sha_meta(self):
        self.init();self.sql('UPDATE meta SET gate_sha=?',('a'*64,))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_28_tamper_session_meta(self):
        self.init();self.sql('UPDATE meta SET session_id=?',('OTHER',))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_29_tamper_initial_set(self):
        self.init();self.sql('DELETE FROM cases WHERE case_key=?',(t._key(self.gate['cases'][0]),))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_30_reject_extra_table(self):
        self.init();self.sql('CREATE TABLE operational_transition (x TEXT)')
        with self.assertRaises(t.SimulatorError):self.read()
    def test_31_reject_duplicate_meta(self):
        self.init();self.sql('INSERT INTO meta SELECT * FROM meta')
        with self.assertRaises(t.SimulatorError):self.read()
    def test_32_reject_event_sequence_hole(self):
        self.init();self.move();self.sql('UPDATE events SET seq=42')
        with self.assertRaises(t.SimulatorError):self.read()
    def test_33_reject_event_request_change(self):
        self.init();self.move();self.sql('UPDATE events SET request_id=?',('SIM_CHANGED',))
        with self.assertRaises(t.SimulatorError):self.read()
    def test_34_reject_additional_event(self):
        self.init();self.move();self.sql("INSERT INTO events SELECT 2,'SIM_FAKE',case_key,before_phase,after_phase,0,1,prev_sha,sha FROM events")
        with self.assertRaises(t.SimulatorError):self.read()
    def test_35_reject_invalid_db_permissions(self):
        self.init();os.chmod(self.db(),0o644)
        with self.assertRaises(t.SimulatorError):self.read()
    def test_36_reject_db_symlink(self):
        self.init();original=self.db();moved=original.with_suffix('.backup');original.rename(moved);original.symlink_to(moved)
        with self.assertRaises(t.SimulatorError):self.read()
    def test_37_reject_root_mode(self):
        self.init();os.chmod(self.sim,0o755)
        with self.assertRaises(ValueError):self.read()
    def test_38_reject_same_root_as_gate(self):
        self.params=(self.gate_root,self.gate_root,self.proposal,{}, {}, {}, {})
        with self.assertRaises(t.SimulatorError):self.init()
    def test_39_reject_same_root_as_proposal(self):
        self.params=(self.proposal,self.gate_root,self.proposal,{}, {}, {}, {})
        with self.assertRaises(t.SimulatorError):self.init()
    def test_40_reject_unsafe_root_symlink(self):
        link=self.sim.parent/'alias';link.symlink_to(self.sim,target_is_directory=True)
        self.params=(link,self.gate_root,self.proposal,{}, {}, {}, {})
        with self.assertRaises(ValueError):self.init()
    def test_41_bad_source_count(self):
        self.gate['request_count']=9
        with self.assertRaises(t.SimulatorError):self.init()
    def test_42_bad_source_authority(self):
        self.gate['signed_approval_attested']=True
        with self.assertRaises(t.SimulatorError):self.init()
    def test_43_bad_case_approval(self):
        self.gate['cases'][0]['review_outcome']='APPROVED'
        with self.assertRaises(t.SimulatorError):self.init()
    def test_44_bad_case_unattested(self):
        self.gate['cases'][0]['independent_authority_attested']=True
        with self.assertRaises(t.SimulatorError):self.init()
    def test_45_not_dispatch(self):
        self.init();self.move();r=self.read();self.assertFalse(r['operational_dispatch'])
    def test_46_not_technical_truth(self):
        self.init();self.move();self.assertEqual(self.read()['a6_classification'],'ND')
    def test_47_no_final_risk(self):
        self.init();self.move();self.assertIsNone(self.read()['confirmed_final_risk'])
    def test_48_no_publication(self):
        self.init();self.move();self.assertIsNone(self.read()['published_generation'])
    def test_49_p8_no_go(self):
        self.init();self.move();self.assertEqual(self.read()['p8_operational'],'NO-GO')
    def test_50_immutable_source_replay_rejected(self):
        self.init();self.gate['sha256']='f'*64
        with self.assertRaises(t.SimulatorError):self.init()
    def test_51_can_simulate_at_most_eight(self):
        self.init()
        for n,x in enumerate(self.gate['cases'][:8]):self.move(x['case_id_a7'],f'SIM_EIGHT_{n}')
        self.assertEqual(self.read()['simulated_pending_count'],8)
    def test_52_no_double_simulate_eight(self):
        self.init()
        for n,x in enumerate(self.gate['cases'][:8]):self.move(x['case_id_a7'],f'SIM_EIGHT_{n}')
        with self.assertRaises(t.SimulatorError):self.move(self.good,'SIM_NINTH')
    def test_53_event_not_operational(self):
        self.init();self.move();self.assertFalse(self.read()['operational_state_mutated'])
    def test_54_get_invalid_request_numerical(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(req=42)
    def test_55_invalid_fault_type(self):
        self.init()
        with self.assertRaises(t.SimulatorError):self.move(fault_before_commit='yes')
    def test_56_source_change_between_operations(self):
        self.init();self.gate['session_id']='OTHER'
        with self.assertRaises(t.SimulatorError):self.read()
    def test_57_simulator_path_is_private_file(self):
        self.init();self.assertEqual(self.db().stat().st_mode & 0o777,0o600)
    def test_58_no_host_external_calls(self):
        self.init();self.move();self.assertEqual(self.read()['operational_transitions_applied'],0)


if __name__=='__main__':unittest.main()
