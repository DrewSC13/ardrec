"""R58-U atomic offline state overlay: adversarial tests, no host/VM/network."""
from __future__ import annotations

from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r58u_counterfactual_pause_recovery as u


def fixture():
    cases = [('case-'+format(n,'02d'),'CASE_'+format(n,'048X'),
              'PENDIENTE' if n < 2 else 'PREPARADO') for n in range(29)]
    gate = {'session_id':'DEV_TUTOR_001','sha256':'a'*64,
            'case_count':29,'family_count':25}
    t1 = {'last_event_sha256':'b'*64,'simulated_t1_count':2,
          'source_gate_sha256':'a'*64, 'simulated_pending_count':2,
          'case_count':29,'operational_transitions_applied':0,
          'operational_state_mutated':False,'operational_dispatch':False,
          'p8_operational':'NO-GO'}
    return cases, gate, t1


PAUSE={'external_wait_registered':'SIM_WAIT_ONE','pause_authorized':'SIM_AUTH_ONE',
       'precedence_resolved':'SIM_PRECEDENCE'}
RESUME={'new_authorization':'SIM_AUTH_TWO','wait_resolved':'SIM_WAIT_ONE',
        'preconditions_valid':'SIM_PRECONDITIONS'}
STOP={'cause_verified':'SIM_STOP_CAUSE','effect_processable':'SIM_EFFECT'}


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-r58u-unit-')
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.roots=[root/x for x in ('overlay','t1','gate','proposal')]
        for p in self.roots:p.mkdir(mode=0o700)
        self.data,self.gate,self.t1=fixture()
        mock1=patch.object(u,'_source',side_effect=lambda *a:(self.gate,self.t1))
        mock2=patch.object(u,'_source_state',side_effect=lambda *a:self.data)
        mock1.start();mock2.start()
        self.addCleanup(mock1.stop);self.addCleanup(mock2.stop)
        self.args=(*self.roots, {}, {}, {}, {})
        self.c0=self.data[0][1];self.c1=self.data[1][1];self.c2=self.data[2][1]

    def init(self): return u.initialize_overlay(*self.args)
    def inspect(self):return u.inspect_overlay(*self.args)
    def change(self,case=None,req='SIM_REQUEST_01',code='T8',refs=None,
               revision=0,cause=None,fault=False):
        if refs is None:refs=PAUSE if code=='T8' else RESUME if code=='T9' else STOP
        return u.simulate_transition(*self.args,case_id_a7=case or self.c0,
                                     request_id=req,transition_code=code,
                                     model_condition_references=refs,
                                     expected_revision=revision,stop_cause=cause,
                                     fault_before_commit=fault)
    def file(self): return u._path(self.roots[0],self.gate)
    def sql(self,statement,args=()):
        c=sqlite3.connect(self.file())
        try:c.execute(statement,args);c.commit()
        finally:c.close()
    def paused(self):
        self.init();return self.change()
    def resumed(self):
        self.paused();return self.change(req='SIM_REQUEST_02',code='T9',revision=1)
    def stopped(self):
        self.resumed();return self.change(req='SIM_REQUEST_03',code='T10',
                                          revision=2,cause='SEGURIDAD')

    def test_01_create(self):
        r=self.init();self.assertEqual(r['persist_status'],'CREATED')
        self.assertEqual(r['case_count'],29)
    def test_02_initial_phases(self):
        r=self.init();self.assertEqual(r['simulated_phase_counts'],
            {'PREPARADO':27,'PENDIENTE':2,'PAUSADO':0,'DETENIDO':0})
    def test_03_initial_head_zero(self):self.assertEqual(self.init()['last_event_sha256'],u.ZERO_SHA)
    def test_04_replay_init(self):self.init();self.assertEqual(self.init()['persist_status'],'REPLAY_IDENTICAL')
    def test_05_first_pause(self):
        r=self.paused();self.assertEqual(r['persist_status'],'COMMITTED_IN_SANDBOX_ONLY')
        self.assertEqual(r['simulated_phase_counts']['PAUSADO'],1)
    def test_06_pause_replay(self):
        self.paused();self.assertEqual(self.change()['persist_status'],'REPLAY_IDENTICAL')
    def test_07_resume(self):
        r=self.resumed();self.assertEqual(r['simulated_phase_counts']['PENDIENTE'],2)
    def test_08_stop(self):
        r=self.stopped();self.assertEqual(r['simulated_phase_counts']['DETENIDO'],1)
    def test_09_history(self):self.assertEqual(self.stopped()['simulated_event_count'],3)
    def test_10_second_connection_recovers(self):
        self.stopped();self.assertEqual(self.inspect()['simulated_event_count'],3)
    def test_11_original_t1_unmodified(self):
        self.stopped();self.assertEqual(self.t1['simulated_t1_count'],2)
    def test_12_operational_no_go(self):
        r=self.stopped();self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertEqual(r['operational_transitions_applied'],0)
        self.assertFalse(r['operational_dispatch'])
    def test_13_no_a6(self):
        r=self.stopped();self.assertEqual(r['a6_classification'],'ND')
        self.assertIsNone(r['confirmed_final_risk'])
    def test_14_no_a9(self):self.assertIsNone(self.stopped()['published_generation'])
    def test_15_pause_requires_pending(self):
        self.init()
        with self.assertRaisesRegex(u.OverlayError,'PAUSE_REQUIRES_PENDING'):
            self.change(self.c2)
    def test_16_resume_requires_paused(self):
        self.init()
        with self.assertRaisesRegex(u.OverlayError,'RESUME_REQUIRES_PAUSED'):
            self.change(code='T9')
    def test_17_stop_prepared_allowed(self):
        self.init();r=self.change(self.c2,code='T10',cause='CONTROL')
        self.assertEqual(r['simulated_phase_counts']['DETENIDO'],1)
    def test_18_stop_while_paused_allowed(self):
        self.paused();r=self.change(req='SIM_STOP',code='T10',revision=1,cause='CONTROL')
        self.assertEqual(r['simulated_phase_counts']['DETENIDO'],1)
    def test_19_terminal_cannot_reenter(self):
        self.stopped()
        with self.assertRaisesRegex(u.OverlayError,'TERMINAL_PHASE_IMMUTABLE'):
            self.change(req='SIM_AFTER_STOP',code='T10',revision=3,cause='CONTROL')
    def test_20_wrong_resume_wait_ref(self):
        self.paused()
        with self.assertRaisesRegex(u.OverlayError,'RESUME_WAIT_REFERENCE_MISMATCH'):
            self.change(req='SIM_WRONG',code='T9',revision=1,
                        refs={**RESUME,'wait_resolved':'SIM_UNKNOWN'})
    def test_21_resume_reuses_auth(self):
        self.paused()
        with self.assertRaisesRegex(u.OverlayError,'RESUME_REQUIRES_DIFFERENT'):
            self.change(req='SIM_WRONG',code='T9',revision=1,
                        refs={**RESUME,'new_authorization':'SIM_AUTH_ONE'})
    def test_22_wrong_revision(self):
        self.paused()
        with self.assertRaisesRegex(u.OverlayError,'MODEL_REVISION_CONFLICT'):
            self.change(req='SIM_WRONG',code='T9',revision=0)
    def test_23_revision_bool(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(revision=False)
    def test_24_request_id_lower(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(req='sim_bad')
    def test_25_unknown_case(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(case='CASE_'+'F'*48)
    def test_26_bad_case_type(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(case=2)
    def test_27_request_replay_change_target(self):
        self.init();self.change()
        with self.assertRaisesRegex(u.OverlayError,'MODEL_REQUEST_REPLAY_CONFLICT'):
            self.change(case=self.c1)
    def test_28_request_replay_change_facts(self):
        self.init();self.change()
        with self.assertRaisesRegex(u.OverlayError,'MODEL_REQUEST_REPLAY_CONFLICT'):
            self.change(refs={**PAUSE,'precedence_resolved':'SIM_OTHER'})
    def test_29_unknown_transition(self):
        self.init()
        with self.assertRaisesRegex(u.OverlayError,'MODEL_FACTS_NOT_EXACT'):
            self.change(code='T2')
    def test_30_extra_facts(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(refs={**PAUSE,'fake':'SIM_X'})
    def test_31_missing_facts(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(refs={'pause_authorized':'SIM_X'})
    def test_32_reference_forgery(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(refs={**PAUSE,'pause_authorized':'verified'})
    def test_33_stop_missing_cause(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(code='T10')
    def test_34_stop_unknown_cause(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(code='T10',cause='PENTEST')
    def test_35_stop_cause_on_pause(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(cause='CONTROL')
    def test_36_injected_rollback(self):
        self.init()
        with self.assertRaisesRegex(u.OverlayError,'INJECTED_ROLLBACK'):
            self.change(fault=True)
        self.assertEqual(self.inspect()['simulated_event_count'],0)
    def test_37_retry_after_rollback(self):
        self.init()
        with self.assertRaises(u.OverlayError):self.change(fault=True)
        self.assertEqual(self.change()['simulated_event_count'],1)
    def test_38_hash_first_event(self):
        self.paused();self.assertNotEqual(self.inspect()['last_event_sha256'],u.ZERO_SHA)
    def test_39_hash_tamper(self):
        self.paused();self.sql('UPDATE events SET sha=?',('a'*64,))
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_40_prev_hash_tamper(self):
        self.paused();self.sql('UPDATE events SET prev_sha=?',('a'*64,))
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_41_state_tamper(self):
        self.paused();self.sql("UPDATE cases SET phase='DETENIDO'")
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_42_revision_tamper(self):
        self.paused();self.sql('UPDATE cases SET revision=0')
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_43_meta_sha_tamper(self):
        self.init();self.sql('UPDATE meta SET t1_head=?',('f'*64,))
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_44_source_t1_drift(self):
        self.init();self.t1['last_event_sha256']='f'*64
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_45_source_gate_drift(self):
        self.init();self.gate['sha256']='f'*64
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_46_db_mode(self):
        self.init();os.chmod(self.file(),0o644)
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_47_db_symlink(self):
        self.init();p=self.file();backup=p.with_suffix('.backup');p.rename(backup);p.symlink_to(backup)
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_48_root_mode(self):
        self.init();os.chmod(self.roots[0],0o755)
        with self.assertRaises(ValueError):self.inspect()
    def test_49_root_alias(self):
        self.init();self.args=(self.roots[1],*self.roots[1:4],{},{},{},{})
        with self.assertRaises(ValueError):self.inspect()
    def test_50_extra_table(self):
        self.init();self.sql('CREATE TABLE fake(x TEXT)')
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_51_duplicate_meta(self):
        self.init();self.sql('INSERT INTO meta SELECT * FROM meta')
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_52_bad_event_ref_tamper(self):
        self.paused();self.sql('UPDATE events SET reference_json=?',('{}',))
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_53_wrong_event_order(self):
        self.stopped();self.sql('UPDATE events SET seq=7 WHERE seq=2')
        with self.assertRaises(u.OverlayError):self.inspect()
    def test_54_duplicate_request(self):
        self.paused()
        with self.assertRaises(u.OverlayError):self.change(req='SIM_REQUEST_01',code='T10',revision=1,cause='CONTROL')
    def test_55_model_event_budget(self):
        self.init()
        self.change()
        for n in range(3):
            self.change(req=f'SIM_RES_{n}',code='T9',revision=1+n*2,
                        refs={**RESUME,'new_authorization':f'SIM_AUTH_RES_{n}'})
            if n < 2:
                self.change(req=f'SIM_PAUSE_{n}',code='T8',revision=2+n*2,
                            refs={**PAUSE,'pause_authorized':f'SIM_AUTH_PAUSE_{n}'})
        self.assertEqual(self.inspect()['simulated_event_count'],6)
    def test_56_no_network(self):
        self.init();self.change();self.assertEqual(self.inspect()['operational_dispatch'],False)
    def test_57_counts_other_case_unchanged(self):
        self.paused();self.assertEqual(self.inspect()['simulated_phase_counts']['PREPARADO'],27)
    def test_58_stop_is_absorbing(self):
        self.stopped()
        with self.assertRaises(u.OverlayError):
            self.change(req='SIM_RESUME_STOPPED',code='T9',revision=3)


if __name__ == '__main__':unittest.main()
