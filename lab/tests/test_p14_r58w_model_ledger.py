"""R58-W isolated deterministic cases. Full catalog is tested by CLI in CI."""
from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import os
import sqlite3
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from ardrec.analytics.exact_preview import digest
from ardrec.coordination import r58w_declared_a5_model_ledger as w


def fixture() -> dict:
    cases=[]
    for i in range(29):
        phase=('PENDIENTE' if i==0 else 'DETENIDO' if i==1 else 'PREPARADO')
        cases.append({'case_id_a7':'CASE_'+format(i+1,'048X'),
                      'current_model_phase':phase,
                      'logical_candidate':i<8,
                      'model_a5_disposition':('MODEL_PENDING_REVIEW_ONLY_NO_DISPATCH'
                          if phase=='PENDIENTE' else 'MODEL_TERMINAL_NO_ATTEMPT'
                          if phase=='DETENIDO' else 'MODEL_PREPARED_NO_ATTEMPT'),
                      'deny_reason':('INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED'
                                     if i<8 else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE'),
                      'a5_intent_submitted':False,'a5_start_count':0,
                      'a6_classification':'ND','evidence_accredited':False})
    d={'schema':'ardrec-r58v-sandbox-a5-a6-readonly-handoff-v1',
       'mode':'OFFLINE_HANDOFF_NO_ATTEMPT_NO_EVIDENCE',
       'session_id':'DEV_TUTOR_001','case_count':29,'family_count':25,
       'source_r58s_deny_sha256':'a'*64,'source_t1_event_count':2,
       'source_overlay_event_count':3,'model_a5_review_candidate_count':1,
       'simulated_phase_counts':{'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1},
       'cases':cases,'all_source_requests_denied':True,'a5_status':'NOT_SUBMITTED_NO_START',
       'a5_intents_submitted':0,'a5_attempts_reserved':0,'a5_attempts_started':0,
       'a6_accredited_evidence_count':0,'a6_classification':'ND',
       'technical_truth_accredited':False,'confirmed_final_risk':None,
       'published_generation':None,'operational_transitions_applied':0,
       'operational_dispatch':False,'p8_operational':'NO-GO'}
    d['sha256']=digest(d)
    return d


class ModelLedgerTests(unittest.TestCase):
    def setUp(self):
        temp=TemporaryDirectory(prefix='r58w-unit-')
        self.addCleanup(temp.cleanup)
        path=Path(temp.name)
        self.directories=[path/name for name in ('model','handoff','overlay','sim','gate','proposal')]
        for directory in self.directories:directory.mkdir(mode=0o700)
        self.report=fixture()
        self.source=(*self.directories[2:],{},{},{},{})
        self.args=(self.directories[0],self.directories[1],*self.source)
        src=patch.object(w,'build_handoff',side_effect=lambda *args:self.report)
        verify=patch.object(w,'verify_persisted_handoff',side_effect=lambda *args:{
            'verification':'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6',
            'receipt_sha256':self.report['sha256'],'a5_attempts_started':0,
            'a6_classification':'ND','operational_dispatch':False,
            'p8_operational':'NO-GO'})
        for p in (src,verify):p.start();self.addCleanup(p.stop)
        self.good=self.report['cases'][0]['case_id_a7']
        self.bad=self.report['cases'][1]['case_id_a7']

    def init(self):return w.initialize_model_ledger(*self.args)
    def status(self):return w.inspect_model_ledger(*self.args)
    def declare(self,**kw):
        options={'case_id_a7':self.good,'request_id':'SIM_TEST_DECLARE'}
        options.update(kw)
        return w.declare_model_intent(*self.args,**options)
    def resolve(self,**kw):
        options={'case_id_a7':self.good,'request_id':'SIM_TEST_RESOLVE'}
        options.update(kw)
        return w.resolve_model_no_start(*self.args,**options)
    def path(self):return w._path(self.directories[0],self.report)
    def mutate(self,sql,values=()):
        db=sqlite3.connect(self.path())
        try:db.execute(sql,values);db.commit()
        finally:db.close()

    def test_01_initial_created(self):self.assertEqual(self.init()['persist_status'],'CREATED')
    def test_02_initial_replay(self):
        self.init();self.assertEqual(self.init()['persist_status'],'REPLAY_IDENTICAL')
    def test_03_initial_zero_events(self):self.assertEqual(self.init()['model_event_count'],0)
    def test_04_initial_zero_declared(self):self.assertEqual(self.init()['model_intents_declared'],0)
    def test_05_initial_zero_open(self):self.assertEqual(self.init()['model_intents_open'],0)
    def test_06_initial_no_resolutions(self):self.assertEqual(self.init()['model_no_start_resolutions'],0)
    def test_07_initial_chain_zero(self):self.assertEqual(self.init()['last_event_sha256'],w.ZERO)
    def test_08_initial_count(self):self.assertEqual(self.init()['case_count'],29)
    def test_09_initial_family_count(self):self.assertEqual(self.init()['family_count'],25)
    def test_10_initial_candidate_count(self):self.assertEqual(self.init()['model_review_candidate_count'],1)
    def test_11_declare(self):
        self.init();self.assertEqual(self.declare()['persist_status'],'COMMITTED_IN_MODEL_ONLY')
    def test_12_declare_open(self):
        self.init();self.declare();self.assertEqual(self.status()['model_intents_open'],1)
    def test_13_declare_count(self):
        self.init();self.declare();self.assertEqual(self.status()['model_intents_declared'],1)
    def test_14_declare_one_event(self):
        self.init();self.declare();self.assertEqual(self.status()['model_event_count'],1)
    def test_15_declare_replay(self):
        self.init();self.declare();self.assertEqual(self.declare()['persist_status'],'REPLAY_IDENTICAL')
    def test_16_declare_second_request_same_case_rejected(self):
        self.init();self.declare()
        with self.assertRaisesRegex(w.ModelIntentError,'MODEL_INTENT_ALREADY_EXISTS'):self.declare(request_id='SIM_ANOTHER')
    def test_17_resolve_without_declare_rejected(self):
        self.init()
        with self.assertRaisesRegex(w.ModelIntentError,'MODEL_INTENT_NOT_OPEN'):self.resolve()
    def test_18_resolve_after_declare(self):
        self.init();self.declare();self.assertEqual(self.resolve()['persist_status'],'COMMITTED_IN_MODEL_ONLY')
    def test_19_resolve_zero_open(self):
        self.init();self.declare();self.resolve();self.assertEqual(self.status()['model_intents_open'],0)
    def test_20_resolve_one(self):
        self.init();self.declare();self.resolve();self.assertEqual(self.status()['model_no_start_resolutions'],1)
    def test_21_two_events(self):
        self.init();self.declare();self.resolve();self.assertEqual(self.status()['model_event_count'],2)
    def test_22_resolve_replay(self):
        self.init();self.declare();self.resolve();self.assertEqual(self.resolve()['persist_status'],'REPLAY_IDENTICAL')
    def test_23_resolve_new_request_same_case_rejected(self):
        self.init();self.declare();self.resolve()
        with self.assertRaisesRegex(w.ModelIntentError,'MODEL_INTENT_NOT_OPEN'):self.resolve(request_id='SIM_NEW')
    def test_24_replay_request_wrong_case(self):
        self.init();self.declare()
        with self.assertRaises(w.ModelIntentError):self.resolve(request_id='SIM_TEST_DECLARE',case_id_a7=self.bad)
    def test_25_ineligible_case_declared_rejected(self):
        self.init()
        with self.assertRaisesRegex(w.ModelIntentError,'MODEL_CASE_NOT_PENDING'):self.declare(case_id_a7=self.bad)
    def test_26_unknown_case_rejected(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(case_id_a7='CASE_'+'F'*48)
    def test_27_invalid_request(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(request_id='bad')
    def test_28_empty_request(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(request_id='')
    def test_29_invalid_request_type(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(request_id=23)
    def test_30_bool_fault_rejected(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(fault_before_commit='yes')
    def test_31_fault_rolls_back_declaration(self):
        self.init()
        with self.assertRaisesRegex(w.ModelIntentError,'INJECTED_MODEL_ROLLBACK'):self.declare(fault_before_commit=True)
        self.assertEqual(self.status()['model_event_count'],0)
    def test_32_fault_then_retry_declaration(self):
        self.init()
        with self.assertRaises(w.ModelIntentError):self.declare(fault_before_commit=True)
        self.assertEqual(self.declare()['model_event_count'],1)
    def test_33_fault_rolls_back_resolution(self):
        self.init();self.declare()
        with self.assertRaises(w.ModelIntentError):self.resolve(fault_before_commit=True)
        self.assertEqual(self.status()['model_intents_open'],1)
    def test_34_fault_then_retry_resolution(self):
        self.init();self.declare()
        with self.assertRaises(w.ModelIntentError):self.resolve(fault_before_commit=True)
        self.assertEqual(self.resolve()['model_no_start_resolutions'],1)
    def test_35_tamper_event_hash(self):
        self.init();self.declare();self.mutate("UPDATE events SET sha='"+'f'*64+"'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_36_tamper_prev_hash(self):
        self.init();self.declare();self.mutate("UPDATE events SET prev_sha='"+'f'*64+"'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_37_tamper_request(self):
        self.init();self.declare();self.mutate("UPDATE events SET request_id='SIM_FORGED'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_38_tamper_materialized_status(self):
        self.init();self.declare();self.mutate("UPDATE intents SET status='RESOLVED_NO_START'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_39_tamper_materialized_declaration(self):
        self.init();self.declare();self.mutate("UPDATE intents SET declare_request='SIM_FORGED'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_40_tamper_meta(self):
        self.init();self.mutate("UPDATE meta SET handoff_sha='"+'f'*64+"'")
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_41_extra_table(self):
        self.init();self.mutate('CREATE TABLE malicious (x TEXT)')
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_42_extra_meta_row(self):
        self.init();self.mutate('INSERT INTO meta SELECT * FROM meta')
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_43_invalid_file_mode(self):
        self.init();os.chmod(self.path(),0o644)
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_44_root_too_permissive(self):
        self.init();os.chmod(self.directories[0],0o755)
        with self.assertRaises(ValueError):self.status()
    def test_45_root_overlap(self):
        args=(self.directories[1],self.directories[1],*self.source)
        with self.assertRaises(w.ModelIntentError):w.initialize_model_ledger(*args)
    def test_46_symlink_db(self):
        self.init();original=self.path();moved=original.with_suffix('.saved');original.rename(moved);original.symlink_to(moved)
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_47_false_source_authority(self):
        self.report['operational_dispatch']=True
        self.report['sha256']=digest({k:v for k,v in self.report.items() if k!='sha256'})
        with self.assertRaises(w.ModelIntentError):self.init()
    def test_48_false_source_a6(self):
        self.report['a6_classification']='VERDADERO'
        self.report['sha256']=digest({k:v for k,v in self.report.items() if k!='sha256'})
        with self.assertRaises(w.ModelIntentError):self.init()
    def test_49_false_source_start(self):
        self.report['a5_attempts_started']=1
        self.report['sha256']=digest({k:v for k,v in self.report.items() if k!='sha256'})
        with self.assertRaises(w.ModelIntentError):self.init()
    def test_50_source_sha_change(self):
        self.init();self.report['case_count']=28
        self.report['sha256']=digest({k:v for k,v in self.report.items() if k!='sha256'})
        with self.assertRaises(w.ModelIntentError):self.status()
    def test_51_no_operational_attempts(self):
        self.init();self.declare();self.resolve()
        self.assertEqual(self.status()['a5_attempts_started'],0)
    def test_52_no_operational_reservation(self):
        self.init();self.declare();self.resolve()
        self.assertEqual(self.status()['a5_operational_reservations'],0)
    def test_53_no_a6_accreditation(self):
        self.init();self.declare();self.resolve()
        self.assertEqual(self.status()['a6_accredited_evidence_count'],0)
    def test_54_a6_nd(self):
        self.init();self.declare();self.resolve()
        self.assertEqual(self.status()['a6_classification'],'ND')
    def test_55_no_published_generation(self):
        self.init();self.declare();self.resolve()
        self.assertIsNone(self.status()['published_generation'])
    def test_56_p8_no_go(self):
        self.init();self.declare();self.resolve()
        self.assertEqual(self.status()['p8_operational'],'NO-GO')
    def test_57_no_operational_dispatch(self):
        self.init();self.declare();self.resolve()
        self.assertFalse(self.status()['operational_dispatch'])
    def test_58_deterministic_sha(self):
        self.init();self.declare();self.resolve()
        x=self.status();self.assertNotEqual(x['last_event_sha256'],w.ZERO)
        self.assertEqual(x,self.status())
    def test_59_private_file(self):
        self.init();self.assertEqual(self.path().stat().st_mode & 0o777,0o600)
    def test_60_one_db(self):
        self.init();self.init();self.assertEqual(len(list(self.directories[0].iterdir())),1)



class VerifiedBatchTests(unittest.TestCase):
    """Real file-byte fingerprint invalidation and bounded full verification."""

    def setUp(self):
        temp = TemporaryDirectory(prefix='r58w-batch-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.dirs = [root/name for name in
                     ('model','handoff','overlay','t1','gate','proposal')]
        for directory in self.dirs:
            directory.mkdir(mode=0o700)
        self.contents = []
        for idx, directory in enumerate(self.dirs[1:]):
            file = directory / ('private_%d.dat' % idx)
            file.write_bytes(b'fixed-private-source-%d' % idx)
            os.chmod(file, 0o600)
            self.contents.append(file)
        self.report = fixture()
        self.documents = ({},{},{},{})
        self.args = (self.dirs[0],self.dirs[1],*self.dirs[2:],*self.documents)
        self.p1 = patch.object(w,'build_handoff',side_effect=lambda *args:self.report)
        self.p2 = patch.object(w,'verify_persisted_handoff',side_effect=lambda *args:{
            'verification':'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6',
            'receipt_sha256':self.report['sha256'],'a5_attempts_started':0,
            'a6_classification':'ND','operational_dispatch':False,
            'p8_operational':'NO-GO'})
        self.spy_build = self.p1.start()
        self.spy_verify = self.p2.start()
        self.addCleanup(self.p1.stop)
        self.addCleanup(self.p2.stop)
        self.good = self.report['cases'][0]['case_id_a7']

    def test_batch_no_recursive_full_source_per_operation(self):
        with w.verified_model_source_batch(*self.args):
            w.initialize_model_ledger(*self.args)
            w.initialize_model_ledger(*self.args)
            w.declare_model_intent(*self.args,case_id_a7=self.good,
                                   request_id='SIM_BATCH_DECLARE')
            w.resolve_model_no_start(*self.args,case_id_a7=self.good,
                                     request_id='SIM_BATCH_RESOLVE')
            final = w.inspect_model_ledger(*self.args)
            self.assertEqual(final['model_event_count'],2)
        self.assertEqual(self.spy_build.call_count,1)
        self.assertEqual(self.spy_verify.call_count,1)

    def test_outside_batch_each_action_verifies_again(self):
        w.initialize_model_ledger(*self.args)
        w.inspect_model_ledger(*self.args)
        self.assertEqual(self.spy_build.call_count,2)
        self.assertEqual(self.spy_verify.call_count,2)

    def test_changed_source_bytes_denied(self):
        with self.assertRaisesRegex(w.ModelIntentError,'BATCH_SOURCE_CHANGED'):
            with w.verified_model_source_batch(*self.args):
                w.initialize_model_ledger(*self.args)
                self.contents[0].write_bytes(b'changed')
                w.inspect_model_ledger(*self.args)

    def test_source_inventory_added_denied(self):
        with self.assertRaises(w.ModelIntentError):
            with w.verified_model_source_batch(*self.args):
                extra = self.dirs[2] / 'unexpected.dat'
                extra.write_bytes(b'unexpected')
                os.chmod(extra,0o600)
                w.initialize_model_ledger(*self.args)

    def test_source_file_permission_changed_denied(self):
        with self.assertRaises(w.ModelIntentError):
            with w.verified_model_source_batch(*self.args):
                os.chmod(self.contents[1],0o644)
                w.initialize_model_ledger(*self.args)

    def test_cannot_nest_batch(self):
        with w.verified_model_source_batch(*self.args):
            with self.assertRaisesRegex(w.ModelIntentError,'BATCH_NESTING'):
                with w.verified_model_source_batch(*self.args):
                    pass

    def test_reset_after_normal_exit(self):
        with w.verified_model_source_batch(*self.args):
            w.initialize_model_ledger(*self.args)
        w.inspect_model_ledger(*self.args)
        self.assertEqual(self.spy_verify.call_count,2)

    def test_reset_after_error(self):
        with self.assertRaisesRegex(RuntimeError,'synthetic-fault'):
            with w.verified_model_source_batch(*self.args):
                raise RuntimeError('synthetic-fault')
        self.assertIsNone(w._VERIFIED_BATCH.get())

    def test_batch_rejects_model_root_switch(self):
        with w.verified_model_source_batch(*self.args):
            with self.assertRaisesRegex(w.ModelIntentError,'BATCH_MODEL'):
                w.initialize_model_ledger(self.dirs[1], *self.args[1:])

    def test_no_change_to_source_during_ledger_commits(self):
        before=w._source_fingerprint(self.args[1],self.args[2:])
        with w.verified_model_source_batch(*self.args):
            w.initialize_model_ledger(*self.args)
            w.declare_model_intent(*self.args,case_id_a7=self.good,
                                   request_id='SIM_BATCH_DECLARE')
        self.assertEqual(before,w._source_fingerprint(self.args[1],self.args[2:]))

    def test_document_content_mutation_denied(self):
        mutable={'changeable':[1]}
        args=(*self.args[:6],mutable,*self.args[7:])
        with self.assertRaises(w.ModelIntentError):
            with w.verified_model_source_batch(*args):
                mutable['changeable'].append(2)
                w.initialize_model_ledger(*args)

    def test_symlink_source_denied(self):
        link = self.dirs[2] / 'fake_symlink'
        link.symlink_to(self.contents[0])
        with self.assertRaises(w.ModelIntentError):
            with w.verified_model_source_batch(*self.args):
                pass

if __name__=='__main__':unittest.main()
