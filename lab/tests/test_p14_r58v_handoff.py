"""R58-V: adversarial tests for read-only A5/A6 handoff of offline T1/overlay."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ardrec.analytics.exact_preview import digest
from ardrec.coordination import r58v_a5_a6_readonly_handoff as v


def sample():
    gate_cases=[]
    initial=[]
    for i in range(29):
        row={
            'service_id':'SSH_DEV' if i<8 else 'FTP_DEV' if i<18 else 'SMB_DEV',
            'session_id':'DEV_TUTOR_001','derived_case_id':f'DERIVED_{i:03d}',
            'assessment_index':0,'family_id':f'FAMILY_{i%25:02d}',
            'case_id_a7':'CASE_'+format(i,'048X'),
            'logical_candidate':i<8,
            'deny_reason': ('INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED'
                            if i<8 else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE'),
            'review_outcome':'DENIED','state_committed':None,
            'independent_authority_attested':False,'signed_approval_attested':False,
            'transition_commit_attested':False,
            'a3_guard_truth':'VERDADERO' if i<8 else 'ND',
        }
        gate_cases.append(row)
        initial.append((v.t._key(row),row['case_id_a7'],
                        'PENDIENTE' if i<2 else 'PREPARADO'))
    gate={'session_id':'DEV_TUTOR_001','sha256':'a'*64,'case_count':29,
          'family_count':25,'all_requests_denied':True,
          'operational_dispatch':False,'a6_classification':'ND',
          'state_machine_mutated':False,'p8_operational':'NO-GO','cases':gate_cases}
    t1={'last_event_sha256':'b'*64,'simulated_t1_count':2}
    overlay={'schema':v.u.SCHEMA,'mode':v.u.MODE,'case_count':29,
             'source_gate_sha256':'a'*64,'source_t1_head_sha256':'b'*64,
             'last_event_sha256':'c'*64,'simulated_event_count':3,
             'simulated_phase_counts':{'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1},
             'operational_transitions_applied':0,'operational_state_mutated':False,
             'operational_dispatch':False,'a6_classification':'ND',
             'confirmed_final_risk':None,'published_generation':None,'p8_operational':'NO-GO'}
    review={'source_catalog_sha256':'d'*64,'source_thesis_sha256':'e'*64}
    return gate,t1,overlay,initial,review


class HandoffTests(unittest.TestCase):
    def setUp(self):
        work=tempfile.TemporaryDirectory(prefix='r58v-unit-')
        self.addCleanup(work.cleanup)
        root=Path(work.name)
        self.roots=[root/item for item in ('overlay','t1','gate','proposal')]
        self.dest=root/'receipt'
        for p in (*self.roots,self.dest):p.mkdir(mode=0o700)
        self.gate,self.t1,self.overlay,self.initial,self.review=sample()
        self.path=v.u._path(self.roots[0],self.gate)
        con=sqlite3.connect(self.path)
        try:
            con.execute('CREATE TABLE cases(case_key TEXT,case_id TEXT,initial_phase TEXT,phase TEXT,revision INTEGER)')
            for i,(key,cid,first) in enumerate(self.initial):
                phase='DETENIDO' if i==0 else first
                rev=3 if i==0 else 0
                con.execute('INSERT INTO cases VALUES(?,?,?,?,?)',(key,cid,first,phase,rev))
            con.commit()
        finally:con.close()
        os.chmod(self.path,0o600)
        self.fake=patch.object(v.u,'_context',side_effect=lambda *args:(self.gate,self.t1,self.initial,self.path))
        self.fake2=patch.object(v.u,'inspect_overlay',side_effect=lambda *args:self.overlay)
        self.fake3=patch.object(v.t,'inspect_simulator',side_effect=lambda *args:self.t1)
        for item in (self.fake,self.fake2,self.fake3):
            item.start()
            self.addCleanup(item.stop)
        self.args=(*self.roots,{}, {},self.review,{})

    def report(self):return v.build_handoff(*self.args)
    def persist(self):return v.persist_handoff(self.dest,*self.args)
    def verify(self):return v.verify_persisted_handoff(self.dest,*self.args)
    def mutate_sql(self,statement,values=()):
        con=sqlite3.connect(self.path)
        try:con.execute(statement,values);con.commit()
        finally:con.close()

    def test_01_basic_schema(self):self.assertEqual(self.report()['schema'],v.SCHEMA)
    def test_02_count(self):self.assertEqual(self.report()['case_count'],29)
    def test_03_family_count(self):self.assertEqual(self.report()['family_count'],25)
    def test_04_phases(self):self.assertEqual(self.report()['simulated_phase_counts'],self.overlay['simulated_phase_counts'])
    def test_05_pending(self):self.assertEqual(self.report()['model_a5_review_candidate_count'],1)
    def test_06_no_submitted(self):self.assertEqual(self.report()['a5_intents_submitted'],0)
    def test_07_no_reserved(self):self.assertEqual(self.report()['a5_attempts_reserved'],0)
    def test_08_no_started(self):self.assertEqual(self.report()['a5_attempts_started'],0)
    def test_09_no_accreditation(self):self.assertEqual(self.report()['a6_accredited_evidence_count'],0)
    def test_10_a6_nd(self):self.assertEqual(self.report()['a6_classification'],'ND')
    def test_11_no_risk(self):self.assertIsNone(self.report()['confirmed_final_risk'])
    def test_12_no_generation(self):self.assertIsNone(self.report()['published_generation'])
    def test_13_p8_no_go(self):self.assertEqual(self.report()['p8_operational'],'NO-GO')
    def test_14_no_operational(self):self.assertFalse(self.report()['operational_dispatch'])
    def test_15_reproducible(self):self.assertEqual(self.report(),self.report())
    def test_16_verify_exact(self):self.assertTrue(v.verify_handoff(self.report(),*self.args))
    def test_17_verify_forged_sha(self):
        report=self.report();report['sha256']='f'*64
        with self.assertRaises(v.HandoffError):v.verify_handoff(report,*self.args)
    def test_18_verify_forged_a6(self):
        report=self.report();report['a6_classification']='VERDADERO';report['sha256']=digest({k:val for k,val in report.items() if k!='sha256'})
        with self.assertRaises(v.HandoffError):v.verify_handoff(report,*self.args)
    def test_19_verify_forged_dispatch(self):
        report=self.report();report['operational_dispatch']=True;report['sha256']=digest({k:val for k,val in report.items() if k!='sha256'})
        with self.assertRaises(v.HandoffError):v.verify_handoff(report,*self.args)
    def test_20_first_persist(self):self.assertEqual(self.persist()['persist_status'],'CREATED')
    def test_21_replay(self):
        self.persist();self.assertEqual(self.persist()['persist_status'],'REPLAY_IDENTICAL')
    def test_22_verified_receipt(self):
        self.persist();self.assertEqual(self.verify()['verification'],'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6')
    def test_23_only_one_receipt(self):
        self.persist();self.persist();self.assertEqual(len(list(self.dest.iterdir())),1)
    def test_24_reject_source_new_event(self):
        self.persist();self.overlay['last_event_sha256']='f'*64
        with self.assertRaises(v.HandoffError):self.verify()
    def test_25_reject_source_t1_change(self):
        self.persist();self.t1['last_event_sha256']='f'*64
        with self.assertRaises(v.HandoffError):self.verify()
    def test_26_reject_source_case_change(self):
        self.persist();self.mutate_sql("UPDATE cases SET phase='PAUSADO' WHERE phase='PENDIENTE'")
        with self.assertRaises(v.HandoffError):self.verify()
    def test_27_reject_case_revision_change(self):
        self.mutate_sql('UPDATE cases SET revision=7 WHERE revision=0')
        with self.assertRaises(v.HandoffError):self.report()
    def test_28_reject_duplicate_identity(self):
        self.gate['cases'].append(self.gate['cases'][0]);self.gate['case_count']+=1
        with self.assertRaises(v.HandoffError):self.report()
    def test_29_reject_false_gate(self):
        self.gate['all_requests_denied']=False
        with self.assertRaises(v.HandoffError):self.report()
    def test_30_reject_false_gate_approval(self):
        self.gate['cases'][0]['signed_approval_attested']=True
        with self.assertRaises(v.HandoffError):self.report()
    def test_31_reject_false_model_authority(self):
        self.overlay['operational_dispatch']=True
        with self.assertRaises(v.HandoffError):self.report()
    def test_32_reject_bad_case_id(self):
        self.gate['cases'][0]['case_id_a7']='CASE_BAD'
        with self.assertRaises(v.HandoffError):self.report()
    def test_33_reject_unsafe_root(self):
        os.chmod(self.roots[0],0o755)
        with self.assertRaises(ValueError):self.report()
    def test_34_reject_readonly_root_as_receipt(self):
        with self.assertRaises(v.HandoffError):v.persist_handoff(self.roots[0],*self.args)
    def test_35_reject_symlink_receipt(self):
        target=v._record_path(self.dest,'DEV_TUTOR_001')
        target.symlink_to(self.path)
        with self.assertRaises(v.HandoffError):self.persist()
    def test_36_reject_changed_receipt_content(self):
        self.persist();target=v._record_path(self.dest,'DEV_TUTOR_001')
        target.write_bytes(b'changed')
        with self.assertRaises(v.HandoffError):self.verify()
    def test_37_reject_duplicate_json_key(self):
        self.persist();target=v._record_path(self.dest,'DEV_TUTOR_001')
        target.write_bytes(b'{"a":1,"a":2}\n')
        with self.assertRaises(v.HandoffError):self.verify()
    def test_38_reject_receipt_world_readable(self):
        self.persist();target=v._record_path(self.dest,'DEV_TUTOR_001')
        os.chmod(target,0o644)
        with self.assertRaises(ValueError):self.verify()
    def test_39_reject_overlay_db_world_readable(self):
        os.chmod(self.path,0o644)
        with self.assertRaises(v.HandoffError):self.report()
    def test_40_readonly_source_permission(self):
        self.report();self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
    def test_41_no_source_write(self):
        before=self.path.stat();self.report();after=self.path.stat()
        self.assertEqual((before.st_size,before.st_mtime_ns),(after.st_size,after.st_mtime_ns))
    def test_42_reject_unknown_phase(self):
        self.mutate_sql("UPDATE cases SET phase='ACTIVO' WHERE phase='PENDIENTE'")
        with self.assertRaises(v.HandoffError):self.report()
    def test_43_reject_phase_noneligible(self):
        self.mutate_sql("UPDATE cases SET phase='PENDIENTE' WHERE initial_phase='PREPARADO'")
        with self.assertRaises(v.HandoffError):self.report()
    def test_44_reject_case_key_mismatch(self):
        self.mutate_sql("UPDATE cases SET case_key='X' WHERE revision=3")
        with self.assertRaises(v.HandoffError):self.report()
    def test_45_reject_empty_review_source(self):
        self.review['source_catalog_sha256']='BAD'
        with self.assertRaises(v.HandoffError):self.report()
    def test_46_reject_bad_session(self):
        self.gate['session_id']='../../bad'
        with self.assertRaises(v.HandoffError):self.persist()
    def test_47_reject_model_count(self):
        self.overlay['simulated_phase_counts']['PENDIENTE']=2
        with self.assertRaises(v.HandoffError):self.report()
    def test_48_receipt_hash(self):
        self.persist();vfy=self.verify();self.assertEqual(vfy['receipt_sha256'],self.report()['sha256'])
    def test_49_distinct_states(self):
        cases=self.report()['cases']
        self.assertEqual(sum(x['current_model_phase']=='DETENIDO' for x in cases),1)
        self.assertEqual(sum(x['current_model_phase']=='PENDIENTE' for x in cases),1)
    def test_50_no_case_started(self):
        self.assertTrue(all(x['a5_start_count']==0 for x in self.report()['cases']))

if __name__=='__main__':unittest.main()
