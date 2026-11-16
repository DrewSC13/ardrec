"""R58-X: A5 no-start cannot be A6 evidence; A7 must stay an exact interval."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import os
import sqlite3
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
from ardrec.analytics.exact_preview import digest
from ardrec.coordination import r58w_declared_a5_model_ledger as w
from ardrec.coordination import r58x_no_start_a6_a7_envelope as x


def fixed_scenario():
    return {'format':'ardrec-p14-r26-fixed-three-service-scenario-v1',
            'session_id':'DEV_TUTOR_001','services':[
         {'id':'SSH_DEV','protocol':'SSH','fact':'VERDADERO','initial_risk':'1/4','normalized_criticality':'1/2'},
         {'id':'FTP_DEV','protocol':'FTP','fact':'AUSENTE','initial_risk':'1/4','normalized_criticality':'1/2'},
         {'id':'SMB_DEV','protocol':'SMB','fact':'FALSO','initial_risk':'1/4','normalized_criticality':'1/2'}]}


def fixture():
    cases=[]
    for i in range(29):
        protocol=('SSH_DEV' if i<8 else 'FTP_DEV' if i<18 else 'SMB_DEV')
        phase='PENDIENTE' if i==0 else 'DETENIDO' if i==1 else 'PREPARADO'
        cases.append({'case_id_a7':'CASE_'+format(i+1,'048X'),
            'service_id':protocol,'session_id':'DEV_TUTOR_001',
            'derived_case_id':'DERIVED_'+format(i,'04d'),
            'assessment_index':0,'family_id':'FAMILY_'+format(i%25,'02d'),
            'current_model_phase':phase,'logical_candidate':i<8,
            'model_a5_disposition':('MODEL_PENDING_REVIEW_ONLY_NO_DISPATCH'
                if phase=='PENDIENTE' else 'MODEL_TERMINAL_NO_ATTEMPT'
                if phase=='DETENIDO' else 'MODEL_PREPARED_NO_ATTEMPT'),
            'deny_reason':('INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED'
                if i<8 else 'CASE_NOT_A3_LOGICALLY_ELIGIBLE'),
            'a5_intent_submitted':False,'a5_start_count':0,
            'a6_classification':'ND','evidence_accredited':False})
    doc={'schema':'ardrec-r58v-sandbox-a5-a6-readonly-handoff-v1',
      'mode':'OFFLINE_HANDOFF_NO_ATTEMPT_NO_EVIDENCE',
      'session_id':'DEV_TUTOR_001','case_count':29,'family_count':25,
      'source_r58s_deny_sha256':'a'*64,
      'source_catalog_sha256':'b'*64,'source_thesis_sha256':'c'*64,
      'model_a5_review_candidate_count':1,
      'simulated_phase_counts':{'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1},
      'cases':cases,'all_source_requests_denied':True,
      'a6_classification':'ND','a6_accredited_evidence_count':0,
      'a5_attempts_started':0,'a5_intents_submitted':0,
      'a5_attempts_reserved':0,'operational_dispatch':False,
      'p8_operational':'NO-GO'}
    doc['sha256']=digest(doc)
    return doc


class NoStartEnvelopeTests(unittest.TestCase):
    def setUp(self):
        work=TemporaryDirectory(prefix='ardrec-r58x-unit-')
        self.addCleanup(work.cleanup)
        root=Path(work.name)
        self.dirs=[root/name for name in ('model','handoff','overlay','t1','gate','proposal')]
        for p in self.dirs:p.mkdir(mode=0o700)
        self.handoff=fixture()
        self.scenario=fixed_scenario()
        self.source=(*self.dirs[2:],{},self.scenario,{}, {})
        self.args=(self.dirs[0],self.dirs[1],*self.source)
        p=patch.object(w,'_source',side_effect=lambda *a:self.handoff)
        p.start();self.addCleanup(p.stop)
        w.initialize_model_ledger(*self.args)
        self.cid=self.handoff['cases'][0]['case_id_a7']

    def apply(self):
        w.declare_model_intent(*self.args,case_id_a7=self.cid,request_id='SIM_X_DECLARE')
        w.resolve_model_no_start(*self.args,case_id_a7=self.cid,request_id='SIM_X_RESOLVE')

    def report(self):return x.build_no_start_envelope(*self.args)

    def mutate(self,sql,args=()):
        db=sqlite3.connect(w._path(self.dirs[0],self.handoff))
        try:db.execute(sql,args);db.commit()
        finally:db.close()

    def test_01_initial_no_start_zero(self):
        self.assertEqual(self.report()['model_no_start_case_count'],0)
    def test_02_initial_29_cases(self):
        self.assertEqual(self.report()['case_count'],29)
    def test_03_initial_25_families(self):
        self.assertEqual(self.report()['family_count'],25)
    def test_04_initial_29_nd(self):
        self.assertEqual(self.report()['a6_unaccredited_count'],29)
    def test_05_all_missing_admissions(self):
        self.assertTrue(all(c['a7_evidence_status']=='FULLY_UNRESOLVED_MATHEMATICAL_ONLY' for c in self.report()['cases']))
    def test_06_math_lower(self):
        self.assertEqual({c['a7_rf_lower'] for c in self.report()['cases']},{'1/4'})
    def test_07_math_upper(self):
        self.assertEqual({c['a7_rf_upper'] for c in self.report()['cases']},{'7/12'})
    def test_08_math_no_point(self):
        self.assertTrue(all(c['a7_rf_lower']!=c['a7_rf_upper'] for c in self.report()['cases']))
    def test_09_no_confirmed_rf(self):
        self.assertTrue(all(c['confirmed_rf'] is None for c in self.report()['cases']))
    def test_10_no_operational_rf(self):
        self.assertIsNone(self.report()['confirmed_final_risk'])
    def test_11_no_a5_starts(self):
        self.assertEqual(self.report()['a5_attempts_started'],0)
    def test_12_no_p8(self):
        self.assertEqual(self.report()['p8_operational'],'NO-GO')
    def test_13_no_a9(self):
        self.assertIsNone(self.report()['published_generation'])
    def test_14_denial_kept(self):
        self.assertEqual(self.report()['source_r58s_denial_sha256'],'a'*64)
    def test_15_source_hash(self):
        self.assertEqual(self.report()['source_r58v_handoff_sha256'],self.handoff['sha256'])
    def test_16_no_intent_status(self):
        self.assertTrue(all(c['a5_model_resolution']=='NO_MODEL_INTENT' for c in self.report()['cases']))
    def test_17_declared_but_not_resolved(self):
        w.declare_model_intent(*self.args,case_id_a7=self.cid,request_id='SIM_X_DECLARE')
        r=self.report();self.assertEqual(r['model_intents_open'],1)
        self.assertEqual(sum(c['a5_model_resolution']=='DECLARED' for c in r['cases']),1)
    def test_18_resolved_count(self):
        self.apply();self.assertEqual(self.report()['model_no_start_case_count'],1)
    def test_19_model_event_count(self):
        self.apply();self.assertEqual(self.report()['model_event_count'],2)
    def test_20_model_no_start_status(self):
        self.apply();self.assertEqual(sum(c['a5_model_resolution']=='RESOLVED_NO_START' for c in self.report()['cases']),1)
    def test_21_model_no_start_still_nd(self):
        self.apply();self.assertEqual({c['a6_classification'] for c in self.report()['cases']},{'ND'})
    def test_22_model_no_start_still_unresolved(self):
        self.apply();self.assertEqual({c['a7_rf_upper'] for c in self.report()['cases']},{'7/12'})
    def test_23_no_model_state_transition(self):
        self.apply();self.assertEqual(self.report()['simulated_phase_counts']['PENDIENTE'],1)
    def test_24_verified(self):
        self.apply();r=self.report();self.assertTrue(x.verify_no_start_envelope(r,*self.args))
    def test_25_deterministic(self):
        self.apply();self.assertEqual(self.report(),self.report())
    def test_26_tampered_hash(self):
        r=self.report();r['sha256']='e'*64
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_27_forged_accreditation(self):
        r=self.report();r['a6_classification']='VERDADERO'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_28_forged_risk(self):
        r=self.report();r['confirmed_final_risk']='0'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_29_forged_dispatch(self):
        r=self.report();r['operational_dispatch']=True
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_30_missing_field(self):
        r=self.report();del r['cases']
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_31_extra_field(self):
        r=self.report();r['promoted']=True
        with self.assertRaises(x.NoStartEnvelopeError):x.verify_no_start_envelope(r,*self.args)
    def test_32_bad_handoff_denial(self):
        self.handoff['all_source_requests_denied']=False
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_33_bad_handoff_evidence(self):
        self.handoff['a6_accredited_evidence_count']=1
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_34_bad_handoff_attempt(self):
        self.handoff['a5_attempts_started']=1
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_35_bad_handoff_dispatch(self):
        self.handoff['operational_dispatch']=True
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_36_bad_handoff_session(self):
        self.handoff['session_id']='DEV_OTHER'
        with self.assertRaises((x.NoStartEnvelopeError,w.ModelIntentError)):self.report()
    def test_37_bad_handoff_cases(self):
        self.handoff['cases'].append(self.handoff['cases'][0]);self.handoff['case_count']+=1
        with self.assertRaises((x.NoStartEnvelopeError,w.ModelIntentError)):self.report()
    def test_38_bad_case_accreditation(self):
        self.handoff['cases'][0]['evidence_accredited']=True
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_39_bad_case_id(self):
        self.handoff['cases'][0]['case_id_a7']='CASE_BAD'
        with self.assertRaises((x.NoStartEnvelopeError,w.ModelIntentError)):self.report()
    def test_40_bad_scenario_risk(self):
        self.scenario['services'][0]['initial_risk']='0'
        with self.assertRaises(ValueError):self.report()
    def test_41_bad_scenario_service(self):
        self.scenario['services'][0]['id']='UNEXPECTED'
        with self.assertRaises(ValueError):self.report()
    def test_42_bad_scenario_extra(self):
        self.scenario['extra']='promote'
        with self.assertRaises(ValueError):self.report()
    def test_43_bad_handoff_key(self):
        self.handoff['cases'][0]['service_id']='UNEXPECTED'
        with self.assertRaises(x.NoStartEnvelopeError):self.report()
    def test_44_event_hash_tampered(self):
        self.apply();self.mutate('UPDATE events SET sha=?',('f'*64,))
        with self.assertRaises(w.ModelIntentError):self.report()
    def test_45_materialization_tampered(self):
        self.apply();self.mutate("UPDATE intents SET status='DECLARED'")
        with self.assertRaises(w.ModelIntentError):self.report()
    def test_46_sqlite_world_readable(self):
        p=w._path(self.dirs[0],self.handoff);os.chmod(p,0o644)
        with self.assertRaises(w.ModelIntentError):self.report()
    def test_47_sqlite_symlink(self):
        p=w._path(self.dirs[0],self.handoff);other=p.with_suffix('.saved');p.rename(other);p.symlink_to(other)
        with self.assertRaises((w.ModelIntentError,x.NoStartEnvelopeError)):self.report()
    def test_48_readonly_preserves_source(self):
        self.apply();p=w._path(self.dirs[0],self.handoff)
        stat0=p.stat();self.report();stat1=p.stat()
        self.assertEqual((stat0.st_size,stat0.st_mtime_ns),(stat1.st_size,stat1.st_mtime_ns))
    def test_49_no_new_receipts(self):
        self.apply();before=len(list(self.dirs[0].iterdir()));self.report()
        self.assertEqual(before,len(list(self.dirs[0].iterdir())))
    def test_50_no_external_network_dependencies(self):
        self.apply();self.assertFalse(self.report()['operational_dispatch'])


if __name__ == '__main__':unittest.main()
