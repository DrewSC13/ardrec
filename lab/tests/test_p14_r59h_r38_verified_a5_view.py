"""R59-H: real R38 presentation contract, using a test-only R38 stub offline.

Prometheus CI executes the same tests against its original R38 renderer.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from ardrec.coordination import r59h_r38_verified_a5_view as h
from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import dashboard_tui as r38

A='a'*64
B='b'*64
C='c'*64
D='d'*64
ID='ATT_R59F_FTP_T02_DATA'


def artifacts(outcome='NO_START', service='FTP_DEV', variant='DATA'):
    svc={'SSH_DEV':'SSH','FTP_DEV':'FTP','SMB_DEV':'SMB'}[service]
    fid={'SSH_DEV':'SSH-T02','FTP_DEV':'FTP-T02','SMB_DEV':'SMB-T03'}[service]
    v2={
        'sha256':A,
        'source_bridge_sha256':B,
        'legacy_candidate_sha256':C,
        'variant_bound_at_origin':True,
        'a5_start_independently_attested':False,
        'technical_truth_accredited':False,
        'a6_classification':'ND',
        'published_generation':None,
        'confirmed_rf':None,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'intent':{'service_id':service,'family_id':fid,
                  'derived_case_id':fid+'-S01-01',
                  'session_id':'DEV_TUTOR_001','attempt_id':ID,
                  'variant':variant,'sha256':D,'source_catalog_sha256':A},
        'receipt':{'v2_intent_sha256':D,'declared_outcome':outcome,
                   'source_kind':'LOCAL_BENIGN_FIXTURE' if outcome=='NO_START' else 'EXTERNAL_UNVERIFIED',
                   'support_sha256':None if outcome=='NO_START' else C,
                   'support_bytes':0 if outcome=='NO_START' else 7},
    }
    bridge={
        'sha256':B,'source_candidate_sha256':C,
        'identity':{'attempt_id':ID},
        'variant':variant,'source_catalog_sha256':A,
        'declared_outcome':outcome,
        'technical_truth_accredited':False,'a6_classification':'ND',
        'confirmed_rf':None,'published_generation':None,'p8_operational':'NO-GO',
        'hypothetical_family_class':('NO_INTENTO_NO_CLASIFICACION'
                                     if outcome=='NO_START' else 'INCONCLUSO'),
        'hypothetical_family_reason':('NO_START_HAS_NO_EVIDENCE'
                                      if outcome=='NO_START' else 'UNRESOLVED_SUPPORT'),
        'unresolved_preconditions':['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED'],
        'unresolved_supports':['TARGET_ATTESTATION'],
    }
    return v2,bridge


def build_view(outcome='NO_START',service='FTP_DEV',variant='DATA',
               alter_v2=None,alter_bridge=None):
    receipt,bridge=artifacts(outcome,service,variant)
    if alter_v2:alter_v2(receipt)
    if alter_bridge:alter_bridge(bridge)
    workspace=z.build_workspace([])
    with patch.object(h.z,'from_database',return_value=workspace), \
         patch.object(h.v2,'verify_stored',return_value=receipt), \
         patch.object(h.e,'verify_stored_bridge',return_value=bridge):
        return h.load_view(database=Path('/private/r58y.sqlite'),
                           v2_root=Path('/private/v2'),
                           a5_root=Path('/private/a5'),
                           a6_root=Path('/private/a6'),attempt_id=ID)


class H(unittest.TestCase):
    def test_01_valid_ftp_no_start(self):
        v=build_view()
        self.assertEqual((v.service,v.family,v.variant,v.outcome),
                         ('FTPS','FTP-T02','DATA','NO_START'))
    def test_02_valid_ssh(self):self.assertEqual(build_view(service='SSH_DEV',variant=None).service,'SSH')
    def test_03_valid_smb(self):self.assertEqual(build_view(service='SMB_DEV',variant='SIGNING').service,'SMB')
    def test_04_valid_declared_positive(self):
        v=build_view('OBSERVADO_POSITIVO')
        self.assertEqual(v.hypothetical_class,'INCONCLUSO')
    def test_05_a5_rows_identification(self):
        v=build_view()
        s=h.detail_rows(v,1,4)
        self.assertIn('CASO: FTP-T02-S01-01',s)
        self.assertIn('INTENTO: '+ID,s)
        self.assertIn('A5 FISICO: NO ACREDITADO',s)
    def test_06_a6_rows_not_accredited(self):
        s=h.detail_rows(build_view(),1,5)
        self.assertIn('A6 ACREDITADA: ND',s)
        self.assertIn('CLASE HIPOTETICA: NO_INTENTO_NO_CLASIFICACION',s)
    def test_07_other_service_no_case(self):
        s=h.detail_rows(build_view(),0,4)
        self.assertFalse(any('INTENTO: '+ID in r for r in s))
    def test_08_audit_rows_policy(self):
        s=' '.join(h.audit_rows(build_view(),1))
        for word in ('A5 FISICO: NO ACREDITADO','A6: ND','P8: NO-GO','R58-Y: FUENTE SEPARADA'):
            self.assertIn(word,s)
    def test_09_audit_other_service(self):
        self.assertIn('FTPS',h.audit_rows(build_view(),0))
    def test_10_120x32_three_panels(self):
        fr=h.render_frame(build_view(),1,width=120,height=32)
        self.assertEqual(len(fr),32)
        self.assertTrue(all(len(s)==120 for s in fr))
        self.assertTrue(any('ESTADO / AUDITORIA' in s for s in fr))
        self.assertTrue(any('A5 / CASO' in s for s in fr))
    def test_11_140x40(self):
        fr=h.render_frame(build_view(),1,width=140,height=40)
        self.assertEqual(len(fr),40)
        self.assertTrue(all(len(s)==140 for s in fr))
    def test_12_90x25(self):
        fr=h.render_frame(build_view(),1,width=90,height=25)
        self.assertTrue(all(len(s)==90 for s in fr))
    def test_13_70x20(self):
        fr=h.render_frame(build_view(),1,width=70,height=20)
        self.assertTrue(all(len(s)==70 for s in fr))
    def test_14_30x9(self):
        fr=h.render_frame(build_view(),1,width=30,height=9)
        self.assertTrue(all(len(s)==30 for s in fr))
    def test_15_120x32_no_case_service(self):
        fr=h.render_frame(build_view(),0,width=120,height=32)
        self.assertIn('SSH',fr[1]);self.assertIn('NO-GO',fr[1])
    def test_16_nav_next_service(self):
        i,s=h.handle_event(build_view(),1,r38.DashboardState(selected=4),'v')
        self.assertEqual((i,s.selected),(2,4))
    def test_17_nav_prev_service(self):
        i,_=h.handle_event(build_view(),1,r38.DashboardState(selected=4),'V')
        self.assertEqual(i,0)
    def test_18_nav_algorithm(self):
        i,s=h.handle_event(build_view(),1,r38.DashboardState(selected=4),'6')
        self.assertEqual((i,s.selected),(1,5))
    def test_19_help_no_overlay(self):
        fr=h.render_frame(build_view(),1,r38.DashboardState(selected=4,help_open=True),120,32)
        self.assertEqual(len(fr),32)
    def test_20_invalid_service(self):
        with self.assertRaises(h.CaseViewError):h.audit_rows(build_view(),3)
    def test_21_invalid_stage(self):
        with self.assertRaises(h.CaseViewError):h.detail_rows(build_view(),1,10)
    def test_22_reject_bridge_hash_drift(self):
        with self.assertRaisesRegex(h.CaseViewError,'MISMATCH'):
            build_view(alter_bridge=lambda b:b.__setitem__('sha256',D))
    def test_23_reject_variant_change(self):
        with self.assertRaisesRegex(h.CaseViewError,'MISMATCH'):
            build_view(alter_bridge=lambda b:b.__setitem__('variant','CONTROL'))
    def test_24_reject_attempt_change(self):
        with self.assertRaisesRegex(h.CaseViewError,'MISMATCH'):
            build_view(alter_bridge=lambda b:b['identity'].__setitem__('attempt_id','ATT_FALSE'))
    def test_25_reject_catalog_change(self):
        with self.assertRaisesRegex(h.CaseViewError,'MISMATCH'):
            build_view(alter_bridge=lambda b:b.__setitem__('source_catalog_sha256',D))
    def test_26_reject_false_physical_authority(self):
        with self.assertRaisesRegex(h.CaseViewError,'UNAUTHORIZED'):
            build_view(alter_v2=lambda b:b.__setitem__('a5_start_independently_attested',True))
    def test_27_reject_a6_positive_promotion(self):
        with self.assertRaisesRegex(h.CaseViewError,'UNAUTHORIZED'):
            build_view(alter_bridge=lambda b:b.__setitem__('a6_classification','POSITIVO_VALIDO'))
    def test_28_reject_a9_forgery(self):
        with self.assertRaisesRegex(h.CaseViewError,'UNAUTHORIZED'):
            build_view(alter_v2=lambda b:b.__setitem__('published_generation','A9'))
    def test_29_reject_no_start_support(self):
        with self.assertRaisesRegex(h.CaseViewError,'NO_START'):
            build_view(alter_v2=lambda b:b['receipt'].__setitem__('support_bytes',5))
    def test_30_reject_no_start_model_positive(self):
        with self.assertRaisesRegex(h.CaseViewError,'NO_START'):
            build_view(alter_bridge=lambda b:b.__setitem__('hypothetical_family_class','POSITIVO_VALIDO'))
    def test_31_no_external_operations(self):
        import inspect
        src=inspect.getsource(h)
        self.assertNotIn('subprocess.',src)
        self.assertNotIn('os.system',src)
        self.assertNotIn('socket.',src)
        self.assertNotIn('virsh ',src)
        self.assertNotIn('nft ',src)
    def test_32_same_view_same_render(self):
        v=build_view();a=h.render_frame(v,1);b=h.render_frame(v,1)
        self.assertEqual(a,b)
    def test_33_warehouse_input_missing_rejected(self):
        with self.assertRaises(h.CaseViewError):
            h.render_frame(None,1)
    def test_34_classification_not_confused(self):
        v=build_view('OBSERVADO_POSITIVO')
        rows=h.detail_rows(v,1,5)
        self.assertIn('A6 ACREDITADA: ND',rows)
        self.assertIn('CLASE HIPOTETICA: INCONCLUSO',rows)
    def test_35_source_sha_visible(self):
        v=build_view();s=' '.join(h.detail_rows(v,1,4))
        self.assertIn(v.source_v2_sha256,s)
        self.assertIn(v.bridge_sha256,s)
    def test_36_wide_other_service_base_kept(self):
        v=build_view();x=h.render_frame(v,0,width=120,height=32)
        self.assertTrue(any('ESTADO / AUDITORIA' in s for s in x))
    def test_37_clamped_size(self):
        fr=h.render_frame(build_view(),1,width=999,height=999)
        self.assertEqual((len(fr),len(fr[0])),(100,240))
    def test_38_any_other_stage_context(self):
        v=build_view();rows=h.detail_rows(v,1,6)
        self.assertTrue(any('A5 FISICO: NO ACREDITADO' in r for r in rows))
        self.assertTrue(any('RESULTADO DECLARADO: NO_START' in r for r in rows))

if __name__=='__main__':unittest.main()
