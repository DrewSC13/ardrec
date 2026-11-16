"""R58-I adversarial FTP/FTPS family cases; synthetic only, no real A6 authority."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.analytics.exact_preview import digest
from ardrec.evidence import r58i_ftp_family_logic as m
from scripts.ardrec_p14_r58i_ftp_family_demo import synthetic_ftp_cases

COMMON = 'SCOPE_APPROVED LAB_ISOLATION_CONFIRMED DESTINATION_AUTHORIZED CLIENT_COMPATIBLE'
SPEC = (
 ('FTP-T01',1,'SERVICE_READY','CONTROL_CHANNEL_RESPONSE'),
 ('FTP-T02',[1,3],'SERVICE_READY TLS_CHANNEL_PREDEFINED','TLS_NEGOTIATION TLS_CHANNEL_PROTECTION CONTROL_DATA_CORRELATION'),
 ('FTP-T03',2,'CONTROL_CHANNEL_VERIFIED GUEST_POLICY_PREDEFINED','AUTH_COMPLETION SESSION_CORRELATION'),
 ('FTP-T04',2,'CONTROL_CHANNEL_VERIFIED SYNTHETIC_IDENTITY_PREPARED PROTECTED_CREDENTIAL_REF','AUTH_COMPLETION EFFECTIVE_IDENTITY'),
 ('FTP-T05',3,'SESSION_AUTHENTICATED SYNTHETIC_RESOURCE_PREPARED','DIRECTORY_LISTING CONTROL_DATA_CORRELATION'),
 ('FTP-T06',3,'SESSION_AUTHENTICATED READ_FIXTURE_PREPARED','RESOURCE_READ KNOWN_CONTENT_DIGEST CONTROL_DATA_CORRELATION'),
 ('FTP-T07',4,'SESSION_AUTHENTICATED WRITE_FIXTURE_PREPARED CLEANUP_VERIFIABLE','MARKER_CREATED MARKER_VERIFIED CLEANUP_CONFIRMED'),
 ('FTP-T08',[3,4],'SESSION_AUTHENTICATED REFERENCE_BASELINE_PREPARED RESTRICTED_RESOURCE_PREDEFINED','ACCESS_COMPARISON OPERATION_RESPONSE'),
)


def specs():
    rows=[]
    for fid,precedence,other,s in SPEC:
        variant = ({'dimension':'channel','precedence_by_option':{'CONTROL':1,'DATA':3}}
                   if fid=='FTP-T02' else
                   {'dimension':'operation_class','precedence_by_option':{'READ':3,'WRITE':4}}
                   if fid=='FTP-T08' else None)
        rows.append({'id':fid,'protocol':'ftp','precedence':precedence,
                     'variants':variant,'preconditions':COMMON.split()+other.split(),
                     'required_supports':['TARGET_ATTESTATION','INTEGRITY_PROVENANCE',*s.split()],
                     'acceptance_supports':([x for x in s.split() if x!='CONTROL_DATA_CORRELATION']
                                            if fid=='FTP-T02' else s.split()),
                     'cleanup':('VERIFY_THEN_REMOVE_MARKER' if fid=='FTP-T07' else
                                'CONDITIONAL_WRITE_MARKER_CLEANUP' if fid=='FTP-T08' else
                                'NO_MUTATION')})
    return rows


def family(fid):
    return next(f for f in m._specs(specs()) if f['id']==fid)


def unit(fid='FTP-T01',variant=None,outcome='OBSERVADO_POSITIVO'):
    f=family(fid)
    pre,sup,_,_,needs_cleanup=m._requirements(f,variant)
    return {'family_id':fid,'derived_case_id':fid+'-S01-01',
            'assessment_index':0,'session_id':'DEV_TUTOR_001','phase':'PENDIENTE',
            'variant':variant,'preconditions':{k:'VERDADERO' for k in pre},
            'supports':{k:'VERDADERO' for k in sup},
            'integrity':'VERDADERO','provenance':'VERDADERO',
            'cleanup':'VERDADERO' if needs_cleanup else 'NO_APLICA',
            'outcome':outcome}


def report(rows):
    return m.build_ftp_simulation(rows,_test_families=specs())


def verify(doc):
    return m.verify_ftp_simulation(doc,_test_families=specs())


def refreshed(doc):
    doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
    return doc


class FTPFamilyTests(unittest.TestCase):
    def setUp(self):
        self.base=unit();self.families=specs()

    def test_exact_eight_families(self):
        self.assertEqual([f['id'] for f in m._specs(self.families)],list(m.FAMILY_IDS))
    def test_all_families_have_required_supports(self):
        self.assertEqual(len([f for f in self.families if 'INTEGRITY_PROVENANCE' in f['required_supports']]),8)
    def test_one_case_positive(self):
        d=report([self.base]);self.assertEqual(d['decisions'][0]['hypothetical_result_class'],'POSITIVO_VALIDO')
        self.assertTrue(verify(d))
    def test_one_case_negative(self):
        d=report([unit(outcome='OBSERVADO_NEGATIVO')]);self.assertEqual(d['decisions'][0]['hypothetical_result_class'],'NEGATIVO_VALIDO')
    def test_negative_requires_explicit_observation(self):
        d=report([unit(outcome='INCONCLUSO')]);self.assertEqual(d['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_all_eight_positive_preview(self):
        rows=[unit(fid, 'CONTROL' if fid=='FTP-T02' else 'READ' if fid=='FTP-T08' else None)
              for fid,*_ in SPEC]
        d=report(rows)
        self.assertEqual(len(d['decisions']),8)
        self.assertTrue(all(x['hypothetical_result_class']=='POSITIVO_VALIDO' for x in d['decisions']))
    def test_all_eight_negative_preview(self):
        rows=[unit(fid, 'CONTROL' if fid=='FTP-T02' else 'READ' if fid=='FTP-T08' else None,'OBSERVADO_NEGATIVO')
              for fid,*_ in SPEC]
        self.assertEqual(len([x for x in report(rows)['decisions'] if x['hypothetical_result_class']=='NEGATIVO_VALIDO']),8)
    def test_demo_fixture_ten_options(self):
        self.assertEqual(len(synthetic_ftp_cases(m._specs(specs()))),10)
    def test_variant_ftp_t02_control(self):
        d=report([unit('FTP-T02','CONTROL')]);x=d['decisions'][0]
        self.assertEqual(x['precedence'],1)
        self.assertNotIn('CONTROL_DATA_CORRELATION',x['required_supports'])
    def test_variant_ftp_t02_data(self):
        d=report([unit('FTP-T02','DATA')]);x=d['decisions'][0]
        self.assertEqual(x['precedence'],3)
        self.assertIn('CONTROL_DATA_CORRELATION',x['required_supports'])
        self.assertIn('CONTROL_CHANNEL_VERIFIED',x['required_preconditions'])
    def test_variant_ftp_t08_read(self):
        d=report([unit('FTP-T08','READ')]);self.assertEqual(d['decisions'][0]['precedence'],3)
        self.assertFalse(d['decisions'][0]['cleanup_required'])
    def test_variant_ftp_t08_write(self):
        d=report([unit('FTP-T08','WRITE')]);x=d['decisions'][0]
        self.assertEqual(x['precedence'],4)
        self.assertTrue(x['cleanup_required'])
        self.assertIn('MARKER_CREATED',x['required_supports'])
    def test_t07_cleanup_required(self):
        self.assertTrue(report([unit('FTP-T07')])['decisions'][0]['cleanup_required'])
    def test_t08_write_cleanup_required(self):
        self.assertTrue(report([unit('FTP-T08','WRITE')])['decisions'][0]['cleanup_required'])
    def test_t08_read_not_cleanup_required(self):
        self.assertFalse(report([unit('FTP-T08','READ')])['decisions'][0]['cleanup_required'])
    def test_ftp_t02_variants_independent(self):
        a=unit('FTP-T02','CONTROL');b=unit('FTP-T02','DATA',outcome='OBSERVADO_NEGATIVO');b['derived_case_id']='FTP-T02-S01-02'
        d=report([a,b])
        self.assertEqual({x['variant'] for x in d['decisions']},{'DATA','CONTROL'})
        self.assertEqual({x['hypothetical_result_class'] for x in d['decisions']},{'POSITIVO_VALIDO','NEGATIVO_VALIDO'})
    def test_ftp_t08_variants_independent(self):
        a=unit('FTP-T08','READ');b=unit('FTP-T08','WRITE',outcome='OBSERVADO_NEGATIVO');b['derived_case_id']='FTP-T08-S01-02'
        d=report([a,b])
        self.assertEqual({x['precedence'] for x in d['decisions']},{3,4})
    def test_duplicate_case_id_across_variants_refused(self):
        with self.assertRaisesRegex(m.FTPFamilyError,'CASE_ID_REUSED_ACROSS_VARIANTS'):
            report([unit('FTP-T02','CONTROL'),unit('FTP-T02','DATA')])
    def test_ftp_t02_no_automatic_data_inference(self):
        self.assertEqual(report([unit('FTP-T02','CONTROL')])['unit_count'],1)
    def test_unknown_precondition_fails_closed(self):
        x=deepcopy(self.base);x['preconditions']['SCOPE_APPROVED']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_false_precondition_fails_closed(self):
        x=deepcopy(self.base);x['preconditions']['SCOPE_APPROVED']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_false_precondition_overrides_nd(self):
        x=deepcopy(self.base);x['preconditions']['SCOPE_APPROVED']='FALSO';x['preconditions']['CLIENT_COMPATIBLE']='ND'
        self.assertEqual(report([x])['decisions'][0]['guard_simulated'],'FALSO')
    def test_missing_support_not_negative(self):
        x=unit(outcome='OBSERVADO_NEGATIVO');x['supports'].pop('CONTROL_CHANNEL_RESPONSE')
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_false_support_invalid(self):
        x=deepcopy(self.base);x['supports']['CONTROL_CHANNEL_RESPONSE']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_nd_support_inconclusive(self):
        x=deepcopy(self.base);x['supports']['CONTROL_CHANNEL_RESPONSE']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_integrity_nd_inconclusive(self):
        x=deepcopy(self.base);x['integrity']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_provenance_nd_inconclusive(self):
        x=deepcopy(self.base);x['provenance']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_integrity_false_invalid(self):
        x=deepcopy(self.base);x['integrity']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_provenance_false_invalid(self):
        x=deepcopy(self.base);x['provenance']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_incident_not_positive(self):
        self.assertEqual(report([unit(outcome='INCIDENCIA')])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_t07_cleanup_failure_incident(self):
        x=unit('FTP-T07');x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_t07_cleanup_unknown(self):
        x=unit('FTP-T07');x['cleanup']='ND';x['supports']['CLEANUP_CONFIRMED']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_t07_cleanup_contradiction(self):
        x=unit('FTP-T07');x['cleanup']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_t07_cleanup_status_true_support_false(self):
        x=unit('FTP-T07');x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_t08_write_cleanup_failure_incident(self):
        x=unit('FTP-T08','WRITE');x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_t08_write_cleanup_unknown(self):
        x=unit('FTP-T08','WRITE');x['cleanup']='ND';x['supports']['CLEANUP_CONFIRMED']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_t08_write_marker_support_missing(self):
        x=unit('FTP-T08','WRITE');x['supports'].pop('MARKER_VERIFIED')
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_t02_data_missing_correlation(self):
        x=unit('FTP-T02','DATA');x['supports'].pop('CONTROL_DATA_CORRELATION')
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_t02_data_no_control_guard(self):
        x=unit('FTP-T02','DATA');x['preconditions']['CONTROL_CHANNEL_VERIFIED']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_t02_data_no_session_guard(self):
        x=unit('FTP-T02','DATA');x['preconditions']['SESSION_AUTHENTICATED']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_t08_write_not_prepared(self):
        x=unit('FTP-T08','WRITE');x['preconditions']['WRITE_FIXTURE_PREPARED']='ND'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_t08_write_cleanup_not_prepared(self):
        x=unit('FTP-T08','WRITE');x['preconditions']['CLEANUP_VERIFIABLE']='FALSO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_phase_not_pending(self):
        x=deepcopy(self.base);x['phase']='CERRADO'
        self.assertEqual(report([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_invalid_phase(self):
        x=deepcopy(self.base);x['phase']='SUPER_ADMIN'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_no_evidence_accredited(self):
        d=report([self.base]);self.assertFalse(d['technical_truth_accredited'])
        self.assertEqual(d['decisions'][0]['a6_classification'],'ND')
    def test_no_risk_or_generation(self):
        d=report([self.base]);self.assertIsNone(d['confirmed_final_risk']);self.assertIsNone(d['published_generation'])
        self.assertIsNone(d['applied_state_transition'])
    def test_no_host_or_dispatch(self):
        d=report([self.base]);self.assertIs(d['operational_dispatch'],False)
        self.assertEqual(d['host_mutations'],0);self.assertEqual(d['p8_operational'],'NO-GO')
    def test_permutation_invariant(self):
        rows=synthetic_ftp_cases(m._specs(specs()))
        self.assertEqual(report(rows),report(list(reversed(rows))))
    def test_double_session_separation(self):
        a=unit();b=unit();b['session_id']='SECOND_SESSION'
        self.assertEqual(report([a,b])['unit_count'],2)
    def test_separate_assessment_index(self):
        a=unit();b=unit();b['assessment_index']=1
        self.assertEqual(report([a,b])['unit_count'],2)
    def test_duplicate_variant_window_blocked(self):
        with self.assertRaisesRegex(m.FTPFamilyError,'DUPLICATE_CASE_VARIANT_WINDOW'):
            report([self.base,self.base])
    def test_54_units(self):
        rows=[{**unit(), 'derived_case_id':f'FTP-T01-S{i//99:02}-{(i%99)+1:02}'} for i in range(54)]
        self.assertEqual(report(rows)['unit_count'],54)
    def test_55_units_rejected(self):
        rows=[{**unit(), 'derived_case_id':f'FTP-T01-S{i//99:02}-{(i%99)+1:02}'} for i in range(55)]
        with self.assertRaises(m.FTPFamilyError):report(rows)
    def test_empty_batch(self):
        with self.assertRaises(m.FTPFamilyError):report([])
    def test_invalid_batch_type(self):
        with self.assertRaises(m.FTPFamilyError):report({})
    def test_bool_assessment_index(self):
        x=deepcopy(self.base);x['assessment_index']=True
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_negative_assessment_index(self):
        x=deepcopy(self.base);x['assessment_index']=-1
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_overflow_assessment_index(self):
        x=deepcopy(self.base);x['assessment_index']=2**31
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_unknown_variant(self):
        x=unit('FTP-T02','DATA');x['variant']='TLS'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_variant_required(self):
        x=unit('FTP-T02','DATA');x['variant']=None
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_variant_forbidden_on_other_family(self):
        x=unit();x['variant']='CONTROL'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_extra_support_rejected(self):
        x=deepcopy(self.base);x['supports']['FAKE']='VERDADERO'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_extra_precondition_rejected(self):
        x=deepcopy(self.base);x['preconditions']['FAKE']='VERDADERO'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_missing_precondition_rejected(self):
        x=deepcopy(self.base);x['preconditions'].pop('SCOPE_APPROVED')
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_string_boolean_guard_rejected(self):
        x=deepcopy(self.base);x['preconditions']['SCOPE_APPROVED']=True
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_unknown_outcome_rejected(self):
        x=deepcopy(self.base);x['outcome']='ARBITRARY'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_unexpected_cleanup_rejected(self):
        x=deepcopy(self.base);x['cleanup']='VERDADERO'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_missing_cleanup_rejected(self):
        x=unit('FTP-T07');x['cleanup']='NO_APLICA'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_invalid_case_format(self):
        x=deepcopy(self.base);x['derived_case_id']='FTP-T01-S1-1'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_wrong_case_family(self):
        x=deepcopy(self.base);x['derived_case_id']='FTP-T02-S01-01'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_wrong_service_family(self):
        x=deepcopy(self.base);x['family_id']='SMB-T01'
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_extra_unit_field_rejected(self):
        x=deepcopy(self.base);x['technical_truth_accredited']=True
        with self.assertRaises(m.FTPFamilyError):report([x])
    def test_report_roundtrip(self):
        self.assertTrue(verify(report(synthetic_ftp_cases(m._specs(specs())))))
    def test_report_tampered_digest(self):
        d=report([self.base]);d['decisions'][0]['precedence']=4
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_risk(self):
        d=report([self.base]);d['confirmed_final_risk']='1/2';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_a6_truth(self):
        d=report([self.base]);d['decisions'][0]['a6_classification']='VERDADERO';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_p8(self):
        d=report([self.base]);d['p8_operational']='GO';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_transition(self):
        d=report([self.base]);d['applied_state_transition']='APLICAR_RESULTADO';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_generation(self):
        d=report([self.base]);d['published_generation']=1;refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_family(self):
        d=report([self.base]);d['decisions'][0]['family_id']='SSH-T01';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_variant(self):
        d=report([unit('FTP-T02','CONTROL')]);d['decisions'][0]['variant']='DATA';refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_report_rehashed_fake_catalog_pin(self):
        d=report([self.base]);d['source_catalog_sha256']='a'*64;refreshed(d)
        with self.assertRaises(m.FTPFamilyError):verify(d)
    def test_spec_missing_one(self):
        with self.assertRaises(m.FTPFamilyError):m._specs(self.families[:-1])
    def test_spec_repeated_one(self):
        with self.assertRaises(m.FTPFamilyError):m._specs(self.families+[self.families[-1]])
    def test_spec_bad_t02_variant(self):
        rows=deepcopy(self.families);rows[1]['variants']['precedence_by_option']['DATA']=4
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_spec_bad_t08_variant(self):
        rows=deepcopy(self.families);rows[-1]['variants']['dimension']='channel'
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_spec_bad_t07_cleanup(self):
        rows=deepcopy(self.families);rows[6]['cleanup']='NO_MUTATION'
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_spec_bad_t08_cleanup(self):
        rows=deepcopy(self.families);rows[-1]['cleanup']='NO_MUTATION'
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_spec_acceptance_beyond_required(self):
        rows=deepcopy(self.families);rows[0]['acceptance_supports'].append('FORGED')
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_spec_bad_precedence(self):
        rows=deepcopy(self.families);rows[0]['precedence']=True
        with self.assertRaises(m.FTPFamilyError):m._specs(rows)
    def test_catalog_pin_production_constant(self):
        self.assertEqual(m.CATALOG_SHA256,'5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e')
    def test_thesis_pin_production_constant(self):
        self.assertEqual(m.THESIS_SHA256,'6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72')
    def test_catalog_loader_pin_fails_closed(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'catalog.json';p.write_text('{"fake":true}')
            with patch.object(m,'CATALOG_PATH',p):
                with self.assertRaisesRegex(m.FTPFamilyError,'CATALOG_PIN_MISMATCH'):
                    m.load_pinned_ftp_catalog()
    def test_catalog_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'real.json';p.write_text('{}')
            l=Path(t)/'link.json';l.symlink_to(p)
            with patch.object(m,'CATALOG_PATH',l):
                with self.assertRaisesRegex(m.FTPFamilyError,'CATALOG_NOT_REGULAR'):
                    m.load_pinned_ftp_catalog()
    def test_pinned_loader_with_test_document(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'catalog.json'
            doc={'thesis_sha256':m.THESIS_SHA256,
                 'counts':{'ssh':8,'ftp':8,'smb':9,'total':25},
                 'status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
                 'execution_enabled':False,'families':self.families}
            raw=json.dumps(doc).encode();p.write_bytes(raw)
            with patch.object(m,'CATALOG_PATH',p), patch.object(m,'CATALOG_SHA256',hashlib.sha256(raw).hexdigest()):
                self.assertEqual(len(m.load_pinned_ftp_catalog()),8)
    def test_catalog_modified_after_pin_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'catalog.json'
            doc={'thesis_sha256':m.THESIS_SHA256,
                 'counts':{'ssh':8,'ftp':8,'smb':9,'total':25},
                 'status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
                 'execution_enabled':False,'families':self.families}
            raw=json.dumps(doc).encode();p.write_bytes(raw)
            with patch.object(m,'CATALOG_PATH',p), patch.object(m,'CATALOG_SHA256',hashlib.sha256(raw).hexdigest()):
                p.write_bytes(raw+b'\n')
                with self.assertRaises(m.FTPFamilyError):m.load_pinned_ftp_catalog()

if __name__=='__main__':
    unittest.main()
