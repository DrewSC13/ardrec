"""R58-H adversarial tests: SSH-T01..08 exact catalogue rules, synthetic A6 only."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

from ardrec.analytics.exact_preview import digest
from ardrec.evidence import r58h_ssh_family_logic as m
from scripts import ardrec_p14_r58h_ssh_family_demo as demo

# Test fixture is explicitly NOT the authoritative catalog. Production checks
# the full SHA-256-pinned original from lab/operational-catalog-v1/catalog.json.
SPEC = [
 ('SSH-T01',1,'SERVICE_READY HOST_KEY_PREDEFINED','TRANSPORT_NEGOTIATION HOST_KEY_MATCH'),
 ('SSH-T02',1,'TRANSPORT_VERIFIED SYNTHETIC_IDENTITY_PREPARED','AUTH_METHODS_LIST SESSION_CORRELATION'),
 ('SSH-T03',2,'TRANSPORT_VERIFIED SYNTHETIC_IDENTITY_PREPARED PROTECTED_CREDENTIAL_REF','AUTH_COMPLETION EFFECTIVE_IDENTITY SESSION_CORRELATION'),
 ('SSH-T04',2,'TRANSPORT_VERIFIED SYNTHETIC_IDENTITY_PREPARED PROTECTED_CREDENTIAL_REF','AUTH_COMPLETION EFFECTIVE_IDENTITY SESSION_CORRELATION'),
 ('SSH-T05',3,'SESSION_AUTHENTICATED BENIGN_OPERATION_PREDEFINED','CHANNEL_OPEN EFFECTIVE_IDENTITY OPERATION_RESPONSE'),
 ('SSH-T06',3,'SESSION_AUTHENTICATED READ_FIXTURE_PREPARED','RESOURCE_READ KNOWN_CONTENT_DIGEST'),
 ('SSH-T07',4,'SESSION_AUTHENTICATED WRITE_FIXTURE_PREPARED CLEANUP_VERIFIABLE','MARKER_CREATED MARKER_VERIFIED CLEANUP_CONFIRMED'),
 ('SSH-T08',4,'SESSION_AUTHENTICATED PRIVILEGE_SCOPE_EXPLICITLY_APPROVED BENIGN_OPERATION_PREDEFINED','PRIVILEGE_SCOPE OPERATION_RESPONSE EFFECTIVE_IDENTITY'),
]
COMMON='SCOPE_APPROVED LAB_ISOLATION_CONFIRMED DESTINATION_AUTHORIZED CLIENT_COMPATIBLE'


def specs():
    out=[]
    for fid, prec, extra, supports in SPEC:
        need=(['TARGET_ATTESTATION','INTEGRITY_PROVENANCE']+supports.split())
        out.append({'id':fid,'protocol':'ssh','precedence':prec,
                    'preconditions':COMMON.split()+extra.split(),
                    'required_supports':need,'acceptance_supports':supports.split(),
                    'cleanup':'VERIFY_THEN_REMOVE_MARKER' if fid=='SSH-T07' else 'NO_MUTATION'})
    return out


def unit(family,*,outcome='OBSERVADO_POSITIVO'):
    return {'family_id':family['id'],'derived_case_id':family['id']+'-S01-01',
            'assessment_index':0,'session_id':'DEV_TUTOR_001','phase':'PENDIENTE',
            'preconditions':{x:'VERDADERO' for x in family['preconditions']},
            'supports':{x:'VERDADERO' for x in family['required_supports']},
            'integrity':'VERDADERO','provenance':'VERDADERO',
            'cleanup':'VERDADERO' if family['id']=='SSH-T07' else 'NO_APLICA',
            'outcome':outcome}


class SSHFamilyLogicTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog=specs()
        cls.units=[unit(x) for x in cls.catalog]

    def run_case(self, x, family_idx=0):
        return m.build_ssh_simulation([x],_test_families=self.catalog)

    def test_exact_8_catalogue_families(self):
        self.assertEqual([f['id'] for f in m._specs(self.catalog)],list(m.FAMILY_IDS))
    def test_thesis_and_catalogue_sha_pinned(self):
        self.assertEqual(m.THESIS_SHA256,'6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72')
        self.assertEqual(m.CATALOG_SHA256,'5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e')
    def test_all_8_preview_positive_without_accreditation(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        self.assertEqual(d['unit_count'],8)
        self.assertTrue(m.verify_ssh_simulation(d,_test_families=self.catalog))
        self.assertTrue(all(x['hypothetical_result_class']=='POSITIVO_VALIDO' for x in d['decisions']))
        self.assertTrue(all(x['a6_classification']=='ND' and x['confirmed_rf'] is None for x in d['decisions']))
        self.assertIsNone(d['published_generation'])
        self.assertIsNone(d['confirmed_final_risk'])
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertEqual(d['catalog_source'],'TEST_FIXTURE_NOT_PINNED')
    def test_all_8_preview_negative_without_accreditation(self):
        d=m.build_ssh_simulation([unit(x,outcome='OBSERVADO_NEGATIVO') for x in self.catalog],_test_families=self.catalog)
        self.assertTrue(all(x['hypothetical_result_class']=='NEGATIVO_VALIDO' and x['hypothetical_condition_truth']=='FALSO' for x in d['decisions']))
        self.assertIsNone(d['confirmed_final_risk'])
    def test_negative_requires_explicit_observation(self):
        d=self.run_case(unit(self.catalog[0],outcome='INCONCLUSO'))
        self.assertEqual(d['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
        self.assertEqual(d['decisions'][0]['hypothetical_condition_truth'],'ND')
    def test_kleene_three_valued_conjunction(self):
        for a in m.TRUTH:
            for b in m.TRUTH:
                exp='FALSO' if 'FALSO' in (a,b) else 'ND' if 'ND' in (a,b) else 'VERDADERO'
                self.assertEqual(m._guard([a,b]),exp)
    def test_false_guard_blocks_positive(self):
        x=unit(self.catalog[2]);x['preconditions']['PROTECTED_CREDENTIAL_REF']='FALSO'
        d=self.run_case(x)['decisions'][0]
        self.assertEqual(d['guard_simulated'],'FALSO');self.assertEqual(d['hypothetical_result_class'],'NO_ADMITIDO')
    def test_nd_guard_blocks_positive(self):
        x=unit(self.catalog[2]);x['preconditions']['PROTECTED_CREDENTIAL_REF']='ND'
        d=self.run_case(x)['decisions'][0]
        self.assertEqual(d['guard_simulated'],'ND');self.assertEqual(d['hypothetical_result_class'],'NO_ADMITIDO')
    def test_false_overrides_nd_in_guard(self):
        x=unit(self.catalog[2]);x['preconditions']['PROTECTED_CREDENTIAL_REF']='ND';x['preconditions']['SCOPE_APPROVED']='FALSO'
        self.assertEqual(self.run_case(x)['decisions'][0]['guard_simulated'],'FALSO')
    def test_phase_not_pending_blocks(self):
        for phase in ('PREPARADO','ACTIVO','VALIDACION','ACTUALIZADO','PAUSADO','CERRADO','DETENIDO'):
            x=unit(self.catalog[0]);x['phase']=phase
            self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_all_family_supports_from_catalogue(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        self.assertEqual([x['required_supports'] for x in d['decisions']],
                         [x['required_supports'] for x in self.catalog])
    def test_absent_required_support_is_not_negative_valid(self):
        x=unit(self.catalog[0]);del x['supports']['HOST_KEY_MATCH']
        d=self.run_case(x)['decisions'][0]
        self.assertEqual(d['hypothetical_result_class'],'INCONCLUSO')
        self.assertEqual(d['missing_required_supports'],['HOST_KEY_MATCH'])
    def test_nd_required_support_is_not_positive(self):
        x=unit(self.catalog[5]);x['supports']['KNOWN_CONTENT_DIGEST']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_contradicted_required_support_invalid(self):
        x=unit(self.catalog[5]);x['supports']['RESOURCE_READ']='FALSO'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_ssh_t03_requires_complete_authentication(self):
        x=unit(self.catalog[2]);x['supports']['AUTH_COMPLETION']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_ssh_t04_requires_complete_authentication(self):
        x=unit(self.catalog[3]);del x['supports']['AUTH_COMPLETION']
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_ssh_t05_identity_must_be_supported(self):
        x=unit(self.catalog[4]);del x['supports']['EFFECTIVE_IDENTITY']
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_ssh_t06_resource_digest_must_be_supported(self):
        x=unit(self.catalog[5]);del x['supports']['KNOWN_CONTENT_DIGEST']
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_ssh_t07_cleanup_required(self):
        x=unit(self.catalog[6]);x['cleanup']='ND';x['supports']['CLEANUP_CONFIRMED']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_ssh_t07_cleanup_failed_incident(self):
        x=unit(self.catalog[6]);x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_ssh_t07_cleanup_failed_conflicting_support_invalid(self):
        x=unit(self.catalog[6]);x['cleanup']='FALSO'
        d=self.run_case(x)['decisions'][0]
        self.assertEqual(d['hypothetical_result_class'],'INVALIDO')
    def test_ssh_t07_cleanup_false_when_other_support_true_and_cleanup_support_false(self):
        x=unit(self.catalog[6]);x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_ssh_t08_requires_privilege_scope(self):
        x=unit(self.catalog[7]);x['preconditions']['PRIVILEGE_SCOPE_EXPLICITLY_APPROVED']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
    def test_integrity_false_invalid(self):
        x=unit(self.catalog[0]);x['integrity']='FALSO'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_integrity_nd_inconclusive(self):
        x=unit(self.catalog[0]);x['integrity']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_provenance_false_invalid(self):
        x=unit(self.catalog[0]);x['provenance']='FALSO'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INVALIDO')
    def test_provenance_nd_inconclusive(self):
        x=unit(self.catalog[0]);x['provenance']='ND'
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')
    def test_incident_is_not_positive(self):
        x=unit(self.catalog[0],outcome='INCIDENCIA')
        self.assertEqual(self.run_case(x)['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
    def test_bogus_cleanup_with_no_mutation_blocked(self):
        x=unit(self.catalog[0]);x['cleanup']='VERDADERO'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_malicious_expansion_of_supports_blocked(self):
        x=unit(self.catalog[0]);x['supports']['EXTERNAL_TARGETS']='VERDADERO'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_extra_precondition_blocked(self):
        x=unit(self.catalog[0]);x['preconditions']['FORGED']='VERDADERO'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_missing_precondition_blocked(self):
        x=unit(self.catalog[0]);del x['preconditions']['SCOPE_APPROVED']
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_bool_assessment_index_blocked(self):
        x=unit(self.catalog[0]);x['assessment_index']=True
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_negative_assessment_blocked(self):
        x=unit(self.catalog[0]);x['assessment_index']=-1
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_overflow_assessment_blocked(self):
        x=unit(self.catalog[0]);x['assessment_index']=2**31
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_wrong_case_family_blocked(self):
        x=unit(self.catalog[0]);x['derived_case_id']='SSH-T02-S01-01'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_wrong_case_format_blocked(self):
        x=unit(self.catalog[0]);x['derived_case_id']='SSH-T01-CUSTOM'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_wrong_service_family_blocked(self):
        x=unit(self.catalog[0]);x['family_id']='FTP-T01'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_unknown_outcome_blocked(self):
        x=unit(self.catalog[0]);x['outcome']='EXPLOITED'
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_bool_guard_blocked(self):
        x=unit(self.catalog[0]);x['preconditions']['SCOPE_APPROVED']=True
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_unknown_field_blocked(self):
        x=unit(self.catalog[0]);x['operational_dispatch']=True
        with self.assertRaises(m.FamilyError):self.run_case(x)
    def test_duplicate_case_window_blocked(self):
        x=unit(self.catalog[0]);with_cases=[x,deepcopy(x)]
        with self.assertRaises(m.FamilyError):m.build_ssh_simulation(with_cases,_test_families=self.catalog)
    def test_different_assessment_window_allowed(self):
        x=unit(self.catalog[0]);y=deepcopy(x);y['assessment_index']=1
        self.assertEqual(m.build_ssh_simulation([x,y],_test_families=self.catalog)['unit_count'],2)
    def test_two_sessions_do_not_mix_results(self):
        x=unit(self.catalog[0]);y=deepcopy(x)
        y['session_id']='DEV_TUTOR_002';y['outcome']='OBSERVADO_NEGATIVO'
        d=m.build_ssh_simulation([y,x],_test_families=self.catalog)
        self.assertEqual([z['session_id'] for z in d['decisions']],
                         ['DEV_TUTOR_001','DEV_TUTOR_002'])
        self.assertEqual([z['hypothetical_condition_truth'] for z in d['decisions']],
                         ['VERDADERO','FALSO'])
    def test_missing_supports_not_equivalent_to_zero(self):
        x=unit(self.catalog[0]);x['supports']={}
        d=self.run_case(x)['decisions'][0]
        self.assertEqual(d['hypothetical_condition_truth'],'ND')
        self.assertEqual(len(d['missing_required_supports']),4)
    def test_preserved_session_in_report(self):
        x=unit(self.catalog[0]);x['session_id']='DEV_ABC_01'
        self.assertEqual(self.run_case(x)['decisions'][0]['session_id'],'DEV_ABC_01')
    def test_max_54_units(self):
        units=[]
        for j in range(54):
            x=unit(self.catalog[j%8]);x['derived_case_id']=x['family_id']+f'-S{j//99:02}-'+f'{j%99+1:02}'
            x['assessment_index']=j
            units.append(x)
        d=m.build_ssh_simulation(units,_test_families=self.catalog)
        self.assertEqual(d['unit_count'],54)
        self.assertTrue(m.verify_ssh_simulation(d,_test_families=self.catalog))
    def test_55_units_blocked(self):
        units=[]
        for j in range(55):
            x=unit(self.catalog[j%8]);x['assessment_index']=j;units.append(x)
        with self.assertRaises(m.FamilyError):m.build_ssh_simulation(units,_test_families=self.catalog)
    def test_rejects_empty(self):
        with self.assertRaises(m.FamilyError):m.build_ssh_simulation([],_test_families=self.catalog)
    def test_permutation_invariant(self):
        a=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        b=m.build_ssh_simulation(list(reversed(self.units)),_test_families=self.catalog)
        self.assertEqual(a,b)
    def test_rehashed_false_a6_accreditation_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['a6_classification']='VERDADERO';d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_risk_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['confirmed_final_risk']='1/4';d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_transition_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['decisions'][0]['applied_transition']='T8';d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_p8_go_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['p8_operational']='GO';d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_catalog_pin_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['source_catalog_sha256']=m.CATALOG_SHA256;d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_generation_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['published_generation']=1;d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_rehashed_false_classification_rejected(self):
        d=m.build_ssh_simulation(self.units,_test_families=self.catalog)
        d['decisions'][0]['hypothetical_result_class']='NEGATIVO_VALIDO';d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(m.FamilyError):m.verify_ssh_simulation(d,_test_families=self.catalog)
    def test_catalog_sha_pin_fails_on_modified_file(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'catalog.json';p.write_bytes(b'{}')
            with patch.object(m,'CATALOG_PATH',p):
                with self.assertRaisesRegex(m.FamilyError,'CATALOG_PIN_MISMATCH'):
                    m.load_pinned_catalog()
    def test_catalog_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'catalog.json';source=Path(td)/'source';source.write_text('x')
            p.symlink_to(source)
            with patch.object(m,'CATALOG_PATH',p):
                with self.assertRaisesRegex(m.FamilyError,'CATALOG_NOT_REGULAR'):m.load_pinned_catalog()
    def test_catalog_loader_checks_all_8_and_thesis(self):
        doc={'thesis_sha256':m.THESIS_SHA256,'status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
             'counts':{'ssh':8,'ftp':8,'smb':9,'total':25},'execution_enabled':False,
             'families':self.catalog}
        data=json.dumps(doc).encode()
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'catalog.json';p.write_bytes(data)
            with patch.object(m,'CATALOG_PATH',p),patch.object(m,'CATALOG_SHA256',hashlib.sha256(data).hexdigest()):
                self.assertEqual(len(m.load_pinned_catalog()),8)
    def test_catalog_duplicate_family_rejected(self):
        bad=deepcopy(self.catalog);bad[0]=deepcopy(bad[1])
        with self.assertRaises(m.FamilyError):m._specs(bad)
    def test_catalog_bad_acceptance_rejected(self):
        bad=deepcopy(self.catalog);bad[0]['acceptance_supports']=['NONEXISTENT']
        with self.assertRaises(m.FamilyError):m._specs(bad)
    def test_catalog_bad_cleanup_rejected(self):
        bad=deepcopy(self.catalog);bad[6]['cleanup']='NO_MUTATION'
        with self.assertRaises(m.FamilyError):m._specs(bad)
    def test_fixture_is_not_pinned(self):
        d=self.run_case(unit(self.catalog[0]))
        self.assertIsNone(d['source_catalog_sha256'])

if __name__=='__main__':unittest.main()
