"""R58-J: adversarial tests of SMB catalogue semantics, no physical I/O."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence import r58j_smb_family_logic as sm
from scripts.ardrec_p14_r58j_smb_family_demo import synthetic_smb_cases

# Synthetic family specs mirror the original P7 schema. Only loader of a truly
# pinned full catalogue can provide production authority; these are NOT pinned.
COMMON = ['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED','DESTINATION_AUTHORIZED','CLIENT_COMPATIBLE']
BASE = ['TARGET_ATTESTATION','INTEGRITY_PROVENANCE']
DESCRIPTORS = {
    1: (['SERVICE_READY'], ['SMB_DIALECT','TRANSPORT_NEGOTIATION'], 1),
    2: (['SERVICE_READY','SMBV1_CHECK_PREDEFINED'], ['SMBV1_RESPONSE','SMB_DIALECT'], 1),
    3: (['SESSION_AUTHENTICATED','SMB_PROTECTION_PREDEFINED','BENIGN_OPERATION_PREDEFINED'],
        ['SMB_SIGNATURE','SMB_ENCRYPTION','OPERATION_RESPONSE'], 3),
    4: (['SERVICE_READY','GUEST_POLICY_PREDEFINED'], ['GUEST_SESSION_TYPE','AUTH_COMPLETION'], 2),
    5: (['SERVICE_READY','SYNTHETIC_IDENTITY_PREPARED','PROTECTED_CREDENTIAL_REF'],
        ['AUTH_COMPLETION','EFFECTIVE_IDENTITY'], 2),
    6: (['SESSION_AUTHENTICATED','SYNTHETIC_RESOURCE_PREPARED'],
        ['SHARE_ACCESS','DIRECTORY_LISTING'], 3),
    7: (['SESSION_AUTHENTICATED','READ_FIXTURE_PREPARED'],
        ['RESOURCE_READ','KNOWN_CONTENT_DIGEST'], 3),
    8: (['SESSION_AUTHENTICATED','WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'],
        ['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'], 4),
    9: (['SESSION_AUTHENTICATED','REFERENCE_BASELINE_PREPARED','RESTRICTED_RESOURCE_PREDEFINED'],
        ['ACCESS_COMPARISON','OPERATION_RESPONSE'], [3,4]),
}


def specs():
    out = []
    for i, (more_pre, more_support, precedence) in DESCRIPTORS.items():
        fid = f'SMB-T{i:02}'
        variant = ({'dimension':'protection','precedence_by_option':{'SIGNING':3,'ENCRYPTION':3}}
                   if i == 3 else
                   {'dimension':'operation_class','precedence_by_option':{'READ':3,'WRITE':4}}
                   if i == 9 else None)
        cleanup = ('VERIFY_THEN_REMOVE_MARKER' if i == 8 else
                   'CONDITIONAL_WRITE_MARKER_CLEANUP' if i == 9 else 'NO_MUTATION')
        supports = [*BASE, *more_support]
        accept = (['OPERATION_RESPONSE'] if i == 3 else more_support)
        out.append({'id':fid, 'protocol':'smb','variants':variant,
                    'precedence':precedence,'cleanup':cleanup,
                    'preconditions':[*COMMON,*more_pre],
                    'required_supports':supports,'acceptance_supports':accept})
    return out


def cases():
    return synthetic_smb_cases(sm._specs(specs()))


def build(units):
    return sm.build_smb_simulation(units, _test_families=specs())


def fresh(report):
    report['sha256'] = digest({k:v for k,v in report.items() if k != 'sha256'})
    return report


class SMBFamilyTests(unittest.TestCase):
    def setUp(self):
        self.units = cases()
        self.report = build(self.units)

    def expect_code(self, replacement, code=None):
        with self.assertRaises(ValueError) as ctx:
            build(replacement)
        if code is not None:
            self.assertIn(code, str(ctx.exception))

    def row(self, fid, variant=None):
        return deepcopy(next(u for u in self.units if u['family_id']==fid and u['variant']==variant))

    def test_nine_families_eleven_cases(self):
        self.assertEqual(self.report['unit_count'],11)
        self.assertEqual(len(self.report['smb_family_ids']),9)
        self.assertEqual(len({d['derived_case_id'] for d in self.report['decisions']}),11)
        self.assertEqual(len({d['family_id'] for d in self.report['decisions']}),9)

    def test_real_pinned_catalog_smb_t03_precedence(self):
        families = sm.load_pinned_smb_catalog()
        by_id = {f['id']: f for f in families}

        self.assertEqual(len(families), 9)
        self.assertEqual(
            by_id['SMB-T03']['precedence_by_variant'],
            {'SIGNING': 3, 'ENCRYPTION': 3}
        )
        self.assertEqual(
            by_id['SMB-T09']['precedence_by_variant'],
            {'READ': 3, 'WRITE': 4}
        )

    def test_schema_catalog_constants(self):
        self.assertEqual(sm.CATALOG_SHA256,'5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e')
        self.assertEqual(sm.THESIS_SHA256,'6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72')

    def test_technical_limits(self):
        self.assertEqual(self.report['a6_classification'],'ND')
        self.assertEqual(self.report['p8_operational'],'NO-GO')
        self.assertIs(self.report['technical_truth_accredited'],False)
        self.assertIs(self.report['operational_dispatch'],False)
        self.assertEqual(self.report['host_mutations'],0)
        for key in ('confirmed_final_risk','published_generation','applied_state_transition'):
            self.assertIsNone(self.report[key])
        for d in self.report['decisions']:
            self.assertEqual(d['a6_classification'],'ND')
            self.assertIsNone(d['technical_contribution'])
            self.assertIsNone(d['confirmed_rf'])
            self.assertFalse(d['technical_truth_accredited'])
            self.assertIsNone(d['applied_transition'])

    def test_test_fixture_is_not_catalog_pin(self):
        self.assertIsNone(self.report['source_catalog_sha256'])
        self.assertEqual(self.report['catalog_source'],'TEST_FIXTURE_NOT_PINNED')

    def test_roundtrip(self):
        self.assertTrue(sm.verify_smb_simulation(self.report,_test_families=specs()))

    def test_deterministic(self):
        self.assertEqual(self.report,build(self.units))

    def test_permutation(self):
        self.assertEqual(self.report,build(list(reversed(self.units))))

    def test_all_positive(self):
        x=deepcopy(self.units)
        for u in x:u['outcome']='OBSERVADO_POSITIVO'
        self.assertTrue(all(d['hypothetical_result_class']=='POSITIVO_VALIDO' for d in build(x)['decisions']))

    def test_all_negative(self):
        x=deepcopy(self.units)
        for u in x:u['outcome']='OBSERVADO_NEGATIVO'
        self.assertTrue(all(d['hypothetical_result_class']=='NEGATIVO_VALIDO' for d in build(x)['decisions']))

    def test_missing_support_never_negative(self):
        x=self.row('SMB-T02')
        x['outcome']='OBSERVADO_NEGATIVO'
        del x['supports']['SMBV1_RESPONSE']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_smbv1_negative_requires_compatible_client(self):
        x=self.row('SMB-T02')
        x['outcome']='OBSERVADO_NEGATIVO'
        x['preconditions']['CLIENT_COMPATIBLE']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')

    def test_smbv1_needs_specific_response(self):
        x=self.row('SMB-T02')
        x['supports']['SMBV1_RESPONSE']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_smbv1_no_unbounded_fallback(self):
        x=self.row('SMB-T02')
        x['fallback_used']=True
        self.expect_code([x],'UNIT_SCHEMA')

    def test_signing_and_encryption_independent(self):
        sig=self.row('SMB-T03','SIGNING')
        enc=self.row('SMB-T03','ENCRYPTION')
        self.assertEqual(set(sig['supports']) & {'SMB_SIGNATURE','SMB_ENCRYPTION'},{'SMB_SIGNATURE'})
        self.assertEqual(set(enc['supports']) & {'SMB_SIGNATURE','SMB_ENCRYPTION'},{'SMB_ENCRYPTION'})
        result=build([sig,enc])
        support_sets=[set(d['required_supports']) for d in result['decisions']]
        self.assertTrue(any('SMB_SIGNATURE' in x and 'SMB_ENCRYPTION' not in x for x in support_sets))
        self.assertTrue(any('SMB_ENCRYPTION' in x and 'SMB_SIGNATURE' not in x for x in support_sets))

    def test_signing_does_not_prove_encryption(self):
        x=self.row('SMB-T03','ENCRYPTION')
        del x['supports']['SMB_ENCRYPTION']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_encryption_does_not_prove_signing(self):
        x=self.row('SMB-T03','SIGNING')
        del x['supports']['SMB_SIGNATURE']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_cross_variant_support_not_accepted(self):
        x=self.row('SMB-T03','SIGNING')
        x['supports']['SMB_ENCRYPTION']='VERDADERO'
        self.expect_code([x],'SUPPORT_SCHEMA')

    def test_signing_response_needed(self):
        x=self.row('SMB-T03','SIGNING')
        del x['supports']['OPERATION_RESPONSE']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_guest_session_not_share_access(self):
        x=self.row('SMB-T04')
        x['supports']['SHARE_ACCESS']='VERDADERO'
        self.expect_code([x],'SUPPORT_SCHEMA')

    def test_share_access_separate_from_directory_listing(self):
        x=self.row('SMB-T06')
        del x['supports']['DIRECTORY_LISTING']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_resource_read_needs_digest(self):
        x=self.row('SMB-T07')
        del x['supports']['KNOWN_CONTENT_DIGEST']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_t08_cleanup_failure(self):
        x=self.row('SMB-T08')
        x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')

    def test_t08_cleanup_unknown(self):
        x=self.row('SMB-T08')
        x['cleanup']='ND';x['supports']['CLEANUP_CONFIRMED']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_t08_cleanup_contradiction(self):
        x=self.row('SMB-T08')
        x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='VERDADERO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')

    def test_t08_cleanup_true_but_support_false(self):
        x=self.row('SMB-T08')
        x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')

    def test_t09_read_no_cleanup(self):
        x=self.row('SMB-T09','READ')
        self.assertEqual(x['cleanup'],'NO_APLICA')
        self.assertFalse(build([x])['decisions'][0]['cleanup_required'])

    def test_t09_write_cleanup_needed(self):
        x=self.row('SMB-T09','WRITE')
        del x['supports']['CLEANUP_CONFIRMED']
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_t09_write_cleanup_failure(self):
        x=self.row('SMB-T09','WRITE')
        x['cleanup']='FALSO';x['supports']['CLEANUP_CONFIRMED']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')

    def test_t09_write_requires_prepared_marker(self):
        x=self.row('SMB-T09','WRITE')
        x['preconditions']['WRITE_FIXTURE_PREPARED']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')

    def test_t09_read_no_write_marker_inference(self):
        x=self.row('SMB-T09','READ')
        x['supports']['MARKER_CREATED']='VERDADERO'
        self.expect_code([x],'SUPPORT_SCHEMA')

    def test_t09_distinct_precedence(self):
        x=build([self.row('SMB-T09','READ'),self.row('SMB-T09','WRITE')])
        self.assertEqual(set(d['precedence'] for d in x['decisions']),{3,4})

    def test_same_case_id_two_variants_rejected(self):
        a=self.row('SMB-T03','SIGNING')
        b=self.row('SMB-T03','ENCRYPTION')
        b['derived_case_id']=a['derived_case_id']
        self.expect_code([a,b],'DUPLICATE_CASE_OR_VARIANT_WINDOW')

    def test_unrelated_sessions_do_not_mix(self):
        x=self.row('SMB-T01')
        y=deepcopy(x);y['session_id']='SECOND_SESSION';y['outcome']='OBSERVADO_NEGATIVO'
        self.assertEqual(len(build([x,y])['decisions']),2)

    def test_different_windows_allowed(self):
        x=self.row('SMB-T01')
        y=deepcopy(x);y['assessment_index']=1
        self.assertEqual(len(build([x,y])['decisions']),2)

    def test_duplicate_same_window_rejected(self):
        x=self.row('SMB-T01')
        self.expect_code([x,deepcopy(x)],'DUPLICATE_CASE_OR_VARIANT_WINDOW')

    def test_max_54(self):
        x=self.row('SMB-T01')
        many=[{**x,'derived_case_id':f'SMB-T01-S01-{i:02}'} for i in range(1,55)]
        self.assertEqual(build(many)['unit_count'],54)

    def test_55_rejected(self):
        x=self.row('SMB-T01')
        many=[{**x,'derived_case_id':f'SMB-T01-S01-{i:02}'} for i in range(1,56)]
        self.expect_code(many,'UNIT_COUNT')

    def test_empty(self):
        self.expect_code([],'UNIT_COUNT')

    def test_wrong_batch_type(self):
        with self.assertRaises(ValueError): build({})

    def test_invalid_unit_type(self):
        self.expect_code([None],'UNIT_NOT_DICT')

    def test_unknown_family(self):
        x=self.row('SMB-T01');x['family_id']='SSH-T01'
        self.expect_code([x],'FAMILY_OUT_OF_SCOPE')

    def test_case_binding(self):
        x=self.row('SMB-T01');x['derived_case_id']='SMB-T02-S01-01'
        self.expect_code([x],'DERIVED_CASE_ID')

    def test_case_identifier_format(self):
        x=self.row('SMB-T01');x['derived_case_id']='SMB-T01-S99-100'
        self.expect_code([x],'DERIVED_CASE_ID')

    def test_missing_field(self):
        x=self.row('SMB-T01');del x['outcome']
        self.expect_code([x],'UNIT_SCHEMA')

    def test_extra_field(self):
        x=self.row('SMB-T01');x['a6_classification']='VERDADERO'
        self.expect_code([x],'UNIT_SCHEMA')

    def test_missing_guard(self):
        x=self.row('SMB-T01');del x['preconditions']['CLIENT_COMPATIBLE']
        self.expect_code([x],'PRECONDITION_SCHEMA')

    def test_extra_guard(self):
        x=self.row('SMB-T01');x['preconditions']['ADMIN_AUTHORIZED']='VERDADERO'
        self.expect_code([x],'PRECONDITION_SCHEMA')

    def test_guard_false(self):
        x=self.row('SMB-T01');x['preconditions']['SCOPE_APPROVED']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')

    def test_guard_unknown(self):
        x=self.row('SMB-T01');x['preconditions']['SCOPE_APPROVED']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')

    def test_false_overrides_nd(self):
        x=self.row('SMB-T01');x['preconditions']['SCOPE_APPROVED']='ND'
        x['preconditions']['CLIENT_COMPATIBLE']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['guard_simulated'],'FALSO')

    def test_guard_bool_refused(self):
        x=self.row('SMB-T01');x['preconditions']['SCOPE_APPROVED']=True
        self.expect_code([x],'TRIVALENT_VALUES')

    def test_guard_not_truth_value(self):
        x=self.row('SMB-T01');x['preconditions']['SCOPE_APPROVED']='UNKNOWN'
        self.expect_code([x],'TRIVALENT_VALUES')

    def test_support_false(self):
        x=self.row('SMB-T01');x['supports']['SMB_DIALECT']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')

    def test_support_nd(self):
        x=self.row('SMB-T01');x['supports']['SMB_DIALECT']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_extra_support(self):
        x=self.row('SMB-T01');x['supports']['SMB_ENCRYPTION']='VERDADERO'
        self.expect_code([x],'SUPPORT_SCHEMA')

    def test_integrity_false(self):
        x=self.row('SMB-T01');x['integrity']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')

    def test_integrity_nd(self):
        x=self.row('SMB-T01');x['integrity']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_provenance_false(self):
        x=self.row('SMB-T01');x['provenance']='FALSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INVALIDO')

    def test_provenance_nd(self):
        x=self.row('SMB-T01');x['provenance']='ND'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_phase_not_pending(self):
        x=self.row('SMB-T01');x['phase']='ACTIVO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')

    def test_phase_invalid(self):
        x=self.row('SMB-T01');x['phase']='EXECUTING'
        self.expect_code([x],'PHASE')

    def test_index_bool(self):
        x=self.row('SMB-T01');x['assessment_index']=True
        self.expect_code([x],'ASSESSMENT_INDEX')

    def test_index_negative(self):
        x=self.row('SMB-T01');x['assessment_index']=-1
        self.expect_code([x],'ASSESSMENT_INDEX')

    def test_index_overflow(self):
        x=self.row('SMB-T01');x['assessment_index']=2**31
        self.expect_code([x],'ASSESSMENT_INDEX')

    def test_bad_session(self):
        x=self.row('SMB-T01');x['session_id']='bad session'
        self.expect_code([x],'SESSION_ID')

    def test_unexpected_variant(self):
        x=self.row('SMB-T01');x['variant']='SIGNING'
        self.expect_code([x],'UNEXPECTED_VARIANT')

    def test_required_variant(self):
        x=self.row('SMB-T03','SIGNING');x['variant']=None
        self.expect_code([x],'VARIANT_EXPLICIT_REQUIRED')

    def test_unknown_variant(self):
        x=self.row('SMB-T03','SIGNING');x['variant']='TLS'
        self.expect_code([x],'VARIANT_EXPLICIT_REQUIRED')

    def test_t08_cleanup_missing(self):
        x=self.row('SMB-T08');x['cleanup']='NO_APLICA'
        self.expect_code([x],'CLEANUP_VALUE')

    def test_t09_read_cleanup_unexpected(self):
        x=self.row('SMB-T09','READ');x['cleanup']='VERDADERO'
        self.expect_code([x],'CLEANUP_VALUE')

    def test_outcome_unrecognized(self):
        x=self.row('SMB-T01');x['outcome']='BRUTE_FORCE'
        self.expect_code([x],'OUTCOME')

    def test_incident_not_positive(self):
        x=self.row('SMB-T01');x['outcome']='INCIDENCIA'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')

    def test_outcome_inconclusive(self):
        x=self.row('SMB-T01');x['outcome']='INCONCLUSO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'INCONCLUSO')

    def test_invalid_catalog_count(self):
        self.assertRaisesRegex(ValueError, 'EXACTLY_NINE', sm._specs, specs()[:-1])

    def test_duplicate_catalog_family(self):
        s=specs();s[1]['id']=s[0]['id']
        self.assertRaisesRegex(ValueError,'EXACTLY_NINE', sm._specs, s)

    def test_catalog_wrong_precedence(self):
        s=specs();next(x for x in s if x['id']=='SMB-T03')['precedence']=[1,3]
        self.assertRaisesRegex(ValueError,'CATALOG_VARIANTS',sm._specs,s)

    def test_catalog_wrong_variant_options(self):
        s=specs();next(x for x in s if x['id']=='SMB-T09')['variants']['precedence_by_option']['WRITE']=3
        self.assertRaisesRegex(ValueError,'CATALOG_VARIANTS',sm._specs,s)

    def test_catalog_wrong_cleanup(self):
        s=specs();next(x for x in s if x['id']=='SMB-T08')['cleanup']='NO_MUTATION'
        self.assertRaisesRegex(ValueError,'CATALOG_CLEANUP',sm._specs,s)

    def test_catalog_wrong_support_accept(self):
        s=specs();next(x for x in s if x['id']=='SMB-T01')['acceptance_supports'].append('OTHER')
        self.assertRaisesRegex(ValueError,'CATALOG_ACCEPTANCE',sm._specs,s)

    def test_catalog_wrong_support_duplicate(self):
        s=specs();next(x for x in s if x['id']=='SMB-T01')['required_supports'].append('SMB_DIALECT')
        self.assertRaisesRegex(ValueError,'CATALOG_REQUIRED_SUPPORTS',sm._specs,s)

    def test_catalog_bad_family_id(self):
        s=specs();s[0]['id']='SMB-T10'
        self.assertRaisesRegex(ValueError,'SMB_FAMILY_UNKNOWN',sm._specs,s)

    def test_catalog_loader_fake_hash_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'catalog.json';p.write_text('{}')
            with patch.object(sm,'CATALOG_PATH',p):
                self.assertRaisesRegex(ValueError,'CATALOG_PIN_MISMATCH',sm.load_pinned_smb_catalog)

    def test_catalog_loader_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'symlink.json';p.symlink_to(Path(temp)/'missing.json')
            with patch.object(sm,'CATALOG_PATH',p):
                self.assertRaisesRegex(ValueError,'CATALOG_NOT_REGULAR',sm.load_pinned_smb_catalog)

    def test_catalog_loader_synthetic_pin_success(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'catalog.json'
            body={'thesis_sha256':sm.THESIS_SHA256,
                  'status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
                  'execution_enabled':False,
                  'counts':{'ssh':8,'ftp':8,'smb':9,'total':25},'families':specs()}
            p.write_bytes(canonical(body))
            with patch.object(sm,'CATALOG_PATH',p),\
                 patch.object(sm,'CATALOG_SHA256',hashlib.sha256(p.read_bytes()).hexdigest()):
                self.assertEqual(len(sm.load_pinned_smb_catalog()),9)
                self.assertEqual(sm.build_smb_simulation(self.units)['unit_count'],11)

    def test_rehashed_false_classification(self):
        report=deepcopy(self.report)
        report['decisions'][0]['a6_classification']='VERDADERO';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_risk(self):
        report=deepcopy(self.report)
        report['decisions'][0]['confirmed_rf']='1/2';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_generation(self):
        report=deepcopy(self.report)
        report['published_generation']='GEN1';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_transition(self):
        report=deepcopy(self.report)
        report['applied_state_transition']='APPLIED';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_p8(self):
        report=deepcopy(self.report)
        report['p8_operational']='GO';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_pin(self):
        report=deepcopy(self.report)
        report['catalog_source']='FULL_FILE_SHA256_PINNED';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_rehashed_false_variant(self):
        report=deepcopy(self.report)
        report['decisions'][0]['variant']='ENCRYPTION';fresh(report)
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_tampered_digest(self):
        report=deepcopy(self.report);report['unit_count']=99
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_wrong_hash(self):
        report=deepcopy(self.report);report['sha256']='not-a-hash'
        with self.assertRaises(ValueError):sm.verify_smb_simulation(report,_test_families=specs())

    def test_sha_pinning_input_not_pinnable(self):
        self.assertEqual(self.report['catalog_source'],'TEST_FIXTURE_NOT_PINNED')


# Per-family positive and negative decision tests; each checks one independent
# family and does NOT suggest physical experimental validation.
for _idx in range(1,10):
    def _positive(self, number=_idx):
        x=self.row(f'SMB-T{number:02}', 'SIGNING' if number==3 else 'READ' if number==9 else None)
        x['outcome']='OBSERVADO_POSITIVO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'POSITIVO_VALIDO')
    def _negative(self, number=_idx):
        x=self.row(f'SMB-T{number:02}', 'SIGNING' if number==3 else 'READ' if number==9 else None)
        x['outcome']='OBSERVADO_NEGATIVO'
        self.assertEqual(build([x])['decisions'][0]['hypothetical_result_class'],'NEGATIVO_VALIDO')
    setattr(SMBFamilyTests,f'test_family_{_idx:02}_positive',_positive)
    setattr(SMBFamilyTests,f'test_family_{_idx:02}_negative',_negative)

if __name__=='__main__':unittest.main()
