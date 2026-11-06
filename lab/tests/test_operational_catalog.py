"""P7 synthetic mutation tests: no networking, process execution or credentials."""
from __future__ import annotations
import importlib.util
import hashlib
from contextlib import contextmanager
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('p7_catalog_validator',ROOT/'lab/verify_operational_catalog.py')
V=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
CAT='lab/operational-catalog-v1/catalog.json'
TRACE='docs/traceability/operational-catalog-v1.json'


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ardrec-p7-fixture-')
        self.root=Path(self.temp.name)
        sources=[CAT,TRACE,'lab/scenario-separation-v1/registry.json',
                 'lab/scenario-separation-v1/dev.json', 'lab/scenario-separation-v1/pilot.json',
                 'lab/scenario-separation-v1/exp.json',
                 'lab/operational-catalog-v1/README.md','lab/verify_operational_catalog.py',
                 'lab/tests/test_operational_catalog.py']
        for rel in sources:
            dst=self.root/rel
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/rel,dst)
    def tearDown(self):self.temp.cleanup()
    def load(self,rel):return json.loads((self.root/rel).read_text(encoding='utf-8'))
    def save(self,rel,value):(self.root/rel).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def alter(self,rel,fn):
        c=self.load(rel);fn(c);self.save(rel,c)
    def bad(self):
        with self.assertRaises((ValueError,KeyError,TypeError)):
            V.validate(self.root)
    def synthetic(self,stage='dev',protocol='ssh'):
        path=f'lab/scenario-separation-v1/{stage}.json'
        m=self.load(path)
        m['services']=[{'id':stage+'-svc-fixture','protocol':protocol,'network_id':f'ardrec-{stage}-{protocol}',
                        'instance_ref':stage+'-synthetic'}]
        m['scenarios']=[{'id':stage+'-scn-fixture','service_id':stage+'-svc-fixture',
          'profile':{'version':'SYNTHETIC_ONLY','configuration_sha256':'1'*64,'exposure':'TEST',
                     'authentication':'TEST','controls_sha256':'2'*64,'initial_state_sha256':'3'*64,
                     'context_sha256':'4'*64},
          'technical_fingerprint':V.canonical_sha({'protocol':protocol,'profile':{'version':'SYNTHETIC_ONLY',
                        'configuration_sha256':'1'*64,'exposure':'TEST','authentication':'TEST',
                        'controls_sha256':'2'*64,'initial_state_sha256':'3'*64,'context_sha256':'4'*64}}),
          'prior_use':[],'origin_scenario_ids':[]}]
        self.save(path,m)
        return stage+'-scn-fixture'
    def request(self,stage='dev',protocol='ssh',family='SSH-T01',variant=None):
        scn=self.synthetic(stage,protocol)
        cat=self.load(CAT); f=next(x for x in cat['families'] if x['id']==family)
        return {'stage':stage,'scenario_id':scn,'family_id':family,'scenario_code':'S01',
                'ordinal':1,'variant':variant,'parameter_refs':{p:'ref:synthetic-'+p for p in f['parameter_slots']}}

    @contextmanager
    def rebased_catalog_integrity(self):
        """Synthetic-only semantic oracle: refresh both digest anchors, then restore.

        No production catalogue, trace or verifier is modified. A failed test
        must identify the actual violated rule rather than the stale checksum.
        """
        old=V.CATALOG_SHA256
        digest=hashlib.sha256((self.root/CAT).read_bytes()).hexdigest()
        self.alter(TRACE,lambda r:r.update(catalog_sha256=digest))
        V.CATALOG_SHA256=digest
        try:
            yield
        finally:
            V.CATALOG_SHA256=old

    def assert_semantic_rejection(self, mutation, expected_reason):
        self.alter(CAT,mutation)
        with self.rebased_catalog_integrity():
            with self.assertRaisesRegex(ValueError,expected_reason):
                V.validate(self.root)

    def test_valid_catalog_has_exactly_25_families(self):
        a=V.validate(self.root);self.assertEqual((a['ssh'],a['ftp'],a['smb'],a['families']),(8,8,9,25))
    def test_real_repository_integration(self):
        if (ROOT/'lab/scenario-separation-v1/registry.json').is_file():
            self.assertEqual(V.validate(ROOT)['families'],25)
    def test_all_families_have_preconditions_limits_supports_cleanup(self):
        c=self.load(CAT)
        for f in c['families']:
            with self.subTest(family=f['id']):
                self.assertIn('SCOPE_APPROVED',f['preconditions'])
                self.assertIn('authorization_ref',f['parameter_slots'])
                self.assertIn('INTEGRITY_PROVENANCE',f['required_supports'])
                self.assertTrue(f['acceptance_supports'])
                self.assertIn(f['cleanup'],{'NO_MUTATION','VERIFY_THEN_REMOVE_MARKER','CONDITIONAL_WRITE_MARKER_CLEANUP'})
        self.assertIsNone(c['budget']['timeout_seconds'])
    def test_25_source_tables_and_fixed_precedence(self):
        c=self.load(CAT)
        for f in c['families']:
            self.assertEqual(f['precedence'],V.LEVELS[f['id']])
            self.assertEqual(f['source_table'],{'ssh':'3.9','ftp':'3.10','smb':'3.11'}[f['protocol']])
    def test_zero_actual_cases_and_no_execution(self):
        c=self.load(CAT)
        self.assertFalse(c['execution_enabled'])
        self.assertEqual(c['derived_real_cases'],0)
        self.assertEqual(self.load(TRACE)['declared_case_count'],0)

    def test_family_removed_even_if_manifest_rehashed(self):
        self.alter(CAT,lambda r:r['families'].pop());self.bad()
    def test_family_added_unapproved_vulnerability(self):
        self.alter(CAT,lambda r:r['families'].append({'id':'SSH-VUL-01'}));self.bad()
    def test_duplicate_family_id(self):
        self.alter(CAT,lambda r:r['families'].append(r['families'][0]));self.bad()
    def test_change_cleanup_policy_of_marker(self):
        self.alter(CAT,lambda r:r['families'][6].update(cleanup='NO_MUTATION'));self.bad()
    def test_change_precedence_order(self):
        self.alter(CAT,lambda r:r['families'][7].update(precedence=1));self.bad()
    def test_remove_acceptance_proof(self):
        self.alter(CAT,lambda r:r['families'][0].update(acceptance_supports=['TRANSPORT_NEGOTIATION']));self.bad()
    def test_prohibit_result_becoming_evidence(self):
        self.alter(CAT,lambda r:r['interpretation'].update(technical_result_is_evidence=True));self.bad()
    def test_inconclusive_not_valid_negative(self):
        self.alter(CAT,lambda r:r['interpretation'].update(negative_is_not_unobserved=False));self.bad()
    def test_pilot_limits_must_remain_unfrozen(self):
        self.alter(CAT,lambda r:r['budget'].update(timeout_seconds=60));self.bad()
    def test_hidden_retries_cannot_be_added(self):
        self.alter(CAT,lambda r:r['budget'].update(additional_attempts='AUTO'));self.bad()
    def test_authorization_gate_cannot_be_removed(self):
        self.alter(CAT,lambda r:r['families'][0]['preconditions'].remove('SCOPE_APPROVED'));self.bad()
    def test_prohibitions_not_dropped(self):
        self.alter(CAT,lambda r:r['prohibitions'].remove('UNBOUNDED_ENUMERATION'));self.bad()
    def test_exec_profile_cannot_be_declared(self):
        self.alter(CAT,lambda r:r.update(execution_profile='ssh'));self.bad()
    def test_frozen_flag_cannot_be_set(self):
        self.alter(CAT,lambda r:r.update(catalog_frozen=True));self.bad()
    def test_trace_promoted_claim_rejected(self):
        self.alter(TRACE,lambda r:r.update(experimental_validation='PASS'));self.bad()
    def test_trace_catalog_sha_tamper_rejected(self):
        self.alter(TRACE,lambda r:r.update(catalog_sha256='0'*64));self.bad()
    def test_rehashed_catalog_and_trace_still_fail(self):
        self.alter(CAT,lambda r:r['budget'].update(operation_count=999))
        actual=__import__('hashlib').sha256((self.root/CAT).read_bytes()).hexdigest()
        self.alter(TRACE,lambda r:r.update(catalog_sha256=actual))
        self.bad()
    def test_stage_promoted_to_execution_rejected(self):
        self.alter('lab/scenario-separation-v1/pilot.json',lambda m:m.update(status='DEPLOYED'))
        self.bad()
    def test_real_unit_added_rejected(self):
        self.alter('lab/scenario-separation-v1/exp.json',lambda m:m['units'].append({'id':'exp-unit-synthetic'}));self.bad()
    def test_unexpected_real_scenario_rejected(self):
        self.synthetic();self.bad()
    def test_unknown_json_field_rejected(self):
        self.alter(CAT,lambda c:c.update(unreviewed=True));self.bad()
    def test_duplicate_json_key_rejected(self):
        p=self.root/TRACE
        p.write_text(p.read_text().replace('"schema_version": "1.0",',
                     '"schema_version": "1.0", "schema_version": "1.0",',1),encoding='utf-8')
        self.bad()
    def test_symlink_catalog_rejected(self):
        p=self.root/CAT; target=self.root/'real-catalog.json';p.rename(target);p.symlink_to(target)
        self.bad()

    # These oracles intentionally make the SHA-256 and public trace consistent
    # with the mutated synthetic catalogue. Passing only a hash gate is not proof
    # that an independent semantic guard was exercised.
    def test_semantic_rebased_integrity_positive_control(self):
        with self.rebased_catalog_integrity():
            self.assertEqual(V.validate(self.root)['families'],25)

    def test_semantic_rehashed_execution_block(self):
        self.assert_semantic_rejection(
            lambda c:c.update(execution_enabled=True),
            'Se pretende autorizar o congelar antes de tiempo')

    def test_semantic_rehashed_budget_block(self):
        self.assert_semantic_rejection(
            lambda c:c['budget'].update(timeout_seconds=60),
            'Presupuesto inferido antes del piloto')

    def test_semantic_rehashed_authorization_gate(self):
        self.assert_semantic_rejection(
            lambda c:c['families'][0]['preconditions'].remove('SCOPE_APPROVED'),
            'Guardas comunes ausentes')

    def test_semantic_rehashed_precedence(self):
        self.assert_semantic_rejection(
            lambda c:c['families'][7].update(precedence=1),
            'Precedencia/variantes alteradas')

    def test_semantic_rehashed_critical_acceptance(self):
        self.assert_semantic_rejection(
            lambda c:c['families'][0]['acceptance_supports'].remove('HOST_KEY_MATCH'),
            'Aceptación sin soporte crítico')

    def test_semantic_rehashed_cleanup(self):
        self.assert_semantic_rejection(
            lambda c:c['families'][6].update(cleanup='NO_MUTATION'),
            'Política de limpieza incompatible')

    def test_semantic_rehashed_result_evidence_separation(self):
        self.assert_semantic_rejection(
            lambda c:c['interpretation'].update(technical_result_is_evidence=True),
            'Resultados/evidencia confundidos')

    def test_semantic_rehashed_prohibitions(self):
        self.assert_semantic_rejection(
            lambda c:c['prohibitions'].remove('EXTERNAL_TARGETS'),
            'Prohibiciones ausentes')

    def test_semantic_rehashed_unapproved_family(self):
        self.assert_semantic_rejection(
            lambda c:c['families'][0].update(id='SSH-VUL-01'),
            'Familias duplicadas/ajenas/ausentes')

    def test_no_real_scenario_prevents_derivation(self):
        binding={'stage':'dev','scenario_id':'dev-scn-missing','family_id':'SSH-T01',
                 'scenario_code':'S01','ordinal':1,'variant':None,'parameter_refs':{}}
        with self.assertRaises(ValueError):V.derive_case(self.root,binding)
    def test_valid_synthetic_derivation_is_in_memory_and_not_executable(self):
        req=self.request();before=sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*'))
        case=V.derive_case(self.root,req)
        after=sorted(str(x.relative_to(self.root)) for x in self.root.rglob('*'))
        self.assertEqual(before,after)
        self.assertEqual(case['case_id'],'SSH-T01-S01-01')
        self.assertEqual(case['preconditions_value'],'ND')
        self.assertFalse(case['execution_enabled'])
        self.assertTrue(case['not_an_experimental_unit'])
    def test_cross_protocol_family_rejected(self):
        req=self.request('dev','ssh','FTP-T01')
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_stage_reference_rejected(self):
        req=self.request();req['stage']='exp'
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_parameters_must_use_references_not_secrets(self):
        req=self.request();req['parameter_refs']['authorization_ref']='password=secret'
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_unknown_material_parameter_rejected(self):
        req=self.request();req['parameter_refs']['injected']='ref:bad-value'
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_bool_not_accepted_as_ordinal(self):
        req=self.request();req['ordinal']=True
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_unapproved_variant_rejected(self):
        req=self.request('dev','ftp','FTP-T02','EXTERNAL')
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_ftp_tls_control_and_data_separated(self):
        req=self.request('dev','ftp','FTP-T02','CONTROL')
        self.assertEqual(V.derive_case(self.root,req)['precedence'],1)
        req['variant']='DATA';req['ordinal']=2
        self.assertEqual(V.derive_case(self.root,req)['precedence'],3)
    def test_ftp_resource_read_write_cleanup_differ(self):
        req=self.request('dev','ftp','FTP-T08','READ')
        self.assertEqual(V.derive_case(self.root,req)['cleanup'],'NO_MUTATION')
        req['variant']='WRITE';req['ordinal']=2
        case=V.derive_case(self.root,req)
        self.assertEqual((case['cleanup'],case['precedence']),('VERIFY_THEN_REMOVE_MARKER',4))
    def test_smb_signing_and_encryption_proof_distinct(self):
        req=self.request('dev','smb','SMB-T03','SIGNING')
        self.assertIn('SMB_SIGNATURE',V.derive_case(self.root,req)['acceptance_supports'])
        req['variant']='ENCRYPTION'
        self.assertIn('SMB_ENCRYPTION',V.derive_case(self.root,req)['acceptance_supports'])
    def test_ftp_control_tls_does_not_require_data_channel_evidence(self):
        req=self.request('dev','ftp','FTP-T02','CONTROL')
        case=V.derive_case(self.root,req)
        self.assertNotIn('CONTROL_DATA_CORRELATION',case['required_supports'])
    def test_ftp_data_tls_requires_prior_session_and_data_path(self):
        req=self.request('dev','ftp','FTP-T02','DATA')
        case=V.derive_case(self.root,req)
        self.assertIn('SESSION_AUTHENTICATED',case['preconditions'])
        self.assertIn('DATA_CHANNEL_PREDEFINED',case['preconditions'])
    def test_smb_signing_case_does_not_require_encryption(self):
        req=self.request('dev','smb','SMB-T03','SIGNING')
        case=V.derive_case(self.root,req)
        self.assertNotIn('SMB_ENCRYPTION',case['required_supports'])
        req['variant']='ENCRYPTION'
        other=V.derive_case(self.root,req)
        self.assertNotIn('SMB_SIGNATURE',other['required_supports'])
    def test_write_comparison_requires_marker_preconditions(self):
        req=self.request('dev','ftp','FTP-T08','WRITE')
        case=V.derive_case(self.root,req)
        self.assertIn('WRITE_FIXTURE_PREPARED',case['preconditions'])
        self.assertIn('CLEANUP_VERIFIABLE',case['preconditions'])
    def test_smb_resource_write_cleanup(self):
        req=self.request('dev','smb','SMB-T09','WRITE')
        self.assertEqual(V.derive_case(self.root,req)['cleanup'],'VERIFY_THEN_REMOVE_MARKER')
    def test_changed_scenario_technical_fingerprint_rejected_for_derivation(self):
        req=self.request()
        p='lab/scenario-separation-v1/dev.json'
        self.alter(p,lambda m:m['scenarios'][0].update(technical_fingerprint='f'*64))
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_changed_scenario_namespace_rejected_for_derivation(self):
        req=self.request()
        p='lab/scenario-separation-v1/dev.json'
        self.alter(p,lambda m:m['services'][0].update(network_id='ardrec-exp-ssh'))
        with self.assertRaises(ValueError):V.derive_case(self.root,req)
    def test_write_comparison_requires_cleanup_support_proof(self):
        req=self.request('dev','ftp','FTP-T08','WRITE')
        case=V.derive_case(self.root,req)
        self.assertIn('CLEANUP_CONFIRMED',case['required_supports'])
        self.assertIn('CLEANUP_CONFIRMED',case['acceptance_supports'])
    def test_ftp_data_tls_has_data_channel_proof(self):
        req=self.request('dev','ftp','FTP-T02','DATA')
        self.assertIn('CONTROL_DATA_CORRELATION',V.derive_case(self.root,req)['acceptance_supports'])
    def test_marker_cleanup_separate(self):
        req=self.request('dev','ssh','SSH-T07')
        x=V.derive_case(self.root,req)
        self.assertIn('CLEANUP_CONFIRMED',x['acceptance_supports'])
    def test_batch_duplicate_case_ids_rejected(self):
        req=self.request()
        with self.assertRaises(ValueError):V.derive_batch(self.root,[req,req])
    def test_batch_distinct_serials_allowed(self):
        req=self.request();other=dict(req);other['ordinal']=2
        result=V.derive_batch(self.root,[req,other]);self.assertEqual(len(result),2)
    def test_no_automatic_case_generation_from_25_families(self):
        self.assertEqual(self.load(TRACE)['declared_case_count'],0)
        self.assertEqual(self.load('lab/scenario-separation-v1/exp.json')['cases'],[])

if __name__=='__main__':unittest.main()
