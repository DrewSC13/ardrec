"""P8 R1 fail-closed profile-slot tests. Tests only synthetic copies, never run commands."""
from __future__ import annotations
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('ardrec_p8_validator',ROOT/'lab/verify_execution_profiles.py')
V=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
PROFILE=V.REL
TRACE=V.TRACE
P7=V.P7_REL
SOURCES=[PROFILE,TRACE,'lab/execution-profiles-v1/README.md','lab/verify_execution_profiles.py',
  'lab/tests/test_execution_profiles.py',P7,V.P7_VALIDATOR,
  'docs/traceability/operational-catalog-v1.json',
  'lab/operational-catalog-v1/README.md',
  'lab/tests/test_operational_catalog.py',
  'lab/scenario-separation-v1/registry.json',
  'lab/scenario-separation-v1/dev.json','lab/scenario-separation-v1/pilot.json',
  'lab/scenario-separation-v1/exp.json']

class ProfilesTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ardrec-p8-synthetic-')
        self.root=Path(self.temp.name)
        for rel in SOURCES:
            dst=self.root/rel
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/rel,dst)
    def tearDown(self):
        self.temp.cleanup()
    def load(self,rel):
        return json.loads((self.root/rel).read_text(encoding='utf-8'))
    def save(self,rel,value):
        (self.root/rel).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def mutate(self,rel,change):
        val=self.load(rel);change(val);self.save(rel,val)
    def bad(self,reason):
        with self.assertRaisesRegex((ValueError,KeyError,TypeError),reason):
            V.validate(self.root)
    def rehash_and_bad(self,reason):
        # The referenced bytes are rehashed in this synthetic fixture, so the test
        # proves the semantic guard and NOT merely a mismatch in anchored integrity.
        fresh=hashlib.sha256((self.root/PROFILE).read_bytes()).hexdigest()
        self.mutate(TRACE,lambda t:t.update(profile_sha256=fresh))
        with patch.object(V,'PROFILE_SHA',fresh):
            self.bad(reason)
    def sample_request(self,profile_id='SSH-T01-BASE'):
        p=next(x for x in self.load(PROFILE)['profiles'] if x['profile_id']==profile_id)
        return {'profile_id':profile_id,
                'parameter_refs':{k:'ref:synthetic-'+k for k in p['required_material_parameter_slots']}}

    def test_valid_exact_25_families_29_variant_slots(self):
        out=V.validate(self.root)
        self.assertEqual((out['families'],out['slots'],out['authorized_profiles']),(25,29,0))
    def test_real_repo_integration(self):
        self.assertEqual(V.validate(ROOT)['slots'],29)
    def test_exact_variant_counts(self):
        ps=self.load(PROFILE)['profiles']
        self.assertEqual(sum(p['protocol']=='ssh' for p in ps),8)
        self.assertEqual(sum(p['protocol']=='ftp' for p in ps),10)
        self.assertEqual(sum(p['protocol']=='smb' for p in ps),11)
    def test_four_variant_families_have_two_distinct_profiles(self):
        p=self.load(PROFILE)['profiles']
        for id_,opts in [('FTP-T02',{'CONTROL','DATA'}),('FTP-T08',{'READ','WRITE'}),
                         ('SMB-T03',{'SIGNING','ENCRYPTION'}),('SMB-T09',{'READ','WRITE'})]:
            self.assertEqual({z['variant'] for z in p if z['family_id']==id_},opts)
    def test_every_binding_is_unset(self):
        for p in self.load(PROFILE)['profiles']:
            self.assertEqual(set(p['binding']),set(V.BINDING_FIELDS))
            self.assertTrue(all(v is None for v in p['binding'].values()))
    def test_preview_ref_only_and_denied(self):
        o=V.preview(self.root,self.sample_request())
        self.assertFalse(o['dispatch_allowed'])
        self.assertIsNone(o['argv'])
        self.assertIsNone(o['executable'])
        self.assertEqual(o['preconditions_value'],'ND')
        self.assertTrue(len(o['missing_binding_fields'])>0)
    def test_preview_is_pure_no_files_written(self):
        before=sorted((str(p.relative_to(self.root)),p.stat().st_size) for p in self.root.rglob('*') if p.is_file())
        V.preview(self.root,self.sample_request())
        after=sorted((str(p.relative_to(self.root)),p.stat().st_size) for p in self.root.rglob('*') if p.is_file())
        self.assertEqual(before,after)
    def test_preview_all_variants_denied(self):
        for p in self.load(PROFILE)['profiles']:
            with self.subTest(profile=p['profile_id']):
                self.assertFalse(V.preview(self.root,self.sample_request(p['profile_id']))['dispatch_allowed'])
    def test_preview_unknown_profile_rejected(self):
        with self.assertRaisesRegex(ValueError,'not registered'):
            V.preview(self.root,self.sample_request()|{'profile_id':'SSH-T99-BASE'})
    def test_preview_raw_secret_rejected(self):
        req=self.sample_request();req['parameter_refs']['authorization_ref']='secret@example'
        with self.assertRaisesRegex(ValueError,'symbolic reference'):
            V.preview(self.root,req)
    def test_preview_unknown_slot_rejected(self):
        req=self.sample_request();req['parameter_refs']['extraneous']='ref:not-allowed'
        with self.assertRaisesRegex(ValueError,'references mismatch'):
            V.preview(self.root,req)
    def test_preview_missing_slot_rejected(self):
        req=self.sample_request();req['parameter_refs'].pop('target_ref')
        with self.assertRaisesRegex(ValueError,'references mismatch'):
            V.preview(self.root,req)
    def test_preview_path_traversal_in_ref_rejected(self):
        req=self.sample_request();req['parameter_refs']['target_ref']='ref:../../etc/passwd'
        with self.assertRaisesRegex(ValueError,'symbolic reference'):
            V.preview(self.root,req)
    def test_preview_bool_or_non_dict_rejected(self):
        with self.assertRaisesRegex(ValueError,'request'):
            V.preview(self.root,{'profile_id':'SSH-T01-BASE','parameter_refs':{},'execute':True})
    def test_profile_hash_modified_rejected(self):
        self.mutate(PROFILE,lambda p:p['profiles'][0].update(status='TAMPERED'))
        self.bad('integrity')
    def test_semantic_candidate_executable_unblocked_rejected(self):
        self.mutate(PROFILE,lambda p:p['profiles'][0]['binding'].update(executable_absolute_path='/usr/bin/ssh'))
        self.rehash_and_bad('unknown binary or executable binding')
    def test_semantic_candidate_argv_unblocked_rejected(self):
        self.mutate(PROFILE,lambda p:p['profiles'][0]['binding'].update(argv_typed_vector=['--help']))
        self.rehash_and_bad('unknown binary or executable binding')
    def test_semantic_parent_environment_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(no_parent_env_inheritance=False))
        self.rehash_and_bad('guard disabled')
    def test_semantic_shell_fallback_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(no_shell_fallback=False))
        self.rehash_and_bad('guard disabled')
    def test_semantic_hidden_retries_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(no_hidden_retries=False))
        self.rehash_and_bad('guard disabled')
    def test_semantic_path_search_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(no_path_lookup=False))
        self.rehash_and_bad('guard disabled')
    def test_semantic_secret_resolver_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(no_secret_values_in_public_artifacts=False))
        self.rehash_and_bad('guard disabled')
    def test_semantic_execution_enabled_rejected(self):
        self.mutate(PROFILE,lambda p:p.update(execution_enabled=True))
        self.rehash_and_bad('premature enablement')
    def test_semantic_case_count_inflation_rejected(self):
        self.mutate(PROFILE,lambda p:p.update(real_cases=54))
        self.rehash_and_bad('unapproved real cases')
    def test_semantic_frozen_profile_rejected(self):
        self.mutate(PROFILE,lambda p:p.update(profile_frozen=True))
        self.rehash_and_bad('premature enablement')
    def test_semantic_numeric_limits_rejected(self):
        self.mutate(PROFILE,lambda p:p['policy'].update(pilot_numeric_limits=30))
        self.rehash_and_bad('policy or limits altered')
    def test_semantic_variant_mutation_rejected(self):
        self.mutate(PROFILE,lambda p:next(x for x in p['profiles'] if x['profile_id']=='FTP-T02-DATA').update(variant='CONTROL'))
        self.rehash_and_bad('family/variant/precedence mismatch')
    def test_semantic_ftp_data_protection_rejected(self):
        self.mutate(PROFILE,lambda p:next(x for x in p['profiles'] if x['profile_id']=='FTP-T02-DATA')
                    ['required_preconditions'].remove('DATA_CHANNEL_PREDEFINED'))
        self.rehash_and_bad('material/guard/support/cleanup mismatch')
    def test_semantic_smb_signing_encryption_distinct(self):
        p=self.load(PROFILE)['profiles']
        s=next(x for x in p if x['profile_id']=='SMB-T03-SIGNING')
        e=next(x for x in p if x['profile_id']=='SMB-T03-ENCRYPTION')
        self.assertIn('SMB_SIGNATURE',s['required_supports'])
        self.assertNotIn('SMB_ENCRYPTION',s['required_supports'])
        self.assertIn('SMB_ENCRYPTION',e['required_supports'])
        self.assertNotIn('SMB_SIGNATURE',e['required_supports'])
    def test_semantic_comparison_write_cleanup_rejected(self):
        self.mutate(PROFILE,lambda p:next(x for x in p['profiles'] if x['profile_id']=='SMB-T09-WRITE')
                    .update(cleanup='NO_MUTATION'))
        self.rehash_and_bad('material/guard/support/cleanup mismatch')
    def test_semantic_duplicate_profile_rejected(self):
        self.mutate(PROFILE,lambda p:p['profiles'].__setitem__(1,p['profiles'][0]))
        self.rehash_and_bad('invalid/duplicate profile id')
    def test_semantic_extra_field_rejected(self):
        self.mutate(PROFILE,lambda p:p.update(ready_for_prod=True))
        self.rehash_and_bad('unexpected/missing keys')
    def test_semantic_physical_isolation_false(self):
        self.mutate(PROFILE,lambda p:p.update(physical_isolation_verified=True))
        self.rehash_and_bad('premature enablement')
    def test_trace_claim_promotion_rejected(self):
        self.mutate(TRACE,lambda t:t.update(experimental_validation='PASS'))
        self.bad('trace promotion')
    def test_trace_binary_pins_promotion_rejected(self):
        self.mutate(TRACE,lambda t:t.update(executables_pinned=29))
        self.bad('trace promotion')
    def test_trace_extra_key_rejected(self):
        self.mutate(TRACE,lambda t:t.update(secret_ref='raw'))
        self.bad('unexpected/missing keys')
    def test_duplicate_json_key_rejected(self):
        path=self.root/TRACE
        raw=path.read_text()
        path.write_text(raw.replace('"schema_version": "1.0",','"schema_version": "1.0", "schema_version": "1.0",',1))
        self.bad('Clave JSON duplicada')
    def test_symlink_to_profile_rejected(self):
        path=self.root/PROFILE
        dest=self.root/'moved.json';path.rename(dest);path.symlink_to(dest)
        self.bad('Enlace simbólico')
    def test_p7_catalog_changed_rejected(self):
        self.mutate(P7,lambda p:p.update(execution_enabled=True))
        self.bad('P7 catalogue integrity')
    def test_p7_stage_promoted_rejected(self):
        self.mutate('lab/scenario-separation-v1/exp.json',lambda m:m.update(status='DEPLOYED'))
        self.bad('P7 source contracts changed|Registro P6|Casos reales')

if __name__=='__main__': unittest.main()
