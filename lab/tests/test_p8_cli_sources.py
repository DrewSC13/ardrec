"""P8-R11 adversarial source pinning: documentary data only, always DENY."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

LAB=Path(__file__).resolve().parents[1]
if str(LAB) not in sys.path:sys.path.insert(0,str(LAB))
import verify_p8_cli_sources as subject

class P8R11Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=LAB.parent
        cls.good=subject.checked_source(cls.root,subject.EVIDENCE)
        cls.prior=subject.checked_source(cls.root,subject.R10_CONTRACTS,subject.R10_SHA)
        cls.inv=subject.checked_source(cls.root,subject.R9_INV,subject.r10.R9_INV_SHA)

    def setUp(self):
        self.record=copy.deepcopy(self.good)
        self.prior_copy=copy.deepcopy(self.prior)
        self.inv_copy=copy.deepcopy(self.inv)

    def verify(self):
        return subject.validate(self.record,self.prior_copy,self.inv_copy)

    def rejected(self):
        with self.assertRaises(subject.EvidenceError):self.verify()

    def test_baseline_29_docs_deny_all(self):
        row=self.verify()
        self.assertEqual(row['profile_documentary_candidates'],29)
        self.assertEqual(row['effective_cli_grammars'],0)
        self.assertFalse(row['dispatch_allowed'])

    def test_real_repo_integration(self):
        if not (self.root/'lab/operational-catalog-v1/catalog.json').is_file():
            self.skipTest('Synthetic test scaffold has no P7/P8 ancestry')
        self.assertEqual(subject.verify_repository()['status'],
                         'PASS_P8_R11_MANUAL_DPKG_SOURCES_DENY_ALL')

    def test_extra_top_field(self):
        self.record['unapproved']='x';self.rejected()

    def test_missing_field(self):
        del self.record['manual_sources'];self.rejected()

    def test_wrong_image(self):
        self.record['image_sha256']='0'*64;self.rejected()

    def test_wrong_base(self):
        self.record['base_commit']='0'*40;self.rejected()

    def test_wrong_r10_digest(self):
        self.record['r10_contracts_sha256']='0'*64;self.rejected()

    def test_document_count(self):
        self.record['manual_sources'].pop();self.rejected()

    def test_duplicate_document_row(self):
        self.record['manual_sources'][1]=self.record['manual_sources'][0];self.rejected()

    def test_manpage_path_changed(self):
        self.record['manual_sources'][0]['absolute_path']='/tmp/ssh.1.gz';self.rejected()

    def test_manpage_sha_changed(self):
        self.record['manual_sources'][0]['compressed_sha256']='0'*64;self.rejected()

    def test_manpage_compressed_size(self):
        self.record['manual_sources'][0]['compressed_bytes']+=1;self.rejected()

    def test_manpage_decompressed_size(self):
        self.record['manual_sources'][1]['decompressed_bytes']+=1;self.rejected()

    def test_fake_manual_review(self):
        self.record['manual_sources'][0]['documentation_semantics_verified']=True;self.rejected()

    def test_manual_unexpected_key(self):
        self.record['manual_sources'][0]['optional_flags']=['-x'];self.rejected()

    def test_package_count(self):
        self.record['declared_packages'].pop();self.rejected()

    def test_package_name_changed(self):
        self.record['declared_packages'][0]['name']='evil';self.rejected()

    def test_package_version_changed(self):
        self.record['declared_packages'][0]['version']='0';self.rejected()

    def test_package_depends_changed(self):
        self.record['declared_packages'][1]['depends_declaration']='libc6';self.rejected()

    def test_claim_dependency_closure(self):
        self.record['declared_packages'][0]['dependency_closure_verified']=True;self.rejected()

    def test_claim_runtime_loader(self):
        self.record['declared_packages'][2]['runtime_loader_resolution_verified']=True;self.rejected()

    def test_missing_profile(self):
        self.record['profile_documentation_candidates'].pop();self.rejected()

    def test_reorder_profiles(self):
        a=self.record['profile_documentation_candidates'];a[0],a[1]=a[1],a[0];self.rejected()

    def test_fake_doc_ref(self):
        self.record['profile_documentation_candidates'][0]['documentation_candidates']=['/tmp/manual'];self.rejected()

    def test_candidate_binary_drift(self):
        self.record['profile_documentation_candidates'][10]['candidate_binary']='/bin/sh';self.rejected()

    def test_op_changed(self):
        self.record['profile_documentation_candidates'][0]['operation_id']='OTHER';self.rejected()

    def test_material_hash_changed(self):
        self.record['profile_documentation_candidates'][0]['candidate_binary_sha256']='0'*64;self.rejected()

    def test_cli_grammar_promotion(self):
        self.record['profile_documentation_candidates'][0]['cli_argument_grammar']=['ssh'];self.rejected()

    def test_rendered_argv(self):
        self.record['profile_documentation_candidates'][0]['rendered_argv']=['ssh'];self.rejected()

    def test_ssh_remote_ast(self):
        self.record['profile_documentation_candidates'][4]['remote_command_ast']={'cmd':'id'};self.rejected()

    def test_smb_command_ast(self):
        self.record['profile_documentation_candidates'][23]['smb_command_ast']={'cmd':'ls'};self.rejected()

    def test_accepted_option_tokens(self):
        self.record['profile_documentation_candidates'][0]['accepted_option_tokens']=['-o'];self.rejected()

    def test_manual_semantic_review_faked(self):
        self.record['profile_documentation_candidates'][0]['manual_option_semantics_reviewed']=True;self.rejected()

    def test_tool_capability_faked(self):
        self.record['profile_documentation_candidates'][0]['tool_capability_verified']=True;self.rejected()

    def test_profile_dependency_closure_faked(self):
        self.record['profile_documentation_candidates'][10]['dependency_closure_verified']=True;self.rejected()

    def test_credential_injected(self):
        self.record['profile_documentation_candidates'][2]['credential_delivery']={'secret':'x'};self.rejected()

    def test_environment_injected(self):
        self.record['profile_documentation_candidates'][0]['environment']={'PATH':'/bin'};self.rejected()

    def test_auxiliary_promotion(self):
        self.record['profile_documentation_candidates'][0]['auxiliary_resolution']=['ssh-keyscan'];self.rejected()

    def test_case_authorization_faked(self):
        self.record['profile_documentation_candidates'][0]['case_authorization']='approved';self.rejected()

    def test_budget_faked(self):
        self.record['profile_documentation_candidates'][0]['budget']={'timeout_ms':100};self.rejected()

    def test_cleanup_receipt_faked(self):
        self.record['profile_documentation_candidates'][6]['cleanup_receipt']='done';self.rejected()

    def test_profile_dispatch_true(self):
        self.record['profile_documentation_candidates'][0]['dispatch_allowed']=True;self.rejected()

    def test_profile_status_promoted(self):
        self.record['profile_documentation_candidates'][0]['status']='READY';self.rejected()

    def test_global_dispatch_true(self):
        self.record['dispatch_allowed']=True;self.rejected()

    def test_global_cases_true(self):
        self.record['authorized_cases']=1;self.rejected()

    def test_global_algorithms_started(self):
        self.record['algorithms_started']=True;self.rejected()

    def test_global_grammar_claim(self):
        self.record['effective_cli_grammars']=1;self.rejected()

    def test_removed_limitation(self):
        self.record['limitations'].pop();self.rejected()

    def test_r10_prior_operation_drift(self):
        self.prior_copy['profiles'][0]['semantic_operation_id']='DRIFT';self.rejected()

    def test_r9_image_drift(self):
        self.inv_copy['image']['sha256']='0'*64;self.rejected()

    def test_duplicate_json_rejected(self):
        with self.assertRaises(subject.EvidenceError):subject.decode(b'{"x":1,"x":2}')

    def test_nonfinite_json_rejected(self):
        with self.assertRaises(subject.EvidenceError):subject.decode(b'{"x":NaN}')

    def test_invalid_json_path(self):
        with self.assertRaises(subject.EvidenceError):subject.checked_source(self.root,'../outside')

    def test_offline_no_operator_privileges(self):
        with mock.patch.object(subject.os,'geteuid',return_value=0):
            with self.assertRaises(subject.EvidenceError):subject.verify_offline_image(self.record)

    def test_offline_bad_image_stops_before_manuals(self):
        with mock.patch.object(subject.os,'geteuid',return_value=1000):
            with mock.patch.object(subject,'safe_command',return_value=b'wrong metadata') as checker:
                with self.assertRaises(subject.EvidenceError):subject.verify_offline_image(self.record)
                self.assertEqual(checker.call_count,1)

    def test_absent_package_fails_closed(self):
        self.assertNotIn('curl',subject.parse_dpkg(b'Package: other\nStatus: install ok installed\nVersion: 1\n\n'))

    def test_malicious_dpkg_duplicate_field(self):
        with self.assertRaises(subject.EvidenceError):subject.parse_dpkg(b'Package: curl\nPackage: evil\nStatus: install ok installed\n\n')

    def test_ssh_t03_password_not_auto_resolved(self):
        row=self.record['profile_documentation_candidates'][2]
        self.assertEqual(row['profile_id'],'SSH-T03-BASE')
        self.assertIsNone(row['credential_delivery'])
        self.assertFalse(row['tool_capability_verified'])

    def test_smb_signing_vs_encryption_different(self):
        a=self.record['profile_documentation_candidates']
        s=next(x for x in a if x['profile_id']=='SMB-T03-SIGNING')
        e=next(x for x in a if x['profile_id']=='SMB-T03-ENCRYPTION')
        self.assertNotEqual(s['operation_id'],e['operation_id'])

if __name__=='__main__':unittest.main()
