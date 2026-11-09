"""P8-R12 adversarial tests: excerpts are never operational capabilities."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

LAB=Path(__file__).resolve().parents[1]
if str(LAB) not in sys.path:sys.path.insert(0,str(LAB))
import verify_p8_cli_semantics as subject

class P8R12Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=LAB.parent
        cls.good=subject.read_file(cls.root,subject.SOURCE)
        cls.r11=subject.read_file(cls.root,subject.R11)
        cls.r10=subject.read_file(cls.root,subject.R10)

    def setUp(self):
        self.record=copy.deepcopy(self.good)
        self.prev=copy.deepcopy(self.r11)
        self.con=copy.deepcopy(self.r10)

    def verify(self):return subject.validate(self.record,self.prev,self.con)
    def rejected(self):
        with self.assertRaises(subject.R12Error):self.verify()

    def test_baseline_91_and_29(self):
        r=self.verify()
        self.assertEqual(r['terms'],91)
        self.assertEqual(r['profiles'],29)
        self.assertEqual(r['approved_cli_options'],0)
        self.assertFalse(r['dispatch_allowed'])

    def test_real_repository_and_prior_chain(self):
        if not (self.root/'lab/operational-catalog-v1/catalog.json').is_file():
            self.skipTest('Standalone test scaffold: upstream P6/P7/P8 not present')
        self.assertEqual(subject.verify_repository()['status'],
                         'PASS_P8_R12_91_EXCERPT_NOTES_29_PROFILES_DENY_ALL')

    def test_source_pin_matches_payload(self):
        p=self.root/subject.SOURCE
        self.assertEqual(subject.sha(p.read_bytes()),subject.SOURCE_SHA)

    def test_no_effective_cli_grammar(self):
        self.assertTrue(all(p['cli_grammar'] is None for p in self.record['profiles']))
        self.assertEqual(self.record['approved_cli_grammars'],0)

    def test_destructive_smb_delete_not_a_write_candidate(self):
        r={x['id']:x for x in self.record['term_reviews']}
        self.assertEqual(r['smbclient.1.gz:del']['design_disposition'],
                         'EXCLUDE_FREEFORM_OR_DOWNGRADE')

    def test_curl_ftp_cleartext_tls_fallback_excluded(self):
        r={x['id']:x for x in self.record['term_reviews']}
        for x in ('curl.1.gz:--ftp-ssl-control','curl.1.gz:--ftp-ssl-ccc'):
            self.assertEqual(r[x]['design_disposition'],
                             'EXCLUDE_FREEFORM_OR_DOWNGRADE')

    def test_short_option_case_collision_preserved(self):
        terms={t['id']:t for t in self.record['term_reviews']}
        for x in ('ssh.1.gz:-o','ssh.1.gz:-l'):
            self.assertEqual(terms[x]['review_class'],'AMBIGUOUS_SHORT_TOKEN')

    def test_ssh_keyscan_T_and_t_distinct(self):
        names={t['id'] for t in self.record['term_reviews']}
        self.assertIn('ssh-keyscan.1.gz:-T',names)
        self.assertIn('ssh-keyscan.1.gz:-t',names)

    def test_ftp_control_data_variants_distinct(self):
        p={x['profile_id']:x for x in self.record['profiles']}
        self.assertNotEqual(p['FTP-T02-CONTROL']['source_term_ids'],p['FTP-T02-DATA']['source_term_ids'])

    def test_smb_sign_vs_encrypt_not_operational(self):
        p={x['profile_id']:x for x in self.record['profiles']}
        for key in ('SMB-T03-SIGNING','SMB-T03-ENCRYPTION'):
            self.assertIn('smbclient.1.gz:--client-protection',p[key]['source_term_ids'])
            self.assertFalse(p[key]['profile_capability_verified'])

    def test_five_write_profiles_still_blocked(self):
        p={x['profile_id']:x for x in self.record['profiles']}
        for key in ('SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE','SMB-T08-BASE','SMB-T09-WRITE'):
            self.assertIsNone(p[key]['cleanup_receipt_ref'])
            self.assertFalse(p[key]['dispatch_allowed'])

    def test_text_does_not_contain_actual_credentials(self):
        self.assertNotIn('password=',json.dumps(self.record))

    def test_unknown_root_field(self):self.record['admitted']=True;self.rejected()
    def test_missing_root_field(self):del self.record['profiles'];self.rejected()
    def test_wrong_base(self):self.record['base_commit']='0'*40;self.rejected()
    def test_wrong_probe_sha(self):self.record['probe_report_sha256']='0'*64;self.rejected()
    def test_wrong_r11_sha(self):self.record['r11_evidence_sha256']='0'*64;self.rejected()
    def test_wrong_r10_sha(self):self.record['r10_contracts_sha256']='0'*64;self.rejected()
    def test_wrong_image_sha(self):self.record['image_sha256']='0'*64;self.rejected()
    def test_alter_manual_count(self):self.record['manual_count']=8;self.rejected()
    def test_alter_lexical_count(self):self.record['lexical_term_count']=92;self.rejected()
    def test_alter_review_count(self):self.record['complete_manual_semantic_reviews']=1;self.rejected()
    def test_promote_cli_grammar_count(self):self.record['approved_cli_grammars']=1;self.rejected()
    def test_promote_cli_options_count(self):self.record['approved_cli_options']=1;self.rejected()
    def test_promote_capability_count(self):self.record['verified_tool_capabilities']=1;self.rejected()
    def test_promote_cases(self):self.record['authorized_cases']=1;self.rejected()
    def test_promote_profiles(self):self.record['authorized_profiles']=1;self.rejected()
    def test_promote_dispatch(self):self.record['dispatch_allowed']=True;self.rejected()
    def test_promote_algorithm(self):self.record['algorithms_started']=True;self.rejected()
    def test_promote_guest(self):self.record['guest_binaries_executed']=True;self.rejected()
    def test_promote_lab(self):self.record['physical_laboratory_contact']='READ';self.rejected()
    def test_delete_term(self):self.record['term_reviews'].pop();self.rejected()
    def test_duplicate_term(self):self.record['term_reviews'][1]=self.record['term_reviews'][0];self.rejected()
    def test_unknown_review_class(self):self.record['term_reviews'][0]['review_class']='ALLOW';self.rejected()
    def test_unknown_design_disposition(self):self.record['term_reviews'][0]['design_disposition']='APPROVED';self.rejected()
    def test_fake_manual_complete(self):self.record['term_reviews'][0]['complete_manual_semantics_verified']=True;self.rejected()
    def test_fake_cli_flag(self):self.record['term_reviews'][0]['cli_flag_approved']=True;self.rejected()
    def test_fake_tool_capability(self):self.record['term_reviews'][0]['runtime_capability_verified']=True;self.rejected()
    def test_extra_term_field(self):self.record['term_reviews'][0]['argv']='ssh';self.rejected()
    def test_bad_anchor_shape(self):self.record['term_reviews'][0]['evidence_anchors'][0]['extra']=True;self.rejected()
    def test_bad_anchor_digest(self):self.record['term_reviews'][0]['evidence_anchors'][0]['context_sha256']='not_sha';self.rejected()
    def test_bad_anchor_line(self):self.record['term_reviews'][0]['evidence_anchors'][0]['line_1based']=0;self.rejected()
    def test_missing_analyst_note(self):self.record['term_reviews'][0]['bounded_excerpt_interpretation_es']='';self.rejected()
    def test_missing_profile(self):self.record['profiles'].pop();self.rejected()
    def test_reorder_profiles(self):a=self.record['profiles'];a[0],a[1]=a[1],a[0];self.rejected()
    def test_unknown_profile(self):self.record['profiles'][0]['profile_id']='SSH-X';self.rejected()
    def test_unapproved_doc(self):self.record['profiles'][0]['source_term_ids']=['curl.1.gz:--quote'];self.rejected()
    def test_unknown_term(self):self.record['profiles'][0]['source_term_ids']=['ssh.1.gz:-X'];self.rejected()
    def test_duplicate_profile_term(self):self.record['profiles'][0]['source_term_ids']=['ssh.1.gz:-T']*2;self.rejected()
    def test_rendered_argv_denied(self):self.record['profiles'][0]['rendered_argv']=['ssh'];self.rejected()
    def test_ssh_remote_ast_denied(self):self.record['profiles'][0]['remote_command_ast']={};self.rejected()
    def test_smb_command_ast_denied(self):self.record['profiles'][20]['smb_command_ast']={};self.rejected()
    def test_raw_credentials_denied(self):self.record['profiles'][0]['credential_ref']='password';self.rejected()
    def test_target_denied(self):self.record['profiles'][0]['approved_target_ref']='ref:private';self.rejected()
    def test_budget_denied(self):self.record['profiles'][0]['budget_ref']='ref:budget';self.rejected()
    def test_cleanup_denied(self):self.record['profiles'][0]['cleanup_receipt_ref']='ref:cleanup';self.rejected()
    def test_option_tokens_denied(self):self.record['profiles'][0]['effective_cli_option_tokens']=['-N'];self.rejected()
    def test_profile_source_semantics_denied(self):self.record['profiles'][0]['source_semantics_complete']=True;self.rejected()
    def test_profile_capability_denied(self):self.record['profiles'][0]['profile_capability_verified']=True;self.rejected()
    def test_profile_dispatch_denied(self):self.record['profiles'][0]['dispatch_allowed']=True;self.rejected()
    def test_profile_status_denied(self):self.record['profiles'][0]['status']='ACTIVE';self.rejected()
    def test_prior_profile_mismatch(self):self.con['profiles'][0]['semantic_operation_id']='OTHER';self.rejected()
    def test_prior_document_removed(self):self.prev['profile_documentation_candidates'][0]['documentation_candidates']=[];self.rejected()
    def test_duplicate_json_parser(self):
        with self.assertRaises(subject.R12Error):subject.parse(b'{"x":1,"x":2}')
    def test_nan_parser(self):
        with self.assertRaises(subject.R12Error):subject.parse(b'{"x":NaN}')
    def test_excessively_large_json(self):
        with self.assertRaises(subject.R12Error):subject.parse(b' '*1048577)
    def test_private_report_exact_match_optional(self):
        # Synthetic scaffold does not ship operator private report; real validation uses --probe.
        report=self.root/'../ARDREC_P8_R12_MANPAGE_EVIDENCE_20261109.json'
        if report.is_file():
            self.assertEqual(subject.sha(report.read_bytes()),subject.PROBE_SHA)
            self.assertEqual(subject.validate_private_probe(subject.parse(report.read_bytes()),self.record)['private_probe'],
                             'MATCH_91_TERMS_0_AUTHORIZATION')

if __name__=='__main__':unittest.main()
