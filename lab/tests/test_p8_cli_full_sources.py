"""P8-R14 anchor and deny-only tests; never calls guest/client binaries."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import verify_p8_cli_full_sources as r14
BASE=Path(__file__).resolve().parents[2]

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=r14.safe_read(BASE,r14.SOURCE,r14.SOURCE_SHA)
        cls.r12=r14.safe_read(BASE,r14.R12,r14.R12_SHA)
        cls.r13=r14.safe_read(BASE,r14.R13,r14.R13_SHA)
    def mutated(self):return copy.deepcopy(self.source)
    def reject(self,data):
        with self.assertRaises(r14.FullSourceError):r14.check_catalog(data,self.r12,self.r13)
    def test_valid(self):
        self.assertEqual(r14.check_catalog(self.source,self.r12,self.r13)['terms'],91)
    def test_full_anchor_count(self):self.assertEqual(len(self.source['term_anchors']),91)
    def test_every_profile(self):self.assertEqual(len(self.source['profile_refs']),29)
    def test_source_hash(self):self.assertEqual(r14.sha((BASE/r14.SOURCE).read_bytes()),r14.SOURCE_SHA)
    def test_zero_semantic_reviews(self):self.assertEqual(self.source['complete_semantic_reviews'],0)
    def test_no_option_flags(self):self.assertEqual(self.source['approved_cli_options'],0)
    def test_no_argv(self):self.assertEqual(self.source['approved_argv_renderers'],0)
    def test_no_dispatch(self):self.assertIs(self.source['dispatch_allowed'],False)
    def test_profile_order(self):
        x=self.mutated();x['profile_refs'].reverse();self.reject(x)
    def test_reorder_terms(self):
        x=self.mutated();x['term_anchors'].reverse();self.reject(x)
    def test_bad_manual_sha(self):
        x=self.mutated();x['source_manifests'][0]['uncompressed_sha256']='0'*64;self.reject(x)
    def test_bad_compressed_sha(self):
        x=self.mutated();x['source_manifests'][0]['compressed_sha256']='0'*64;self.reject(x)
    def test_manual_size(self):
        x=self.mutated();x['source_manifests'][0]['uncompressed_bytes']+=1;self.reject(x)
    def test_manual_duplicate(self):
        x=self.mutated();x['source_manifests'][1]['manual_path']=x['source_manifests'][0]['manual_path'];self.reject(x)
    def test_wrong_increment(self):
        x=self.mutated();x['increment']='P8-R15';self.reject(x)
    def test_wrong_base(self):
        x=self.mutated();x['base_commit']='0'*40;self.reject(x)
    def test_wrong_private_report_sha(self):
        x=self.mutated();x['private_report_sha256']='0'*64;self.reject(x)
    def test_prior_r12_drift(self):
        x=self.mutated();x['r12_semantics_sha256']='0'*64;self.reject(x)
    def test_prior_r13_drift(self):
        x=self.mutated();x['r13_symbolic_spec_sha256']='0'*64;self.reject(x)
    def test_promote_full_review(self):
        x=self.mutated();x['complete_semantic_reviews']=7;self.reject(x)
    def test_promote_cli(self):
        x=self.mutated();x['approved_cli_grammars']=1;self.reject(x)
    def test_promote_argv(self):
        x=self.mutated();x['approved_argv_renderers']=1;self.reject(x)
    def test_promote_cases(self):
        x=self.mutated();x['authorized_cases']=1;self.reject(x)
    def test_promote_profiles(self):
        x=self.mutated();x['authorized_profiles']=1;self.reject(x)
    def test_promote_dispatch(self):
        x=self.mutated();x['dispatch_allowed']=True;self.reject(x)
    def test_promote_guest(self):
        x=self.mutated();x['guest_binaries_executed']=True;self.reject(x)
    def test_promote_algorithm(self):
        x=self.mutated();x['algorithms_started']=True;self.reject(x)
    def test_publish_originals(self):
        x=self.mutated();x['full_original_manual_text_published']=True;self.reject(x)
    def test_anchor_false_class(self):
        x=self.mutated();x['term_anchors'][0]['anchor_class']='ALLOWED';self.reject(x)
    def test_anchor_hash_invalid(self):
        x=self.mutated();x['term_anchors'][0]['exact_roff_line_sha256']='abcd';self.reject(x)
    def test_anchor_status(self):
        x=self.mutated();x['term_anchors'][0]['annotation_status']='REVIEW_DONE';self.reject(x)
    def test_anchor_approval(self):
        x=self.mutated();x['term_anchors'][0]['option_authorized']=True;self.reject(x)
    def test_anchor_values(self):
        x=self.mutated();x['term_anchors'][0]['caller_supplied_values_approved']=True;self.reject(x)
    def test_anchor_reorder(self):
        x=self.mutated();x['term_anchors'][0],x['term_anchors'][1]=x['term_anchors'][1],x['term_anchors'][0];self.reject(x)
    def test_anchor_foreign_term(self):
        x=self.mutated();x['term_anchors'][0]['term_id']='foreign';self.reject(x)
    def test_extra_root_field(self):
        x=self.mutated();x['runtime_permission']=True;self.reject(x)
    def test_extra_term_field(self):
        x=self.mutated();x['term_anchors'][0]['argv']=['ssh'];self.reject(x)
    def test_fake_profile(self):
        x=self.mutated();x['profile_refs'][0]['profile_id']='OTHER';self.reject(x)
    def test_enable_profile(self):
        x=self.mutated();x['profile_refs'][0]['approved_for_execution']=True;self.reject(x)
    def test_profile_complete_review(self):
        x=self.mutated();x['profile_refs'][0]['complete_semantic_review']=True;self.reject(x)
    def test_profile_extra_command(self):
        x=self.mutated();x['profile_refs'][0]['shell_command']='id';self.reject(x)
    def test_fake_risk_guard(self):
        x=self.mutated();x['safety_boundaries'][0]['guard_verified_operationally']=True;self.reject(x)
    def test_fake_risk_approval(self):
        x=self.mutated();x['safety_boundaries'][0]['approved_for_execution']=True;self.reject(x)
    def test_risk_without_anchor(self):
        x=self.mutated();x['safety_boundaries'][0]['term_id']='UNTRUSTED';self.reject(x)
    def test_risk_count(self):
        x=self.mutated();x['safety_boundaries'].pop();self.reject(x)
    def test_no_private_full_in_repo(self):
        self.assertNotIn('full_roff_source_b64',json.dumps(self.source))
    def test_risk_permanent_readonly(self):
        self.assertTrue(all(a['approved_for_execution'] is False for a in self.source['safety_boundaries']))
    def test_exact_short_flag_discrimination(self):
        self.assertTrue(r14.matches_entry('ssh.1.gz','-o','.It Fl o Ar option'))
        self.assertFalse(r14.matches_entry('ssh.1.gz','-o','.It Fl O Ar control'))
        self.assertFalse(r14.matches_entry('ssh.1.gz','-l','.It Fl L Ar forward'))
        self.assertTrue(r14.matches_entry('ssh.1.gz','-l','.It Fl l Ar login_name'))
    def test_curl_no_prefix_collision(self):
        self.assertTrue(r14.matches_entry('curl.1.gz','--proto','.IP "\\-\\-proto"'))
        self.assertFalse(r14.matches_entry('curl.1.gz','--proto','.IP "\\-\\-proto\\-redir"'))
    def test_samba_escaped_flag(self):
        self.assertTrue(r14.matches_entry('smbclient.1.gz','--client-protection',r'\-\-client\-protection=sign|encrypt|off'))
    def test_no_term_in_examples(self):
        self.assertFalse(r14.matches_entry('ssh-keyscan.1.gz','-T','example -T 5'))
    def test_private_wrong_digest(self):
        with self.assertRaises(r14.FullSourceError):r14.private_reconcile(b'{}',self.source)
    def test_readonly_module_no_dispatch_import(self):
        code=Path(r14.__file__).read_text()
        for name in ('import subprocess','import socket','os.system','exec(','eval('):
            self.assertNotIn(name,code)
    def test_hash_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as td:
            target=Path(td)/'source.json';target.write_text('{}')
            with self.assertRaises(r14.FullSourceError):r14.safe_read(td,'source.json',r14.SOURCE_SHA)
    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as td:
            t=Path(td)/'source.json';t.write_text('{}');s=Path(td)/'link.json';s.symlink_to(t)
            with self.assertRaises(r14.FullSourceError):r14.safe_read(td,'link.json',r14.SOURCE_SHA)
    def test_json_duplicate_denied(self):
        with self.assertRaises(ValueError):r14.parse(b'{"a":1,"a":2}')
    def test_json_nan_denied(self):
        with self.assertRaises(ValueError):r14.parse(b'{"a":NaN}')
    def test_json_oversized_denied(self):
        with self.assertRaises(r14.FullSourceError):r14.parse(b' '* (1024*1024+1))
    def test_repository_full_chain(self):
        if not (BASE/'lab/p8-material-inventory-v1/compatibility.json').exists():
            self.skipTest('full ARDREC repo not available in synthetic bundle')
        output=r14.verify_repository(root=BASE)
        self.assertEqual(output['status'],'PASS_P8_R14_91_EXACT_FULL_SOURCE_ENTRY_ANCHORS_25_GUARDS_DENY_ALL')

if __name__=='__main__':unittest.main()
