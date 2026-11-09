"""P8-R15 non-executable review gate tests. Synthetic intents only."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import verify_p8_cli_review_gates as r15
ROOT=Path(__file__).resolve().parents[2]

class ReviewGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc=r15.source_read(ROOT,r15.SOURCE,r15.SOURCE_SHA)
        cls.anchors=r15.source_read(ROOT,r15.R14,r15.R14_SHA)
        cls.typed=r15.source_read(ROOT,r15.R13,r15.R13_SHA)

    def obj(self):return copy.deepcopy(self.doc)
    def reject(self,obj):
        with self.assertRaises(r15.ReviewGateError):
            r15.validate_matrix(obj,self.anchors,self.typed)

    def request(self,row):
        return json.dumps({f:('SYNTHETIC_SCHEMA_ONLY' if f=='test_scope' else row[f])
                           for f in r15.r14.r13.REQ_FIELDS},sort_keys=True).encode()

    def test_valid(self):
        got=r15.validate_matrix(self.doc,self.anchors,self.typed)
        self.assertEqual(got['status'],'PASS_P8_R15_29_PROFILES_25_RISKS_238_LINKS_DENY_ALL')
    def test_source_hash(self):
        self.assertEqual(hashlib.sha256((ROOT/r15.SOURCE).read_bytes()).hexdigest(),r15.SOURCE_SHA)
    def test_unchanged_r14(self):
        self.assertEqual(self.doc['r14_full_anchor_sha256'],r15.R14_SHA)
    def test_unchanged_r13(self):
        self.assertEqual(self.doc['r13_symbolic_spec_sha256'],r15.R13_SHA)
    def test_zero_cli(self):self.assertEqual(self.doc['approved_cli_grammars'],0)
    def test_zero_dispatch(self):self.assertIs(self.doc['dispatch_allowed'],False)
    def test_pins(self):
        self.assertEqual(self.doc['base_commit'],r15.BASE)
        self.assertEqual(self.doc['image_sha256'],r15.IMAGE_SHA)
    def test_all_29(self):self.assertEqual(len(self.doc['profiles']),29)
    def test_all_25(self):self.assertEqual(len(self.doc['risks']),25)
    def test_links(self):
        self.assertEqual(sum(len(p['documented_risks']) for p in self.doc['profiles']),238)
    def test_5_writers(self):
        writers=[p for p in self.doc['profiles'] if p['effect_class']=='WRITE_MARKER_PENDING_CLEANUP']
        self.assertEqual(len(writers),5)
        for p in writers:self.assertEqual(p['required_evidence_gates'][-2:],list(r15.WRITER_GATES))
    def test_no_write_receipt_for_readers(self):
        for p in self.doc['profiles']:
            if p['effect_class']!='WRITE_MARKER_PENDING_CLEANUP':
                self.assertEqual(p['required_evidence_gates'],list(r15.GATES))
    def test_conservative_projection(self):
        for row in self.doc['profiles']:
            self.assertEqual(row['risk_projection'],'CONSERVATIVE_PROTOCOL_WIDE_NOT_OPERATIONAL_PROOF')
    def test_no_manual_originals(self):
        self.assertTrue(all('full_roff_source_b64' not in x for x in self.doc['risks']))
    def test_no_cli_tokens(self):
        self.assertTrue(all('argv' not in p and 'command' not in p for p in self.doc['profiles']))
    def test_profile_order(self):
        x=self.obj();x['profiles'].reverse();self.reject(x)
    def test_risk_order(self):
        x=self.obj();x['risks'].reverse();self.reject(x)
    def test_extra_root_field(self):
        x=self.obj();x['secret']=1;self.reject(x)
    def test_extra_risk_field(self):
        x=self.obj();x['risks'][0]['approved_argv']=['ssh'];self.reject(x)
    def test_extra_profile_field(self):
        x=self.obj();x['profiles'][0]['target']='127.0.0.1';self.reject(x)
    def test_wrong_base(self):
        x=self.obj();x['base_commit']='0'*40;self.reject(x)
    def test_wrong_image(self):
        x=self.obj();x['image_sha256']='0'*64;self.reject(x)
    def test_wrong_r14(self):
        x=self.obj();x['r14_full_anchor_sha256']='0'*64;self.reject(x)
    def test_wrong_r13(self):
        x=self.obj();x['r13_symbolic_spec_sha256']='0'*64;self.reject(x)
    def test_wrong_private_pin(self):
        x=self.obj();x['r14_private_full_report_sha256']='0'*64;self.reject(x)
    def test_promote_cli_option(self):
        x=self.obj();x['approved_cli_options']=1;self.reject(x)
    def test_promote_cli_grammar(self):
        x=self.obj();x['approved_cli_grammars']=1;self.reject(x)
    def test_promote_renderer(self):
        x=self.obj();x['approved_argv_renderers']=1;self.reject(x)
    def test_promote_semantic_review(self):
        x=self.obj();x['semantic_reviews_completed']=1;self.reject(x)
    def test_promote_authorized_profile(self):
        x=self.obj();x['authorized_profiles']=1;self.reject(x)
    def test_promote_authorized_case(self):
        x=self.obj();x['authorized_cases']=1;self.reject(x)
    def test_promote_dispatch(self):
        x=self.obj();x['dispatch_allowed']=True;self.reject(x)
    def test_promote_guest(self):
        x=self.obj();x['guest_binaries_executed']=True;self.reject(x)
    def test_promote_algorithm(self):
        x=self.obj();x['algorithms_started']=True;self.reject(x)
    def test_promote_physical_lab(self):
        x=self.obj();x['physical_laboratory_contact']='APPROVED';self.reject(x)
    def test_promote_risk(self):
        x=self.obj();x['risks'][0]['approved_for_execution']=True;self.reject(x)
    def test_promote_review_complete(self):
        x=self.obj();x['risks'][0]['semantic_review_complete']=True;self.reject(x)
    def test_promote_operational_guard(self):
        x=self.obj();x['risks'][0]['operational_control_verified']=True;self.reject(x)
    def test_forget_risk(self):
        x=self.obj();x['risks'].pop();self.reject(x)
    def test_forge_risk_id(self):
        x=self.obj();x['risks'][0]['risk_id']='SOMETHING';self.reject(x)
    def test_forge_risk_category(self):
        x=self.obj();x['risks'][0]['category']='OTHER';self.reject(x)
    def test_forge_line_hash(self):
        x=self.obj();x['risks'][0]['source_line_sha256']='0'*64;self.reject(x)
    def test_forge_guard(self):
        x=self.obj();x['risks'][0]['required_design_guard']='SKIP';self.reject(x)
    def test_reorder_risk_links(self):
        x=self.obj();x['profiles'][0]['documented_risks'].reverse();self.reject(x)
    def test_drop_risk_link(self):
        x=self.obj();x['profiles'][0]['documented_risks'].pop();self.reject(x)
    def test_add_out_of_scope_risk(self):
        x=self.obj();x['profiles'][0]['documented_risks'].append('CURL_INSECURE');self.reject(x)
    def test_promote_profile_status(self):
        x=self.obj();x['profiles'][0]['status']='AUTHORIZED';self.reject(x)
    def test_promote_profile_case(self):
        x=self.obj();x['profiles'][0]['case_authorized']=True;self.reject(x)
    def test_promote_profile_grammar(self):
        x=self.obj();x['profiles'][0]['cli_grammar_authorized']=True;self.reject(x)
    def test_promote_profile_dispatch(self):
        x=self.obj();x['profiles'][0]['dispatch_allowed']=True;self.reject(x)
    def test_drop_common_gate(self):
        x=self.obj();x['profiles'][0]['required_evidence_gates'].pop();self.reject(x)
    def test_drop_writer_cleanup(self):
        x=self.obj();p=next(p for p in x['profiles'] if p['effect_class']=='WRITE_MARKER_PENDING_CLEANUP');p['required_evidence_gates'].pop();self.reject(x)
    def test_change_profile_effect(self):
        x=self.obj();x['profiles'][0]['effect_class']='WRITE_MARKER_PENDING_CLEANUP';self.reject(x)
    def test_wrong_protocol(self):
        x=self.obj();x['profiles'][0]['protocol']='FTP';self.reject(x)
    def test_fake_profile(self):
        x=self.obj();x['profiles'][0]['profile_id']='FAKE';self.reject(x)
    def test_free_form_argv_rejected(self):
        row=self.typed['profiles'][0];req=json.loads(self.request(row));req['argv']=['ssh','localhost']
        with self.assertRaises(r15.r14.r13.GrammarError):
            r15.assess_request(json.dumps(req).encode(),self.doc,self.typed)
    def test_free_form_target_rejected(self):
        row=self.typed['profiles'][0];req=json.loads(self.request(row));req['host']='127.0.0.1'
        with self.assertRaises(r15.r14.r13.GrammarError):
            r15.assess_request(json.dumps(req).encode(),self.doc,self.typed)
    def test_duplicate_json_rejected(self):
        data=b'{"profile_id":"a","profile_id":"a"}'
        with self.assertRaises((r15.r14.r13.GrammarError,r15.ReviewGateError)):
            r15.assess_request(data,self.doc,self.typed)
    def test_untrusted_matrix_object(self):
        x=self.obj();x['profiles'][0]['status']='AUTHORIZED'
        with self.assertRaises(r15.ReviewGateError):
            r15.assess_request(self.request(self.typed['profiles'][0]),x,self.typed)
    def test_real_repo_integration(self):
        if not (ROOT/'lab/p8-material-inventory-v1/compatibility.json').is_file():
            self.skipTest('synthetic fixture lacks R11 chain')
        self.assertEqual(r15.verify_repository(ROOT)['profiles'],29)
    def test_no_unsafe_exec_imports(self):
        s=(LAB/'verify_p8_cli_review_gates.py').read_text()
        for x in ('subprocess','os.system','eval(','exec(','paramiko','popen','socket.connect'):
            self.assertNotIn(x,s)

# 29 separate positive cases: all still BLOCKED
for profile in json.loads((ROOT/'lab/p8-cli-review-gates-v1/gates.json').read_text())['profiles']:
    pid=profile['profile_id']
    def make(pid):
        def test(self):
            source=next(p for p in self.typed['profiles'] if p['profile_id']==pid)
            out=r15.assess_request(self.request(source),self.doc,self.typed)
            self.assertEqual(out['status'],'BLOCKED_REVIEW_GATES_NOT_CLEARED')
            self.assertFalse(out['dispatch_allowed'])
            self.assertIsNone(out['runnable_argv'])
            self.assertEqual(out['profile_id'],pid)
        return test
    setattr(ReviewGateTests,'test_blocked_'+pid.replace('-','_'),make(pid))

if __name__=='__main__':unittest.main(verbosity=2)
