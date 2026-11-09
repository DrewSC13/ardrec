"""P8-R13: adversarial pure typed-intent compilation; no real CLI execution."""
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
import verify_p8_cli_grammar as subject

class GrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=LAB.parent
        cls.good=subject.safe_read(cls.root,subject.SPEC,subject.SPEC_SHA)
        cls.prev=subject.safe_read(cls.root,subject.R12,subject.R12_SHA)

    def setUp(self):
        self.record=copy.deepcopy(self.good)
        self.prior=copy.deepcopy(self.prev)

    def check(self):return subject.validate_spec(self.record,self.prior)

    def rejects(self):
        with self.assertRaises(subject.GrammarError):self.check()

    def row(self,pid='SSH-T01-BASE'):
        return next(x for x in self.record['profiles'] if x['profile_id']==pid)

    def valid_req(self,pid='SSH-T01-BASE'):
        p=self.row(pid)
        return {key:(self.record['request_scope'] if key=='test_scope' else p[key])
                for key in subject.REQ_FIELDS}

    def compile_req(self,request):
        return subject.symbolic_plan(json.dumps(request).encode(),self.record)

    def req_rejects(self,request):
        with self.assertRaises(subject.GrammarError):self.compile_req(request)

    def test_schema_29_and_writers(self):
        r=self.check();self.assertEqual(r['profiles'],29)
        self.assertEqual(r['write_cleanup_gates'],5)
        self.assertEqual(r['effective_cli_grammars'],0)
        self.assertFalse(r['dispatch_allowed'])

    def test_all_protocols(self):
        self.assertEqual({k:sum(p['protocol']==k for p in self.record['profiles'])
                          for k in ('SSH','FTP','SMB')},{'SSH':8,'FTP':10,'SMB':11})

    def test_real_repository_integration(self):
        if not (self.root/'lab/operational-catalog-v1/catalog.json').is_file():
            self.skipTest('Synthetic scaffold: upstream complete chain unavailable')
        self.assertEqual(subject.verify_repository()['profiles'],29)

    def test_versioned_source_sha(self):
        self.assertEqual(hashlib.sha256((self.root/subject.SPEC).read_bytes()).hexdigest(),
                         subject.SPEC_SHA)

    def test_all_pure_compilations(self):
        hashes=set()
        for p in self.record['profiles']:
            out=self.compile_req(self.valid_req(p['profile_id']))
            self.assertIsNone(out['runnable_argv'])
            self.assertIsNone(out['remote_command_ast'])
            self.assertIsNone(out['smb_command_ast'])
            self.assertFalse(out['dispatch_allowed'])
            self.assertEqual(len(out['atoms']),8)
            hashes.add(out['plan_sha256'])
        self.assertEqual(len(hashes),29)

    def test_canonical_order_not_json_order(self):
        q=self.valid_req()
        a=self.compile_req(q)
        b=self.compile_req(dict(reversed(list(q.items()))))
        self.assertEqual(a,b)

    def test_no_materials_no_uri_no_argv(self):
        out=json.dumps(self.compile_req(self.valid_req()))
        for s in ('/usr/bin/ssh','--insecure','password','ftp://','smbclient','ssh -o',
                  '$(id)',';rm','/etc/passwd'):
            self.assertNotIn(s,out)

    def test_short_option_collision_not_approved(self):
        self.assertEqual(self.record['approved_cli_options'],0)
        p=self.row('SSH-T01-BASE')
        self.assertEqual(p['accepted_cli_options'],[])

    def test_ftp_control_data_distinct(self):
        a=self.row('FTP-T02-CONTROL');b=self.row('FTP-T02-DATA')
        self.assertNotEqual(a['assurance_design'],b['assurance_design'])
        self.assertEqual(a['assurance_design'],'FTP_CONTROL_TLS_UNVERIFIED')
        self.assertEqual(b['assurance_design'],'FTP_DATA_TLS_UNVERIFIED')

    def test_smb_sign_encryption_distinct(self):
        self.assertNotEqual(self.row('SMB-T03-SIGNING')['assurance_design'],
                            self.row('SMB-T03-ENCRYPTION')['assurance_design'])

    def test_smbv1_not_enabled(self):
        p=self.row('SMB-T02-BASE')
        self.assertEqual(p['assurance_design'],'SMBV1_ISOLATED_FIXTURE_ONLY_UNVERIFIED')
        self.assertFalse(p['runtime_permission'])

    def test_writes_have_cleanup_but_no_receipt(self):
        self.assertEqual({p['profile_id'] for p in self.record['profiles'] if
                         p['effect_class']=='WRITE_MARKER_PENDING_CLEANUP'},subject.WRITE)
        for k in subject.WRITE:
            self.assertEqual(self.row(k)['cleanup_contract'],'VERIFY_THEN_REMOVE_MARKER')
            self.assertFalse(self.row(k)['dispatch_allowed'])

    def test_ssh_password_not_automated(self):
        p=self.row('SSH-T03-BASE')
        self.assertEqual(p['command_surface'],'SSH_CONFIGURATION_UNBOUND')
        self.assertIsNone(p['argv_template'])

    def test_no_approved_argv(self):
        self.assertEqual(self.record['approved_argv_renderers'],0)

    def test_no_guest_executions(self):
        self.assertFalse(self.record['guest_binaries_executed'])

    def test_unknown_schema_key(self):self.record['runnable']=True;self.rejects()
    def test_missing_schema_key(self):del self.record['design_only'];self.rejects()
    def test_wrong_base(self):self.record['base_commit']='f'*40;self.rejects()
    def test_wrong_r12_sha(self):self.record['r12_semantics_sha256']='0'*64;self.rejects()
    def test_wrong_image_sha(self):self.record['image_sha256']='0'*64;self.rejects()
    def test_wrong_step(self):self.record['roadmap_step']=9;self.rejects()
    def test_wrong_step_type(self):self.record['roadmap_step']=True;self.rejects()
    def test_promote_approved_cli(self):self.record['approved_cli_grammars']=1;self.rejects()
    def test_promote_approved_flags(self):self.record['approved_cli_options']=1;self.rejects()
    def test_promote_renderer(self):self.record['approved_argv_renderers']=1;self.rejects()
    def test_promote_authorized_cases(self):self.record['authorized_cases']=1;self.rejects()
    def test_promote_authorized_profiles(self):self.record['authorized_profiles']=1;self.rejects()
    def test_promote_dispatch(self):self.record['dispatch_allowed']=True;self.rejects()
    def test_promote_algorithms(self):self.record['algorithms_started']=True;self.rejects()
    def test_promote_guest(self):self.record['guest_binaries_executed']=True;self.rejects()
    def test_promote_physical_lab(self):self.record['physical_laboratory_contact']='YES';self.rejects()
    def test_false_design(self):self.record['design_only']=False;self.rejects()
    def test_bad_request_scope(self):self.record['request_scope']='RUNTIME';self.rejects()
    def test_extra_request_shape(self):self.record['request_shape'].append('host');self.rejects()
    def test_mutate_row_id(self):self.row()['profile_id']='SSH-T99';self.rejects()
    def test_duplicate_row(self):self.record['profiles'][1]=self.record['profiles'][0];self.rejects()
    def test_drop_row(self):self.record['profiles'].pop();self.rejects()
    def test_reorder_rows(self):self.record['profiles'][0],self.record['profiles'][1]=self.record['profiles'][1],self.record['profiles'][0];self.rejects()
    def test_mutate_operation(self):self.row()['semantic_operation_id']='ANY';self.rejects()
    def test_mutate_reference(self):self.row()['source_term_ids']=[];self.rejects()
    def test_wrong_family(self):self.row()['protocol']='FTP';self.rejects()
    def test_forge_effect(self):self.row()['effect_class']='WRITE_MARKER_PENDING_CLEANUP';self.rejects()
    def test_forge_resource(self):self.row()['resource_tag']='FIXTURE_MARKER';self.rejects()
    def test_forge_assurance(self):self.row()['assurance_design']='SSH_FAKE_UNVERIFIED';self.rejects()
    def test_forge_surface(self):self.row()['command_surface']='SSH_REMOTE_COMMAND_AST_UNDEFINED';self.rejects()
    def test_forge_smb_sign_to_encrypt(self):self.row('SMB-T03-SIGNING')['assurance_design']='SMB_ENCRYPTION_UNVERIFIED';self.rejects()
    def test_forge_ftp_control_to_data(self):self.row('FTP-T02-CONTROL')['assurance_design']='FTP_DATA_TLS_UNVERIFIED';self.rejects()
    def test_drop_smbv1_isolation(self):self.row('SMB-T02-BASE')['assurance_design']='SMB_PROTECTION_UNVERIFIED';self.rejects()
    def test_write_no_cleanup(self):self.row('FTP-T07-BASE')['cleanup_contract']='NO_MUTATION';self.rejects()
    def test_read_cleanup_forgery(self):self.row()['cleanup_contract']='VERIFY_THEN_REMOVE_MARKER';self.rejects()
    def test_cli_options_injected(self):self.row()['accepted_cli_options']=['--insecure'];self.rejects()
    def test_argv_template_injected(self):self.row()['argv_template']=['ssh','target'];self.rejects()
    def test_remote_ast_injected(self):self.row()['remote_command_ast']={'shell':'id'};self.rejects()
    def test_smb_ast_injected(self):self.row('SMB-T06-BASE')['smb_command_ast']='dir;del';self.rejects()
    def test_runtime_permission_injected(self):self.row()['runtime_permission']=True;self.rejects()
    def test_profile_dispatch_injected(self):self.row()['dispatch_allowed']=True;self.rejects()
    def test_profile_status_promoted(self):self.row()['grammar_status']='APPROVED';self.rejects()
    def test_extra_profile_field(self):self.row()['password']='xyz';self.rejects()
    def test_forge_prior(self):self.prior['profiles'][0]['profile_id']='OTHER';self.rejects()
    def test_json_duplicate_key(self):
        with self.assertRaises(subject.GrammarError):subject.strict_json(b'{"x":1,"x":2}')
    def test_json_nan(self):
        with self.assertRaises(subject.GrammarError):subject.strict_json(b'{"x":NaN}')
    def test_json_non_utf8(self):
        with self.assertRaises(subject.GrammarError):subject.strict_json(b'\xff')
    def test_json_large(self):
        with self.assertRaises(subject.GrammarError):subject.strict_json(b' '*4097,4096)
    def test_json_invalid_top(self):self.req_rejects(['foo'])
    def test_request_extra_field(self):q=self.valid_req();q['target']='127.0.0.1';self.req_rejects(q)
    def test_request_shell_field(self):q=self.valid_req();q['shell']='$(id)';self.req_rejects(q)
    def test_request_proxy_command(self):q=self.valid_req();q['ProxyCommand']='x';self.req_rejects(q)
    def test_request_credential(self):q=self.valid_req();q['password']='secret';self.req_rejects(q)
    def test_request_argv(self):q=self.valid_req();q['argv']=['ssh'];self.req_rejects(q)
    def test_request_ftp_quote(self):q=self.valid_req('FTP-T07-BASE');q['--quote']='DELE';self.req_rejects(q)
    def test_request_smb_chain(self):q=self.valid_req('SMB-T08-BASE');q['-c']='dir;del *';self.req_rejects(q)
    def test_request_unknown_profile(self):q=self.valid_req();q['profile_id']='SSH-T99';self.req_rejects(q)
    def test_request_wrong_operation(self):q=self.valid_req();q['semantic_operation_id']='ssh';self.req_rejects(q)
    def test_request_wrong_effect(self):q=self.valid_req();q['effect_class']='WRITE_MARKER_PENDING_CLEANUP';self.req_rejects(q)
    def test_request_wrong_resource(self):q=self.valid_req();q['resource_tag']='/etc/passwd';self.req_rejects(q)
    def test_request_wrong_assurance(self):q=self.valid_req();q['assurance_design']='TLS_DISABLED';self.req_rejects(q)
    def test_request_claim_verified_tls(self):q=self.valid_req('FTP-T02-DATA');q['assurance_design']='FTP_DATA_TLS_VERIFIED';self.req_rejects(q)
    def test_request_smb_downgrade(self):q=self.valid_req('SMB-T03-ENCRYPTION');q['assurance_design']='SMB_SIGNING_UNVERIFIED';self.req_rejects(q)
    def test_request_non_synthetic_scope(self):q=self.valid_req();q['test_scope']='REAL_CASE';self.req_rejects(q)
    def test_request_duplicate_json(self):
        raw=b'{"profile_id":"A","profile_id":"B"}'
        with self.assertRaises(subject.GrammarError):subject.symbolic_plan(raw,self.record)
    def test_request_nul(self):q=self.valid_req();q['profile_id']='SSH-T01-BASE\x00';self.req_rejects(q)
    def test_request_injected_flag(self):q=self.valid_req();q['profile_id']='SSH-T01-BASE --insecure';self.req_rejects(q)
    def test_request_case_mismatch(self):q=self.valid_req();q['profile_id']='ssh-t01-base';self.req_rejects(q)
    def test_request_unexpected_bool(self):q=self.valid_req();q['test_scope']=True;self.req_rejects(q)
    def test_request_missing_field(self):q=self.valid_req();del q['resource_tag'];self.req_rejects(q)
    def test_request_empty(self):
        with self.assertRaises(subject.GrammarError):subject.symbolic_plan(b'',self.record)
    def test_source_rejects_symlink(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as d:
            root=Path(d);(root/'sym').symlink_to('/etc/hosts')
            with self.assertRaises(subject.GrammarError):subject.safe_read(root,'sym','0'*64)

# Per-profile unit cases produce individually countable coverage, not only a loop.
def make_case(pid):
    def test(self):
        p=self.row(pid)
        out=self.compile_req(self.valid_req(pid))
        self.assertEqual(out['atoms'][0],{'kind':'PROFILE','value':pid})
        self.assertEqual(out['atoms'][1]['value'],p['semantic_operation_id'])
        self.assertFalse(out['case_authorized'])
    return test

for _row in subject.safe_read(LAB.parent,subject.SPEC,subject.SPEC_SHA)['profiles']:
    name='test_valid_profile_'+_row['profile_id'].replace('-','_')
    setattr(GrammarTests,name,make_case(_row['profile_id']))

if __name__=='__main__':unittest.main(verbosity=2)
