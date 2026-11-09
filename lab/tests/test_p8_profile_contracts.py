"""P8-R10: adversarial structural tests, no network, CLI, guest or dispatch."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

LAB = Path(__file__).resolve().parents[1]
if str(LAB) not in sys.path:
    sys.path.insert(0,str(LAB))
import verify_p8_profile_contracts as v


class P8R10ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root=LAB.parent
        cls.contract=v.from_root(cls.root,v.CONTRACT)
        cls.compat=v.from_root(cls.root,v.R9_COMPAT,v.R9_COMPAT_SHA)
        cls.inventory=v.from_root(cls.root,v.R9_INV,v.R9_INV_SHA)
        # Real P8 document is source pinned by the predecessor R9 validator.
        cls.p8=v.from_root(cls.root,v.P8,v.r9.P8_SHA)

    def base(self):
        return copy.deepcopy(self.contract)

    def validate(self,clone):
        return v.validate(clone,self.compat,self.inventory,self.p8)

    def row(self,c,profile='SSH-T01-BASE'):
        return next(x for x in c['profiles'] if x['profile_id']==profile)

    def intent(self,profile='SSH-T01-BASE'):
        p=self.row(self.contract,profile)
        a=p['argument_contract']
        return {'profile_id':profile,'operation_id':p['semantic_operation_id'],
                'candidate_binary_sha256':p['candidate_binary_sha256'],
                'control_atoms':list(a['required_control_atoms']),
                'material_reference_names':list(a['material_reference_names']),
                'rendered_argv':None,'remote_command_ast':None,'smb_command_ast':None,
                'desired_action':'REVIEW_ONLY'}

    def rejected(self,change,match=None):
        clone=self.base()
        change(clone)
        with self.assertRaises(v.ContractError) as ctx:
            self.validate(clone)
        if match:
            self.assertIn(match,str(ctx.exception))

    def test_base_all_29(self):
        x=self.validate(self.base())
        self.assertEqual(x['profiles'],29)
        self.assertFalse(x['dispatch_allowed'])
        self.assertFalse(x['argv_renderable'])

    def test_real_repo_consistency_and_prior_r9(self):
        if not (self.root / "lab/operational-catalog-v1/catalog.json").exists():
            self.skipTest("Synthetic source-only stub: full P6/P7/P8 not mounted")
        x=v.verify_repository(self.root)
        self.assertEqual(x['status'],'PASS_P8_R10_29_STRUCTURED_INTENTS_DENY_ALL')

    def test_one_profile_missing(self): self.rejected(lambda c:c['profiles'].pop())
    def test_profile_reordered(self): self.rejected(lambda c:c['profiles'].reverse())
    def test_profile_duplicate(self): self.rejected(lambda c:c['profiles'].append(c['profiles'][0]))
    def test_unknown_profile_id(self): self.rejected(lambda c:c['profiles'][0].__setitem__('profile_id','SSH-T99-BASE'))
    def test_wrong_family(self): self.rejected(lambda c:c['profiles'][0].__setitem__('family_id','FTP-T01'))
    def test_wrong_protocol(self): self.rejected(lambda c:c['profiles'][0].__setitem__('protocol','ftp'))
    def test_wrong_variant(self): self.rejected(lambda c:c['profiles'][9].__setitem__('variant','DATA'))
    def test_wrong_semantic_operation(self): self.rejected(lambda c:c['profiles'][0].__setitem__('semantic_operation_id','DELETE_ROOT'))
    def test_wrong_primary_binary(self): self.rejected(lambda c:c['profiles'][0].__setitem__('candidate_binary','/bin/bash'))
    def test_wrong_primary_sha(self): self.rejected(lambda c:c['profiles'][0].__setitem__('candidate_binary_sha256','f'*64))
    def test_wrong_image_manifest_sha(self): self.rejected(lambda c:c.__setitem__('r9_material_inventory_sha256','0'*64))
    def test_added_cli_option(self): self.rejected(lambda c:c['profiles'][0]['argument_contract']['required_control_atoms'].append('RAW_SHELL'))
    def test_removed_cli_control(self): self.rejected(lambda c:c['profiles'][0]['argument_contract']['required_control_atoms'].pop())
    def test_duplicate_cli_control(self): self.rejected(lambda c:c['profiles'][0]['argument_contract']['required_control_atoms'].append('SSH_NO_PROXYCOMMAND'))
    def test_material_slot_injection(self): self.rejected(lambda c:c['profiles'][0]['argument_contract']['material_reference_names'].append('$(id)'))
    def test_material_slot_reordering(self): self.rejected(lambda c:c['profiles'][0]['argument_contract']['material_reference_names'].reverse())
    def test_shell_script_not_accepted(self): self.rejected(lambda c:c['profiles'][4]['argument_contract'].__setitem__('remote_command_ast',{'shell':'id; echo hello'}))
    def test_smb_cmd_not_accepted(self): self.rejected(lambda c:c['profiles'][20]['argument_contract'].__setitem__('smb_command_ast','ls; put payload'))
    def test_materialized_argv_not_accepted(self): self.rejected(lambda c:c['profiles'][8]['argument_contract'].__setitem__('rendered_argv',['/usr/bin/curl','ftp://x']))
    def test_raw_string_flag(self): self.rejected(lambda c:c['profiles'][0]['argument_contract'].__setitem__('raw_command_strings_allowed',True))
    def test_budget_fabrication(self): self.rejected(lambda c:c['profiles'][0]['execution_boundary'].__setitem__('resource_budget',{'timeout_ms':1000}))
    def test_authorization_fabrication(self): self.rejected(lambda c:c['profiles'][0]['execution_boundary'].__setitem__('private_case_authorization','APPROVED'))
    def test_isolation_promotion(self): self.rejected(lambda c:c['profiles'][0]['execution_boundary'].__setitem__('isolation_verified',True))
    def test_runtime_pin_promotion(self): self.rejected(lambda c:c['profiles'][0]['execution_boundary'].__setitem__('runtime_binary_identity_verified',True))
    def test_dispatch_promotion(self): self.rejected(lambda c:c['profiles'][0]['execution_boundary'].__setitem__('dispatch_allowed',True))
    def test_cleanup_removed_from_ssh_write(self): self.rejected(lambda c:self.row(c,'SSH-T07-BASE').__setitem__('cleanup_contract','NO_MUTATION'))
    def test_cleanup_removed_from_ftp_write(self): self.rejected(lambda c:self.row(c,'FTP-T08-WRITE').__setitem__('cleanup_contract','NO_MUTATION'))
    def test_cleanup_removed_from_smb_write(self): self.rejected(lambda c:self.row(c,'SMB-T09-WRITE').__setitem__('cleanup_contract','NO_MUTATION'))
    def test_tls_control_data_not_interchangeable(self): self.rejected(lambda c:self.row(c,'FTP-T02-DATA').__setitem__('semantic_operation_id','VERIFY_TLS_CONTROL_CHANNEL'))
    def test_smb_signing_not_encryption(self): self.rejected(lambda c:self.row(c,'SMB-T03-SIGNING').__setitem__('semantic_operation_id','VERIFY_ENCRYPTED_SMB_OPERATION'))
    def test_password_mechanism_not_assumed(self): self.rejected(lambda c:self.row(c,'SSH-T03-BASE')['argument_contract']['required_control_atoms'].remove('PASSWORD_TRANSPORT_UNRESOLVED_WITHOUT_SSHPASS'))
    def test_extra_field_fails_closed(self): self.rejected(lambda c:c.__setitem__('shell_allowed',False))
    def test_denial_policy_true_rejected(self): self.rejected(lambda c:c['global_denials'].__setitem__('remote_shell_text',True))
    def test_algorithm_flag_rejected(self): self.rejected(lambda c:c.__setitem__('algorithm_implementation','STARTED'))

    def test_symbolic_request_accepted_but_denied(self):
        for pid in ('SSH-T01-BASE','FTP-T02-DATA','FTP-T08-WRITE','SMB-T03-ENCRYPTION','SMB-T09-WRITE'):
            r=v.assess_symbolic_intent(self.intent(pid),self.contract)
            self.assertEqual(r['status'],'BLOCKED_SYMBOLIC_CONTRACT_ONLY')
            self.assertFalse(r['dispatch_allowed'])

    def test_symbolic_injected_command_rejected(self):
        q=self.intent('SSH-T06-BASE')
        q['remote_command_ast']={'shell':'cat a; cat b'}
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_symbolic_injected_flag_rejected(self):
        q=self.intent('FTP-T01-BASE')
        q['control_atoms'].append('--config=/tmp/evil')
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_symbolic_wrong_operation_rejected(self):
        q=self.intent('SMB-T03-SIGNING')
        q['operation_id']='VERIFY_ENCRYPTED_SMB_OPERATION'
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_symbolic_extraneous_key_rejected(self):
        q=self.intent();q['shell']='bash -c id'
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_symbolic_dispatch_requested_rejected(self):
        q=self.intent();q['desired_action']='DISPATCH'
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_symbolic_wrong_digest_rejected(self):
        q=self.intent();q['candidate_binary_sha256']='0'*64
        with self.assertRaises(v.ContractError):v.assess_symbolic_intent(q,self.contract)

    def test_parse_duplicate_json_key(self):
        with self.assertRaises(v.ContractError):v.parse(b'{"a":1,"a":2}')

    def test_parse_nan(self):
        with self.assertRaises(v.ContractError):v.parse(b'{"a":NaN}')

    def test_source_cannot_import_operation_execution(self):
        source=(LAB/'verify_p8_profile_contracts.py').read_text()
        for forbidden in ("import subprocess", "import socket", "os.system(", "os.spawn", "eval(", "exec(", "std::process::Command("):
            self.assertNotIn(forbidden,source)

if __name__=='__main__':unittest.main()
