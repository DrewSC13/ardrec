#!/usr/bin/env python3
"""P8-R17 isolated cross-source 29x12 source and denial adversarial tests."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r17_material_closure as m
import verify_p8_r17_material_closure as v

SPEC=json.loads((LAB/'p8-r17-material-closure-v1/spec.json').read_text())


def mock_sources():
    a={'profile_slot_count':29,'execution_enabled':False,'profiles':[]}
    b={'profile_count':29,'fully_bound_profiles':0,'authorized_cases':0,
       'dispatch_allowed':False,'profiles':[]}
    c={'profile_count':29,'approved_argv_renderers':0,'dispatch_allowed':False,'profiles':[]}
    d={'profile_count':29,'approved_cli_grammars':0,'semantic_reviews_completed':0,
       'dispatch_allowed':False,'required_common_gates':list(m.SHARED_GATES),
       'required_write_gates':list(m.WRITE_GATES), 'writer_count':5,'risk_count':25,
       'profiles':[]}
    for i,pid in enumerate(SPEC['profile_ids']):
        proto=pid.split('-')[0]
        writer=pid in m.WRITER_IDS
        cleanup='VERIFY_THEN_REMOVE_MARKER' if writer else 'NO_MUTATION'
        op='SYMBOLIC_OPERATION_'+pid
        variant=None if pid.endswith('-BASE') else pid.split('-')[-1]
        binary={'SSH':'ssh','FTP':'curl','SMB':'smbclient'}[proto]
        material=['authorization_ref','target_ref']
        a['profiles'].append({'profile_id':pid,'status':'BLOCKED_UNBOUND_NO_EXECUTION',
           'protocol':proto.lower(),'variant':variant,'cleanup':cleanup,
           'required_material_parameter_slots':material,
           'binding':dict.fromkeys(m.BINDING_FIELDS)})
        b['profiles'].append({'profile_id':pid,'protocol':proto.lower(),
           'variant':variant,'semantic_operation_id':op,'cleanup_contract':cleanup,
           'contract_status':'BLOCKED_UNBOUND_NO_EXECUTION',
           'candidate_binary':'/usr/bin/'+binary,'candidate_binary_sha256':'1'*64,
           'argument_contract':{'representation':'TYPED_SYMBOLIC_INTENT_NOT_ARGV',
           'material_reference_names':material,'rendered_argv':None,
           'remote_command_ast':None,'smb_command_ast':None,
           'raw_command_strings_allowed':False},
           'execution_boundary':{'dispatch_allowed':False,
                'runtime_binary_identity_verified':False,'environment':None,
                'working_directory':None,'auxiliary_pins':None,
                'credential_delivery':None,'capture_policy':None,
                'resource_budget':None,'private_case_authorization':None,
                'approved_target':None,'post_execution_cleanup_receipt':None}})
        c['profiles'].append({'profile_id':pid,'protocol':proto,
            'semantic_operation_id':op,'cleanup_contract':cleanup,
            'grammar_status':'ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE',
            'argv_template':None,'remote_command_ast':None,'smb_command_ast':None,
            'accepted_cli_options':[],'runtime_permission':False,'dispatch_allowed':False})
        risk_count={'SSH':9,'FTP':10,'SMB':6}[proto]
        d['profiles'].append({'profile_id':pid,'protocol':proto,
           'semantic_operation_id':op,'status':'BLOCKED_UNREVIEWED',
           'case_authorized':False,'cli_grammar_authorized':False,
           'dispatch_allowed':False,
           'documented_risks':[proto+'_RISK_'+str(k) for k in range(risk_count)],
           'required_evidence_gates':list(m.SHARED_GATES)+list(m.WRITE_GATES if writer else ())})
    return [a,b,c,d]


class Tests(unittest.TestCase):
    def fresh(self):return mock_sources()
    def test_01_complete_29_profile_gate(self):
        d=m.evaluate(*self.fresh())
        self.assertEqual(d['status'],'PASS_DENY_ONLY_29_PROFILE_MATERIAL_GAPS')
        self.assertEqual(d['missing_material_bindings'],348)
        self.assertEqual(d['risk_profile_links'],238)
        self.assertEqual(d['open_evidence_gate_links'],271)
        self.assertEqual(d['write_cleanup_profiles'],5)
        self.assertFalse(d['dispatch_allowed'])
    def test_02_complete_29_order(self):
        self.assertEqual([p['profile_id'] for p in m.evaluate(*self.fresh())['profiles']],SPEC['profile_ids'])
    def test_03_three_protocols(self):
        self.assertEqual(m.evaluate(*self.fresh())['protocol_counts'],{'SSH':8,'FTP':10,'SMB':11})
    def test_04_no_argv_or_case_authority(self):
        d=m.evaluate(*self.fresh())
        self.assertTrue(all(p['argv_runnable'] is False and p['case_authorized'] is False for p in d['profiles']))
    def test_05_five_writers_independent_gates(self):
        d=m.evaluate(*self.fresh())
        self.assertEqual({p['profile_id'] for p in d['profiles'] if p['write_cleanup_required']},m.WRITER_IDS)
        self.assertTrue(all(p['open_evidence_gates'][-2:]==list(m.WRITE_GATES) for p in d['profiles'] if p['write_cleanup_required']))
    def test_06_deterministic(self):
        self.assertEqual(m.evaluate(*self.fresh()),m.evaluate(*self.fresh()))
    def test_07_literal_candidate_is_not_binding(self):
        d=m.evaluate(*self.fresh())
        self.assertEqual(d['profiles'][0]['binding_missing'],list(m.BINDING_FIELDS))
        self.assertEqual(d['profiles'][0]['candidate_executable_observed_only'],'/usr/bin/ssh')
    def test_08_no_guest_execution_import(self):
        source=(LAB/'p8_r17_material_closure.py').read_text()
        self.assertNotIn('import subprocess',source)
        self.assertNotIn('os.system',source)
        self.assertNotIn('Popen(',source)
    def test_09_duplicate_json(self):
        with self.assertRaises(m.MaterialError):m.decode(b'{"a":1,"a":2}')
    def test_10_nan_json(self):
        with self.assertRaises(m.MaterialError):m.decode(b'{"x":NaN}')
    def test_11_size_bound(self):
        with self.assertRaises(m.MaterialError):m.decode(b'x'*2_000_001)
    def test_12_wrong_source_pin(self):
        with self.assertRaises(m.MaterialError):m.read_pinned('/tmp','wrong.json','0'*64)
    def test_13_private_receipts_absent(self):
        self.assertNotIn('PRIVATE_OUTPUT',json.dumps(m.evaluate(*self.fresh())))
    def test_14_full_verifier_spec_and_receipt_oracle(self):
        # Test the outer oracle against the staged, pinned spec without needing
        # any private source or external repository.
        result=m.evaluate(*self.fresh())
        with patch.object(m,'verify_repository',return_value=result):
            got=v.verify(root=LAB.parent,deep=False)
        self.assertEqual(got['profiles_reviewed'],29)
        self.assertEqual(got['missing_material_bindings'],348)
    def test_15_verify_rejects_promoted_report(self):
        result=m.evaluate(*self.fresh())
        result['approved_profiles']=1
        with patch.object(m,'verify_repository',return_value=result):
            with self.assertRaises(m.MaterialError):
                v.verify(root=LAB.parent,deep=False)

# The following deliberately test each distinct promotion or source drift.
NEGATIVE=[
 ('duplicate_profile',lambda d:d[0]['profiles'].__setitem__(1,copy.deepcopy(d[0]['profiles'][0]))),
 ('swap_order',lambda d:d[1]['profiles'].reverse()),
 ('wrong_protocol',lambda d:d[2]['profiles'][0].__setitem__('protocol','FTP')),
 ('wrong_variant',lambda d:d[1]['profiles'][10].__setitem__('variant','CONTROL')),
 ('r1_binding_argv',lambda d:d[0]['profiles'][0]['binding'].__setitem__('argv_typed_vector',['-G'])),
 ('r1_binding_binary',lambda d:d[0]['profiles'][0]['binding'].__setitem__('executable_sha256','a'*64)),
 ('r1_binding_budget',lambda d:d[0]['profiles'][0]['binding'].__setitem__('fixed_resource_budget',{'seconds':999})),
 ('r1_binding_target',lambda d:d[0]['profiles'][0]['binding'].__setitem__('approved_target_ref','ref:any')),
 ('r1_extra_binding_field',lambda d:d[0]['profiles'][0]['binding'].__setitem__('extra',None)),
 ('r10_dispatch',lambda d:d[1].__setitem__('dispatch_allowed',True)),
 ('r10_fully_bound',lambda d:d[1].__setitem__('fully_bound_profiles',1)),
 ('r10_hidden_argv',lambda d:d[1]['profiles'][0]['argument_contract'].__setitem__('rendered_argv',['ssh'])),
 ('r10_remote_ast',lambda d:d[1]['profiles'][0]['argument_contract'].__setitem__('remote_command_ast',{})),
 ('r10_smb_ast',lambda d:d[1]['profiles'][0]['argument_contract'].__setitem__('smb_command_ast','something')),
 ('r10_free_string',lambda d:d[1]['profiles'][0]['argument_contract'].__setitem__('raw_command_strings_allowed',True)),
 ('r10_runtime_identity_claim',lambda d:d[1]['profiles'][0]['execution_boundary'].__setitem__('runtime_binary_identity_verified',True)),
 ('r10_budget_promotion',lambda d:d[1]['profiles'][0]['execution_boundary'].__setitem__('resource_budget',{'seconds':5})),
 ('r10_fake_authorization',lambda d:d[1]['profiles'][0]['execution_boundary'].__setitem__('private_case_authorization','yes')),
 ('r10_fake_cleanup',lambda d:d[1]['profiles'][0]['execution_boundary'].__setitem__('post_execution_cleanup_receipt','yes')),
 ('r13_runtime',lambda d:d[2]['profiles'][0].__setitem__('runtime_permission',True)),
 ('r13_approved_flag',lambda d:d[2]['profiles'][0].__setitem__('accepted_cli_options',['-G'])),
 ('r13_approved_template',lambda d:d[2]['profiles'][0].__setitem__('argv_template',['ssh'])),
 ('r15_promo_grammar',lambda d:d[3]['profiles'][0].__setitem__('cli_grammar_authorized',True)),
 ('r15_promo_case',lambda d:d[3]['profiles'][0].__setitem__('case_authorized',True)),
 ('r15_missing_evidence',lambda d:d[3]['profiles'][0]['required_evidence_gates'].pop()),
 ('r15_missing_write_receipt',lambda d:d[3]['profiles'][6]['required_evidence_gates'].pop()),
 ('r15_wrong_risk',lambda d:d[3]['profiles'][0].__setitem__('documented_risks',[])),
 ('r15_global_semantic_review',lambda d:d[3].__setitem__('semantic_reviews_completed',1)),
 ('r1_duplicate_field',lambda d:d[0]['profiles'][0]['binding'].__setitem__('case_authorization_ref','x')),
 ('cleanup_wrong_writer',lambda d:d[1]['profiles'][6].__setitem__('cleanup_contract','NO_MUTATION')),
 ('cleanup_wrong_reader',lambda d:d[2]['profiles'][0].__setitem__('cleanup_contract','VERIFY_THEN_REMOVE_MARKER')),
 ('cross_operation_changed',lambda d:d[3]['profiles'][0].__setitem__('semantic_operation_id','OTHER')),
 ('candidate_path_relative',lambda d:d[1]['profiles'][0].__setitem__('candidate_binary','ssh')),
 ('candidate_digest_bad',lambda d:d[1]['profiles'][0].__setitem__('candidate_binary_sha256','broken')),
 ('r1_global_execution_enabled',lambda d:d[0].__setitem__('execution_enabled',True)),
 ('r15_wrong_gates',lambda d:d[3].__setitem__('required_common_gates',['MISSING'])),
]

def make_case(label,mutation):
    def case(self):
        docs=mock_sources(); mutation(docs)
        with self.assertRaises((m.MaterialError,TypeError,KeyError),msg=label):m.evaluate(*docs)
    return case

for index,(label,mutation) in enumerate(NEGATIVE):
    setattr(Tests,'test_negative_%02d_%s'%(index,label),make_case(label,mutation))

if __name__=='__main__':unittest.main(verbosity=2)
