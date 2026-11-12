"""P8-R29 adversarial tests. No filesystem, subprocess, network or guest."""
from __future__ import annotations
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r29_typed_declaration as mod


def fixture():
    ids=mod.canonical_ids()
    refs=['authorization_ref','target_ref','scope_ref']
    p8={'status':'P8_R1_UNBOUND_PROFILE_DESIGN_ONLY',
        'execution_enabled':False,'profile_slot_count':29,
        'count_by_protocol':mod.PROTO_COUNTS,'cases_authorized':0,
        'policy':{'pending_binding_fields':list(mod.FIELDS)},'profiles':[]}
    r10={'contract_kind':'DECLARATIVE_PER_FAMILY_SYMBOLIC_ONLY_NOT_RENDERABLE',
         'fully_bound_profiles':0,'authorized_cases':0,
         'verified_executable_capabilities':0,'dispatch_allowed':False,
         'global_denials':{k:False for k in ('shell_process','dynamic_cli_flags',
         'path_lookup','inherited_environment','remote_shell_text',
         'smb_command_language_text','opportunistic_authentication',
         'automatic_retry','operation_dispatch')},'profiles':[]}
    r13={'profile_count':29,'approved_cli_options':0,'approved_argv_renderers':0,
         'approved_cli_grammars':0,'authorized_cases':0,'dispatch_allowed':False,'profiles':[]}
    common=[f'GATE_{i}' for i in range(9)]
    r15={'profile_count':29,'semantic_reviews_completed':0,'approved_cli_options':0,
         'approved_argv_renderers':0,'approved_cli_grammars':0,'authorized_cases':0,
         'dispatch_allowed':False,'writer_count':5,
         'required_common_gates':common,'required_write_gates':['INDEPENDENT_CLEANUP_RECEIPT','RESTORATION_PROOF'],
         'profiles':[]}
    for n,pid in enumerate(ids):
        proto=pid.split('-')[0].lower(); writing=pid in mod.WRITES
        operation='SYNTHETIC_OPERATION_'+str(n)
        effect='WRITE_MARKER_PENDING_CLEANUP' if writing else 'OBSERVE_OR_READ'
        cleanup='VERIFY_THEN_REMOVE_MARKER' if writing else 'NO_MUTATION'
        supports=['EVIDENCE'] + (['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'] if writing else [])
        pre=['SCOPE_APPROVED']+(['WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'] if writing else [])
        risks=[f'RISK_{i}' for i in range(14 if n==0 else 8)]
        # 14+28*8=238
        fam=pid.rsplit('-',1)[0]; variant=None if pid.endswith('-BASE') else pid.rsplit('-',1)[1]
        p8['profiles'].append({'profile_id':pid,'family_id':fam,'protocol':proto,
            'variant':variant,'binding':dict.fromkeys(mod.FIELDS),'status':'BLOCKED_UNBOUND_NO_EXECUTION',
            'required_material_parameter_slots':refs[:], 'required_preconditions':pre,
            'required_supports':supports,'required_acceptance_supports':supports[:],
            'cleanup':cleanup})
        r10['profiles'].append({'profile_id':pid,'family_id':fam,'protocol':proto,
            'variant':variant,'semantic_operation_id':operation,'candidate_binary':mod.EXECUTABLE[proto],
            'candidate_binary_sha256':'a'*64,
            'argument_contract':{'representation':'TYPED_SYMBOLIC_INTENT_NOT_ARGV',
                'material_reference_names':refs[:], 'required_control_atoms':list(mod.COMMON[proto]),
                'command_surface':sorted(mod.SURFACE[proto])[0],
                'rendered_argv':None,'remote_command_ast':None,'smb_command_ast':None,
                'raw_command_strings_allowed':False},
            'execution_boundary':{**{k:None for k in ('environment','working_directory',
                'auxiliary_pins','credential_delivery','capture_policy','resource_budget',
                'private_case_authorization','approved_target','post_execution_cleanup_receipt')},
                **{k:False for k in ('isolation_verified','capability_verified',
                'issuer_and_revocation_verified','runtime_binary_identity_verified','dispatch_allowed')}},
            'cleanup_contract':cleanup,'contract_status':'BLOCKED_UNBOUND_NO_EXECUTION'})
        r13['profiles'].append({'profile_id':pid,'protocol':proto.upper(),
            'semantic_operation_id':operation,'effect_class':effect,'resource_tag':'FIXTURE',
            'grammar_status':'ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE',
            'accepted_cli_options':[],'argv_template':None,'remote_command_ast':None,
            'smb_command_ast':None,'runtime_permission':False,'dispatch_allowed':False,
            'cleanup_contract':cleanup})
        r15['profiles'].append({'profile_id':pid,'protocol':proto.upper(),
            'semantic_operation_id':operation,'effect_class':effect,'resource_tag':'FIXTURE',
            'required_evidence_gates':common+ (r15['required_write_gates'] if writing else []),
            'documented_risks':risks,'status':'BLOCKED_UNREVIEWED',
            'case_authorized':False,'cli_grammar_authorized':False,'dispatch_allowed':False})
    return p8,r10,r13,r15


def approved_request(row):
    return {k:copy.deepcopy(row[k]) for k in ('profile_id','operation_id',
            'material_reference_names','required_control_atoms','effect_class','cleanup_contract')}


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=fixture()
        cls.rows=mod.compile_registry(*cls.data)

    def test_all_29_cross_source_consistent(self):
        self.assertEqual(len(self.rows),29)
        self.assertEqual(mod.summarize(self.rows)['material_bindings_unbound'],348)
        self.assertEqual(mod.summarize(self.rows)['runtime_proof_gate_instances_unverified'],261)
        self.assertEqual(mod.summarize(self.rows)['documentary_gate_links'],271)
        self.assertEqual(mod.summarize(self.rows)['documentary_risk_links'],238)

    def test_all_29_symbolic_requests_remain_denied(self):
        for row in self.rows:
            with self.subTest(profile=row['profile_id']):
                result=mod.review_declaration(self.rows,approved_request(row))
                self.assertTrue(result['declaration_matched'])
                self.assertEqual(result['decision'],'DENY')
                self.assertIsNone(result['argv'])
                self.assertFalse(result['spawn'])
                self.assertFalse(result['dispatch_allowed'])

    def test_29_each_write_and_cleanup_exact(self):
        self.assertEqual({row['profile_id'] for row in self.rows if row['write_variant']},mod.WRITES)
        for row in self.rows:
            with self.subTest(row=row['profile_id']):
                self.assertEqual(row['cleanup_contract'],
                    'VERIFY_THEN_REMOVE_MARKER' if row['write_variant'] else 'NO_MUTATION')

    def test_unsafe_request_fields_denied(self):
        for field,value in [('argv',['/usr/bin/curl']),('authorization',True),
                            ('secret','password'),('case_id','real'),('shell','sh -c'),
                            ('dispatch_allowed',True),('cli_options',['--url'])]:
            with self.subTest(field=field):
                req=approved_request(self.rows[0]);req[field]=value
                with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_rejected_on_missing_or_extra_refs(self):
        req=approved_request(self.rows[8]);req['material_reference_names'].pop()
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)
        req=approved_request(self.rows[8]);req['material_reference_names'].append('arbitrary_ref')
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_rejected_on_injected_tokens(self):
        for s in ('../../secret_ref','name;exec_ref','HTTP_PROXY','authorization_ref\x00'):
            req=approved_request(self.rows[8]);req['material_reference_names'][0]=s
            with self.subTest(s=repr(s)),self.assertRaises(mod.Denied):
                mod.review_declaration(self.rows,req)

    def test_request_rejected_on_missing_protocol_atom(self):
        req=approved_request(self.rows[18]);req['required_control_atoms'].pop()
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_rejected_on_attempted_effect_change(self):
        req=approved_request(self.rows[6]);req['effect_class']='OBSERVE_OR_READ'
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_rejected_on_attempted_cleanup_change(self):
        req=approved_request(self.rows[6]);req['cleanup_contract']='NO_MUTATION'
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_unknown_profile_denied(self):
        req=approved_request(self.rows[0]);req['profile_id']='SSH-T99-BASE'
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_request_wrong_type_rejected(self):
        req=approved_request(self.rows[0]);req['operation_id']=True
        with self.assertRaises(mod.Denied):mod.review_declaration(self.rows,req)

    def test_all_five_writer_profiles_reject_lost_cleanup(self):
        for pid in mod.WRITES:
            with self.subTest(pid=pid):
                src=copy.deepcopy(self.data)
                idx=list(mod.canonical_ids()).index(pid)
                src[0]['profiles'][idx]['required_acceptance_supports'].remove('CLEANUP_CONFIRMED')
                with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_all_protocols_reject_removed_common_security_atom(self):
        for proto in mod.PROTO_COUNTS:
            with self.subTest(proto=proto):
                src=copy.deepcopy(self.data)
                idx=next(i for i,x in enumerate(src[0]['profiles']) if x['protocol']==proto)
                src[1]['profiles'][idx]['argument_contract']['required_control_atoms'].pop(0)
                with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_all_protocols_reject_any_rendered_argv(self):
        for proto in mod.PROTO_COUNTS:
            with self.subTest(proto=proto):
                src=copy.deepcopy(self.data)
                idx=next(i for i,x in enumerate(src[0]['profiles']) if x['protocol']==proto)
                src[1]['profiles'][idx]['argument_contract']['rendered_argv']=['/usr/bin/x']
                with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_all_protocols_reject_cli_option_approval(self):
        for proto in mod.PROTO_COUNTS:
            with self.subTest(proto=proto):
                src=copy.deepcopy(self.data)
                idx=next(i for i,x in enumerate(src[0]['profiles']) if x['protocol']==proto)
                src[2]['profiles'][idx]['accepted_cli_options']=['--unsafe']
                with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_case_authority_promotion(self):
        src=copy.deepcopy(self.data);src[3]['profiles'][8]['case_authorized']=True
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_material_binding_promotion(self):
        src=copy.deepcopy(self.data);src[0]['profiles'][8]['binding']['argv_typed_vector']='abc'
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_hidden_retry(self):
        src=copy.deepcopy(self.data)
        src[1]['profiles'][8]['argument_contract']['required_control_atoms'].remove('FTP_NO_HIDDEN_RETRY')
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_protocol_mismatch(self):
        src=copy.deepcopy(self.data);src[1]['profiles'][8]['protocol']='smb'
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_unapproved_binary_proof(self):
        src=copy.deepcopy(self.data);src[1]['profiles'][8]['execution_boundary']['runtime_binary_identity_verified']=True
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_raw_shell(self):
        src=copy.deepcopy(self.data);src[1]['profiles'][0]['argument_contract']['raw_command_strings_allowed']=True
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_wrong_gate(self):
        src=copy.deepcopy(self.data);src[3]['profiles'][8]['required_evidence_gates'][2]='UNVERIFIED'
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_unauthorized_global_state(self):
        src=copy.deepcopy(self.data);src[2]['authorized_cases']=1
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_duplicate_symbols(self):
        src=copy.deepcopy(self.data);src[1]['profiles'][0]['argument_contract']['required_control_atoms'].append('SSH_NO_PROXYCOMMAND')
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

    def test_registry_rejects_missing_reference(self):
        src=copy.deepcopy(self.data);src[0]['profiles'][8]['required_material_parameter_slots'].pop()
        with self.assertRaises(mod.Denied):mod.compile_registry(*src)

if __name__=='__main__':unittest.main()
