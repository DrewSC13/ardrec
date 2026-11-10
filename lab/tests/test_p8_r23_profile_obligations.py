#!/usr/bin/env python3
"""Pure deny-only R23 tests, no GitHub, QCOW2, private source or subprocess."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r23_profile_obligations as g

PRE=['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED','DESTINATION_AUTHORIZED','CLIENT_COMPATIBLE']
SUP=['TARGET_ATTESTATION','INTEGRITY_PROVENANCE']


def fixture():
    family={}
    for proto,count in (('ssh',8),('ftp',8),('smb',9)):
        for n in range(1,count+1):
            f=f'{proto.upper()}-T{n:02d}'
            family[f]={'id':f,'protocol':proto}
    observed=[{'absolute_path':path,'sha256':hashlib.sha256(path.encode()).hexdigest(),
               'status':'IMAGE_BYTES_OBSERVED_NOT_LIVE_PIN'}
              for path in g.PROTOCOL_BINARY.values()]
    ps=[];cs=[]
    for pid in g.canonical_ids():
        proto=pid.split('-')[0].lower()
        write=pid in g.WRITING
        fid=pid.rsplit('-',1)[0]
        pre=PRE+(['WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'] if write else [])
        sup=SUP+(['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'] if write else ['OPERATION_RESPONSE'])
        ps.append({'profile_id':pid,'family_id':fid,'protocol':proto,
                   'variant':None if pid.endswith('-BASE') else pid.rsplit('-',1)[1],
                   'precedence':4 if write else 1,
                   'required_material_parameter_slots':['authorization_ref','target_ref'],
                   'required_preconditions':pre,'required_supports':sup,
                   'required_acceptance_supports':sup[2:],
                   'cleanup':'VERIFY_THEN_REMOVE_MARKER' if write else 'NO_MUTATION',
                   'binding':dict.fromkeys(g.REQUIRED_BINDING),
                   'status':'BLOCKED_UNBOUND_NO_EXECUTION'})
        cs.append({'profile_id':pid,'candidate_primary_binary':g.PROTOCOL_BINARY[proto],
                   'capability_tested':False,'case_binding_verified':False,
                   'argv_frozen':False,'resource_budget_frozen':False,
                   'approval_verified':False,'status':'BLOCKED_UNBOUND_NO_EXECUTION',
                   'additional_gate':('WRITE_CLEANUP_NOT_VERIFIED' if write else
                   'PASSWORD_MECHANISM_NOT_VERIFIED' if pid==g.PASSWORD else
                   'EXACT_OPERATION_NOT_VERIFIED')})
    pol={key:True for key in ('no_shell_command_strings','no_shell_fallback',
                'no_path_lookup','no_parent_env_inheritance','no_hidden_retries',
                'no_material_substitution','no_discovery_extending_scope',
                'no_process_spawn_in_this_increment','no_secret_values_in_public_artifacts',
                'negative_or_nd_never_authorizes','binary_and_auxiliary_sha256_required_before_approval',
                'absolute_executable_path_required_before_approval',
                'typed_argv_required_before_approval','authorization_and_budget_required_before_approval',
                'physical_lab_isolation_required_before_approval')}
    pol.update({'max_ordinary_attempts':1,'cleanup_independently_verified':True,
                'pilot_numeric_limits':None,'pending_binding_fields':list(g.REQUIRED_BINDING)})
    p={'status':'P8_R1_UNBOUND_PROFILE_DESIGN_ONLY','execution_enabled':False,
       'profile_frozen':False,'pilot_limits_frozen':False,'cases_authorized':0,
       'real_cases':0,'count_by_protocol':g.COUNTS,'profile_slot_count':29,
       'policy':pol,'profiles':ps}
    c={'mapping_kind':'PROTOCOL_LEVEL_CANDIDATE_NOT_PROFILE_CAPABILITY_PROOF',
       'scope':'CANDIDATE_MAPPING_ONLY','approved_profiles':0,
       'dispatch_allowed':False,'profiles':cs}
    inv={'image':{'sha256':g.IMAGE_SHA},
         'record_kind':'OPERATOR_REPORTED_OFFLINE_IMAGE_OBSERVATION_NOT_AUTHORITY',
         'dispatch_allowed':False,'selected_profile_count':0,'authorized_case_count':0,
         'future_runtime_material_identity_verified':False,
         'binary_observations':observed}
    cat={'execution_enabled':False,'families':list(family.values())}
    return p,c,inv,cat


def fake_r22():
    return {'schema_version':'1.0',
            'scope':'P8_R22_OFFLINE_RECEIPT_ONLY_LOADER_SEARCH_BOUNDARY_NOT_LOADER_PROOF',
            'base_main_commit':g.R22_BASE,'image_sha256':g.IMAGE_SHA,
            'private_receipts_replayed':True,'qcow2_accessed':False,
            'guest_binaries_executed':False,'loader_executed':False,
            'effective_loader_resolution_verified':False,
            'effective_configuration_verified':False,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
            'result':{'scope':'STATIC_METADATA_ONLY_NOT_LD_SO_SEMANTICS',
                'summary':{'candidate_dso_nodes':138,'candidate_roots':3,
                    'candidate_graph_edges':906,'static_candidate_edges_without_candidate':0,
                    'search_flagged_objects':66,'search_path_segments':66,
                    'search_tag_counts':{'DT_RUNPATH':66},
                    'segment_risk_counts':{'ABSOLUTE_DIRECTORY_NOT_EFFECTIVE_PROOF':66},
                    'candidate_only':True,'effective_loader_resolution_verified':False,
                    'loader_search_order_verified':False,'runtime_binary_identity_verified':False,
                    'effective_configuration_verified':False,
                    'transitive_runtime_closure_verified':False,
                    'environment_and_preload_verified':False,'dispatch_allowed':False}}}


class ValidLedger(unittest.TestCase):
    def setUp(self):
        self.inputs=fixture()
    def rows(self):return g.profile_rows(*self.inputs)
    def test_source_matrix(self):
        rows=self.rows();s=g.summarize(rows)
        self.assertEqual(len(rows),29)
        self.assertEqual(s['unbound_material_fields'],348)
        self.assertEqual(s['candidate_distribution'],{'ssh':8,'ftp':10,'smb':11})
        self.assertEqual(s['writing_variants_with_independent_cleanup_pending'],5)
    def test_source_order(self):
        self.assertEqual([r['profile_id'] for r in self.rows()],g.canonical_ids())
    def test_flags_are_false(self):
        for row in self.rows():
            with self.subTest(row=row['profile_id']):
                self.assertFalse(row['dispatch_allowed'])
                self.assertFalse(row['capability_tested'])
                self.assertEqual(len(row['binding_fields_unbound']),12)
    def test_write_is_independent(self):
        for r in self.rows():
            with self.subTest(id=r['profile_id']):
                self.assertEqual(r['write_cleanup_independent_pending'],r['profile_id'] in g.WRITING)
                self.assertFalse(r['approved'])
    def test_sha_stable(self):
        self.assertEqual(g.summarize(self.rows())['profile_obligation_ledger_sha256'],
                         g.summarize(self.rows())['profile_obligation_ledger_sha256'])
    def test_no_dispatch_even_credible_claims(self):
        rows=self.rows()
        for pid in g.canonical_ids():
            with self.subTest(id=pid):
                self.assertEqual(g.deny_request(rows,pid,{'all_checks':True,'approval':True})
                                 ['decision'],'DENY')
    def test_unknown_profile_no_dispatch(self):
        self.assertEqual(g.deny_request(self.rows(),'SSH-T99-BASE')['reason'],'NO_PROFILE_MATCH')
    def test_empty_claim_is_deny(self):
        self.assertFalse(g.deny_request(self.rows(),'FTP-T01-BASE',{})['spawn'])
    def test_r22_provenance(self):
        self.assertEqual(g.authenticate_r22_receipt(fake_r22())['r22_candidate_edges'],906)


class FailClosedMutation(unittest.TestCase):
    def reject(self,mutate):
        a=list(fixture())
        mutate(*a)
        with self.assertRaises(g.GateError):
            g.profile_rows(*a)
    def test_missing_profile(self):self.reject(lambda p,c,i,f:p['profiles'].pop())
    def test_reordered_profile(self):self.reject(lambda p,c,i,f:p['profiles'].reverse())
    def test_duplicate_profile(self):self.reject(lambda p,c,i,f:p['profiles'].__setitem__(1,p['profiles'][0]))
    def test_extra_compat(self):self.reject(lambda p,c,i,f:c['profiles'].append(c['profiles'][0]))
    def test_wrong_family(self):self.reject(lambda p,c,i,f:p['profiles'][0].update(family_id='SMB-T01'))
    def test_wrong_variant(self):self.reject(lambda p,c,i,f:p['profiles'][9].update(variant='DATA'))
    def test_wrong_protocol(self):self.reject(lambda p,c,i,f:p['profiles'][0].update(protocol='ftp'))
    def test_wrong_precedence(self):self.reject(lambda p,c,i,f:p['profiles'][0].update(precedence=True))
    def test_argv_material_not_empty(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].update(argv_typed_vector=[]))
    def test_auth_material_not_empty(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].update(case_authorization_ref='fake'))
    def test_secret_material_not_empty(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].update(auxiliary_executables={}))
    def test_executable_sha_not_empty(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].update(executable_sha256='0'*64))
    def test_binding_missing_field(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].pop('working_directory'))
    def test_binding_order_drift(self):self.reject(lambda p,c,i,f:p['profiles'][0]['binding'].update({'new_field':None}))
    def test_wrong_candidate_binary(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(candidate_primary_binary='/usr/bin/bash'))
    def test_candidate_approval(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(approval_verified=True))
    def test_candidate_capability(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(capability_tested=True))
    def test_candidate_budget(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(resource_budget_frozen=True))
    def test_candidate_argv(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(argv_frozen=True))
    def test_candidate_case_binding(self):self.reject(lambda p,c,i,f:c['profiles'][0].update(case_binding_verified=True))
    def test_p8_execution_enabled(self):self.reject(lambda p,c,i,f:p.update(execution_enabled=True))
    def test_p8_cases_authorized(self):self.reject(lambda p,c,i,f:p.update(cases_authorized=1))
    def test_compat_approved_profiles(self):self.reject(lambda p,c,i,f:c.update(approved_profiles=1))
    def test_compat_dispatch(self):self.reject(lambda p,c,i,f:c.update(dispatch_allowed=True))
    def test_image_future_pin(self):self.reject(lambda p,c,i,f:i.update(future_runtime_material_identity_verified=True))
    def test_bad_image_hash(self):self.reject(lambda p,c,i,f:i['image'].update(sha256='0'*64))
    def test_bad_primary_sha(self):self.reject(lambda p,c,i,f:i['binary_observations'][0].update(sha256='not-sha'))
    def test_wrong_observation_state(self):self.reject(lambda p,c,i,f:i['binary_observations'][0].update(status='LIVE_VERIFIED'))
    def test_catalog_enabled(self):self.reject(lambda p,c,i,f:f.update(execution_enabled=True))
    def test_catalog_duplicate_family(self):self.reject(lambda p,c,i,f:f['families'].__setitem__(1,f['families'][0]))
    def test_source_preconditions_missing(self):self.reject(lambda p,c,i,f:p['profiles'][0]['required_preconditions'].pop(0))
    def test_source_preconditions_duplicate(self):self.reject(lambda p,c,i,f:p['profiles'][0]['required_preconditions'].append('SCOPE_APPROVED'))
    def test_source_supports_missing(self):self.reject(lambda p,c,i,f:p['profiles'][0]['required_supports'].remove('TARGET_ATTESTATION'))
    def test_source_unsupported_acceptance(self):self.reject(lambda p,c,i,f:p['profiles'][0]['required_acceptance_supports'].append('FAKE_SUPPORT'))
    def test_source_parameter_bad(self):self.reject(lambda p,c,i,f:p['profiles'][0]['required_material_parameter_slots'].append('credential_plaintext'))
    def test_write_support_missing(self):self.reject(lambda p,c,i,f:p['profiles'][6]['required_acceptance_supports'].remove('CLEANUP_CONFIRMED'))
    def test_write_precondition_missing(self):self.reject(lambda p,c,i,f:p['profiles'][6]['required_preconditions'].remove('CLEANUP_VERIFIABLE'))
    def test_write_mutation_wrong(self):self.reject(lambda p,c,i,f:p['profiles'][6].update(cleanup='NO_MUTATION'))
    def test_write_gate_wrong(self):self.reject(lambda p,c,i,f:c['profiles'][6].update(additional_gate='EXACT_OPERATION_NOT_VERIFIED'))
    def test_read_wrong_cleanup(self):self.reject(lambda p,c,i,f:p['profiles'][0].update(cleanup='VERIFY_THEN_REMOVE_MARKER'))
    def test_policy_shell_fallback(self):self.reject(lambda p,c,i,f:p['policy'].update(no_shell_fallback=False))
    def test_policy_inherit_env(self):self.reject(lambda p,c,i,f:p['policy'].update(no_parent_env_inheritance=False))
    def test_policy_unauthorized_retries(self):self.reject(lambda p,c,i,f:p['policy'].update(max_ordinary_attempts=2))
    def test_policy_pilot_limits(self):self.reject(lambda p,c,i,f:p['policy'].update(pilot_numeric_limits={'timeout':1}))
    def test_policy_binding_add(self):self.reject(lambda p,c,i,f:p['policy']['pending_binding_fields'].append('unsafe'))
    def test_permission_escalation_in_summary(self):
        rows=g.profile_rows(*fixture());rows[0]['approved']=True
        with self.assertRaises(g.GateError):g.summarize(rows)
    def test_incomplete_ledger_summary(self):
        rows=g.profile_rows(*fixture());rows.pop()
        with self.assertRaises(g.GateError):g.summarize(rows)
    def test_r22_claim_loader_resolved(self):
        r=fake_r22();r['effective_loader_resolution_verified']=True
        with self.assertRaises(g.GateError):g.authenticate_r22_receipt(r)
    def test_r22_claim_runtime_via_summary(self):
        r=fake_r22();r['result']['summary']['runtime_binary_identity_verified']=True
        with self.assertRaises(g.GateError):g.authenticate_r22_receipt(r)
    def test_r22_wrong_graph(self):
        r=fake_r22();r['result']['summary']['candidate_graph_edges']=905
        with self.assertRaises(g.GateError):g.authenticate_r22_receipt(r)
    def test_r22_fake_dynamic_path(self):
        r=fake_r22();r['result']['summary']['search_tag_counts']={'DT_RPATH':66}
        with self.assertRaises(g.GateError):g.authenticate_r22_receipt(r)

if __name__=='__main__':unittest.main()
