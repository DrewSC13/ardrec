#!/usr/bin/env python3
"""P8-R23: pure 29-profile obligation ledger; always deny execution.

Source evidence: public P7/P8/R9 material inventory, R22 receipt metadata only.
Never tests runtime capability, reads credentials, constructs argv, spawns tools,
connects to services, changes a case or authorizes a dispatch.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import re

BASE='f9fc5c42141bfe1e66672ecb71b4ab6fef9debcc'
R22_SHA='3c67529808db1ab8ddc05f5e2cf9a4b0ce7d34ca4bcb0e28993c4cb0db200408'
R22_BASE='0abec70380976b15a674580ab600f9bd933678c8'
IMAGE_SHA='fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
SHA64=re.compile(r'[0-9a-f]{64}\Z')
REFERENCE=re.compile(r'[a-z][a-z0-9_]*_ref\Z')
FLAG=re.compile(r'[A-Z][A-Z0-9_]*\Z')
PROTOCOL_BINARY={'ssh':'/usr/bin/ssh','ftp':'/usr/bin/curl','smb':'/usr/bin/smbclient'}
WRITING=frozenset({'SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE',
                   'SMB-T08-BASE','SMB-T09-WRITE'})
PASSWORD='SSH-T03-BASE'
COUNTS={'ssh':8,'ftp':10,'smb':11}
REQUIRED_BINDING=(
 'executable_absolute_path','executable_sha256','executable_version',
 'argv_typed_vector','working_directory','environment_allowlist',
 'auxiliary_executables','case_authorization_ref','approved_target_ref',
 'fixed_resource_budget','capture_policy_ref','cleanup_receipt_ref'
)
EXPECTED_RUNTIME_GATES=(
 'actual_binary_identity','effective_loader_and_environment',
 'client_option_capability','service_configuration_and_scope',
 'case_and_target_authority','typed_argv_and_auxiliary_pinning',
 'fixed_resource_budget','evidence_capture_and_provenance',
 'independent_cleanup_if_mutating'
)

class GateError(ValueError):
    pass


def need(cond,why):
    if not cond:
        raise GateError('p8_r23_fail_closed:'+why)


def canonical_ids():
    return (
        [f'SSH-T{i:02d}-BASE' for i in range(1,9)] +
        ['FTP-T01-BASE','FTP-T02-CONTROL','FTP-T02-DATA'] +
        [f'FTP-T{i:02d}-BASE' for i in range(3,8)] +
        ['FTP-T08-READ','FTP-T08-WRITE','SMB-T01-BASE','SMB-T02-BASE',
         'SMB-T03-SIGNING','SMB-T03-ENCRYPTION'] +
        [f'SMB-T{i:02d}-BASE' for i in range(4,9)] +
        ['SMB-T09-READ','SMB-T09-WRITE']
    )


def check_symbols(values,pattern,why):
    need(type(values) is list and len(values)>0 and len(values)<64 and
         len(values)==len(set(values)),why+'_cardinality')
    for s in values:
        need(type(s) is str and len(s)<96 and pattern.fullmatch(s) is not None,
             why+'_token')
    return list(values)


def profile_rows(profiles,compat,inventory,catalog):
    """Check exact source-level controls and derive a non-authorizing gate ledger.

    Expects R9 public validator to run independently first in CI/collector;
    rechecks the assumptions most sensitive to unsafe promotion.
    """
    need(type(profiles) is dict and type(compat) is dict and
         type(inventory) is dict and type(catalog) is dict,'source_types')
    need(profiles.get('status')=='P8_R1_UNBOUND_PROFILE_DESIGN_ONLY' and
         profiles.get('execution_enabled') is False and
         profiles.get('profile_frozen') is False and
         profiles.get('pilot_limits_frozen') is False and
         profiles.get('cases_authorized')==0 and
         profiles.get('real_cases')==0 and
         profiles.get('count_by_protocol')==COUNTS and
         profiles.get('profile_slot_count')==29,'p8_source_state')
    pol=profiles.get('policy')
    need(type(pol) is dict and pol.get('pending_binding_fields')==list(REQUIRED_BINDING)
         and pol.get('pilot_numeric_limits') is None,'binding_policy')
    for key in ('no_shell_command_strings','no_shell_fallback','no_path_lookup',
                'no_parent_env_inheritance','no_hidden_retries',
                'no_material_substitution','no_discovery_extending_scope',
                'no_process_spawn_in_this_increment','no_secret_values_in_public_artifacts',
                'negative_or_nd_never_authorizes','binary_and_auxiliary_sha256_required_before_approval',
                'absolute_executable_path_required_before_approval',
                'typed_argv_required_before_approval','authorization_and_budget_required_before_approval',
                'physical_lab_isolation_required_before_approval'):
        need(pol.get(key) is True,'policy_'+key)
    need(pol.get('max_ordinary_attempts')==1 and
         pol.get('cleanup_independently_verified') is True,'attempt_cleanup_policy')
    need(compat.get('mapping_kind')=='PROTOCOL_LEVEL_CANDIDATE_NOT_PROFILE_CAPABILITY_PROOF'
         and compat.get('scope')=='CANDIDATE_MAPPING_ONLY'
         and compat.get('approved_profiles')==0 and compat.get('dispatch_allowed') is False,
         'compatibility_promotion')
    need(inventory.get('image',{}).get('sha256')==IMAGE_SHA and
         inventory.get('record_kind')=='OPERATOR_REPORTED_OFFLINE_IMAGE_OBSERVATION_NOT_AUTHORITY'
         and inventory.get('dispatch_allowed') is False and
         inventory.get('selected_profile_count')==0 and
         inventory.get('authorized_case_count')==0 and
         inventory.get('future_runtime_material_identity_verified') is False,
         'inventory_promotion')
    need(catalog.get('execution_enabled') is False and
         len(catalog.get('families',[]))==25,'catalog_state')
    fam={f['id']:f for f in catalog['families']}
    need(len(fam)==25,'catalog_duplicate_family')
    for proto,n in (('SSH',8),('FTP',8),('SMB',9)):
        need(all(f'{proto}-T{i:02d}' in fam for i in range(1,n+1)),
             'catalog_family_'+proto)
    observed={r['absolute_path']:r for r in inventory.get('binary_observations',[])}
    for path in PROTOCOL_BINARY.values():
        o=observed.get(path)
        need(type(o) is dict and o.get('status')=='IMAGE_BYTES_OBSERVED_NOT_LIVE_PIN'
             and SHA64.fullmatch(o.get('sha256','')) is not None,'source_binary_'+path)
    p8=profiles.get('profiles');p9=compat.get('profiles')
    need(type(p8) is list and type(p9) is list and
         len(p8)==len(p9)==29,'profile_count')
    ids=canonical_ids()
    need([p.get('profile_id') for p in p8]==ids and
         [p.get('profile_id') for p in p9]==ids,'profile_id_order')
    rows=[]
    for slot,comp in zip(p8,p9):
        pid=slot['profile_id']
        protocol=slot.get('protocol')
        need(protocol in PROTOCOL_BINARY and pid.lower().startswith(protocol+'-'),
             'profile_protocol_'+pid)
        family=slot.get('family_id')
        need(family in fam and family==pid.rsplit('-',1)[0] and
             fam[family].get('protocol')==protocol,'family_'+pid)
        expected_variant=None if pid.endswith('-BASE') else pid.rsplit('-',1)[1]
        need(slot.get('variant')==expected_variant,'variant_'+pid)
        prec=slot.get('precedence')
        need(type(prec) is int and 1<=prec<=4,'precedence_'+pid)
        bindings=slot.get('binding')
        need(type(bindings) is dict and list(bindings)==list(REQUIRED_BINDING)
             and all(v is None for v in bindings.values()),'unbound_'+pid)
        need(slot.get('status')=='BLOCKED_UNBOUND_NO_EXECUTION'
             and comp.get('profile_id')==pid
             and comp.get('status')=='BLOCKED_UNBOUND_NO_EXECUTION','state_'+pid)
        for key in ('capability_tested','case_binding_verified','argv_frozen',
                    'resource_budget_frozen','approval_verified'):
            need(comp.get(key) is False,'unsafe_capability_'+pid+'_'+key)
        pre=check_symbols(slot.get('required_preconditions'),FLAG,'preconditions_'+pid)
        supports=check_symbols(slot.get('required_supports'),FLAG,'supports_'+pid)
        accepted=check_symbols(slot.get('required_acceptance_supports'),FLAG,'acceptance_'+pid)
        params=check_symbols(slot.get('required_material_parameter_slots'),REFERENCE,
                             'parameters_'+pid)
        need(set(accepted).issubset(supports) and
             {'SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED','DESTINATION_AUTHORIZED',
              'CLIENT_COMPATIBLE'}.issubset(pre) and
             {'TARGET_ATTESTATION','INTEGRITY_PROVENANCE'}.issubset(supports),
             'support_or_scope_'+pid)
        write=pid in WRITING
        cleanup=slot.get('cleanup')
        need(cleanup==('VERIFY_THEN_REMOVE_MARKER' if write else 'NO_MUTATION'),
             'cleanup_'+pid)
        need((not write or {'MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'}.issubset(accepted))
             and (not write or {'WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'}.issubset(pre)),
             'write_independent_cleanup_'+pid)
        path=PROTOCOL_BINARY[protocol]
        gate=('WRITE_CLEANUP_NOT_VERIFIED' if write else
              'PASSWORD_MECHANISM_NOT_VERIFIED' if pid==PASSWORD else
              'EXACT_OPERATION_NOT_VERIFIED')
        need(comp.get('candidate_primary_binary')==path and
             comp.get('additional_gate')==gate,'candidate_gate_'+pid)
        rows.append({
            'profile_id':pid,'family_id':family,'protocol':protocol,'variant':expected_variant,
            'precedence':prec,'primary_binary_candidate':path,
            'image_candidate_sha256':observed[path]['sha256'],
            'required_material_parameters':params,'required_preconditions':pre,
            'required_supports':supports,'required_acceptance_supports':accepted,
            'binding_fields_unbound':list(REQUIRED_BINDING),
            'additional_gate':gate,'cleanup_plan':cleanup,
            'write_cleanup_independent_pending':write,
            'runtime_gates_unverified':list(EXPECTED_RUNTIME_GATES),
            'capability_tested':False,'effective_configuration_verified':False,
            'case_authorization_verified':False,'runtime_binary_identity_verified':False,
            'approved':False,'dispatch_allowed':False,
            'status':'BLOCKED_MATERIAL_UNBOUND_NO_EXECUTION',
        })
    need({p:sum(row['protocol']==p for row in rows) for p in COUNTS}==COUNTS,
         'protocol_distribution')
    need({r['profile_id'] for r in rows if r['write_cleanup_independent_pending']}==WRITING,
         'write_set')
    return rows


def summarize(rows):
    need(type(rows) is list and len(rows)==29 and
         [r['profile_id'] for r in rows]==canonical_ids(),'ledger_identity')
    for row in rows:
        need(row.get('status')=='BLOCKED_MATERIAL_UNBOUND_NO_EXECUTION' and
             row.get('dispatch_allowed') is False and row.get('approved') is False and
             row.get('capability_tested') is False and
             row.get('case_authorization_verified') is False and
             row.get('runtime_binary_identity_verified') is False and
             row.get('effective_configuration_verified') is False and
             row.get('runtime_gates_unverified')==list(EXPECTED_RUNTIME_GATES) and
             row.get('binding_fields_unbound')==list(REQUIRED_BINDING),'row_promotion')
    digest=hashlib.sha256((json.dumps(rows,sort_keys=True,separators=(',',':'),
                                      ensure_ascii=False)+'\n').encode()).hexdigest()
    return {
        'status':'PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY',
        'base_main_commit':BASE,'candidate_profiles':29,
        'candidate_families':25,'candidate_distribution':dict(COUNTS),
        'unbound_material_fields':29*len(REQUIRED_BINDING),
        'distinct_material_fields_per_profile':len(REQUIRED_BINDING),
        'writing_variants_with_independent_cleanup_pending':len(WRITING),
        'runtime_gates_unverified_per_profile':len(EXPECTED_RUNTIME_GATES),
        'image_pinned_candidate_binary_kinds':3,
        'profile_obligation_ledger_sha256':digest,
        'candidate_only':True,'capability_tested':False,
        'runtime_identity_verified':False,'effective_configuration_verified':False,
        'case_authorization_verified':False,
        'authorized_profiles':0,'authorized_cases':0,
        'dispatch_allowed':False,'guest_binaries_executed':False,
    }


def deny_request(rows, profile_id, assertions=None):
    """Non-authorizing lookup only; never outputs argv or executable material."""
    need(type(profile_id) is str and len(profile_id)<64,'request_id_type')
    need(assertions is None or type(assertions) is dict,'request_assertions_type')
    need(type(rows) is list,'request_rows')
    known=next((r for r in rows if r.get('profile_id')==profile_id),None)
    return {'profile_id':profile_id,'decision':'DENY',
            'reason':('NO_PROFILE_MATCH' if known is None else
                      'REQUIRED_RUNTIME_MATERIAL_AND_AUTHORITY_NOT_VERIFIED'),
            'spawn':False,'dispatch_allowed':False,'authorized_cases':0}


def authenticate_r22_receipt(doc):
    """R22 SHA checked by caller; validate security boundary and aggregate identity."""
    need(type(doc) is dict and doc.get('schema_version')=='1.0' and
         doc.get('scope')=='P8_R22_OFFLINE_RECEIPT_ONLY_LOADER_SEARCH_BOUNDARY_NOT_LOADER_PROOF'
         and doc.get('base_main_commit')==R22_BASE and
         doc.get('image_sha256')==IMAGE_SHA and
         doc.get('private_receipts_replayed') is True and
         doc.get('qcow2_accessed') is False and
         doc.get('guest_binaries_executed') is False and
         doc.get('loader_executed') is False and
         doc.get('effective_loader_resolution_verified') is False and
         doc.get('effective_configuration_verified') is False and
         doc.get('authorized_profiles')==0 and
         doc.get('authorized_cases')==0 and
         doc.get('dispatch_allowed') is False,'r22_receipt_policy')
    r=doc.get('result')
    need(type(r) is dict and r.get('scope')=='STATIC_METADATA_ONLY_NOT_LD_SO_SEMANTICS',
         'r22_scope')
    s=r.get('summary')
    need(type(s) is dict and s.get('candidate_dso_nodes')==138 and
         s.get('candidate_roots')==3 and s.get('candidate_graph_edges')==906 and
         s.get('static_candidate_edges_without_candidate')==0 and
         s.get('search_flagged_objects')==66 and
         s.get('search_path_segments')==66 and
         s.get('search_tag_counts')=={'DT_RUNPATH':66} and
         s.get('segment_risk_counts')=={'ABSOLUTE_DIRECTORY_NOT_EFFECTIVE_PROOF':66} and
         s.get('candidate_only') is True,'r22_counts')
    for field in ('effective_loader_resolution_verified','loader_search_order_verified',
                  'runtime_binary_identity_verified','effective_configuration_verified',
                  'transitive_runtime_closure_verified','environment_and_preload_verified',
                  'dispatch_allowed'):
        need(s.get(field) is False,'r22_unsafe_'+field)
    return {'r22_candidate_nodes':138,'r22_candidate_edges':906,
            'r22_search_flagged_objects':66,
            'r22_effective_loader_resolution_verified':False}
