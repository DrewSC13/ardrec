#!/usr/bin/env python3
"""P8-R24: deterministic proof-sufficiency boundary over R23's unbound profiles.

Never executes binaries, constructs argv, reads QCOW2, loads private material,
accesses network or treats offline references as an operational proof.
"""
from __future__ import annotations
import hashlib
import json
import re
from collections import Counter

import p8_r23_profile_obligations as r23

BASE='7df89ca81d04a796fed86896c1e09e255f8f4bc0'
R23_RECEIPT_SHA='42b7ff79f73d589be96a8d76e1bcb812a5374112679c277a23f598eeb851f1c3'
R23_LEDGER_SHA='8557bd27144ac390d72dec2337ac4d246fdb388571242de49a31f21441607330'
R22_RECEIPT_SHA=r23.R22_SHA
EXPECTED_GATES=tuple(r23.EXPECTED_RUNTIME_GATES)
SOURCE_ONLY={'actual_binary_identity','effective_loader_and_environment'}
WRITE=set(r23.WRITING)
PROOF_CLASSES={
 'actual_binary_identity':'PINNED_R9_IMAGE_CANDIDATE_ONLY',
 'effective_loader_and_environment':'R22_STATIC_LOADER_SEARCH_METADATA_ONLY',
 'client_option_capability':'OPERATION_SPECIFIC_CLIENT_EVIDENCE_REQUIRED',
 'service_configuration_and_scope':'CASE_BOUND_SERVER_CONFIGURATION_REQUIRED',
 'case_and_target_authority':'SIGNED_CASE_SCOPE_AND_TARGET_AUTHORITY_REQUIRED',
 'typed_argv_and_auxiliary_pinning':'EXACT_TYPED_PLAN_AND_DEPENDENCY_PIN_REQUIRED',
 'fixed_resource_budget':'FIXED_CASE_BUDGET_REQUIRED',
 'evidence_capture_and_provenance':'CASE_BOUND_CAPTURE_PROVENANCE_REQUIRED',
 'independent_cleanup_if_mutating':'INDEPENDENT_CLEANUP_REQUIRED_IF_MUTATING',
}
ORIGINS={
 'actual_binary_identity':'R9_IMAGE_BYTES_OBSERVED_NOT_RUNTIME',
 'effective_loader_and_environment':'R22_STATIC_METADATA_NOT_EFFECTIVE_LD_SO',
}
SHA64=re.compile(r'[0-9a-f]{64}\Z')

class BoundaryError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise BoundaryError('p8_r24_fail_closed:'+reason)


def json_digest(value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def _validate_rows(rows, r23_digest=None):
    prev=r23.summarize(rows)
    require(prev['status']=='PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY',
            'r23_summary')
    if r23_digest is not None:
        require(type(r23_digest) is str and SHA64.fullmatch(r23_digest) is not None and
                prev['profile_obligation_ledger_sha256']==r23_digest,'r23_digest')
    require(len(rows)==29 and len(EXPECTED_GATES)==9 and set(PROOF_CLASSES)==set(EXPECTED_GATES),
            'gate_identity')
    return prev


def proof_matrix(rows, r23_digest=None):
    """Create 29x9 *unresolved* proof barriers; accepts only R23-denied rows.

    Source metadata is useful as a candidate reference but never closes a gate.
    Non-writing cleanup is a conditional requirement, NOT verified restoration.
    """
    prev=_validate_rows(rows,r23_digest)
    result=[]
    for row in rows:
        pid=row['profile_id']
        writing=pid in WRITE
        require(row['write_cleanup_independent_pending'] is writing and
                row['runtime_gates_unverified']==list(EXPECTED_GATES) and
                row['status']=='BLOCKED_MATERIAL_UNBOUND_NO_EXECUTION',
                'profile_runtime_gates:'+pid)
        require(row['image_candidate_sha256'] and
                SHA64.fullmatch(row['image_candidate_sha256']) is not None,
                'image_candidate_sha:'+pid)
        gate_rows=[]
        for gate in EXPECTED_GATES:
            gate_rows.append({
                'gate_id':gate,
                'required_proof_class':PROOF_CLASSES[gate],
                'offline_reference_available':gate in SOURCE_ONLY,
                'offline_reference_origin':ORIGINS.get(gate),
                'requires_future_material_or_case_evidence':True,
                'conditional_on_mutation':gate=='independent_cleanup_if_mutating',
                'mutation_variant_declared':writing if gate=='independent_cleanup_if_mutating' else False,
                'proof_verified':False,
                'authority_verified':False,
                'operational_capability_verified':False,
                'gate_closed':False,
                'status':'UNVERIFIED_DENY',
            })
        result.append({
            'profile_id':pid,'protocol':row['protocol'],'family_id':row['family_id'],
            'candidate_binary':row['primary_binary_candidate'],
            'candidate_image_sha256':row['image_candidate_sha256'],
            'pending_binding_fields':list(row['binding_fields_unbound']),
            'write_cleanup_pending':writing,'gates':gate_rows,
            'status':'BLOCKED_PROOF_INSUFFICIENT_NO_DISPATCH',
            'approved':False,'authorized_cases':0,'dispatch_allowed':False,
        })
    require(len({r['profile_id'] for r in result})==29,'duplicate_profiles')
    require(prev['unbound_material_fields']==348 and
            prev['writing_variants_with_independent_cleanup_pending']==5,
            'upstream_counts')
    return result


def summarize(matrix):
    require(type(matrix) is list and len(matrix)==29,'matrix_count')
    expected=r23.canonical_ids()
    require([r.get('profile_id') for r in matrix]==expected,'matrix_order')
    protocol_counts=Counter()
    writes=[]
    origins=Counter()
    for row in matrix:
        pid=row['profile_id']; proto=pid.split('-',1)[0].lower()
        require(set(row)=={'profile_id','protocol','family_id','candidate_binary',
                          'candidate_image_sha256','pending_binding_fields',
                          'write_cleanup_pending','gates','status','approved',
                          'authorized_cases','dispatch_allowed'},'row_keys:'+pid)
        require(row['protocol']==proto and row['family_id']==pid.rsplit('-',1)[0] and
                row['candidate_binary']==r23.PROTOCOL_BINARY[proto] and
                type(row['candidate_image_sha256']) is str and
                SHA64.fullmatch(row['candidate_image_sha256']) is not None and
                row['pending_binding_fields']==list(r23.REQUIRED_BINDING) and
                row['write_cleanup_pending'] is (pid in WRITE) and
                row['status']=='BLOCKED_PROOF_INSUFFICIENT_NO_DISPATCH' and
                row['approved'] is False and row['authorized_cases']==0 and
                row['dispatch_allowed'] is False,'row_controls:'+pid)
        protocol_counts[proto]+=1
        if row['write_cleanup_pending']:writes.append(pid)
        gs=row['gates']
        require(type(gs) is list and len(gs)==len(EXPECTED_GATES) and
                [x.get('gate_id') for x in gs]==list(EXPECTED_GATES),
                'gate_order:'+pid)
        for g in gs:
            gate=g['gate_id']
            require(set(g)=={'gate_id','required_proof_class',
                            'offline_reference_available','offline_reference_origin',
                            'requires_future_material_or_case_evidence','conditional_on_mutation',
                            'mutation_variant_declared','proof_verified','authority_verified',
                            'operational_capability_verified','gate_closed','status'},
                    'gate_keys:'+pid+':'+gate)
            require(g['required_proof_class']==PROOF_CLASSES[gate] and
                    g['offline_reference_available'] is (gate in SOURCE_ONLY) and
                    g['offline_reference_origin']==ORIGINS.get(gate) and
                    g['requires_future_material_or_case_evidence'] is True and
                    g['conditional_on_mutation'] is (gate=='independent_cleanup_if_mutating') and
                    g['mutation_variant_declared'] is
                      ((pid in WRITE) if gate=='independent_cleanup_if_mutating' else False) and
                    g['proof_verified'] is False and g['authority_verified'] is False and
                    g['operational_capability_verified'] is False and
                    g['gate_closed'] is False and g['status']=='UNVERIFIED_DENY',
                    'unauthorized_gate_promotion:'+pid+':'+gate)
            if gate in SOURCE_ONLY:origins[gate]+=1
    require(dict(protocol_counts)==r23.COUNTS and set(writes)==WRITE and
            dict(origins)=={x:29 for x in SOURCE_ONLY},'derived_distribution')
    return {
        'status':'PASS_P8_R24_PROOF_SUFFICIENCY_BOUNDARY_DENY_ONLY',
        'base_main_commit':BASE,
        'profiles':29,'families':25,'protocol_distribution':dict(r23.COUNTS),
        'pending_binding_fields':348,'unverified_gates_per_profile':9,
        'unverified_gate_instances':29*9,
        'offline_candidate_reference_instances':29*2,
        'offline_candidate_reference_kinds':2,
        'writing_variants_independent_cleanup_pending':5,
        'candidate_binary_kinds':3,
        'matrix_sha256':json_digest(matrix),
        'candidate_only':True,'effective_loader_resolution_verified':False,
        'operational_capability_verified':False,'effective_configuration_verified':False,
        'runtime_binary_identity_verified':False,'case_authority_verified':False,
        'approved_profiles':0,'authorized_cases':0,
        'dispatch_allowed':False,'guest_binaries_executed':False,
        'qcow2_accessed':False,
    }


def inspect_claim(matrix, claim):
    """Recognize only two pinned *static* reference claims; always DENY.

    Unknown/fake scopes, status escalation, arbitrary files, malformed material
    or gate identities are rejected, not silently promoted. A recognized claim
    is a *reference to upstream candidate evidence*, not a gate closure.
    """
    require(type(claim) is dict and set(claim)=={
        'profile_id','gate_id','claim_kind','origin','source_sha256','asserted_status'
    },'claim_shape')
    pid=claim['profile_id'];gate=claim['gate_id']
    require(type(pid) is str and type(gate) is str and
            len(pid)<64 and len(gate)<80,'claim_id_type')
    require(type(matrix) is list,'claim_matrix_type')
    row=next((x for x in matrix if x.get('profile_id')==pid),None)
    require(row is not None,'claim_unknown_profile')
    require(gate in SOURCE_ONLY and claim['claim_kind']=='PINNED_SOURCE_REFERENCE' and
            claim['origin']==ORIGINS[gate] and
            claim['asserted_status']=='CANDIDATE_ONLY',
            'claim_not_static_candidate')
    expected=(row['candidate_image_sha256'] if gate=='actual_binary_identity'
              else R22_RECEIPT_SHA)
    require(type(claim['source_sha256']) is str and
            claim['source_sha256']==expected,'claim_digest')
    require(row['approved'] is False and row['dispatch_allowed'] is False and
            row['status']=='BLOCKED_PROOF_INSUFFICIENT_NO_DISPATCH','claim_row')
    item=next(x for x in row['gates'] if x['gate_id']==gate)
    require(item['offline_reference_available'] is True and
            item['gate_closed'] is False and
            item['proof_verified'] is False,'claim_gate')
    return {'profile_id':pid,'gate_id':gate,'decision':'DENY',
            'reference_recognized':True,'evidence_admitted_as_runtime_proof':False,
            'authorized_cases':0,'dispatch_allowed':False,'spawn':False}


def deny_profile(matrix, profile_id, assertions=None):
    """A hostile assertion never changes authority, including nested spoofing."""
    require(type(profile_id) is str and len(profile_id)<64,'request_id')
    require(assertions is None or type(assertions) is dict,'assertion_type')
    require(type(matrix) is list,'matrix_type')
    target=next((r for r in matrix if r.get('profile_id')==profile_id),None)
    return {'profile_id':profile_id,'decision':'DENY',
            'reason':('NO_PROFILE_MATCH' if target is None else
                      'NINE_PROOF_GATES_AND_MATERIAL_BINDINGS_NOT_VERIFIED'),
            'authorized_cases':0,'dispatch_allowed':False,'spawn':False}


def authenticate_r23_receipt(doc):
    """Caller authenticates SHA/mode; we check the private ledger's boundary."""
    require(type(doc) is dict and doc.get('schema_version')=='1.0' and
            doc.get('scope')=='P8_R23_PUBLISHED_OBLIGATIONS_PRIVATE_NOT_AUTHORITY' and
            doc.get('base_main_commit')==r23.BASE and
            doc.get('image_sha256')==r23.IMAGE_SHA and
            doc.get('r22_private_receipt_sha256')==R22_RECEIPT_SHA and
            doc.get('source')=='R9_PUBLIC_CANDIDATE_BINARY_P8_UNBOUND_PROFILE_MATRIX' and
            doc.get('qcow2_accessed') is False and
            doc.get('guest_binaries_executed') is False and
            doc.get('runtime_loader_executed') is False and
            doc.get('capability_tested') is False and
            doc.get('effective_configuration_verified') is False and
            doc.get('runtime_binary_identity_verified') is False and
            doc.get('authorized_profiles')==0 and doc.get('authorized_cases')==0 and
            doc.get('dispatch_allowed') is False,'r23_receipt_header')
    s=doc.get('summary');rows=doc.get('profile_ledger')
    require(type(s) is dict and type(rows) is list,'r23_receipt_structure')
    require(s.get('status')=='PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY' and
            s.get('profile_obligation_ledger_sha256')==R23_LEDGER_SHA and
            s.get('candidate_profiles')==29 and
            s.get('unbound_material_fields')==348 and
            s.get('writing_variants_with_independent_cleanup_pending')==5 and
            s.get('authorized_profiles')==0 and s.get('authorized_cases')==0 and
            s.get('dispatch_allowed') is False,'r23_summary')
    require(json_digest(rows)==R23_LEDGER_SHA,'r23_private_rows_digest')
    r23.summarize(rows)
    boundary=doc.get('r22_boundary')
    require(type(boundary) is dict and boundary.get('r22_candidate_nodes')==138 and
            boundary.get('r22_candidate_edges')==906 and
            boundary.get('r22_search_flagged_objects')==66 and
            boundary.get('r22_effective_loader_resolution_verified') is False,
            'r22_bridge')
    return {'r23_receipt_sha256_verified_by_caller':True,
            'r23_ledger_sha256_verified':True,'r22_candidate_nodes':138,
            'r22_candidate_edges':906,'r22_search_flagged_objects':66}
