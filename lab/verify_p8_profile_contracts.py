#!/usr/bin/env python3
"""ARDREC P8-R10: 29 strict, symbolic, deny-only execution-intent contracts.

Never renders argv, an SSH remote shell command, smbclient -c, secrets, or an
operational authorization. Uses P8-R9's pinned source validator as prerequisite.
No subprocess, filesystem modification, VM, socket or credential retrieval.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

# P8-R9 is a sibling lab module; it enforces original P6/P7/P8/R9 digests.
import verify_p8_material_inventory as r9

ROOT = Path(__file__).resolve().parents[1]
BASE = '4290e759842fa090a0fb13979501dd8a8cc7d760'
CONTRACT = 'lab/p8-profile-contract-v1/contracts.json'
R9_COMPAT = 'lab/p8-material-inventory-v1/compatibility.json'
R9_INV = 'lab/p8-material-inventory-v1/inventory.json'
P8 = 'lab/execution-profiles-v1/profiles.json'
R9_COMPAT_SHA = '1630b75f86404f6f1b548cc902a36720355b46bb6627474825f372c96d685a53'
R9_INV_SHA = 'a98d4366eebbe555c09b391828d950af981ead106015414f478b2f9a53e22886'

class ContractError(ValueError):
    """Invalid or over-authoritative P8-R10 declaration."""

def need(ok: bool, why: str) -> None:
    if not ok:
        raise ContractError(why)

def exact(data, required: set[str], name: str) -> None:
    need(type(data) is dict and set(data)==required, 'schema_drift:'+name)

def uniq_pairs(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'duplicate_json_key')
        result[k]=v
    return result

def parse(raw: bytes):
    need(len(raw)<=256*1024,'json_too_big')
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=uniq_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ContractError('nonfinite')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as exc:
        raise ContractError('invalid_json') from exc

def from_root(root:Path, rel:str, digest:str|None=None):
    need(rel and not rel.startswith('/') and all(s not in ('','.','..') for s in rel.split('/')),
         'invalid_path')
    p=root/rel
    need(p.is_file() and not p.is_symlink(),'missing_source:'+rel)
    raw=p.read_bytes()
    if digest is not None:
        need(hashlib.sha256(raw).hexdigest()==digest,'pinned_source_drift:'+rel)
    return parse(raw)

OPS = {'SSH-T01-BASE': 'VERIFY_TRANSPORT_AND_PINNED_HOST_KEY', 'SSH-T02-BASE': 'OBSERVE_AUTH_METHODS_FIXED_IDENTITY', 'SSH-T03-BASE': 'AUTHENTICATE_PREAUTHORIZED_PASSWORD', 'SSH-T04-BASE': 'AUTHENTICATE_PREAUTHORIZED_PUBLIC_KEY', 'SSH-T05-BASE': 'OPEN_CHANNEL_AND_VERIFY_IDENTITY', 'SSH-T06-BASE': 'READ_KNOWN_SYNTHETIC_RESOURCE', 'SSH-T07-BASE': 'CREATE_VERIFY_REMOVE_SYNTHETIC_MARKER', 'SSH-T08-BASE': 'VERIFY_SINGLE_PREAUTHORIZED_PRIVILEGE', 'FTP-T01-BASE': 'CONNECT_PREAUTHORIZED_CONTROL_CHANNEL', 'FTP-T02-CONTROL': 'VERIFY_TLS_CONTROL_CHANNEL', 'FTP-T02-DATA': 'VERIFY_TLS_DATA_CHANNEL', 'FTP-T03-BASE': 'AUTHENTICATE_PREDEFINED_GUEST', 'FTP-T04-BASE': 'AUTHENTICATE_SYNTHETIC_ACCOUNT', 'FTP-T05-BASE': 'LIST_ONLY_KNOWN_SYNTHETIC_DIRECTORY', 'FTP-T06-BASE': 'DOWNLOAD_KNOWN_SYNTHETIC_FILE', 'FTP-T07-BASE': 'UPLOAD_VERIFY_REMOVE_SYNTHETIC_MARKER', 'FTP-T08-READ': 'COMPARE_READ_ON_KNOWN_CONTROL_AND_RESTRICTED_RESOURCES', 'FTP-T08-WRITE': 'COMPARE_BOUNDED_WRITE_ON_KNOWN_CONTROL_AND_RESTRICTED_RESOURCES', 'SMB-T01-BASE': 'NEGOTIATE_PREAUTHORIZED_SMB_DIALECT', 'SMB-T02-BASE': 'VERIFY_PREDEFINED_SMBV1_NEGOTIATION', 'SMB-T03-SIGNING': 'VERIFY_SIGNED_SMB_OPERATION', 'SMB-T03-ENCRYPTION': 'VERIFY_ENCRYPTED_SMB_OPERATION', 'SMB-T04-BASE': 'IDENTIFY_PREDEFINED_GUEST_SESSION', 'SMB-T05-BASE': 'AUTHENTICATE_SYNTHETIC_SMB_ACCOUNT', 'SMB-T06-BASE': 'LIST_ONLY_KNOWN_SYNTHETIC_SHARE_DIRECTORY', 'SMB-T07-BASE': 'READ_KNOWN_SYNTHETIC_SMB_RESOURCE', 'SMB-T08-BASE': 'CREATE_VERIFY_REMOVE_SYNTHETIC_SMB_MARKER', 'SMB-T09-READ': 'COMPARE_READ_SMB_CONTROL_AND_RESTRICTED_RESOURCES', 'SMB-T09-WRITE': 'COMPARE_BOUNDED_WRITE_SMB_CONTROL_AND_RESTRICTED_RESOURCES'}
CONTROL_ATOMS = {'ssh': ['SSH_EXPLICIT_HOST_KEY_ANCHOR', 'SSH_NO_PROXYCOMMAND', 'SSH_NO_AGENT_FORWARDING', 'SSH_NO_INTERACTIVE_FALLBACK', 'SSH_NO_HIDDEN_RETRY', 'SSH_NO_DEFAULT_USER_CONFIG'], 'ftp': ['FTP_NO_PROXY', 'FTP_NO_URL_GLOBBING', 'FTP_NO_REDIRECT', 'FTP_FIXED_PROTOCOL', 'FTP_PINNED_TLS_POLICY', 'FTP_PASSIVE_CHANNEL_ONLY', 'FTP_NO_HIDDEN_RETRY'], 'smb': ['SMB_FIXED_DIALECT', 'SMB_EXPLICIT_PROTECTION', 'SMB_NO_CONFIG_EXPANSION', 'SMB_NO_C_LANGUAGE_FREEFORM', 'SMB_FIXED_SHARE', 'SMB_NO_HIDDEN_RETRY']}
SPECIAL_ATOMS = {'SSH-T01-BASE': ['HOST_KEY_MATCH_NOT_AUTH_PROOF'], 'SSH-T02-BASE': ['FIXED_IDENTITY_NO_ENUMERATION'], 'SSH-T03-BASE': ['PASSWORD_TRANSPORT_UNRESOLVED_WITHOUT_SSHPASS'], 'SSH-T04-BASE': ['PRIVATE_KEY_CUSTODY_NOT_VERIFIED'], 'SSH-T05-BASE': ['REMOTE_BENIGN_OPERATION_AST_REQUIRED'], 'SSH-T06-BASE': ['REMOTE_READ_OPERATION_AST_REQUIRED'], 'SSH-T07-BASE': ['REMOTE_MARKER_LIFECYCLE_AST_REQUIRED'], 'SSH-T08-BASE': ['SINGLE_PRIVILEGE_HELPER_ALLOWLIST_REQUIRED'], 'FTP-T02-CONTROL': ['CONTROL_CHANNEL_TLS_ONLY'], 'FTP-T02-DATA': ['DATA_CHANNEL_TLS_AND_SESSION_BINDING'], 'FTP-T07-BASE': ['UPLOAD_AND_CLEANUP_RECEIPTS_REQUIRED'], 'FTP-T08-READ': ['TWO_FIXED_RESOURCES_READ_ONLY'], 'FTP-T08-WRITE': ['TWO_FIXED_RESOURCES_WRITE_AND_CLEANUP_REQUIRED'], 'SMB-T02-BASE': ['SMBV1_NEGOTIATION_ONLY_NO_DOWNGRADE_FALLBACK'], 'SMB-T03-SIGNING': ['SIGNING_MUST_NOT_IMPLY_ENCRYPTION'], 'SMB-T03-ENCRYPTION': ['ENCRYPTION_MUST_NOT_IMPLY_SIGNING'], 'SMB-T08-BASE': ['SMB_COMMAND_AST_AND_CLEANUP_REQUIRED'], 'SMB-T09-READ': ['SMB_TWO_FIXED_RESOURCES_READ_ONLY'], 'SMB-T09-WRITE': ['SMB_TWO_FIXED_RESOURCES_WRITE_AND_CLEANUP']}

GLOBAL_DENIALS = {
    'shell_process','dynamic_cli_flags','path_lookup','inherited_environment',
    'remote_shell_text','smb_command_language_text','opportunistic_authentication',
    'automatic_retry','operation_dispatch',
}
EXECUTION_FIELDS = {
    'environment','working_directory','auxiliary_pins','credential_delivery',
    'capture_policy','resource_budget','private_case_authorization',
    'approved_target','post_execution_cleanup_receipt','isolation_verified',
    'capability_verified','issuer_and_revocation_verified',
    'runtime_binary_identity_verified','dispatch_allowed',
}
ARGS_FIELDS = {
    'representation','material_reference_names','required_control_atoms',
    'command_surface','rendered_argv','remote_command_ast','smb_command_ast',
    'raw_command_strings_allowed',
}
PROFILE_FIELDS = {
    'profile_id','family_id','protocol','variant','semantic_operation_id',
    'candidate_binary','candidate_binary_sha256','argument_contract',
    'execution_boundary','cleanup_contract','contract_status',
}


def validate(c, comp, inv, p8):
    exact(c,{'schema_version','roadmap_step','increment','base_commit',
             'r9_material_inventory_sha256','r9_compatibility_sha256',
             'contract_kind','global_denials','profile_count',
             'verified_executable_capabilities','fully_bound_profiles',
             'authorized_cases','dispatch_allowed','algorithm_implementation',
             'physical_lab_contact','profiles'},'root')
    need(c['schema_version']=='1.0' and type(c['roadmap_step']) is int and
         c['roadmap_step']==8 and c['increment']=='P8-R10' and c['base_commit']==BASE and
         c['r9_material_inventory_sha256']==R9_INV_SHA and
         c['r9_compatibility_sha256']==R9_COMPAT_SHA and
         c['contract_kind']=='DECLARATIVE_PER_FAMILY_SYMBOLIC_ONLY_NOT_RENDERABLE',
         'contract_identity')
    exact(c['global_denials'],GLOBAL_DENIALS,'denial_policy')
    need(all(c['global_denials'][k] is False for k in GLOBAL_DENIALS),'denial_disabled')
    for k,value in [('profile_count',29),('verified_executable_capabilities',0),
                    ('fully_bound_profiles',0),('authorized_cases',0)]:
        need(type(c[k]) is int and c[k]==value,'count_drift:'+k)
    need(c['dispatch_allowed'] is False and c['algorithm_implementation']=='NOT_STARTED' and
         c['physical_lab_contact']=='NONE','operational_status_drift')
    need(type(comp) is dict and type(inv) is dict and type(p8) is dict,'source_types')
    need(type(c['profiles']) is list and type(comp.get('profiles')) is list and
         type(p8.get('profiles')) is list and
         len(c['profiles'])==len(comp['profiles'])==len(p8['profiles'])==29,
         '29_profile_alignment')
    binaries={x['absolute_path']:x['sha256'] for x in inv['binary_observations']}
    need(len(binaries)==15,'material_inventory_missing')
    need(set(OPS)=={x['profile_id'] for x in comp['profiles']},'static_operation_registry_drift')
    seen=set()
    for idx,(row,previous,slot) in enumerate(zip(c['profiles'],comp['profiles'],p8['profiles'])):
        exact(row,PROFILE_FIELDS,'profile')
        pid=row['profile_id']
        need(type(pid) is str and pid not in seen and pid==previous['profile_id']==slot['profile_id']
             and pid in OPS,'profile_id_or_order_drift')
        seen.add(pid)
        family=slot['family_id']; proto=slot['protocol']
        variant=slot['variant']
        need(row['family_id']==family and row['protocol']==proto and row['variant']==variant,
             'family_or_variant_drift:'+pid)
        need(row['semantic_operation_id']==OPS[pid], 'operation_drift:'+pid)
        binary=previous['candidate_primary_binary']
        need(row['candidate_binary']==binary and row['candidate_binary_sha256']==binaries.get(binary),
             'unbound_material:'+pid)
        arg=row['argument_contract']
        exact(arg,ARGS_FIELDS,'argument_contract')
        need(arg['representation']=='TYPED_SYMBOLIC_INTENT_NOT_ARGV' and
             arg['material_reference_names']==slot['required_material_parameter_slots'] and
             type(arg['material_reference_names']) is list and
             len(set(arg['material_reference_names']))==len(arg['material_reference_names']),
             'symbolic_slots_drift:'+pid)
        controls=CONTROL_ATOMS[proto]+SPECIAL_ATOMS.get(pid,[])
        need(arg['required_control_atoms']==controls and
             type(arg['required_control_atoms']) is list and
             len(set(controls))==len(controls),'controls_drift:'+pid)
        surface = ('SSH_HANDSHAKE' if pid in ('SSH-T01-BASE','SSH-T02-BASE') else
                   'SSH_AUTHENTICATION' if pid in ('SSH-T03-BASE','SSH-T04-BASE') else
                   'SSH_REMOTE_SHELL_BOUNDARY') if proto=='ssh' else (
                   'CURL_FTP_FTPS_PROTOCOL' if proto=='ftp' else 'SMBCLIENT_COMMAND_LANGUAGE_BOUNDARY')
        need(arg['command_surface']==surface and arg['rendered_argv'] is None and
             arg['remote_command_ast'] is None and arg['smb_command_ast'] is None and
             arg['raw_command_strings_allowed'] is False, 'unsafe_command_surface:'+pid)
        boundary=row['execution_boundary']
        exact(boundary,EXECUTION_FIELDS,'execution_boundary')
        for k in ('environment','working_directory','auxiliary_pins','credential_delivery',
                  'capture_policy','resource_budget','private_case_authorization',
                  'approved_target','post_execution_cleanup_receipt'):
            need(boundary[k] is None,'fabricated_material:'+pid+':'+k)
        for k in ('isolation_verified','capability_verified','issuer_and_revocation_verified',
                  'runtime_binary_identity_verified','dispatch_allowed'):
            need(boundary[k] is False,'fabricated_authorization:'+pid+':'+k)
        need(row['cleanup_contract']==slot['cleanup'] and
             row['contract_status']==slot['status']=='BLOCKED_UNBOUND_NO_EXECUTION' and
             all(x is None for x in slot['binding'].values()), 'p8_promotion_or_cleanup_drift:'+pid)
        # All 5 proposed marker writes require a separately verified cleanup receipt.
        if 'WRITE_CLEANUP_NOT_VERIFIED'==previous['additional_gate']:
            need(row['cleanup_contract']=='VERIFY_THEN_REMOVE_MARKER', 'write_cleanup_missing:'+pid)
    return {'status':'PASS_P8_R10_29_STRUCTURED_INTENTS_DENY_ALL','profiles':len(seen),
            'candidate_materials':len(binaries),'r9_materials_authoritative':False,
            'argv_renderable':False,'remote_command_strings_allowed':False,
            'approved_cases':0,'authorized_profiles':0,'dispatch_allowed':False,
            'algorithms_started':False,'physical_laboratory':'NOT_TOUCHED'}


def assess_symbolic_intent(request,contract):
    """Pure educational/structural oracle: accepted intent is still always DENIED."""
    exact(request,{'profile_id','operation_id','candidate_binary_sha256','control_atoms',
                   'material_reference_names','rendered_argv','remote_command_ast',
                   'smb_command_ast','desired_action'},'request')
    need(request['desired_action']=='REVIEW_ONLY','request_not_review_only')
    need(request['rendered_argv'] is None and request['remote_command_ast'] is None and
         request['smb_command_ast'] is None, 'raw_or_materialized_command_forbidden')
    need(type(request['profile_id']) is str,'request_profile_id_type')
    rows=[x for x in contract['profiles'] if x['profile_id']==request['profile_id']]
    need(len(rows)==1,'unknown_profile')
    row=rows[0]
    need(request['operation_id']==row['semantic_operation_id'] and
         request['candidate_binary_sha256']==row['candidate_binary_sha256'],
         'profile_operation_material_mismatch')
    for k,name in [('control_atoms','required_control_atoms'),
                   ('material_reference_names','material_reference_names')]:
        need(type(request[k]) is list and request[k]==row['argument_contract'][name],
             'typed_intent_mismatch:'+k)
        need(all(type(x) is str for x in request[k]),'invalid_typed_atom')
    return {'status':'BLOCKED_SYMBOLIC_CONTRACT_ONLY','profile_id':row['profile_id'],
            'semantic_operation_id':row['semantic_operation_id'],
            'authorization_verified':False,'argv_renderable':False,
            'dispatch_allowed':False,'reason':'NO_PRIVATE_CASE_AUTHORITY_NO_EFFECTIVE_RUNTIME_PIN'}


def verify_repository(root:Path=ROOT):
    # R9 must pass first: pinned P7/P8, 29 candidate profiles and empty P6 stages.
    root=Path(root)
    if root==ROOT:
        r9.verify_repository()
    contract=from_root(root,CONTRACT)
    inv=from_root(root,R9_INV,R9_INV_SHA)
    compat=from_root(root,R9_COMPAT,R9_COMPAT_SHA)
    p8=from_root(root,P8,digest=r9.P8_SHA)
    return validate(contract,compat,inv,p8)


def main():
    try:
        print(json.dumps(verify_repository(),sort_keys=True))
    except (ContractError,r9.InventoryError,OSError,ValueError) as err:
        print('ARDREC_P8_R10=FAIL_CLOSED: '+str(err),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    raise SystemExit(main())
