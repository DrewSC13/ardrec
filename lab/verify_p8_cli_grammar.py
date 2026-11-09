#!/usr/bin/env python3
"""P8-R13: pure typed intent grammar (no CLI argv, command shells or execution).

A validated symbolic plan is NEVER a permission or a runnable command. Reject
all unknown, free-form and materialized data before producing its canonical tags.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import verify_p8_cli_semantics as r12

ROOT=Path(__file__).resolve().parents[1]
SPEC='lab/p8-cli-grammar-v1/spec.json'
R12='lab/p8-cli-semantics-v1/semantics.json'
SPEC_SHA='df9fbfae39526a70f96972074357f0e4144bd3d39f7f771d291e95c23999f4e0'
R12_SHA='9701bc65e9e62f18389da021c5ac9c1a7e930e30152403a87d81b094cf0dfab0'
BASE='5e8502f1c6f93046fecaab837660e4b8c2caef7a'
IMAGE_SHA='fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
DOC_FIELDS={'schema_version','roadmap_step','increment','base_commit','kind','r12_semantics_sha256',
 'image_sha256','profiles','profile_count','write_variants','approved_cli_grammars',
 'approved_cli_options','approved_argv_renderers','authorized_cases','authorized_profiles',
 'dispatch_allowed','algorithms_started','physical_laboratory_contact','guest_binaries_executed',
 'request_shape','request_scope','design_only'}
PROFILE_FIELDS={'profile_id','semantic_operation_id','protocol','effect_class','resource_tag',
 'assurance_design','command_surface','source_term_ids','cleanup_contract','grammar_status',
 'accepted_cli_options','argv_template','remote_command_ast','smb_command_ast',
 'runtime_permission','dispatch_allowed'}
REQ_FIELDS=('profile_id','semantic_operation_id','effect_class','resource_tag','assurance_design','test_scope')
WRITE={'SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE','SMB-T08-BASE','SMB-T09-WRITE'}

class GrammarError(ValueError):
    """A fail-closed schema or symbolic intent rejection."""

def need(ok,code):
    if not ok: raise GrammarError('P8-R13_FAIL_CLOSED:'+code)

def strict_pairs(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'duplicate_key')
        out[k]=v
    return out

def strict_json(raw,max_bytes=1024*1024):
    need(type(raw) is bytes and 0<len(raw)<=max_bytes,'json_bytes')
    try:
        return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=strict_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(GrammarError('nonfinite')))
    except (ValueError,UnicodeError,RecursionError) as err:
        if isinstance(err,GrammarError): raise
        raise GrammarError('P8-R13_FAIL_CLOSED:invalid_json') from err

def safe_read(root,name,expected):
    need(type(name) is str and '\\' not in name and not name.startswith('/') and
         all(p not in ('','.','..') for p in name.split('/')),'path')
    p=Path(root)
    for part in name.split('/'):
        p=p/part
        need(not p.is_symlink(),'symlink_source')
    need(p.is_file(),'missing_source')
    raw=p.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==expected,'source_sha_drift:'+name)
    return strict_json(raw)

def validate_spec(spec,r12_spec):
    need(type(spec) is dict and set(spec)==DOC_FIELDS,'root_fields')
    need(type(r12_spec) is dict and len(r12_spec.get('profiles',[]))==29,'r12_missing_profiles')
    need(spec['schema_version']=='1.0' and type(spec['roadmap_step']) is int and
         spec['roadmap_step']==8 and spec['increment']=='P8-R13' and spec['base_commit']==BASE and
         spec['kind']=='ABSTRACT_TYPED_INTENT_GRAMMAR_NOT_CLI_ARGUMENT_GRAMMAR' and
         spec['r12_semantics_sha256']==R12_SHA and spec['image_sha256']==IMAGE_SHA,'source_identity')
    for field,count in (('profile_count',29),('write_variants',5),('approved_cli_grammars',0),
                        ('approved_cli_options',0),('approved_argv_renderers',0),
                        ('authorized_cases',0),('authorized_profiles',0)):
        need(type(spec[field]) is int and spec[field]==count,'gate:'+field)
    need(spec['dispatch_allowed'] is False and spec['algorithms_started'] is False and
         spec['guest_binaries_executed'] is False and spec['design_only'] is True and
         spec['physical_laboratory_contact']=='NONE' and
         spec['request_shape']==list(REQ_FIELDS) and
         spec['request_scope']=='SYNTHETIC_SCHEMA_ONLY','global_authority')
    need(type(spec['profiles']) is list and len(spec['profiles'])==29,'profile_list')
    seen=set();writes=set()
    for profile,prior in zip(spec['profiles'],r12_spec['profiles']):
        need(type(profile) is dict and set(profile)==PROFILE_FIELDS,'profile_fields')
        pid=profile['profile_id']
        need(type(pid) is str and pid==prior['profile_id'] and pid not in seen and
             profile['semantic_operation_id']==prior['semantic_operation_id'] and
             profile['source_term_ids']==prior['source_term_ids'],'profile_identity')
        seen.add(pid)
        protocol=pid.split('-')[0]
        need(protocol in ('SSH','FTP','SMB') and profile['protocol']==protocol,'protocol')
        need(profile['effect_class'] in ('WRITE_MARKER_PENDING_CLEANUP','OBSERVE_OR_READ',
                                            'OBSERVE_OR_AUTHENTICATE') and
             profile['resource_tag'] in ('NO_RESOURCE','FIXTURE_FILE','FIXTURE_DIRECTORY',
                                          'FIXTURE_PAIR','FIXTURE_MARKER'),'categories')
        assurance=profile['assurance_design']
        need(type(assurance) is str and assurance.endswith('_UNVERIFIED') and
             assurance.startswith(protocol),'assurance_not_verified')
        surface=profile['command_surface']
        need(type(surface) is str and surface in (
             'SSH_REMOTE_COMMAND_AST_UNDEFINED','SSH_CONFIGURATION_UNBOUND',
             'FTP_NO_ARBITRARY_QUOTE_OR_REQUEST','SMB_COMMAND_AST_UNDEFINED',
             'SMB_CONFIG_UNBOUND'),'command_surface')
        need((protocol=='SSH' and surface.startswith('SSH_')) or
             (protocol=='FTP' and surface.startswith('FTP_')) or
             (protocol=='SMB' and surface.startswith('SMB_')),'command_surface_protocol')
        need(profile['grammar_status']=='ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE' and
             type(profile['accepted_cli_options']) is list and not profile['accepted_cli_options'] and
             profile['argv_template'] is None and profile['remote_command_ast'] is None and
             profile['smb_command_ast'] is None and profile['runtime_permission'] is False and
             profile['dispatch_allowed'] is False,'execution_gate')
        if protocol=='SSH':
            expected_assurance='SSH_PINNED_HOST_KEY_REQUIRED_UNVERIFIED'
            expected_surface=('SSH_REMOTE_COMMAND_AST_UNDEFINED' if pid in (
                'SSH-T05-BASE','SSH-T06-BASE','SSH-T07-BASE','SSH-T08-BASE') else
                'SSH_CONFIGURATION_UNBOUND')
        elif protocol=='FTP':
            expected_assurance=('FTP_CONTROL_TLS_UNVERIFIED' if pid=='FTP-T02-CONTROL' else
                                'FTP_DATA_TLS_UNVERIFIED' if pid=='FTP-T02-DATA' else
                                'FTP_TLS_STATUS_UNVERIFIED')
            expected_surface='FTP_NO_ARBITRARY_QUOTE_OR_REQUEST'
        else:
            expected_assurance=('SMB_SIGNING_UNVERIFIED' if pid=='SMB-T03-SIGNING' else
                                'SMB_ENCRYPTION_UNVERIFIED' if pid=='SMB-T03-ENCRYPTION' else
                                'SMBV1_ISOLATED_FIXTURE_ONLY_UNVERIFIED' if pid=='SMB-T02-BASE' else
                                'SMB_PROTECTION_UNVERIFIED')
            expected_surface=('SMB_COMMAND_AST_UNDEFINED' if pid.startswith((
                'SMB-T06','SMB-T07','SMB-T08','SMB-T09')) else 'SMB_CONFIG_UNBOUND')
        need(assurance==expected_assurance and surface==expected_surface,'assurance_surface_drift')
        expected_resource=(
            'FIXTURE_MARKER' if pid in WRITE else
            'FIXTURE_PAIR' if 'COMPARE_READ' in prior['semantic_operation_id'] else
            'FIXTURE_DIRECTORY' if 'LIST_ONLY' in prior['semantic_operation_id'] else
            'FIXTURE_FILE' if any(s in prior['semantic_operation_id'] for s in (
                'READ','DOWNLOAD')) else 'NO_RESOURCE')
        expected_effect=(
            'WRITE_MARKER_PENDING_CLEANUP' if pid in WRITE else
            'OBSERVE_OR_READ' if any(s in prior['semantic_operation_id'] for s in (
                'READ_','DOWNLOAD','IDENTIFY_PREDEFINED','LIST_ONLY_',
                'COMPARE_READ','VERIFY_ENCRYPTED','VERIFY_SIGNED')) else
            'OBSERVE_OR_AUTHENTICATE')
        need(profile['resource_tag']==expected_resource and
             profile['effect_class']==expected_effect,'effect_resource_drift')
        if pid in WRITE:
            writes.add(pid)
            need(profile['cleanup_contract']=='VERIFY_THEN_REMOVE_MARKER' and
                 profile['resource_tag']=='FIXTURE_MARKER' and
                 profile['effect_class']=='WRITE_MARKER_PENDING_CLEANUP','write_guard')
        else:
            need(profile['cleanup_contract']=='NO_MUTATION' and
                 profile['effect_class']!='WRITE_MARKER_PENDING_CLEANUP' and
                 profile['resource_tag']!='FIXTURE_MARKER','no_write_guard')
        if pid=='FTP-T02-CONTROL':need(assurance=='FTP_CONTROL_TLS_UNVERIFIED','tls_control')
        if pid=='FTP-T02-DATA':need(assurance=='FTP_DATA_TLS_UNVERIFIED','tls_data')
        if pid=='SMB-T03-SIGNING':need(assurance=='SMB_SIGNING_UNVERIFIED','smb_signing')
        if pid=='SMB-T03-ENCRYPTION':need(assurance=='SMB_ENCRYPTION_UNVERIFIED','smb_encryption')
        if pid=='SMB-T02-BASE':need(assurance=='SMBV1_ISOLATED_FIXTURE_ONLY_UNVERIFIED','smbv1')
        if pid=='SSH-T03-BASE':need(surface=='SSH_CONFIGURATION_UNBOUND','password_not_automated')
    need(seen=={x['profile_id'] for x in r12_spec['profiles']} and writes==WRITE,'profile_set')
    return {'status':'PASS_P8_R13_29_TYPED_SYMBOLIC_GRAMMARS_DENY_ALL',
            'profiles':29,'write_cleanup_gates':5,'effective_cli_grammars':0,
            'accepted_cli_options':0,'authorized_profiles':0,'dispatch_allowed':False}

def parse_request(raw,spec):
    need(type(spec) is dict and len(spec.get('profiles',[]))==29,'invalid_spec_request')
    # This API cannot promote a caller-supplied, altered grammar to trusted tags.
    canonical=(json.dumps(spec,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
    need(hashlib.sha256(canonical).hexdigest()==SPEC_SHA,'untrusted_grammar_object')
    request=strict_json(raw,4096)
    need(type(request) is dict and set(request)==set(REQ_FIELDS),'request_shape')
    need(all(type(request[k]) is str for k in REQ_FIELDS),'request_types')
    need(request['test_scope']=='SYNTHETIC_SCHEMA_ONLY','not_synthetic_scope')
    match=next((p for p in spec['profiles'] if p['profile_id']==request['profile_id']),None)
    need(match is not None,'unknown_profile')
    for field in ('semantic_operation_id','effect_class','resource_tag','assurance_design'):
        need(request[field]==match[field],'unexpected_'+field)
    return match

def symbolic_plan(raw,spec):
    """Pure compilation of exact enums into NON-RUNNABLE abstract tags only.

    No binary, host, path, option, shell syntax, network, credential or argv.
    """
    p=parse_request(raw,spec)
    atoms=[('PROFILE',p['profile_id']),('OPERATION',p['semantic_operation_id']),
           ('PROTOCOL',p['protocol']),('EFFECT_CLASS',p['effect_class']),
           ('RESOURCE_TAG',p['resource_tag']),('ASSURANCE_DESIGN',p['assurance_design']),
           ('COMMAND_SURFACE',p['command_surface']),('CLEANUP_CONTRACT',p['cleanup_contract'])]
    digest=hashlib.sha256(json.dumps(atoms,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return {'kind':'NON_EXECUTABLE_SYMBOLIC_INTENT_PLAN','atoms':[{'kind':a,'value':b} for a,b in atoms],
            'plan_sha256':digest,'runnable_argv':None,'remote_command_ast':None,
            'smb_command_ast':None,'case_authorized':False,'dispatch_allowed':False}

def verify_repository(root=ROOT):
    root=Path(root)
    if root==ROOT: r12.verify_repository()
    prev=safe_read(root,R12,R12_SHA)
    spec=safe_read(root,SPEC,SPEC_SHA)
    out=validate_spec(spec,prev)
    for profile in spec['profiles']:
        req={field:(spec['request_scope'] if field=='test_scope' else profile[field]) for field in REQ_FIELDS}
        plan=symbolic_plan(json.dumps(req,sort_keys=True).encode(),spec)
        need(plan['runnable_argv'] is None and plan['dispatch_allowed'] is False,
             'unexpected_symbolic_promotion')
    return out

def main():
    try:
        print(json.dumps(verify_repository(),sort_keys=True))
    except (GrammarError,r12.R12Error,r12.r11.EvidenceError,
            r12.r11.r10.ContractError,r12.r11.r10.r9.InventoryError,
            OSError,KeyError,TypeError) as exc:
        print('ARDREC_P8_R13=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
