#!/usr/bin/env python3
"""ARDREC P8-R15: deterministic fail-closed review obligations, NOT an argv builder.

Nothing in this module executes clients, resolves destinations or grants permissions.
The review matrix projects documented hazards conservatively to 29 symbolic slots;
its only output is a repeatable BLOCKED decision and unmet review requirements.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import verify_p8_cli_full_sources as r14

ROOT=Path(__file__).resolve().parents[1]
SOURCE='lab/p8-cli-review-gates-v1/gates.json'
SOURCE_SHA='90fe31e92366493e97818e2c706c142f91a47eff84446413374fa421169ca716'
R14='lab/p8-cli-full-source-v1/anchors.json'
R14_SHA='6b22b5ae82a3af897516a3c7eb5f37c7bff71ad7a6f2d9382de10b2855fccfb4'
R13='lab/p8-cli-grammar-v1/spec.json'
R13_SHA='df9fbfae39526a70f96972074357f0e4144bd3d39f7f771d291e95c23999f4e0'
BASE='62812d92dd89ccf4559d9d2e7219fd96b197d5c6'
IMAGE_SHA='fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
PRIVATE_SHA='2968e57fc65554735cef5ad349ec8a159dcc42fae3b0f05a653b2df0b20af365'
GATES=('BINARY_IDENTITY_AND_EXECUTABLE_PIN','DEPENDENCY_RUNTIME_CLOSURE',
       'EFFECTIVE_CONFIGURATION_PROVENANCE','ISOLATION_AND_TARGET_BINDING',
       'CASE_SCOPE_AUTHORIZATION','RESOURCE_CREDENTIAL_PROVENANCE',
       'OPERATION_BUDGET_AND_TIMEOUT','SEMANTIC_OPTION_ARGUMENT_REVIEW',
       'EVIDENCE_AND_OBSERVATION_PROTOCOL')
WRITER_GATES=('INDEPENDENT_CLEANUP_RECEIPT','RESTORATION_PROOF')
CATS={
'SSH_CONFIG_PRECEDENCE':'CONFIG_INHERITANCE','SSH_PROXY_SHELL':'INTERPRETER',
'SSH_LOCAL_EXEC':'INTERPRETER','SSH_REMOTE_EXEC':'INTERPRETER',
'SSH_HOST_KEY_PIN':'IDENTITY','SSH_CONFIG_HOOK':'INTERPRETER',
'SSH_CONTROL_REUSE':'SESSION_REUSE','SSH_SCAN_SCOPE':'BUDGET',
'SFTP_BATCH_MUTATION':'MUTATION','CURL_CONFIG_FIRST':'CONFIG_INHERITANCE',
'CURL_TLS_REQUIRED':'CRYPTO_POLICY','CURL_TLS_DOWNGRADE':'CRYPTO_POLICY',
'CURL_TLS_CCC':'CRYPTO_POLICY','CURL_INSECURE':'CRYPTO_POLICY',
'CURL_PROXY':'ROUTE','CURL_RETRY':'BUDGET','CURL_PROTOCOLS':'PROTOCOL',
'CURL_QUOTE':'INTERPRETER','CURL_UPLOAD':'MUTATION',
'SMB_MAX_DIALECT':'PROTOCOL','SMB_SIGN_ENCRYPT':'CRYPTO_POLICY',
'SMB_COMMAND_LIST':'INTERPRETER','SMB_PUT':'MUTATION','SMB_DELETE':'MUTATION',
'RPC_COMMAND':'INTERPRETER'}
ROOT_FIELDS={'schema_version','increment','roadmap_step','base_commit','kind',
 'r13_symbolic_spec_sha256','r14_full_anchor_sha256',
 'r14_private_full_report_sha256','image_sha256','profiles','risks',
 'profile_count','risk_count','writer_count','approved_cli_options',
 'approved_cli_grammars','approved_argv_renderers','semantic_reviews_completed',
 'authorized_profiles','authorized_cases','dispatch_allowed',
 'guest_binaries_executed','algorithms_started','physical_laboratory_contact',
 'risk_mapping_basis','no_runtime_callers','required_common_gates',
 'required_write_gates'}
RISK_FIELDS={'risk_id','term_id','source_line_1based','source_line_sha256',
 'category','documented_boundary','required_design_guard','source_only',
 'semantic_review_complete','operational_control_verified','approved_for_execution'}
PROFILE_FIELDS={'profile_id','protocol','semantic_operation_id','effect_class',
 'resource_tag','assurance_design','documented_risks','required_evidence_gates',
 'risk_projection','status','case_authorized','cli_grammar_authorized','dispatch_allowed'}

class ReviewGateError(ValueError):
    """Deny by construction; no partial consent or hidden defaults."""

def need(ok,reason):
    if not ok:raise ReviewGateError('P8_R15_FAIL_CLOSED:'+reason)

def source_read(root,path,sha):
    return r14.safe_read(root,path,sha)

def exact(o,fields,label):
    need(type(o) is dict and set(o)==fields,'unexpected_fields:'+label)

def in_scope(protocol,risk_id):
    """Conservative grouping; NO claim of actual invocation or exploitability."""
    if protocol=='SSH':return risk_id.startswith(('SSH_','SFTP_'))
    if protocol=='FTP':return risk_id.startswith('CURL_')
    if protocol=='SMB':return risk_id.startswith(('SMB_','RPC_'))
    return False

def validate_matrix(data,anchors,typed):
    exact(data,ROOT_FIELDS,'root')
    need(data['schema_version']=='1.0' and
         type(data['roadmap_step']) is int and data['roadmap_step']==8 and
         data['increment']=='P8-R15' and data['base_commit']==BASE and
         data['kind']=='STATIC_CLI_REVIEW_OBLIGATION_MATRIX_DENY_ALL' and
         data['r13_symbolic_spec_sha256']==R13_SHA and
         data['r14_full_anchor_sha256']==R14_SHA and
         data['r14_private_full_report_sha256']==PRIVATE_SHA and
         data['image_sha256']==IMAGE_SHA,'document_identity')
    for k,v in (('profile_count',29),('risk_count',25),('writer_count',5),
                 ('approved_cli_options',0),('approved_cli_grammars',0),
                 ('approved_argv_renderers',0),('semantic_reviews_completed',0),
                 ('authorized_profiles',0),('authorized_cases',0)):
        need(type(data[k]) is int and data[k]==v,'authority_count:'+k)
    need(data['dispatch_allowed'] is False and data['guest_binaries_executed'] is False
         and data['algorithms_started'] is False and data['no_runtime_callers'] is True and
         data['physical_laboratory_contact']=='NONE' and
         data['risk_mapping_basis']=='CONSERVATIVE_PROTOCOL_WIDE_ONLY' and
         data['required_common_gates']==list(GATES) and
         data['required_write_gates']==list(WRITER_GATES),'global_denial')
    need(type(anchors) is dict and type(anchors.get('safety_boundaries')) is list and
         len(anchors['safety_boundaries'])==25 and
         type(typed) is dict and type(typed.get('profiles')) is list and
         len(typed['profiles'])==29,'prior_source_shapes')
    need(type(data['risks']) is list and len(data['risks'])==25,'risk_count')
    ids=[]
    for i,(risk,prior) in enumerate(zip(data['risks'],anchors['safety_boundaries'])):
        exact(risk,RISK_FIELDS,'risk')
        name=prior['risk_id'];ids.append(name)
        need(name in CATS and risk['risk_id']==name and risk['term_id']==prior['term_id']
             and risk['category']==CATS[name] and
             risk['source_line_1based']==prior['evidence_line_1based'] and
             risk['source_line_sha256']==prior['evidence_line_sha256'] and
             risk['documented_boundary']==prior['documented_boundary'] and
             risk['required_design_guard']==prior['required_design_guard'],
             'risk_mismatch:'+str(i))
        need(risk['source_only'] is True and risk['semantic_review_complete'] is False
             and risk['operational_control_verified'] is False and
             risk['approved_for_execution'] is False,'risk_authority')
    need(len(set(ids))==25 and set(ids)==set(CATS),'risk_identity_set')
    need(type(data['profiles']) is list and len(data['profiles'])==29,'profile_count')
    seen=set();writers=0;links=0
    for n,(row,prior) in enumerate(zip(data['profiles'],typed['profiles'])):
        exact(row,PROFILE_FIELDS,'profile')
        pid=prior['profile_id'];protocol=prior['protocol']
        need(pid not in seen,'duplicate_profile');seen.add(pid)
        need(row['profile_id']==pid and row['protocol']==protocol and
             row['semantic_operation_id']==prior['semantic_operation_id'] and
             row['effect_class']==prior['effect_class'] and
             row['resource_tag']==prior['resource_tag'] and
             row['assurance_design']==prior['assurance_design'],'profile_identity:'+pid)
        expected=[risk_id for risk_id in ids if in_scope(protocol,risk_id)]
        need(row['documented_risks']==expected and len(expected)>=6,
             'risk_projection:'+pid)
        writer=(prior['effect_class']=='WRITE_MARKER_PENDING_CLEANUP')
        writers+=int(writer)
        expected_gates=list(GATES)+list(WRITER_GATES if writer else ())
        need(row['required_evidence_gates']==expected_gates and
             row['risk_projection']=='CONSERVATIVE_PROTOCOL_WIDE_NOT_OPERATIONAL_PROOF'
             and row['status']=='BLOCKED_UNREVIEWED' and
             row['case_authorized'] is False and
             row['cli_grammar_authorized'] is False and
             row['dispatch_allowed'] is False,'profile_deny:'+pid)
        links+=len(expected)
    need(len(seen)==29 and writers==5 and links==238,'profile_coverage')
    return {'status':'PASS_P8_R15_29_PROFILES_25_RISKS_238_LINKS_DENY_ALL',
            'profiles':29,'risk_boundaries':25,'risk_profile_links':238,
            'write_cleanup_gates':5,'semantic_reviews_completed':0,
            'authorized_profiles':0,'approved_cli_options':0,'dispatch_allowed':False}

def assess_request(raw,data,typed):
    """A synthetic review query is ALWAYS blocked, including a matching profile."""
    # Prevent a caller supplying a patched matrix (even with valid-looking fields).
    canonical=(json.dumps(data,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
    need(hashlib.sha256(canonical).hexdigest()==SOURCE_SHA,'untrusted_matrix')
    # Reuse R13 exact six-field parser: no secret, host, argv, shell, path, or URI.
    plan=r14.r13.symbolic_plan(raw,typed)
    match=next((p for p in data['profiles'] if p['profile_id']==plan['atoms'][0]['value']),None)
    need(match is not None,'profile_missing')
    return {'status':'BLOCKED_REVIEW_GATES_NOT_CLEARED',
            'profile_id':match['profile_id'],
            'plan_sha256':plan['plan_sha256'],
            'documented_risks':list(match['documented_risks']),
            'missing_evidence_gates':list(match['required_evidence_gates']),
            'risk_projection':'CONSERVATIVE_PROTOCOL_WIDE_ONLY',
            'cli_grammar_authorized':False,'case_authorized':False,
            'runnable_argv':None,'dispatch_allowed':False}

def verify_repository(root=ROOT):
    root=Path(root)
    if root==ROOT:r14.verify_repository()
    a=source_read(root,R14,R14_SHA)
    t=source_read(root,R13,R13_SHA)
    g=source_read(root,SOURCE,SOURCE_SHA)
    result=validate_matrix(g,a,t)
    for profile in t['profiles']:
        fields=r14.r13.REQ_FIELDS
        r={key:('SYNTHETIC_SCHEMA_ONLY' if key=='test_scope' else profile[key]) for key in fields}
        outcome=assess_request(json.dumps(r,sort_keys=True).encode(),g,t)
        need(outcome['dispatch_allowed'] is False and outcome['runnable_argv'] is None
             and outcome['status']=='BLOCKED_REVIEW_GATES_NOT_CLEARED',
             'review_gate_promoted')
    return result

def main():
    try:print(json.dumps(verify_repository(),sort_keys=True))
    except (ReviewGateError,r14.FullSourceError,r14.r13.GrammarError,
            r14.r13.r12.R12Error,r14.r13.r12.r11.EvidenceError,
            r14.r13.r12.r11.r10.ContractError,
            r14.r13.r12.r11.r10.r9.InventoryError,
            OSError,KeyError,TypeError,ValueError) as e:
        print('ARDREC_P8_R15=FAIL_CLOSED:'+str(e),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
