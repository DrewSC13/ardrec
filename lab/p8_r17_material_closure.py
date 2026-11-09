#!/usr/bin/env python3
"""P8-R17: deterministic 29-profile material-closure gap gate, DENY ONLY.

No binaries, VMs, networks, subprocess, command/argv builder, secrets, or case authority.
A candidate hash from a disk image is NEVER a binding or runtime attestation.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

BASE='b0e805006d6e128f8ebbe3781596a80604e31138'
PINS={
 'lab/execution-profiles-v1/profiles.json':'fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3',
 'lab/p8-profile-contract-v1/contracts.json':'f09e92f395928a52e3c826a11aeef8ed13acb07299b322d173cc03fcf55b4f41',
 'lab/p8-cli-grammar-v1/spec.json':'df9fbfae39526a70f96972074357f0e4144bd3d39f7f771d291e95c23999f4e0',
 'lab/p8-cli-review-gates-v1/gates.json':'90fe31e92366493e97818e2c706c142f91a47eff84446413374fa421169ca716',
}
BINDING_FIELDS=(
 'executable_absolute_path','executable_sha256','executable_version',
 'argv_typed_vector','working_directory','environment_allowlist',
 'auxiliary_executables','case_authorization_ref','approved_target_ref',
 'fixed_resource_budget','capture_policy_ref','cleanup_receipt_ref')
WRITER_IDS=frozenset(('SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE',
                        'SMB-T08-BASE','SMB-T09-WRITE'))
SHARED_GATES=(
 'BINARY_IDENTITY_AND_EXECUTABLE_PIN','DEPENDENCY_RUNTIME_CLOSURE',
 'EFFECTIVE_CONFIGURATION_PROVENANCE','ISOLATION_AND_TARGET_BINDING',
 'CASE_SCOPE_AUTHORIZATION','RESOURCE_CREDENTIAL_PROVENANCE',
 'OPERATION_BUDGET_AND_TIMEOUT','SEMANTIC_OPTION_ARGUMENT_REVIEW',
 'EVIDENCE_AND_OBSERVATION_PROTOCOL')
WRITE_GATES=('INDEPENDENT_CLEANUP_RECEIPT','RESTORATION_PROOF')

class MaterialError(ValueError): pass

def need(cond,why):
    if not cond:raise MaterialError('P8_R17_FAIL_CLOSED:'+why)

def unique_keys(pairs):
    out={}
    for key,val in pairs:
        need(key not in out,'duplicate_json_key:'+key)
        out[key]=val
    return out

def decode(raw):
    need(type(raw) is bytes and 0<len(raw)<=2_000_000,'json_size')
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=unique_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(MaterialError('nonfinite')))
    except (ValueError,UnicodeError,RecursionError) as e:
        if isinstance(e,MaterialError):raise
        raise MaterialError('P8_R17_FAIL_CLOSED:invalid_json') from e

def read_pinned(root,name,expected):
    root=Path(root).resolve(strict=True)
    need(name in PINS and PINS[name]==expected,'unknown_source:'+name)
    path=root
    for frag in name.split('/'):
        path=path/frag
        need(not path.is_symlink(),'source_symlink:'+name)
    need(path.is_file(),'missing_source:'+name)
    need(path.stat().st_size<=2_000_000,'source_too_large:'+name)
    raw=path.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==expected,'source_drift:'+name)
    return decode(raw)

def identity(row):
    need(type(row) is dict and type(row.get('profile_id')) is str,'row')
    return row['profile_id']

def check_29(rows,kind):
    need(type(rows) is list and len(rows)==29,'profile_count:'+kind)
    ids=[identity(row) for row in rows]
    need(len(set(ids))==29,'duplicate_profiles:'+kind)
    return ids

def evaluate(r1,r10,r13,r15):
    """Only accepts original blocked material sources; future bindings require a new authority path."""
    need(type(r1) is dict and type(r10) is dict and type(r13) is dict and
         type(r15) is dict,'document_type')
    ids=check_29(r1.get('profiles'),'r1')
    need(ids==check_29(r10.get('profiles'),'r10')==
         check_29(r13.get('profiles'),'r13')==
         check_29(r15.get('profiles'),'r15'),'cross_registry_order')
    need(len(ids)==29 and sum(pid.startswith('SSH-') for pid in ids)==8
        and sum(pid.startswith('FTP-') for pid in ids)==10
        and sum(pid.startswith('SMB-') for pid in ids)==11,'protocol_counts')
    need(r1.get('profile_slot_count')==29 and
         r10.get('profile_count')==29 and r13.get('profile_count')==29 and
         r15.get('profile_count')==29,'document_profile_counts')
    need(r1.get('execution_enabled') is False and
         r10.get('dispatch_allowed') is False and
         r13.get('dispatch_allowed') is False and
         r15.get('dispatch_allowed') is False,'global_dispatch')
    need(r10.get('fully_bound_profiles')==0 and
         r10.get('authorized_cases')==0 and
         r13.get('approved_argv_renderers')==0 and
         r15.get('approved_cli_grammars')==0 and
         r15.get('semantic_reviews_completed')==0,
         'global_false_approval')
    need(r15.get('required_common_gates')==list(SHARED_GATES) and
         r15.get('required_write_gates')==list(WRITE_GATES) and
         r15.get('writer_count')==5 and r15.get('risk_count')==25,
         'r15_gates')
    results=[];risk_links=0;gates_count=0
    for a,b,c,d in zip(r1['profiles'],r10['profiles'],r13['profiles'],r15['profiles']):
        pid=a['profile_id'];protocol=pid.split('-')[0]
        need(a['status']=='BLOCKED_UNBOUND_NO_EXECUTION' and
             b['contract_status']=='BLOCKED_UNBOUND_NO_EXECUTION' and
             c['grammar_status']=='ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE' and
             d['status']=='BLOCKED_UNREVIEWED','profile_status:'+pid)
        need(a['protocol']==protocol.lower() and b['protocol']==protocol.lower() and
             c['protocol']==protocol and d['protocol']==protocol,'protocol:'+pid)
        need(a['variant']==b['variant'] and
             b['semantic_operation_id']==c['semantic_operation_id']==
             d['semantic_operation_id'],'identity:'+pid)
        need(type(a['binding']) is dict and set(a['binding'])==set(BINDING_FIELDS)
             and all(v is None for v in a['binding'].values()),'r1_bound_field:'+pid)
        need(type(b['execution_boundary']) is dict and
             b['execution_boundary']['dispatch_allowed'] is False and
             all(v is None for k,v in b['execution_boundary'].items() if k in (
                 'environment','working_directory','auxiliary_pins',
                 'credential_delivery','capture_policy','resource_budget',
                 'private_case_authorization','approved_target',
                 'post_execution_cleanup_receipt')) and
             b['execution_boundary']['runtime_binary_identity_verified'] is False,
             'r10_bound_without_proof:'+pid)
        need(b['argument_contract']['representation']=='TYPED_SYMBOLIC_INTENT_NOT_ARGV' and
             b['argument_contract']['rendered_argv'] is None and
             b['argument_contract']['remote_command_ast'] is None and
             b['argument_contract']['smb_command_ast'] is None and
             b['argument_contract']['raw_command_strings_allowed'] is False,
             'unsafe_materialized_argv:'+pid)
        need(b['argument_contract']['material_reference_names']==
             a['required_material_parameter_slots'],'material_slots:'+pid)
        need(c['argv_template'] is None and
             c['remote_command_ast'] is None and c['smb_command_ast'] is None and
             c['accepted_cli_options']==[] and c['runtime_permission'] is False and
             c['dispatch_allowed'] is False,'r13_approval:'+pid)
        need(d['case_authorized'] is False and
             d['cli_grammar_authorized'] is False and d['dispatch_allowed'] is False,
             'r15_approval:'+pid)
        writer=pid in WRITER_IDS
        cleanup='VERIFY_THEN_REMOVE_MARKER' if writer else 'NO_MUTATION'
        need(a['cleanup']==b['cleanup_contract']==c['cleanup_contract']==cleanup,
             'cleanup_mismatch:'+pid)
        gates=list(SHARED_GATES)+list(WRITE_GATES if writer else ())
        need(d['required_evidence_gates']==gates,'missing_evidence_gate:'+pid)
        risk_ids=d['documented_risks']
        need(type(risk_ids) is list and len(risk_ids)>=6 and
             len(set(risk_ids))==len(risk_ids),'risk_refs:'+pid)
        need(type(b['candidate_binary']) is str and b['candidate_binary'].startswith('/usr/bin/')
             and type(b['candidate_binary_sha256']) is str and
             len(b['candidate_binary_sha256'])==64,'candidate_shape:'+pid)
        results.append({'profile_id':pid,'protocol':protocol,'operation':b['semantic_operation_id'],
            'candidate_executable_observed_only':b['candidate_binary'],
            'candidate_sha256_observed_only':b['candidate_binary_sha256'],
            'binding_missing':list(BINDING_FIELDS),
            'open_evidence_gates':gates,
            'documentary_risk_count':len(risk_ids),
            'write_cleanup_required':writer,
            'argv_runnable':False,'case_authorized':False,'dispatch_allowed':False,
            'status':'BLOCKED_NO_MATERIAL_BINDINGS'})
        risk_links+=len(risk_ids);gates_count+=len(gates)
    need(sum(item['write_cleanup_required'] for item in results)==5,
         'writer_count')
    need(risk_links==238 and gates_count==271,'coverage_count')
    return {'scope':'P8_R17_MATERIAL_CLOSURE_AUDIT_ONLY',
            'base_main_commit':BASE,'status':'PASS_DENY_ONLY_29_PROFILE_MATERIAL_GAPS',
            'protocol_counts':{'SSH':8,'FTP':10,'SMB':11},
            'profiles_reviewed':29,'binding_fields_per_profile':12,
            'missing_material_bindings':348,'open_evidence_gate_links':271,
            'risk_profile_links':238,'write_cleanup_profiles':5,
            'approved_argv_renderers':0,'authorized_cases':0,
            'approved_profiles':0,'dispatch_allowed':False,
            'effective_configuration_verified':False,
            'source_status':'HISTORIC_PINNED_DENY_ONLY_NOT_RUNTIME_ATTESTED',
            'profiles':results}

def verify_repository(root):
    doc=[read_pinned(root,path,sha) for path,sha in PINS.items()]
    return evaluate(*doc)
