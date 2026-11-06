#!/usr/bin/env python3
"""ARDREC P8 R1: read-only, fail-closed schema for *unbound* execution slots.

No process spawning, network I/O, secret resolution or executable construction.
Never treat a slot/template as authorization or an executable invocation.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE='009393f34cd548bb79de122de90e992ff285bb5a'
THESIS='6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72'
P7_SHA='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
P7_VALIDATOR_SHA='ac4f05ba0f6f21577236bd822ec5ac0e6d8031a9be7e351ef3c790d8b86281a2'
PROFILE_SHA='fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3'
REL='lab/execution-profiles-v1/profiles.json'
TRACE='docs/traceability/execution-profiles-v1.json'
P7_REL='lab/operational-catalog-v1/catalog.json'
P7_VALIDATOR='lab/verify_operational_catalog.py'
BINDING_FIELDS=('executable_absolute_path','executable_sha256','executable_version',
    'argv_typed_vector','working_directory','environment_allowlist',
    'auxiliary_executables','case_authorization_ref','approved_target_ref',
    'fixed_resource_budget','capture_policy_ref','cleanup_receipt_ref')
POLICY_FIELDS=('status','dispatch_primitive','shells_forbidden','no_shell_command_strings',
    'no_shell_fallback','no_path_lookup','no_parent_env_inheritance','no_hidden_retries',
    'no_material_substitution','no_discovery_extending_scope','no_process_spawn_in_this_increment',
    'no_secret_values_in_public_artifacts','negative_or_nd_never_authorizes',
    'binary_and_auxiliary_sha256_required_before_approval',
    'absolute_executable_path_required_before_approval','typed_argv_required_before_approval',
    'authorization_and_budget_required_before_approval','physical_lab_isolation_required_before_approval',
    'cleanup_independently_verified','max_ordinary_attempts','extra_attempts',
    'pilot_numeric_limits','pending_binding_fields')
TOP_FIELDS=('schema_version','status','roadmap_step','baseline_commit','thesis_sha256',
    'source_sections','p7_catalog_path','p7_catalog_sha256','p7_family_count',
    'profile_slot_count','count_by_protocol','execution_enabled','profile_frozen',
    'physical_isolation_verified','pilot_limits_frozen','cases_authorized','real_cases',
    'policy','profiles')
SLOT_FIELDS=('profile_id','family_id','protocol','variant','precedence',
    'required_material_parameter_slots','required_preconditions','required_supports',
    'required_acceptance_supports','cleanup','binding','status')
TRACE_FIELDS=('schema_version','roadmap_step','status','baseline_commit','source_sha256',
    'source_sections','p7_catalog_sha256','profile_path','profile_sha256','families',
    'profile_slots','real_cases','executables_pinned','argv_vectors_pinned',
    'authorized_profiles','pilot_limits','physical_isolation','functional_acceptance',
    'experimental_validation','unresolved_obligations','open_findings','artifacts')
REF=re.compile(r'^ref:[a-zA-Z0-9][a-zA-Z0-9._:/-]{2,127}$')


def require(ok,why):
    if not ok:
        raise ValueError(why)


def exact_keys(obj,fields,where):
    require(type(obj) is dict and set(obj)==set(fields),where+': unexpected/missing keys')


def load(root,rel):
    root=Path(root).resolve(strict=True)
    part=Path(rel)
    require(not part.is_absolute() and '..' not in part.parts and part.parts,
            'Rutas fuera de raíz')
    path=root
    for item in part.parts:
        path=path/item
        require(not path.is_symlink(),'Enlace simbólico prohibido: '+rel)
    require(path.is_file() and path.resolve().is_relative_to(root),'Archivo fuera de raíz/ausente: '+rel)
    def unique(pairs):
        obj={}
        for k,v in pairs:
            require(k not in obj,'Clave JSON duplicada: '+k)
            obj[k]=v
        return obj
    return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique)


def from_p7_family(f,option):
    prec=f['precedence'] if option is None else f['variants']['precedence_by_option'][option]
    cleanup=f['cleanup']
    if cleanup=='CONDITIONAL_WRITE_MARKER_CLEANUP':
        cleanup='VERIFY_THEN_REMOVE_MARKER' if option=='WRITE' else 'NO_MUTATION'
    pre=list(f['preconditions']);sup=list(f['required_supports']);accept=list(f['acceptance_supports'])
    if f['id']=='FTP-T02':
        if option=='DATA':
            pre+=['SESSION_AUTHENTICATED','DATA_CHANNEL_PREDEFINED']
            accept+=['CONTROL_DATA_CORRELATION']
        else:
            sup.remove('CONTROL_DATA_CORRELATION')
    if f['id']=='SMB-T03':
        other='SMB_ENCRYPTION' if option=='SIGNING' else 'SMB_SIGNATURE'
        sup.remove(other)
        accept.append('SMB_SIGNATURE' if option=='SIGNING' else 'SMB_ENCRYPTION')
    if f['id'] in ('FTP-T08','SMB-T09') and option=='WRITE':
        pre+=['WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE']
        sup+=['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED']
        accept+=['MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED']
    return prec,cleanup,pre,sup,accept


def validate(root=ROOT):
    root=Path(root).resolve(strict=True)
    require(hashlib.sha256((root/REL).read_bytes()).hexdigest()==PROFILE_SHA,
            'P8 profile manifest integrity')
    require(hashlib.sha256((root/P7_REL).read_bytes()).hexdigest()==P7_SHA,
            'P7 catalogue integrity')
    require(hashlib.sha256((root/P7_VALIDATOR).read_bytes()).hexdigest()==P7_VALIDATOR_SHA,
            'P7 source validator integrity')
    # P7 validator independently attests historical stage and catalog semantics.
    spec=importlib.util.spec_from_file_location('ardrec_p8_p7_validator',root/P7_VALIDATOR)
    require(spec is not None and spec.loader is not None,'P7 validation unavailable')
    mod=importlib.util.module_from_spec(spec)
    previous_write_bytecode=sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode=True
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode=previous_write_bytecode
    require(mod.validate(root)['families']==25,'P7 source contracts changed')
    c=load(root,REL)
    exact_keys(c,TOP_FIELDS,'P8 top')
    require(c['schema_version']=='1.0' and c['status']=='P8_R1_UNBOUND_PROFILE_DESIGN_ONLY'
            and type(c['roadmap_step']) is int and c['roadmap_step']==8
            and c['baseline_commit']==BASE and c['thesis_sha256']==THESIS
            and c['source_sections']==['3.7.5','3.9.2'], 'P8 provenance/status')
    require(c['p7_catalog_path']==P7_REL and c['p7_catalog_sha256']==P7_SHA,
            'P8 P7 source relation')
    require(type(c['p7_family_count']) is int and c['p7_family_count']==25 and
            type(c['profile_slot_count']) is int and c['profile_slot_count']==29 and
            c['count_by_protocol']=={'ssh':8,'ftp':10,'smb':11},'P8 count')
    for field in ('execution_enabled','profile_frozen','physical_isolation_verified',
                  'pilot_limits_frozen'):
        require(c[field] is False,'P8 premature enablement: '+field)
    for field in ('cases_authorized','real_cases'):
        require(type(c[field]) is int and c[field]==0,'P8 unapproved real cases')
    policy=c['policy']
    exact_keys(policy,POLICY_FIELDS,'P8 policy')
    require(policy['status']=='REQUIRED_NOT_DEFINED' and
            policy['dispatch_primitive']=='RUST_STD_PROCESS_COMMAND_ARGV_VECTOR' and
            policy['shells_forbidden']==['sh','bash','dash','zsh','ksh','fish','cmd.exe','powershell.exe'] and
            policy['max_ordinary_attempts']==1 and type(policy['max_ordinary_attempts']) is int and
            policy['extra_attempts']=='PREAUTHORIZED_ONLY_NO_HIDDEN_RETRY' and
            policy['pilot_numeric_limits'] is None and
            policy['pending_binding_fields']==list(BINDING_FIELDS), 'P8 policy or limits altered')
    for field in POLICY_FIELDS:
        if field.startswith('no_') or field.endswith('_required_before_approval') or field in (
            'negative_or_nd_never_authorizes','cleanup_independently_verified',
            'physical_lab_isolation_required_before_approval'):
            require(policy[field] is True,'P8 guard disabled: '+field)
    expected=[]
    p7=load(root,P7_REL)
    for family in p7['families']:
        variants=[None] if family['variants'] is None else list(family['variants']['precedence_by_option'])
        for option in variants:
            prec,clean,pre,sup,accept=from_p7_family(family,option)
            expected.append((family,option,prec,clean,pre,sup,accept))
    require(type(c['profiles']) is list and len(c['profiles'])==len(expected)==29,
            'P8 number of profile slots')
    ids=set()
    for p,(f,v,prec,clean,pre,sup,accept) in zip(c['profiles'],expected):
        exact_keys(p,SLOT_FIELDS,'P8 profile')
        identifier=f['id']+'-'+('BASE' if v is None else v)
        require(type(p['profile_id']) is str and p['profile_id']==identifier and identifier not in ids,
                'P8 invalid/duplicate profile id')
        ids.add(identifier)
        require(p['family_id']==f['id'] and p['protocol']==f['protocol'] and
                p['variant']==v and type(p['precedence']) is int and p['precedence']==prec,
                'P8 source family/variant/precedence mismatch')
        require(p['required_material_parameter_slots']==f['parameter_slots'] and
                p['required_preconditions']==pre and p['required_supports']==sup and
                p['required_acceptance_supports']==accept and p['cleanup']==clean,
                'P8 material/guard/support/cleanup mismatch')
        exact_keys(p['binding'],BINDING_FIELDS,'P8 binding')
        require(all(value is None for value in p['binding'].values()),
                'P8 unknown binary or executable binding unexpectedly authorized')
        require(p['status']=='BLOCKED_UNBOUND_NO_EXECUTION','P8 profile execution enabled')
    trace=load(root,TRACE)
    exact_keys(trace,TRACE_FIELDS,'P8 trace')
    require(trace['schema_version']=='1.0' and trace['roadmap_step']==8 and
            trace['status']=='P8_R1_PROFILE_SLOTS_ONLY_NOT_EXECUTABLE' and
            trace['baseline_commit']==BASE and trace['source_sha256']==THESIS and
            trace['source_sections']==c['source_sections'] and
            trace['p7_catalog_sha256']==P7_SHA and trace['profile_path']==REL and
            trace['profile_sha256']==PROFILE_SHA and
            trace['families']==25 and trace['profile_slots']==29 and
            trace['real_cases']==trace['executables_pinned']==trace['argv_vectors_pinned']==
            trace['authorized_profiles']==0 and
            trace['pilot_limits']=='PENDING' and trace['physical_isolation']=='NOT_VERIFIED' and
            trace['functional_acceptance']=='PENDING' and trace['experimental_validation']=='NOT_RUN' and
            trace['unresolved_obligations']==7 and trace['open_findings']==['AL-06','AL-07'],
            'P8 trace promotion or provenance mismatch')
    for rel in trace['artifacts']:
        require(type(rel) is str and rel.startswith(('lab/','docs/')) and
                not Path(rel).is_absolute() and '..' not in Path(rel).parts and
                (root/rel).is_file() and not (root/rel).is_symlink(),
                'P8 trace artifact missing/unsafe')
    return {'status':'PASS_P8_UNBOUND_PROFILE_SLOTS_ONLY','families':25,'slots':29,
            'pinned_executables':0,'authorized_profiles':0,'real_cases':0,
            'real_execution':'NOT_AUTHORIZED', 'pilot_limits':'PENDING',
            'experimental_validation':'NOT_RUN'}


def preview(root, request):
    """Purely summarize missing bindings. Never resolve paths, secrets, argv or permissions."""
    validate(root)
    exact_keys(request,('profile_id','parameter_refs'),'P8 preview request')
    require(type(request['profile_id']) is str,'P8 invalid requested profile')
    catalog=load(root,REL)
    found=[p for p in catalog['profiles'] if p['profile_id']==request['profile_id']]
    require(len(found)==1,'P8 profile not registered')
    p=found[0]
    slots=request['parameter_refs']
    require(type(slots) is dict and set(slots)==set(p['required_material_parameter_slots']),
            'P8 parameter references mismatch')
    for value in slots.values():
        require(type(value) is str and REF.fullmatch(value) and '..' not in value,
                'P8 symbolic reference required; no raw secrets')
    # Returns NO argv, NO binary path, NO executable object, NO authorization.
    return {'profile_id':p['profile_id'],'status':'BLOCKED_UNBOUND_NO_EXECUTION',
            'missing_binding_fields':list(BINDING_FIELDS),
            'preconditions_value':'ND','dispatch_allowed':False,
            'executable':None,'argv':None,'environment':None,
            'case_authorized':False,'is_experimental_unit':False}


if __name__=='__main__':
    try:
        print(json.dumps(validate(),ensure_ascii=False,sort_keys=True))
        print('ARDREC_POINT8_PROFILE_DESIGN=PASS_29_UNBOUND_SLOTS_NO_EXECUTION')
    except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
        print('ARDREC_POINT8_PROFILE_DESIGN=FAIL: '+str(exc))
        raise SystemExit(1)
