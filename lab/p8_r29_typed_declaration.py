#!/usr/bin/env python3
"""P8-R29: total, immutable design review for 29 symbolic operation declarations.

This is a *source-only*, deny-only type checker, NOT an argv builder, client,
proof of runtime capability, case authorization, or execution dispatcher.
All public inputs are read from pinned immutable R1/R10/R13/R15 documents.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

PINS = {
    'lab/execution-profiles-v1/profiles.json': 'fe0fae200ac031622d27020b77d38bd18a22e3ffaa0dd0f57ec4e9f01f284ce3',
    'lab/p8-profile-contract-v1/contracts.json': 'f09e92f395928a52e3c826a11aeef8ed13acb07299b322d173cc03fcf55b4f41',
    'lab/p8-cli-grammar-v1/spec.json': 'df9fbfae39526a70f96972074357f0e4144bd3d39f7f771d291e95c23999f4e0',
    'lab/p8-cli-review-gates-v1/gates.json': '90fe31e92366493e97818e2c706c142f91a47eff84446413374fa421169ca716',
}
PROTO_COUNTS = {'ssh': 8, 'ftp': 10, 'smb': 11}
COMMON = {
    'ssh': ('SSH_EXPLICIT_HOST_KEY_ANCHOR', 'SSH_NO_PROXYCOMMAND',
            'SSH_NO_AGENT_FORWARDING', 'SSH_NO_INTERACTIVE_FALLBACK',
            'SSH_NO_HIDDEN_RETRY', 'SSH_NO_DEFAULT_USER_CONFIG'),
    'ftp': ('FTP_NO_PROXY', 'FTP_NO_URL_GLOBBING', 'FTP_NO_REDIRECT',
            'FTP_FIXED_PROTOCOL', 'FTP_PINNED_TLS_POLICY',
            'FTP_PASSIVE_CHANNEL_ONLY', 'FTP_NO_HIDDEN_RETRY'),
    'smb': ('SMB_FIXED_DIALECT', 'SMB_EXPLICIT_PROTECTION',
            'SMB_NO_CONFIG_EXPANSION', 'SMB_NO_C_LANGUAGE_FREEFORM',
            'SMB_FIXED_SHARE', 'SMB_NO_HIDDEN_RETRY'),
}
SURFACE = {'ssh': {'SSH_HANDSHAKE','SSH_AUTHENTICATION','SSH_REMOTE_SHELL_BOUNDARY'},
           'ftp': {'CURL_FTP_FTPS_PROTOCOL'},
           'smb': {'SMBCLIENT_COMMAND_LANGUAGE_BOUNDARY'}}
EXECUTABLE = {'ssh':'/usr/bin/ssh','ftp':'/usr/bin/curl','smb':'/usr/bin/smbclient'}
WRITES = frozenset(('SSH-T07-BASE','FTP-T07-BASE','FTP-T08-WRITE',
                    'SMB-T08-BASE','SMB-T09-WRITE'))
FIELDS = ('executable_absolute_path','executable_sha256','executable_version',
          'argv_typed_vector','working_directory','environment_allowlist',
          'auxiliary_executables','case_authorization_ref','approved_target_ref',
          'fixed_resource_budget','capture_policy_ref','cleanup_receipt_ref')
SYMBOL = re.compile(r'[A-Z][A-Z0-9_]*\Z', re.ASCII)
REF = re.compile(r'[a-z][a-z0-9_]*_ref\Z', re.ASCII)
ID = re.compile(r'(?:SSH|FTP|SMB)-T[0-9]{2}-(?:BASE|CONTROL|DATA|READ|WRITE|SIGNING|ENCRYPTION)\Z', re.ASCII)
REQUEST_KEYS = frozenset(('profile_id','operation_id','material_reference_names',
                          'required_control_atoms','effect_class','cleanup_contract'))

class Denied(ValueError):
    pass


def must(cond: bool, code: str) -> None:
    if not cond:
        raise Denied('P8_R29_FAIL_CLOSED_' + code)


def digest_obj(v: object) -> str:
    return hashlib.sha256((json.dumps(v, ensure_ascii=False, sort_keys=True,
         separators=(',',':'))+'\n').encode('utf-8')).hexdigest()


def valid_symbols(value: object, patt: re.Pattern, code: str, *, allow_empty=False) -> tuple[str,...]:
    must(type(value) is list and len(value) <= 64 and (allow_empty or len(value)>0),code+'_shape')
    must(all(type(v) is str and 0 < len(v) < 128 and patt.fullmatch(v)
             for v in value), code+'_token')
    must(len(set(value))==len(value),code+'_duplicate')
    return tuple(value)


def canonical_ids() -> tuple[str,...]:
    return tuple([f'SSH-T{i:02d}-BASE' for i in range(1,9)] +
        ['FTP-T01-BASE','FTP-T02-CONTROL','FTP-T02-DATA'] +
        [f'FTP-T{i:02d}-BASE' for i in range(3,8)] +
        ['FTP-T08-READ','FTP-T08-WRITE','SMB-T01-BASE','SMB-T02-BASE',
         'SMB-T03-SIGNING','SMB-T03-ENCRYPTION'] +
        [f'SMB-T{i:02d}-BASE' for i in range(4,9)] +
        ['SMB-T09-READ','SMB-T09-WRITE'])


def compile_registry(p8: object, r10: object, r13: object, r15: object) -> tuple[dict,...]:
    """Cross-validate 29 symbolic declarations without accepting material values."""
    must(all(type(v) is dict for v in (p8,r10,r13,r15)), 'sources_type')
    must(p8.get('status')=='P8_R1_UNBOUND_PROFILE_DESIGN_ONLY' and
         p8.get('execution_enabled') is False and
         p8.get('profile_slot_count')==29 and
         p8.get('count_by_protocol')==PROTO_COUNTS and
         p8.get('cases_authorized')==0, 'r1_global_denial')
    must(r10.get('contract_kind')=='DECLARATIVE_PER_FAMILY_SYMBOLIC_ONLY_NOT_RENDERABLE' and
         r10.get('fully_bound_profiles')==0 and r10.get('authorized_cases')==0 and
         r10.get('verified_executable_capabilities')==0 and
         r10.get('dispatch_allowed') is False, 'r10_global_denial')
    must(r13.get('profile_count')==29 and r13.get('approved_cli_options')==0 and
         r13.get('approved_argv_renderers')==0 and r13.get('approved_cli_grammars')==0 and
         r13.get('authorized_cases')==0 and r13.get('dispatch_allowed') is False,
         'r13_global_denial')
    must(r15.get('profile_count')==29 and r15.get('semantic_reviews_completed')==0 and
         r15.get('approved_cli_options')==0 and r15.get('approved_argv_renderers')==0 and
         r15.get('approved_cli_grammars')==0 and r15.get('authorized_cases')==0 and
         r15.get('dispatch_allowed') is False and r15.get('writer_count')==5,
         'r15_global_denial')
    for k in ('shell_process','dynamic_cli_flags','path_lookup','inherited_environment',
              'remote_shell_text','smb_command_language_text','opportunistic_authentication',
              'automatic_retry','operation_dispatch'):
        must(r10.get('global_denials',{}).get(k) is False, 'r10_denial_'+k)
    p8rows=p8.get('profiles'); p10rows=r10.get('profiles')
    p13rows=r13.get('profiles'); p15rows=r15.get('profiles')
    must(all(type(x) is list and len(x)==29 for x in (p8rows,p10rows,p13rows,p15rows)),
         'row_counts')
    ids=canonical_ids()
    must(all(tuple(r.get('profile_id') for r in rows)==ids
             for rows in (p8rows,p10rows,p13rows,p15rows)), 'identity_order')
    must(tuple(p8.get('policy',{}).get('pending_binding_fields',()))==FIELDS,
         'r1_binding_policy')
    must(type(r15.get('required_common_gates')) is list and
         len(r15['required_common_gates'])==9 and
         type(r15.get('required_write_gates')) is list and
         len(r15['required_write_gates'])==2, 'proof_gate_shape')
    rows=[]
    for p,c,g,r in zip(p8rows,p10rows,p13rows,p15rows):
        pid=p['profile_id']; proto=p.get('protocol')
        must(type(pid) is str and ID.fullmatch(pid) is not None and
             proto in PROTO_COUNTS and pid.lower().startswith(proto+'-'), 'protocol_'+pid)
        must(p.get('family_id')==c.get('family_id')==pid.rsplit('-',1)[0] and
             c.get('protocol')==proto and
             c.get('variant')==p.get('variant'), 'family_variant_'+pid)
        must(type(p.get('binding')) is dict and tuple(p['binding'])==FIELDS and
             all(x is None for x in p['binding'].values()) and
             p.get('status')=='BLOCKED_UNBOUND_NO_EXECUTION' and
             c.get('contract_status')=='BLOCKED_UNBOUND_NO_EXECUTION', 'r1_r10_denial_'+pid)
        arg=c.get('argument_contract'); boundary=c.get('execution_boundary')
        must(type(arg) is dict and type(boundary) is dict, 'argument_shape_'+pid)
        refs=valid_symbols(arg.get('material_reference_names'),REF,'material_refs_'+pid)
        must(refs==valid_symbols(p.get('required_material_parameter_slots'),REF,
                               'r1_material_refs_'+pid),'reference_match_'+pid)
        atoms=valid_symbols(arg.get('required_control_atoms'),SYMBOL,'control_atoms_'+pid)
        must(set(COMMON[proto]).issubset(atoms), 'missing_protocol_control_'+pid)
        must(arg.get('representation')=='TYPED_SYMBOLIC_INTENT_NOT_ARGV' and
             arg.get('command_surface') in SURFACE[proto] and
             arg.get('rendered_argv') is None and arg.get('remote_command_ast') is None and
             arg.get('smb_command_ast') is None and
             arg.get('raw_command_strings_allowed') is False, 'no_render_'+pid)
        for key in ('environment','working_directory','auxiliary_pins',
                    'credential_delivery','capture_policy','resource_budget',
                    'private_case_authorization','approved_target',
                    'post_execution_cleanup_receipt'):
            must(boundary.get(key) is None, 'unbound_boundary_'+pid+'_'+key)
        for key in ('isolation_verified','capability_verified',
                    'issuer_and_revocation_verified','runtime_binary_identity_verified',
                    'dispatch_allowed'):
            must(boundary.get(key) is False, 'unverified_boundary_'+pid+'_'+key)
        must(c.get('candidate_binary')==EXECUTABLE[proto] and
             type(c.get('candidate_binary_sha256')) is str and
             re.fullmatch(r'[a-f0-9]{64}',c['candidate_binary_sha256']) is not None,
             'candidate_only_'+pid)
        must(g.get('semantic_operation_id')==c.get('semantic_operation_id')==
             r.get('semantic_operation_id'), 'operation_match_'+pid)
        must(g.get('protocol')==r.get('protocol')==proto.upper() and
             g.get('grammar_status')=='ABSTRACT_TYPED_INTENT_ONLY_NOT_EXECUTABLE' and
             g.get('accepted_cli_options')==[] and g.get('argv_template') is None and
             g.get('remote_command_ast') is None and g.get('smb_command_ast') is None and
             g.get('runtime_permission') is False and g.get('dispatch_allowed') is False,
             'grammar_denial_'+pid)
        must(r.get('status')=='BLOCKED_UNREVIEWED' and
             r.get('case_authorized') is False and
             r.get('cli_grammar_authorized') is False and
             r.get('dispatch_allowed') is False, 'review_denial_'+pid)
        writing=pid in WRITES
        cleanup='VERIFY_THEN_REMOVE_MARKER' if writing else 'NO_MUTATION'
        must(p.get('cleanup')==c.get('cleanup_contract')==g.get('cleanup_contract')==cleanup,
             'cleanup_contract_'+pid)
        must(r.get('effect_class')==g.get('effect_class') and
             (r['effect_class']=='WRITE_MARKER_PENDING_CLEANUP') is writing,
             'effect_class_'+pid)
        pre=valid_symbols(p.get('required_preconditions'),SYMBOL,'preconditions_'+pid)
        supports=valid_symbols(p.get('required_supports'),SYMBOL,'supports_'+pid)
        accept=valid_symbols(p.get('required_acceptance_supports'),SYMBOL,'acceptance_'+pid)
        must(set(accept).issubset(supports), 'accept_subset_'+pid)
        if writing:
            must({'WRITE_FIXTURE_PREPARED','CLEANUP_VERIFIABLE'}<=set(pre) and
                 {'MARKER_CREATED','MARKER_VERIFIED','CLEANUP_CONFIRMED'}<=set(accept),
                 'write_proof_'+pid)
        gates=valid_symbols(r.get('required_evidence_gates'),SYMBOL,'gates_'+pid)
        must(gates==tuple(r15['required_common_gates']+
                  (r15['required_write_gates'] if writing else [])), 'gate_alignment_'+pid)
        risks=valid_symbols(r.get('documented_risks'),SYMBOL,'risks_'+pid)
        must(g.get('effect_class')==r.get('effect_class') and
             g.get('resource_tag')==r.get('resource_tag'), 'resource_alignment_'+pid)
        rows.append({
            'profile_id':pid,'protocol':proto,'operation_id':c['semantic_operation_id'],
            'effect_class':g['effect_class'],'resource_tag':g['resource_tag'],
            'material_reference_names':list(refs),'required_control_atoms':list(atoms),
            'required_preconditions':list(pre),'required_acceptance_supports':list(accept),
            'documentary_evidence_gates':list(gates),'documented_risks':list(risks),
            'cleanup_contract':cleanup,'write_variant':writing,
            'material_fields_unbound':list(FIELDS),
            'authorization':'DENIED','argv_renderable':False,'dispatch_allowed':False,
            'status':'TYPED_SYMBOLIC_DESIGN_VERIFIED_EXECUTION_BLOCKED'
        })
    must(dict(Counter(x['protocol'] for x in rows))==PROTO_COUNTS,'protocol_distribution')
    must(sum(x['write_variant'] for x in rows)==5,'write_distribution')
    must(sum(len(x['documented_risks']) for x in rows)==238,'risk_links')
    must(sum(len(x['documentary_evidence_gates']) for x in rows)==271,'gate_links')
    return tuple(rows)


def review_declaration(registry: object, request: object) -> dict:
    """Check *names only*; never accept values, executable params or authority."""
    must(type(registry) in (tuple,list) and len(registry)==29,'registry_shape')
    must(type(request) is dict and set(request)==REQUEST_KEYS, 'request_keys')
    pid=request.get('profile_id')
    must(type(pid) is str and ID.fullmatch(pid) is not None,'request_id')
    found=next((x for x in registry if x['profile_id']==pid),None)
    must(found is not None,'profile_unknown')
    for key in ('operation_id','effect_class','cleanup_contract'):
        must(type(request[key]) is str and request[key]==found[key],
             'mismatched_'+key)
    for key,patt in (('material_reference_names',REF),('required_control_atoms',SYMBOL)):
        must(valid_symbols(request[key],patt,key)==tuple(found[key]),'mismatched_'+key)
    must(found['dispatch_allowed'] is False and found['argv_renderable'] is False and
         found['authorization']=='DENIED', 'unsafe_registry')
    return {'profile_id':pid,'declaration_matched':True,
            'semantic_operation_id':found['operation_id'],
            'decision':'DENY','reason':'DESIGN_ONLY_NO_MATERIAL_PROOF_OR_CASE_AUTHORITY',
            'approved_profiles':0,'authorized_cases':0,'argv':None,
            'spawn':False,'dispatch_allowed':False}


def summarize(registry: object) -> dict:
    must(type(registry) in (tuple,list) and len(registry)==29,'summary_shape')
    must(tuple(r.get('profile_id') for r in registry)==canonical_ids(), 'summary_identity')
    must(all(r.get('authorization')=='DENIED' and r.get('argv_renderable') is False
             and r.get('dispatch_allowed') is False for r in registry), 'summary_denial')
    return {'status':'PASS_P8_R29_29_TYPED_SYMBOLIC_DESIGNS_DENY_ONLY',
            'profile_count':29,'protocol_counts':dict(PROTO_COUNTS),
            'write_variants_pending_cleanup':5,
            'material_bindings_unbound':348,
            'runtime_proof_gate_instances_unverified':261,
            'documentary_gate_links':271,'documentary_risk_links':238,
            'symbolic_registry_sha256':digest_obj(list(registry)),
            'semantic_declarations_reviewable':29,
            'approved_argv_renderers':0,'runtime_options_approved':0,
            'authorized_cases':0,'approved_profiles':0,'dispatch_allowed':False,
            'p8_closed':False,'p9_started':False,'a1_to_a10_started':False}


def load_sources(root: Path) -> tuple[dict,dict,dict,dict]:
    root=Path(root)
    must(root.is_dir() and not root.is_symlink(),'root_directory')
    result=[]
    for name,expected in PINS.items():
        path=root
        for element in name.split('/'):
            path=path/element
            must(not path.is_symlink(),'source_symlink')
        must(path.is_file() and path.stat().st_size<=2_000_000,'source_size')
        raw=path.read_bytes()
        must(hashlib.sha256(raw).hexdigest()==expected, 'source_drift')
        # Duplicate keys forbidden: rejects ambiguous JSON semantics.
        def object_hook(pairs):
            out={}
            for key,value in pairs:
                must(key not in out,'duplicate_source_key')
                out[key]=value
            return out
        try:
            doc=json.loads(raw,object_pairs_hook=object_hook,
                           parse_constant=lambda _:(_ for _ in ()).throw(Denied('nonfinite')))
        except (ValueError,UnicodeError,RecursionError) as exc:
            raise Denied('P8_R29_FAIL_CLOSED_SOURCE_JSON') from exc
        result.append(doc)
    return tuple(result)


def verify_repository(root: Path) -> tuple[tuple[dict,...],dict]:
    rows=compile_registry(*load_sources(root))
    return rows,summarize(rows)
