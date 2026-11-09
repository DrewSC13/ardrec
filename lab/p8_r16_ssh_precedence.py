#!/usr/bin/env python3
"""ARDREC P8-R16-R6: pure synthetic SSH config model, denied by design.

Source: authenticated P8-R16-R5 model (source SHA-256
530cc38146f5bbbb2a1a7f996c1f34c885e1e031fcf48520e1ace8e75bf8d343).
No executable grammar, real ssh_config parser, ssh invocation, VM, or dispatch.
This file intentionally has no operational main() or subprocess/network imports.
"""
from __future__ import annotations
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAIN = '4453c98720ba9ee86bcdf9909b71829f15b05dfa'


R4_SHA = 'c2dbfcb7ab667008cb35c7432be883e3cb68b123fb5b1329216a7d012b2697ee'


RULES_SHA = '406cfeaf7fbd677235a520a56c4d324792b58996b9f1e8fe007f92798ba6fd5f'


FIXTURE_SCOPE = 'P8_R16_R5_SYNTHETIC_ONLY_NOT_OPENSSH_CONFIG'


BASELINE_PROFILE = 'SSH-T01-BASE'


TARGET_REF = 'SIM_TGT_A'


ENUM = {
 'stricthostkeychecking': {'yes','ask','accept-new','no'},
 'batchmode': {'yes','no'},
 'canonicalizehostname': {'no','yes','always'},
 'proxyjump': {'none','SIM_JUMP_A'},
 'proxycommand': {'none','SIM_UNSAFE_EXTERNAL'},
 'knownhostscommand': {'none','SIM_UNSAFE_EXTERNAL'},
 'controlmaster': {'no','yes','auto'},
 'controlpath': {'none','REF_SOCKET_A'},
 'controlpersist': {'no','yes','0','60'},
 'updatehostkeys': {'no','yes','ask'},
 'checkhostip': {'no','yes'},
 'verifyhostkeydns': {'no','ask','yes'},
 'identitiesonly': {'yes','no'},
 'identityagent': {'none','REF_AGENT_A'},
 'addkeystoagent': {'no','yes','ask'},
 'permitlocalcommand': {'no','yes'},
 'forwardagent': {'no','yes'},
 'sessiontype': {'none','subsystem','default'},
 'requesttty': {'no','yes','force','auto'},
 'clearallforwardings': {'yes','no'},
 'escapechar': {'none','~'},
 'connectionattempts': {'1','2','3'},
 'connecttimeout': {'5','15','30'},
 'serveraliveinterval': {'0','15','300'},
 'serveralivecountmax': {'1','3'},
 'hostname': {TARGET_REF, 'SIM_OTHER'},
 'port': {'22','2222'},
 'userknownhostsfile': {'REF_TRUST_A','none'},
 'globalknownhostsfile': {'REF_TRUST_G','none'},
 'identityfile': {'REF_KEY_A','REF_KEY_B'},
 'certificatefile': {'REF_CERT_A','REF_CERT_B'},
}


ADDITIVE = frozenset({'identityfile','certificatefile'})


POLICY = {
 'stricthostkeychecking':'yes', 'batchmode':'yes',
 'canonicalizehostname':'no', 'proxyjump':'none', 'proxycommand':'none',
 'knownhostscommand':'none', 'controlmaster':'no', 'controlpath':'none',
 'controlpersist':'no', 'updatehostkeys':'no', 'checkhostip':'no',
 'verifyhostkeydns':'no', 'identitiesonly':'yes', 'identityagent':'none',
 'addkeystoagent':'no', 'permitlocalcommand':'no', 'forwardagent':'no',
 'sessiontype':'none', 'requesttty':'no', 'clearallforwardings':'yes',
 'escapechar':'none', 'connectionattempts':'1', 'connecttimeout':'15',
 'serveraliveinterval':'0', 'serveralivecountmax':'3',
 'hostname':TARGET_REF, 'port':'2222',
 'userknownhostsfile':'REF_TRUST_A', 'globalknownhostsfile':'REF_TRUST_G',
}


DENIALS = {
 'approved_cli_options':0, 'approved_cli_grammars':0,
 'runnable_argv_renderers':0, 'authorized_profiles':0, 'authorized_cases':0,
 'complete_semantic_reviews':0, 'dispatch_allowed':False,
 'configuration_effective_verified':False, 'guest_binaries_executed':False,
 'physical_laboratory_contact':False,
}


class ModelError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise ModelError('P8_R16_R5_FAIL_CLOSED:' + code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def exact(obj, names, label):
    need(type(obj) is dict and set(obj) == set(names), 'fields:' + label)


def deny(obj, label):
    for key, expected in DENIALS.items():
        need(key in obj and type(obj[key]) is type(expected) and obj[key] == expected,
             'deny:' + label + ':' + key)


def bounded_private(path, expected, max_bytes=500_000, is_private=True):
    """Reject symlinks, directories, FIFOs, excessive size, drift, relaxed modes."""
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) |
                     getattr(os,'O_NONBLOCK',0))
    except OSError as e:
        raise ModelError('P8_R16_R5_FAIL_CLOSED:open:' + path.name) from e
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode), 'not_regular:' + path.name)
        if is_private:
            need(stat.S_IMODE(st.st_mode) == 0o600, 'permissions:' + path.name)
        need(0 < st.st_size <= max_bytes, 'size:' + path.name)
        with os.fdopen(fd,'rb',closefd=False) as f:
            raw = f.read(max_bytes+1)
        need(len(raw) == st.st_size and len(raw) <= max_bytes,
             'read_size:' + path.name)
        need(sha(raw) == expected, 'hash:' + path.name)
        return raw
    finally:
        os.close(fd)


def read_json(raw):
    try:
        return json.loads(raw.decode('utf-8'))
    except (UnicodeError,ValueError) as e:
        raise ModelError('P8_R16_R5_FAIL_CLOSED:invalid_json') from e


def validate_r4(doc):
    need(type(doc) is dict and doc.get('scope') ==
         'P8_R16_R4_DOCUMENTARY_SEMANTIC_REVIEW_NO_RUNTIME', 'r4_scope')
    need(doc.get('base_main_commit') == MAIN and
         doc.get('source_entries') == 25 and
         doc.get('source_cross_references') == 17 and
         doc.get('configuration_effective_verified') is False,
         'r4_identity')
    need(type(doc.get('documentary_interpretations')) is list and
         len(doc['documentary_interpretations']) == 25 and
         type(doc.get('cross_option_dependencies')) is list and
         len(doc['cross_option_dependencies']) == 17, 'r4_counts')
    deny(doc, 'r4')
    return True


def validate_fixture(f):
    exact(f, {'schema_version','scope','base_main_commit','source_r4_sha256',
              'profile_id','target_ref','cases'} | set(DENIALS), 'fixture')
    need(f['schema_version']=='1.0' and f['scope']==FIXTURE_SCOPE and
         f['base_main_commit']==MAIN and f['source_r4_sha256']==R4_SHA and
         f['profile_id']==BASELINE_PROFILE and f['target_ref']==TARGET_REF,
         'fixture_header')
    deny(f, 'fixture')
    need(type(f['cases']) is list and 6 <= len(f['cases']) <= 16, 'cases_count')
    names=[]
    for c in f['cases']:
        exact(c,{'id','layers','expected'},'case')
        need(type(c['id']) is str and re.fullmatch(r'SYN_[A-Z0-9_]{2,35}',c['id']), 'case_id')
        names.append(c['id'])
        exact(c['layers'],{'cli','user','system'},'layers')
        need(type(c['layers']['cli']) is list, 'cli_type')
        for item in c['layers']['cli']:
            validate_directive(item)
        need(len(c['layers']['cli']) <= 40, 'cli_count')
        for layer in ('user','system'):
            sections=c['layers'][layer]
            need(type(sections) is list and len(sections)<=16,'sections:'+layer)
            for block in sections:
                exact(block,{'patterns','directives'},'block')
                validate_patterns(block['patterns'])
                need(type(block['directives']) is list and len(block['directives'])<=40,'directives_count')
                for item in block['directives']:
                    validate_directive(item)
        exact(c['expected'],{'status','first_wins','additive_identities','violations'},'expected')
        need(c['expected']['status']=='BLOCKED_MODEL_ONLY' and
             type(c['expected']['violations']) is list and
             all(type(x) is str for x in c['expected']['violations']) and
             c['expected']['violations']==sorted(set(c['expected']['violations'])),
             'expected_violations')
        need(type(c['expected']['first_wins']) is dict and
             type(c['expected']['additive_identities']) is list, 'expected_types')
    need(len(set(names)) == len(names), 'duplicate_case')


def validate_patterns(patterns):
    need(type(patterns) is list and 1<=len(patterns)<=5, 'patterns_count')
    for p in patterns:
        need(type(p) is str and (p=='*' or re.fullmatch(r'!?SIM_[A-Z0-9_*?]{1,32}',p)),
             'pattern_domain')


def validate_directive(d):
    exact(d,{'name','value'},'directive')
    name,val=d['name'],d['value']
    need(type(name) is str and type(val) is str,'directive_types')
    # Case-insensitive directive names, matching ssh_config convention.
    name=name.lower()
    need(name in ENUM, 'unsupported_directive:'+name)
    need(val in ENUM[name], 'invalid_symbolic_value:'+name)
    return name,val


def host_match(patterns, target):
    target=target.lower()
    if any(fnmatch.fnmatchcase(target,p[1:].lower()) for p in patterns if p.startswith('!')):
        return False
    return any(fnmatch.fnmatchcase(target,p.lower()) for p in patterns if not p.startswith('!'))


def simulate(c):
    """Models only a tiny subset: priority CLI > user > system, first wins,
    additive IdentityFile/CertificateFile, restricted Host matching.
    No Include, Match, variable expansion or real SSH parsing.
    """
    values={}
    additive={k:[] for k in ADDITIVE}
    trace=[]
    seq=[]
    for i,d in enumerate(c['layers']['cli']):
        seq.append(('CLI',i,d))
    for layer in ('user','system'):
        for bi,block in enumerate(c['layers'][layer]):
            if host_match(block['patterns'],TARGET_REF):
                for di,d in enumerate(block['directives']):
                    seq.append((layer.upper(),f'{bi}:{di}',d))
    for layer,index,d in seq:
        name,val=validate_directive(d)
        origin=f'{layer}/{index}'
        if name in ADDITIVE:
            additive[name].append({'symbolic_ref':val,'origin':origin})
            trace.append({'option':name,'origin':origin,'resolution':'ADDITIVE_SYMBOLIC_ONLY'})
        elif name not in values:
            values[name]={'value':val,'origin':origin}
            trace.append({'option':name,'origin':origin,'resolution':'FIRST_VALUE'})
        else:
            trace.append({'option':name,'origin':origin,'resolution':'IGNORED_LATER_VALUE'})
    violations=[]
    for key,required in POLICY.items():
        if key not in values:
            violations.append('REQUIRED_EXPLICIT_MISSING:'+key)
        elif values[key]['value'] != required:
            violations.append('POLICY_MISMATCH:'+key)
    # Derived defaults only describe the pinned Debian documentation; they are
    # NOT used to satisfy any explicitly required configuration directive.
    derived=[]
    if 'serveraliveinterval' not in values and values.get('batchmode',{}).get('value')=='yes':
        derived.append('DEBIAN_DOCUMENTED_BATCHMODE_SERVERALIVE_300_NOT_RUNTIME_ATTESTED')
    if not additive['identityfile']:
        violations.append('NO_SYMBOLIC_IDENTITY_REFERENCE')
    # Even an apparently complete *synthetic* configuration is not a trusted
    # target/key/permission/runtime witness. These remain unconditionally absent.
    obligations=['AUTHENTICATED_EFFECTIVE_CONFIG_FROM_PINNED_GUEST_BINARY',
                 'COMPLETE_CONFIG_SOURCE_CLOSURE_AND_PRECEDENCE',
                 'TARGET_AND_TRUST_MATERIAL_BINDING',
                 'RUNTIME_DEPENDENCIES_AND_ENVIRONMENT',
                 'EXTERNAL_OPERATION_DEADLINE_AND_AUTHORIZATION']
    return {'case_id':c['id'],'status':'BLOCKED_MODEL_ONLY',
            'first_value_projection':values,
            'additive_identity_projection':additive['identityfile'],
            'additive_certificate_projection':additive['certificatefile'],
            'trace':trace,'violations':sorted(violations),'documented_derived_defaults':derived,
            'missing_operational_proofs':obligations,
            'configuration_effective_verified':False,
            'runnable_argv':None,'dispatch_allowed':False}


def test_oracles(f):
    """Frozen per-scenario expectations are independent of the projection code."""
    results=[]
    for c in f['cases']:
        r=simulate(c)
        exp=c['expected']
        got={k:v['value'] for k,v in r['first_value_projection'].items() if k in exp['first_wins']}
        need(got==exp['first_wins'],'oracle_first_value:'+c['id'])
        need([x['symbolic_ref'] for x in r['additive_identity_projection']]==
             exp['additive_identities'],'oracle_additive:'+c['id'])
        need(r['violations']==exp['violations'],'oracle_violations:'+c['id'])
        results.append(r)
    return results


def build_report(r4,f):
    validate_r4(r4)
    validate_fixture(f)
    cases=test_oracles(f)
    return {'schema_version':'1.0','scope':FIXTURE_SCOPE,
            'base_main_commit':MAIN,'r4_source_sha256':R4_SHA,
            'fixture_sha256':RULES_SHA,'profile_id':BASELINE_PROFILE,
            'target_ref':TARGET_REF,'simulated_cases':len(cases),
            'model_scope':'STRICT_SYNTHETIC_JSON_NOT_REAL_SSH_CONFIG',
            'precedence_model':'CLI_BEFORE_USER_BEFORE_SYSTEM_FIRST_VALUE',
            'additive_model':'IDENTITYFILE_AND_CERTIFICATEFILE_APPEND',
            'no_include_match_or_runtime_parser':True,
            'cases':cases,
            **DENIALS,
            'limitation':'Pure model of bounded symbolic examples: no SSH runtime, real parser, real target, config provenance, credential material, argv, sandbox dispatch, or complete semantic approval.'}


def write_once(path, data):
    need(path.parent.is_dir() and not path.parent.is_symlink(),'output_directory')
    try:
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|
                   getattr(os,'O_NOFOLLOW',0),0o600)
    except OSError as e:
        raise ModelError('P8_R16_R5_FAIL_CLOSED:output_exists_or_unwritable') from e
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    try:
        dfd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(dfd)
        finally:os.close(dfd)
    except OSError: # A failed directory fsync must not be called durable.
        raise ModelError('P8_R16_R5_FAIL_CLOSED:directory_fsync')
    return sha(data)
