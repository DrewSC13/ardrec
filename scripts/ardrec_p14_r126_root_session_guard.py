#!/usr/bin/env python3
"""R126-B4 immutable root-session guardian: authorize a one-shot DENY timer ONLY.

This independently staged root-owned service is not installed by the source
patch.  It cannot boot VMs, send FTP traffic, or create nft ALLOW rules.
It will refuse all actions unless an external operator stages an immutable
root package, independently signed permits and fresh signed revocations.
The only host-changing action is to invoke pinned R116 --arm-deny once after
all checks pass.  A failure consumes the claim and leaves DENY in force.
"""
from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT=Path('/var/lib/ardrec/r126-ftp-session-guard-v1')
SCRIPT=ROOT/'root-controller.py'
MANIFEST=ROOT/'manifest.json'
GUARD=Path('/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py')
R116_MARKER=GUARD.parent/'arm-consumed.once'
MARKER=ROOT/'attempt-consumed.once'
TRUST=Path('/etc/ardrec/r126-root-session-trust-v1.json')
REVOCATION=Path('/etc/ardrec/r126-root-session-revocation-v1.json')
SCOPE_TRUST=Path('/etc/ardrec/r126-ftp-t01-scope-trust-v2.json')
SCOPE_REV=Path('/etc/ardrec/r126-ftp-t01-scope-revocation-v2.json')
PILOT_TRUST=Path('/etc/ardrec/r115-p7-pilot-trust-v1.json')
PILOT_REV=Path('/etc/ardrec/r115-p7-pilot-revocation-v1.json')
WINDOW_TRUST=Path('/etc/ardrec/r115-p8-trust-v1.json')
WINDOW_REV=Path('/etc/ardrec/r115-p8-revocation-v1.json')
GUARD_PIN='c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
SCHEMA='ARDREC-R126-B4-ROOT-DENY-SESSION-v1'
GRANT_SCHEMA=SCHEMA+'-grant'
REV_SCHEMA=SCHEMA+'-revocation'
TRUST_SCHEMA=SCHEMA+'-trust'
GRANT_PREFIX=(GRANT_SCHEMA+'\0').encode('ascii')
REV_PREFIX=(REV_SCHEMA+'\0').encode('ascii')
SCOPE_AUTH_PREFIX=b'ARDREC-R115-F3-AUTH-V1\x00'
SCOPE_REV_PREFIX=b'ARDREC-R115-F3-REVOCATION-V1\x00'
PILOT_PREFIX=b'ARDREC-R115-F15-P7-PILOT-PERMIT-v1\x00'
PILOT_REV_PREFIX=b'ARDREC-R115-F15-P7-PILOT-REVOCATION-v1\x00'
WINDOW_PREFIX=b'ARDREC-R115-F11-TRAFFIC-WINDOW-v1\x00'
WINDOW_REV_PREFIX=b'ARDREC-R115-F11-P8-REVOCATION-v1\x00'
HEX16=re.compile(r'[0-9a-f]{16}\Z')
HEX40=re.compile(r'[0-9a-f]{40}\Z')
HEX64=re.compile(r'[0-9a-f]{64}\Z')
MAX_BYTES=16384
SYSENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
FILE_NAMES={'manifest.json','root-controller.py','grant.json','contract.json',
            'scope-authorization.json','pilot-permit.json','traffic-window.json'}

class Stop(ValueError):
    """Stable fail-closed error code."""

def need(ok,code):
    if not ok:raise Stop(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(doc):
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),
                       ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def nodup(pairs):
    result={}
    for key,val in pairs:
        need(key not in result,'JSON_DUPLICATE_KEY')
        result[key]=val
    return result

def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES,'JSON_BYTES_INVALID')
    try:
        doc=json.loads(raw,object_pairs_hook=nodup,
                       parse_constant=lambda _:need(False,'NONFINITE_JSON'))
    except (ValueError,UnicodeError,TypeError) as exc:
        raise Stop('JSON_PARSE_INVALID') from exc
    need(type(doc) is dict and raw==canonical(doc),'JSON_NOT_CANONICAL')
    return doc

def exact(doc,fields,code):
    need(type(doc) is dict and set(doc)==set(fields),code)
    return doc

def at(value):
    need(type(value) is str and
         re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',value),
         'TIME_FORMAT_INVALID')
    try: return datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:raise Stop('TIME_VALUE_INVALID') from exc

def current(now):
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None,'CLOCK_INVALID')
    return now.astimezone(timezone.utc)

def safe_read(path,max_bytes=MAX_BYTES):
    need(type(path) is Path and path.is_absolute() and not path.is_symlink(),
         'ROOT_FILE_PATH_UNSAFE')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=max_bytes,
         'ROOT_FILE_METADATA_UNSAFE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        pre=os.fstat(fd)
        need((pre.st_dev,pre.st_ino,pre.st_size,pre.st_uid,pre.st_nlink)==
             (st.st_dev,st.st_ino,st.st_size,st.st_uid,st.st_nlink),
             'ROOT_FILE_RACED')
        raw=os.read(fd,max_bytes+1)
        post=os.fstat(fd)
        need(len(raw)==pre.st_size and
             (post.st_dev,post.st_ino,post.st_size,post.st_mtime_ns)==
             (pre.st_dev,pre.st_ino,pre.st_size,pre.st_mtime_ns),
             'ROOT_FILE_CHANGED')
        return raw
    finally:os.close(fd)

def signer(doc):
    exact(doc,{'key_id','public_key_pem'},'SIGNER_FIELDS')
    need(type(doc['key_id']) is str and
         re.fullmatch(r'[a-zA-Z0-9_.:-]{3,128}',doc['key_id']) and
         type(doc['public_key_pem']) is str and
         32<len(doc['public_key_pem'])<=1024,'SIGNER_INVALID')
    try: pem=doc['public_key_pem'].encode('ascii')
    except UnicodeError as exc:raise Stop('PEM_NOT_ASCII') from exc
    need(pem.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
         pem.endswith(b'-----END PUBLIC KEY-----\n'),'PEM_ENCODING')
    # Require ASN.1 SubjectPublicKeyInfo for Ed25519 (OID 1.3.101.112),
    # never accept a different algorithm even if OpenSSL can verify it.
    lines=pem.splitlines()
    try: der=base64.b64decode(b''.join(lines[1:-1]),validate=True)
    except (binascii.Error,ValueError) as exc:
        raise Stop('PEM_BASE64_INVALID') from exc
    need(len(der)==44 and
         der[:12]==bytes.fromhex('302a300506032b6570032100'),
         'ED25519_SPKI_REQUIRED')
    return pem

def verify(envelope,pub,prefix):
    exact(envelope,{'statement','signer_key_id','signature_b64'},'SIGNED_WRAPPER')
    pem=signer(pub)
    need(envelope['signer_key_id']==pub['key_id'] and
         type(envelope['statement']) is dict and
         type(envelope['signature_b64']) is str,'SIGNER_OR_STATEMENT_MISMATCH')
    try:
        raw=base64.b64decode(envelope['signature_b64'],validate=True)
    except (binascii.Error,ValueError) as exc:raise Stop('SIGNATURE_ENCODING') from exc
    need(len(raw)==64,'ED25519_SIGNATURE_LENGTH')
    # Linux anonymous memory files avoid disk writes and a Python crypto
    # dependency in the root-owned /usr/bin/python3. Exact OpenSSL command,
    # no shell, no caller-controlled path, no inherited unrelated descriptors.
    fds=[]
    try:
        for label,payload in (('ardrec-b4-public',pem),
                              ('ardrec-b4-signature',raw),
                              ('ardrec-b4-signed',prefix+canonical(envelope['statement']))):
            fd=os.memfd_create(label,flags=os.MFD_CLOEXEC)
            fds.append(fd)
            need(os.write(fd,payload)==len(payload),'ANONYMOUS_WRITE_SHORT')
            os.lseek(fd,0,os.SEEK_SET)
        proc=subprocess.run(('/usr/bin/openssl','pkeyutl','-verify','-pubin',
            '-inkey',f'/proc/self/fd/{fds[0]}','-rawin',
            '-in',f'/proc/self/fd/{fds[2]}',
            '-sigfile',f'/proc/self/fd/{fds[1]}'),
            stdin=subprocess.DEVNULL,capture_output=True,check=False,
            timeout=5,env=SYSENV,close_fds=True,pass_fds=tuple(fds))
        need(proc.returncode==0 and len(proc.stdout)<=1024 and
             len(proc.stderr)<=1024,'SIGNATURE_INVALID')
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Stop('ED25519_VERIFIER_UNAVAILABLE') from exc
    finally:
        for fd in fds:os.close(fd)
    return envelope['statement']

def signer_set(root_trust,scope_trust,pilot_trust,window_trust):
    exact(root_trust,{'schema','grant_signer','revocation_signer'},'ROOT_TRUST_FIELDS')
    need(root_trust['schema']==TRUST_SCHEMA,'ROOT_TRUST_SCHEMA')
    exact(scope_trust,{'schema','scope_signer','revocation_signer'},'SCOPE_TRUST_FIELDS')
    exact(pilot_trust,{'schema','pilot_signer','revocation_signer'},'PILOT_TRUST_FIELDS')
    exact(window_trust,{'schema','window_signer','revocation_signer'},'WINDOW_TRUST_FIELDS')
    need(scope_trust['schema']=='ARDREC-R115-F3-EXTERNAL-TRUST-PINS-v1' and
         pilot_trust['schema']=='ARDREC-R115-F15-P7-EXTERNAL-TRUST-v1' and
         window_trust['schema']=='ARDREC-R115-F11-P8-EXTERNAL-TRUST-v1',
         'UPSTREAM_TRUST_SCHEMA_INVALID')
    members=(root_trust['grant_signer'],root_trust['revocation_signer'],
             scope_trust['scope_signer'],scope_trust['revocation_signer'],
             pilot_trust['pilot_signer'],pilot_trust['revocation_signer'],
             window_trust['window_signer'],window_trust['revocation_signer'])
    ids=[x['key_id'] for x in members]
    pins=[sha(signer(x)) for x in members]
    need(len(set(ids))==len(set(pins))==8,'EIGHT_INDEPENDENT_SIGNERS_REQUIRED')

def verify_revocation(rev,pub,prefix,schema,sha_key,expected_sha,id_key,expected_id,now):
    stmt=verify(rev,pub,prefix)
    need(stmt.get('schema')==schema and stmt.get(sha_key)==expected_sha and
         stmt.get(id_key)==expected_id and stmt.get('revoked') is False and
         type(stmt.get('reason_code')) is str,'REVOCATION_NOT_BOUND_OR_REVOKED')
    issued,expires=at(stmt['issued_at']),at(stmt['valid_until'])
    need(issued<=now<expires and 0<=(now-issued).total_seconds()<=30,
         'REVOCATION_NOT_FRESH')
    return stmt

def validate_bundle(documents,*,now,expected_head,boot_id):
    """Pure signed documentary verification; no host mutation or trusted caller flag."""
    now=current(now)
    need(type(expected_head) is str and HEX40.fullmatch(expected_head),
         'APPROVED_HEAD_INVALID')
    root_trust,scope_trust,pilot_trust,window_trust=(documents[k] for k in
               ('root_trust','scope_trust','pilot_trust','window_trust'))
    signer_set(root_trust,scope_trust,pilot_trust,window_trust)
    grant=documents['grant'];rev=documents['root_revocation']
    stmt=verify(grant,root_trust['grant_signer'],GRANT_PREFIX)
    exact(stmt,{'schema','session','head','case_id','target','catalog_sha256',
                'contract_sha256','scope_authorization_sha256','pilot_sha256',
                'window_sha256','budget_sha256','guard_sha256','boot_id',
                'valid_from','valid_until','action','network_traffic_authorized',
                'one_shot','p8'},'GRANT_FIELDS')
    need(stmt['schema']==GRANT_SCHEMA and type(stmt['session']) is str and
         HEX16.fullmatch(stmt['session']) and stmt['head']==expected_head and
         type(stmt['case_id']) is str and 0<len(stmt['case_id'])<=128 and
         stmt['boot_id']==boot_id and stmt['guard_sha256']==GUARD_PIN and
         stmt['action']=='ARM_DENY_BACKUP_ONLY' and
         stmt['network_traffic_authorized'] is False and
         stmt['one_shot'] is True and stmt['p8']=='NO-GO',
         'GRANT_SCOPE_OR_IDENTITY_INVALID')
    need(type(stmt['target']) is dict and
         all(stmt['target'].get(k)==v for k,v in
             {'ip':'10.203.31.2','port':21,
              'vm':'ardrec-r33-dev-ftp',
              'network':'ardrec-r33-dev-net-ftp'}.items()) and
         set(stmt['target']) in ({'ip','port','vm','network'},
                                 {'ip','port','vm','network','mac'}),
         'TARGET_OUTSIDE_ISOLATED_FTP')
    need(all(type(stmt[k]) is str and HEX64.fullmatch(stmt[k]) for k in
             ('catalog_sha256','contract_sha256','scope_authorization_sha256',
              'pilot_sha256','window_sha256','budget_sha256')),
         'GRANT_DIGESTS_INVALID')
    first,last=at(stmt['valid_from']),at(stmt['valid_until'])
    need(first<last and (last-first).total_seconds()<=60 and first<=now<last and
         (last-now).total_seconds()>=46,'GRANT_TIME_BUDGET_TOO_SHORT')
    verify_revocation(rev,root_trust['revocation_signer'],REV_PREFIX,
        REV_SCHEMA,'grant_sha256',sha(canonical(grant)), 'session',stmt['session'],now)
    contract=documents['contract']
    need(type(contract) is dict and contract.get('case_id')==stmt['case_id'] and
         contract.get('source_commit')==stmt['head'] and
         contract.get('catalog_sha256')==stmt['catalog_sha256'] and
         contract.get('target')==stmt['target'] and
         sha(canonical(contract))==stmt['contract_sha256'],
         'CONTRACT_SOURCE_MISMATCH')
    scope=documents['scope_authorization']
    scope_stmt=verify(scope,scope_trust['scope_signer'],SCOPE_AUTH_PREFIX)
    need(sha(canonical(scope))==stmt['scope_authorization_sha256'] and
         scope_stmt.get('schema')=='ARDREC-R115-F3-FTP-T01-AUTHORIZATION-v1' and
         scope_stmt.get('case_id')==stmt['case_id'] and
         scope_stmt.get('target')==stmt['target'] and
         scope_stmt.get('catalog_sha256')==stmt['catalog_sha256'],
         'SCOPE_AUTHORIZATION_MISMATCH')
    verify_revocation(documents['scope_revocation'],scope_trust['revocation_signer'],
        SCOPE_REV_PREFIX,'ARDREC-R115-F3-REVOCATION-REVIEW-v1',
        'authorization_sha256',sha(canonical(scope)),
        'authorization_id',scope_stmt['authorization_id'],now)
    pilot=documents['pilot_permit']
    pilot_stmt=verify(pilot,pilot_trust['pilot_signer'],PILOT_PREFIX)
    need(sha(canonical(pilot))==stmt['pilot_sha256'] and
         pilot_stmt.get('schema')=='ARDREC-R115-F15-FTP-T01-PILOT-PERMIT-v1' and
         pilot_stmt.get('case_id')==stmt['case_id'] and
         pilot_stmt.get('head')==stmt['head'] and
         pilot_stmt.get('target')==stmt['target'] and
         pilot_stmt.get('contract_sha256')==stmt['contract_sha256'] and
         pilot_stmt.get('scope_authorization_sha256')==stmt['scope_authorization_sha256'] and
         pilot_stmt.get('pilot_only_no_production_p8') is True and
         pilot_stmt.get('action')=='ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
         'PILOT_SCOPE_INVALID')
    verify_revocation(documents['pilot_revocation'],pilot_trust['revocation_signer'],
        PILOT_REV_PREFIX,'ARDREC-R115-F15-P7-PILOT-REVOCATION-v1',
        'pilot_sha256',sha(canonical(pilot)),
        'pilot_id',pilot_stmt['pilot_id'],now)
    window=documents['traffic_window']
    window_stmt=verify(window,window_trust['window_signer'],WINDOW_PREFIX)
    need(sha(canonical(window))==stmt['window_sha256'] and
         window_stmt.get('schema')=='ARDREC-R115-F11-FTP-T01-TRAFFIC-WINDOW-v1' and
         window_stmt.get('case_id')==stmt['case_id'] and
         window_stmt.get('head')==stmt['head'] and
         window_stmt.get('target')==stmt['target'] and
         window_stmt.get('contract_sha256')==stmt['contract_sha256'] and
         window_stmt.get('scope_authorization_sha256')==stmt['scope_authorization_sha256'] and
         window_stmt.get('action')=='ONE_FTP_CONTROL_GREETING_READ_ONLY' and
         window_stmt.get('network_traffic_requested') is True,
         'WINDOW_SOURCE_MISMATCH')
    verify_revocation(documents['window_revocation'],window_trust['revocation_signer'],
        WINDOW_REV_PREFIX,'ARDREC-R115-F11-P8-REVOCATION-v1',
        'window_sha256',sha(canonical(window)),
        'window_id',window_stmt['window_id'],now)
    budget=window_stmt['budget']
    need(type(budget) is dict and budget.get('ordinary_attempts')==1 and
         budget.get('additional_attempts')==0 and
         budget.get('max_connections')==1 and
         sha(canonical(budget))==stmt['budget_sha256'],
         'ONE_SHOT_BUDGET_INVALID')
    for kind,policy in ((scope_stmt,contract),(pilot_stmt,contract),(window_stmt,contract)):
        if kind.get('valid_from') is not None and kind.get('valid_until') is not None:
            need(at(kind['valid_from'])<=now<at(kind['valid_until']),
                 'UPSTREAM_PERMIT_EXPIRED')
    need(type(pilot_stmt.get('budget')) is dict and
         all(type(v) is int and v<=pilot_stmt['budget'].get(k,-1)
             for k,v in budget.items()),'WINDOW_EXPANDS_PILOT')
    return {'schema':SCHEMA+'-verified-grant','session':stmt['session'],
            'head':stmt['head'],'case_id':stmt['case_id'],
            'grant_sha256':sha(canonical(grant)),
            'window_sha256':stmt['window_sha256'],
            'scope_sha256':stmt['scope_authorization_sha256'],
            'pilot_sha256':stmt['pilot_sha256'],
            'boot_id':stmt['boot_id'],
            'p8':'NO-GO','network_traffic_authorized':False}

def read_boot_id():
    raw=Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    need(type(raw) is str and re.fullmatch('[0-9a-f-]{36}',raw),
         'BOOT_ID_UNAVAILABLE')
    return raw

def validate_guard_check(doc):
    need(type(doc) is dict and doc.get('schema')==
         'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-check' and
         doc.get('deny')=='MATCH' and doc.get('host_writes')==0 and
         doc.get('p8')=='NO-GO','R116_DENY_CHECK_INVALID')
    states={'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'}
    expected_active=['ftp','runner_ftp','runner_smb','runner_ssh','ssh']
    need(doc.get('states')==states and type(doc.get('policy')) is dict and
         doc['policy'].get('active_count')==5 and
         doc['policy'].get('absent_count')==1 and
         doc['policy'].get('active')==expected_active and
         doc['policy'].get('absent')==['smb'] and
         doc['policy'].get('allow_traffic') is False and
         doc['policy'].get('p8')=='NO-GO',
         'R116_FIVE_ONE_DENY_REQUIRED')
    return doc

def host_run(cmd,timeout=12):
    need(type(cmd) in (list,tuple) and all(type(x) is str for x in cmd) and
         cmd and cmd[0] in ('/usr/bin/python3','/usr/bin/systemctl'),
         'HOST_COMMAND_NOT_ALLOWLISTED')
    try:
        p=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,
                         timeout=timeout,env=SYSENV,check=False,close_fds=True)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Stop('HOST_COMMAND_UNAVAILABLE') from exc
    need(p.returncode==0 and len(p.stdout)<=16384 and len(p.stderr)<=16384,
         'HOST_COMMAND_FAILED_OR_OVERSIZED')
    return p.stdout

def guard_check(run=host_run):
    return validate_guard_check(parse(run(('/usr/bin/python3','-I','-B',
                                           str(GUARD),'--check'))))

def timer_check(session,run=host_run):
    unit='ardrec-r116-f1-deny-'+session
    out=run(('/usr/bin/systemctl','show',unit+'.timer','--no-pager',
             '-p','LoadState','-p','ActiveState','-p','Unit',
             '-p','NextElapseUSecMonotonic'))
    props={}
    for line in out.decode('utf-8','strict').splitlines():
        need('=' in line,'TIMER_PROPERTY_INVALID')
        key,value=line.split('=',1)
        need(key not in props,'TIMER_PROPERTY_DUPLICATE')
        props[key]=value
    need(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active' and
         props.get('Unit')==unit+'.service' and
         props.get('NextElapseUSecMonotonic') not in ('0','','infinity',None),
         'R116_SESSION_TIMER_NOT_ACTIVE')
    return {'unit':unit,'timer_active':True,
            'next_elapse_monotonic':props['NextElapseUSecMonotonic']}

def atomic(root,name,body):
    need(root==ROOT and type(name) is str and
         (name=='attempt-consumed.once' or
          re.fullmatch(r'arm-[0-9a-f]{16}\.json',name)),
         'ROOT_OUTPUT_SCOPE')
    fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(body);out.flush();os.fsync(out.fileno())
    dfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)

def protected_root():
    need(os.geteuid()==0 and Path(__file__).resolve()==SCRIPT,
         'IMMUTABLE_ROOT_STAGING_REQUIRED')
    for folder in (Path('/'),Path('/var'),Path('/var/lib'),Path('/var/lib/ardrec'),
                   ROOT,Path('/etc'),Path('/etc/ardrec')):
        st=folder.lstat()
        need(not folder.is_symlink() and stat.S_ISDIR(st.st_mode) and
             st.st_uid==0 and not(st.st_mode&0o022),'ROOT_PARENT_UNSAFE')
    need(stat.S_IMODE(ROOT.stat().st_mode)==0o700,'ROOT_DIRECTORY_NOT_PRIVATE')
    names={p.name for p in ROOT.iterdir()}
    need(FILE_NAMES<=names and all(n in FILE_NAMES or
         n=='attempt-consumed.once' or
         re.fullmatch(r'arm-[0-9a-f]{16}\.json',n) for n in names),
         'ROOT_BUNDLE_UNEXPECTED_FILES')
    manifest=parse(safe_read(MANIFEST,max_bytes=8192))
    exact(manifest,{'schema','script_sha256','guard_sha256','approved_head',
                    'deny_only','root_install_independent'},'ROOT_MANIFEST_FIELDS')
    need(manifest['schema']==SCHEMA+'-root-bundle' and
         manifest['guard_sha256']==GUARD_PIN and
         manifest['script_sha256']==sha(safe_read(SCRIPT,max_bytes=MAX_BYTES*8)) and
         manifest['root_install_independent'] is True and
         manifest['deny_only'] is True and
         type(manifest['approved_head']) is str and
         HEX40.fullmatch(manifest['approved_head']) and
         sha(safe_read(GUARD,max_bytes=MAX_BYTES*8))==GUARD_PIN,
         'ROOT_MANIFEST_OR_GUARD_DRIFT')
    return manifest

def read_documents():
    paths={'root_trust':TRUST,'scope_trust':SCOPE_TRUST,
           'pilot_trust':PILOT_TRUST,'window_trust':WINDOW_TRUST,
           'root_revocation':REVOCATION,'scope_revocation':SCOPE_REV,
           'pilot_revocation':PILOT_REV,'window_revocation':WINDOW_REV,
           'grant':ROOT/'grant.json','contract':ROOT/'contract.json',
           'scope_authorization':ROOT/'scope-authorization.json',
           'pilot_permit':ROOT/'pilot-permit.json',
           'traffic_window':ROOT/'traffic-window.json'}
    return {k:parse(safe_read(p)) for k,p in paths.items()}

def preflight(manifest,docs,*,now,boot_id,run=host_run):
    verified=validate_bundle(docs,now=now,
             expected_head=manifest['approved_head'],boot_id=boot_id)
    need(not MARKER.exists() and not R116_MARKER.exists(),
         'SESSION_ALREADY_CONSUMED_NO_RETRY')
    guard_check(run)
    return {'schema':SCHEMA+'-readiness','verified_grant_sha256':
            sha(canonical(verified)),'session':verified['session'],
            'root_guard_sha256':GUARD_PIN,'timer_armed':False,
            'deny_readback':'FIVE_ONE_DENY_MATCH',
            'network_traffic_authorized':False,'p8':'NO-GO'}

def arm(manifest,docs,*,now,boot_id,run=host_run,write=atomic,
        clock=time.monotonic_ns,fresh_clock=lambda:datetime.now(timezone.utc)):
    """Actual DENY-only arm, root-staged CLI only, after independent reviews.

    This is the sole host-changing path. It has no traffic-enable primitive.
    It is NOT called by the patch installer nor by the unprivileged CLI.
    """
    ready=preflight(manifest,docs,now=now,boot_id=boot_id,run=run)
    session=ready['session']
    # Do not rely on the clock from the earlier preflight after host I/O.
    fresh=current(fresh_clock())
    validate_bundle(docs,now=fresh,expected_head=manifest['approved_head'],
                    boot_id=boot_id)
    stamped=clock()
    need(type(stamped) is int and stamped>=0,'MONOTONIC_CLOCK_INVALID')
    write(ROOT,'attempt-consumed.once',canonical({
        'schema':SCHEMA+'-claim','session':session,
        'grant_readiness_sha256':sha(canonical(ready)),
        'started_monotonic_ns':stamped,'p8':'NO-GO'}))
    # Failure in this call leaves BOTH stages in DENY and permanently consumes
    # our own marker. No automatic retry, traffic admission, or VM boot.
    data=parse(run(('/usr/bin/python3','-I','-B',str(GUARD),'--arm-deny',session),
                   timeout=15))
    need(data.get('schema')=='ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-arm' and
         data.get('session')==session and data.get('timer_verified') is True and
         data.get('backup_delay_seconds')==45 and
         data.get('duration_seconds')==60 and
         data.get('opens_ports') is False and data.get('p8')=='NO-GO',
         'R116_ARM_RECEIPT_INVALID')
    timer=timer_check(session,run=run)
    receipt={'schema':SCHEMA+'-arm-receipt','session':session,
             'head':manifest['approved_head'],
             'root_readiness_sha256':sha(canonical(ready)),
             'root_guard_arm_sha256':sha(canonical(data)),
             'grant_sha256':sha(canonical(docs['grant'])),
             'boot_id':boot_id,'arm_monotonic_ns':stamped,
             'verified_monotonic_ns':clock(),
             'timer':timer,'network_traffic_authorized':False,
             'physical_window_opened':False,'p8':'NO-GO'}
    need(type(receipt['verified_monotonic_ns']) is int and
         receipt['verified_monotonic_ns']>=stamped and
         receipt['verified_monotonic_ns']-stamped<=15_000_000_000,
         'ARM_READBACK_TOO_SLOW')
    write(ROOT,'arm-'+session+'.json',canonical(receipt))
    return receipt

def capabilities():
    return {'schema':SCHEMA+'-capabilities','root_staging_required':True,
            'requires_eight_independent_ed25519_keys':True,
            'requires_fresh_scope_pilot_window_and_root_revocation':True,
            'requires_exact_five_one_deny':True,'fenced_before_arm':True,
            'r116_autonomous_restore_seconds':45,'deadline_seconds':60,
            'root_action':'ARM_DENY_ONLY','opens_traffic':False,
            'starts_vm':False,'issues_p8':False,'a6':'ND','a9':None,'p8':'NO-GO'}

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--preflight',action='store_true')
    group.add_argument('--arm-deny',action='store_true')
    a=ap.parse_args(argv)
    if a.capabilities:
        print(canonical(capabilities()).decode().strip())
        return 0
    try:
        manifest=protected_root()
        fd=os.open(MANIFEST,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            docs=read_documents()
            now=datetime.now(timezone.utc)
            boot_id=read_boot_id()
            result=(arm(manifest,docs,now=now,boot_id=boot_id)
                    if a.arm_deny else
                    preflight(manifest,docs,now=now,boot_id=boot_id))
        finally:os.close(fd)
        print(canonical(result).decode().strip())
        return 0
    except Exception as exc:
        print(canonical({'schema':SCHEMA+'-refusal',
              'result':'DENY_FAIL_CLOSED_NO_RETRY',
              'reason':type(exc).__name__+':'+str(exc)[:140],
              'p8':'NO-GO'}).decode().strip(),file=sys.stderr)
        return 23

if __name__=='__main__':raise SystemExit(main())
