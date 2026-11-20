#!/usr/bin/env python3
"""ARDREC R116-F1: root-owned DENY-only 5/1 lifecycle recovery and 60 s timer.

This tool CANNOT create an allow rule, authorize a pilot, open a socket or
start a guest. Source installation does not stage or run it as root. A later,
separately authorized operator must stage the signed and reviewed root bundle.

The restore action uses the already authenticated R113-F6 root bundle as a
strict source of six original DENY bindings and the four-rule bridge DENY.
Its only permitted writes are to restore that DENY, replace previously known
candidate bindings with the original DENY, or record/arm an autonomous timer.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from xml.etree import ElementTree as ET

ROOT = Path('/var/lib/ardrec/r116-f1-five-one-deny-v1')
PREVIOUS = Path('/var/lib/ardrec/r113-six-deny-guard-v1')
HELPER = PREVIOUS/'root-recover.py'
HELPER_SHA = '3a9c2d0e70d7b6b808ee2eaf7382b11715c2e2d8e0f777ff627a1ed084a8bb05'
GUARD = ROOT/'root-guard.py'
MANIFEST = ROOT/'manifest.json'
SCHEMA = 'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1'
MANIFEST_SCHEMA = SCHEMA+'-root-bundle'
DURATION = 60
VM = ('ssh', 'runner', 'ftp', 'smb')
KEYS = ('runner_ssh','ssh','runner_ftp','ftp','runner_smb','smb')
VM_KEYS = {'ssh':('ssh',),'runner':('runner_ssh','runner_ftp','runner_smb'),
           'ftp':('ftp',),'smb':('smb',)}
ALLOWED_RUNNING = (frozenset(), frozenset({'ssh'}),
                   frozenset({'ssh','runner'}),
                   frozenset({'ssh','runner','ftp'}))
VIRSH = ('/usr/bin/virsh','-c','qemu:///system')
NFT = ('/usr/sbin/nft','-j','-a','list','table','bridge','ardrec_r34_guard')
SYSENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
MARKER = 'arm-consumed.once'
MAX_IO = 262144

class Stop(ValueError):
    """Stable stop code for unsafe or unknown lifecycle states."""

def need(ok, code):
    if not ok:
        raise Stop(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

def no_duplicates(pairs):
    result={}
    for k,v in pairs:
        need(k not in result,'DUPLICATE_JSON_KEY')
        result[k]=v
    return result

def json_load(raw):
    need(type(raw) is bytes and len(raw)<MAX_IO, 'JSON_BYTES_INVALID')
    return json.loads(raw, object_pairs_hook=no_duplicates,
                      parse_constant=lambda _:need(False,'NONFINITE_JSON'))

def state(text):
    need(type(text) is bytes and 0<len(text)<256,'VM_STATE_BYTES_INVALID')
    raw=text.decode('utf-8','strict').strip().lower()
    if raw in ('running','ejecutando'):
        return 'RUNNING'
    if raw in ('shut off','apagado'):
        return 'OFF'
    raise Stop('VM_UNEXPECTED_STATE_'+raw[:30])

def lifecycle(states):
    """Exact allowed states, including runner's third NIC on SMB network."""
    need(type(states) is dict and set(states)==set(VM),'VM_SET_INVALID')
    need(all(states[k] in ('RUNNING','OFF') for k in VM),'UNKNOWN_VM_STATE')
    running=frozenset(k for k in VM if states[k]=='RUNNING')
    need(running in ALLOWED_RUNNING,'GUEST_LIFECYCLE_NOT_APPROVED')
    active=frozenset(k for role in running for k in VM_KEYS[role])
    off=frozenset(KEYS)-active
    need(not running or 'smb' not in running,'SMB_TARGET_MUST_BE_OFF')
    need(len(active)+len(off)==6,'BINDING_CARDINALITY')
    return {'running':tuple(sorted(running)), 'active':tuple(sorted(active)),
            'absent':tuple(sorted(off)), 'active_count':len(active),
            'absent_count':len(off), 'allow_traffic':False, 'p8':'NO-GO'}

def safe_file(path, *, max_bytes=MAX_IO):
    need(not path.is_symlink(), 'ROOT_FILE_SYMLINK')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
             and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=max_bytes,
             'ROOT_FILE_OWNER_MODE_SIZE')
        raw=os.read(fd,max_bytes+1)
        need(len(raw)==st.st_size,'ROOT_FILE_CHANGED_DURING_READ')
        return raw
    finally:
        os.close(fd)

def protect_root():
    need(os.geteuid()==0 and Path(__file__).resolve()==GUARD,'ROOT_STAGED_REQUIRED')
    for directory in (ROOT,*ROOT.parents):
        st=directory.lstat()
        need(not directory.is_symlink() and stat.S_ISDIR(st.st_mode) and st.st_uid==0
             and not (st.st_mode & 0o022), 'ROOT_DIRECTORY_NOT_TRUSTED')
    need(stat.S_IMODE(ROOT.stat().st_mode)==0o700,'ROOT_DIRECTORY_MODE')
    names={p.name for p in ROOT.iterdir()}
    need({'root-guard.py','manifest.json'}<=names and
         all(x in {'root-guard.py','manifest.json',MARKER} or
             re.fullmatch(r'(?:arm|restore)-[0-9a-f]{16}\.json',x) for x in names),
         'ROOT_FILE_SET_CHANGED')
    data=json_load(safe_file(MANIFEST,max_bytes=8192))
    need(type(data) is dict and set(data)=={'schema','guard_sha256','helper_sha256',
             'window_seconds','scope','p8','opens_ports'} and
         data['schema']==MANIFEST_SCHEMA and
         data['helper_sha256']==HELPER_SHA and
         type(data['window_seconds']) is int and data['window_seconds']==DURATION and
         data['scope']=='DENY_ONLY_FIVE_ACTIVE_ONE_OFF_LIFECYCLE' and
         data['p8']=='NO-GO' and data['opens_ports'] is False and
         data['guard_sha256']==sha(safe_file(GUARD)),
         'ROOT_MANIFEST_INVALID')
    return data

def historical():
    """Only source of historical original/candidate XML and exact nft DENY."""
    need(sha(safe_file(HELPER))==HELPER_SHA,'HISTORICAL_HELPER_DRIFT')
    spec=importlib.util.spec_from_file_location('ardrec_r116_pinned_r113_root',HELPER)
    need(spec is not None and spec.loader is not None,'HELPER_LOAD_FAILED')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    raw=module.root_bundle()
    need(raw['r34-deny-restore.nft']==module.expected_nft(),'R34_SOURCE_NOT_PINNED')
    return module,raw

def invoke(args, *, payload=None, timeout=12, run=subprocess.run):
    """Fixed, no-shell command execution; exact outputs retained by caller."""
    need(type(args) in (list,tuple) and all(type(x) is str for x in args),
         'COMMAND_ARGUMENTS_INVALID')
    try:
        proc=run(list(args),input=payload,
                 stdin=subprocess.DEVNULL if payload is None else None,
                 capture_output=True,check=False,close_fds=True,timeout=timeout,env=SYSENV)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Stop('HOST_COMMAND_UNAVAILABLE') from exc
    need(type(proc.stdout) is bytes and type(proc.stderr) is bytes and
         len(proc.stdout)<MAX_IO and len(proc.stderr)<32768,
         'HOST_COMMAND_OUTPUT_UNSAFE')
    need(type(proc.returncode) is int and proc.returncode==0,
         'HOST_COMMAND_FAILED_'+args[0].rsplit('/',1)[-1])
    return proc.stdout

def guest_states(*, host=invoke):
    return {role:state(host((*VIRSH,'domstate','ardrec-r33-dev-'+role)))
            for role in VM}

def restore(*, f6, bundle, host=invoke):
    """Atomic DENY FIRST, then reconcile known bindings only. Never open ports.

    For unexpected guest state or missing/different binding the nft DENY remains
    installed and no 'PASS' is emitted. No retries are attempted.
    """
    # Even a failed post-restore read cannot re-open traffic: nft is first.
    host(('/usr/sbin/nft','-f','-'),payload=bundle['r34-deny-restore.nft'])
    f6.verify_nft(host(NFT))
    states=guest_states(host=host)
    policy=lifecycle(states)
    listing=host((*VIRSH,'nwfilter-binding-list'))
    events=['R34_DENY_ATOMIC_RESTORED_FIRST']
    for key in KEYS:
        role,net,tap,mac=f6.ROLES[key]
        exists=f6.present(listing,tap)
        if key in policy['absent']:
            need(not exists,'OFFLINE_BINDING_STILL_PRESENT_'+key)
            events.append(key+':OFFLINE_ABSENT')
            continue
        original=bundle[key+'-original.xml']
        candidate=bundle[key+'-candidate.xml']
        domain=host((*VIRSH,'dumpxml','ardrec-r33-dev-'+role))
        f6.verify_domain(domain,key,original)
        if exists:
            current=host((*VIRSH,'nwfilter-binding-dumpxml',tap))
            if f6.xml_equal(current,original):
                events.append(key+':DENY_MATCH')
                continue
            need(f6.xml_equal(current,candidate),'UNKNOWN_BINDING_'+key)
            # Security invariant: only a pinned candidate may be removed.
            host((*VIRSH,'nwfilter-binding-delete',tap))
            events.append(key+':KNOWN_CANDIDATE_REMOVED')
        else:
            events.append(key+':MISSING_WHILE_RUNNING')
        host((*VIRSH,'nwfilter-binding-create',str(PREVIOUS/(key+'-original.xml'))))
        restored=host((*VIRSH,'nwfilter-binding-dumpxml',tap))
        need(f6.xml_equal(restored,original),'BINDING_NOT_DENY_'+key)
        events.append(key+':DENY_RESTORED')
    # Re-attest after any mutation and reject all unexpected binding names.
    f6.verify_nft(host(NFT))
    new_listing=host((*VIRSH,'nwfilter-binding-list'))
    for key in KEYS:
        role,net,tap,mac=f6.ROLES[key]
        exists=f6.present(new_listing,tap)
        if key in policy['absent']:
            need(not exists,'UNEXPECTED_BINDING_POST_RESTORE_'+key)
        else:
            need(exists,'MISSING_BINDING_POST_RESTORE_'+key)
            need(f6.xml_equal(host((*VIRSH,'nwfilter-binding-dumpxml',tap)),
                              bundle[key+'-original.xml']),
                 'DENY_ATTESTATION_FAILED_'+key)
    return {'schema':SCHEMA+'-restore','status':'DENY_RESTORED',
            'states':states,'policy':policy,'events':events,
            'traffic_allowed':False,'p8':'NO-GO',
            'host_writes':'NFT_DENY_AND_KNOWN_BINDING_RESTORE_ONLY'}

def check_deny(*, f6, bundle, host=invoke):
    f6.verify_nft(host(NFT))
    states=guest_states(host=host)
    policy=lifecycle(states)
    listing=host((*VIRSH,'nwfilter-binding-list'))
    for key in KEYS:
        role,net,tap,mac=f6.ROLES[key]
        exists=f6.present(listing,tap)
        if key in policy['absent']:
            need(not exists,'UNEXPECTED_OFFLINE_BINDING_'+key)
            continue
        need(exists,'REQUIRED_ACTIVE_BINDING_ABSENT_'+key)
        domain=host((*VIRSH,'dumpxml','ardrec-r33-dev-'+role))
        original=bundle[key+'-original.xml']
        f6.verify_domain(domain,key,original)
        need(f6.xml_equal(host((*VIRSH,'nwfilter-binding-dumpxml',tap)),original),
             'ACTIVE_BINDING_IS_NOT_DENY_'+key)
    return {'schema':SCHEMA+'-check','policy':policy,'states':states,
            'deny':'MATCH','host_writes':0,'p8':'NO-GO'}

def exclusive(name,raw):
    need(re.fullmatch(r'(?:arm|restore)-[0-9a-f]{16}\.json',name) is not None or
         name==MARKER, 'UNSAFE_OUTPUT_FILE_NAME')
    fd=os.open(ROOT/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    dirfd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(dirfd)
    finally:os.close(dirfd)

def arm(session, *, f6, bundle, host=invoke):
    """Arm fixed 60s autonomous DENY recovery only, with no traffic admission.

    Reserves once before systemd-run. A failed attempt is consumed and cannot
    be re-armed automatically. Root controller F2 must independently verify
    signed authority and remaining time BEFORE opening a narrowly scoped rule.
    """
    need(re.fullmatch('[0-9a-f]{16}',session) is not None,'SESSION_ID_INVALID')
    need(not (ROOT/MARKER).exists(),'ONE_TIMER_ATTEMPT_ALREADY_CONSUMED')
    report=check_deny(f6=f6,bundle=bundle,host=host)
    need(report['policy']['active_count']==5 and
         report['policy']['absent_count']==1,
         'FIVE_ONE_STAGE_REQUIRED_BEFORE_ARM')
    exclusive(MARKER,canon({'session':session,'arm_attempted':True,
                            'ordinary_p8':'NO-GO'}))
    unit='ardrec-r116-f1-deny-'+session
    host(('/usr/bin/systemd-run','--system','--unit='+unit,
          '--on-active=60s','--timer-property=AccuracySec=1s',
          '--description=ARDREC R116 5-1 DENY only autonomous recovery',
          '/usr/bin/python3',str(GUARD),'--restore-deny'),timeout=15)
    timer=host(('/usr/bin/systemctl','show',unit+'.timer','--no-pager',
                '-p','LoadState','-p','ActiveState','-p','Unit',
                '-p','NextElapseUSecMonotonic'))
    props=dict(x.split('=',1) for x in timer.decode('utf-8').splitlines() if '=' in x)
    need(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active'
         and props.get('Unit')==unit+'.service' and
         props.get('NextElapseUSecMonotonic') not in ('0','','infinity'),
         'AUTONOMOUS_TIMER_NOT_CONFIRMED')
    document={'schema':SCHEMA+'-arm','session':session,'unit':unit,
              'duration_seconds':60,'deny_at_arm':'MATCH',
              'p8':'NO-GO','opens_ports':False,'timer_verified':True}
    exclusive('arm-'+session+'.json',canon(document))
    return document

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--check',action='store_true')
    group.add_argument('--restore-deny',action='store_true')
    group.add_argument('--arm-deny',metavar='16-HEX-SESSION')
    args=ap.parse_args(argv)
    os.umask(0o077)
    if args.capabilities:
        print(canon({'schema':SCHEMA+'-capabilities',
                     'root_staging_required':True,'opens_socket':False,
                     'permits_traffic':False,'guest_starts':False,
                     'restore_deny':True,'five_one_lifecycle':True,
                     'autonomous_timer_seconds':60,'p8':'NO-GO'}).decode().strip())
        return 0
    try:
        protect_root()
        f6,raw=historical()
        fd=os.open(MANIFEST,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if args.check:result=check_deny(f6=f6,bundle=raw)
            elif args.restore_deny:
                result=restore(f6=f6,bundle=raw)
                # Receipt is best-effort and must not mask a completed deny restore.
                try:
                    session=sha(canon(result))[:16]
                    exclusive('restore-'+session+'.json',canon(result))
                except (OSError,Stop):pass
            else:result=arm(args.arm_deny,f6=f6,bundle=raw)
        finally:
            os.close(fd)
        print(canon(result).decode().strip(),flush=True)
        return 0
    except Exception as exc:
        print(canon({'result':'STOP_DENY_REVIEW_REQUIRED',
                     'error':type(exc).__name__+':'+str(exc)[:170],
                     'p8':'NO-GO'}).decode().strip(),file=sys.stderr,flush=True)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
