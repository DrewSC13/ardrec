#!/usr/bin/env python3
"""ARDREC R117-F2: one-shot 45s physical DENY-only attestation at 0/6.

Modes: --inspect (read-only), --run (one explicit timer/real nft DENY reapply),
--finalize (verify existing attempt, NEVER schedule a new attempt).

No 5/1 proof, permissive-policy recovery proof, guest starts, FTP, or authority.
Only '--run' may create the immutable attempt, arm systemd and later restore
already-DENY firewall state through signed F1. The proof relies on the
systemd monotonic ExecMainStart/Exit timestamps, not polling latency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/var/lib/ardrec')
F1 = ROOT / 'r116-f1-five-one-deny-v1'
F3 = ROOT / 'r116-f3-ftp-pilot-root-v1'
ARCHIVE = ROOT / 'r117-f1-root-f12-migration-v1/capture-pv19gree'
F11 = ROOT / 'r116-f11-deny-idempotent-60s-v1/result.json'
R114 = ROOT / 'r114-f5-ftp-t01-root-v1'
BASE = ROOT / 'r117-f2-deny45-idempotent-v1'
SOURCE = 'scripts/ardrec_p14_r117_f2_deny_45s_verification.py'
BRANCH = 'feat/p14-r117-piloto-real-a5-a10'
PREVIOUS_HEAD = '81b1ed51d1a6a130d70b7790c34feec9d1a1d8af'
F1_SHA = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
F3_SHA = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
F11_SHA = 'f0edb262a81c8a0581b63df3d388836751136cad5b666be5c5326efa1232a122'
R114_RECEIPT_SHA = 'e80e6f33d7a82ac6e3c76bb70a262d0e65d2b4be0a7feb3558d0d2cd0711a742'
ARCHIVED_F1_RECEIPT_SHA = 'be34354d31c4656dbeb7c447cab42f52b0ee631df5c4e6347d9986c4297e3ec7'
ARCHIVED_RECEIPT = 'restore-be34354d31c4656d.json'
SCHEMA = 'ARDREC-R117-F2-DENY45-ONE-SHOT-0-6-v1'
ENV = {'PATH':'/usr/sbin:/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C', 'PYTHONDONTWRITEBYTECODE':'1'}
MAX = 262144

class Stop(RuntimeError):
    pass

def need(ok, reason):
    if not ok:
        raise Stop(reason)

def emit(key, value):
    print('R117_F2_'+key+'='+str(value), flush=True)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

def strict_obj(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            need(k not in value, 'DUPLICATE_JSON_KEY')
            value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda x: (_ for _ in ()).throw(Stop('NONFINITE_JSON')))

def directory(path, mode=None):
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0
         and not path.is_symlink() and not (st.st_mode & 0o022),
         'UNTRUSTED_ROOT_DIRECTORY_'+str(path))
    if mode is not None:
        need(stat.S_IMODE(st.st_mode) == mode, 'WRONG_ROOT_DIR_MODE_'+str(path))

def root_file(path, *, limit=MAX):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
             and stat.S_IMODE(st.st_mode) == 0o600 and 0 < st.st_size <= limit,
             'UNTRUSTED_ROOT_FILE_'+str(path))
        data = os.read(fd, limit+1)
        need(len(data) == st.st_size, 'ROOT_FILE_READ_DRIFT')
        return data
    finally:
        os.close(fd)

def command(args, *, timeout=20, allow_incomplete=False):
    need(type(args) is list and args and all(type(x) is str for x in args),
         'COMMAND_ARGS_INVALID')
    proc = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=timeout, check=False, close_fds=True, env=ENV)
    need(len(proc.stdout) < MAX and len(proc.stderr) < 32768,
         'COMMAND_OUTPUT_TOO_LARGE')
    if not allow_incomplete:
        need(proc.returncode == 0, 'COMMAND_FAILED_'+Path(args[0]).name+
             '_'+proc.stderr[:100].decode('utf-8','replace'))
    return proc

def git(*args):
    return command(['/usr/bin/git','-c','safe.directory='+str(REPO),
                    '-C',str(REPO),*args],timeout=25).stdout

def get_props(unit):
    data=command(['/usr/bin/systemctl','show',unit,'--no-pager',
                  '-p','LoadState','-p','ActiveState','-p','SubState','-p','Result',
                  '-p','ExecMainStatus','-p','ExecMainStartTimestampMonotonic',
                  '-p','ExecMainExitTimestampMonotonic']).stdout
    return dict(line.split('=',1) for line in data.decode('utf8','strict').splitlines()
                if '=' in line)

def validate_timing(armed, start_us, end_us):
    """Validate systemd CLOCK_MONOTONIC microsecond readings independently of polling."""
    need(type(armed) in (int,float) and type(armed) is not bool and armed > 0,
         'ARMED_TIME_INVALID')
    need(type(start_us) is int and type(end_us) is int and start_us > 0 and end_us > 0,
         'SYSTEMD_MONOTONIC_MISSING')
    start, end = start_us / 1_000_000, end_us / 1_000_000
    need(end >= start >= armed, 'MONOTONIC_ORDER_INVALID')
    start_delta, end_delta = start-armed, end-armed
    return {'start_seconds':round(start_delta,3),
            'restore_exit_seconds':round(end_delta,3),
            'duration_seconds':round(end-start,3),
            'within_60s':end_delta <= 60.0,
            'not_before_40s':start_delta >= 40.0}

def timing_assessment(armed, props):
    """Never claim bounded restoration if systemd monotonic evidence is absent."""
    try:
        timing=validate_timing(armed,
            int(props.get('ExecMainStartTimestampMonotonic','0')),
            int(props.get('ExecMainExitTimestampMonotonic','0')))
    except (Stop, ValueError, TypeError):
        return 'NO_GO_MONOTONIC_NOT_ATTESTED', {'attestation':'UNAVAILABLE'}
    status=('PASS_45S_DENY_ZERO_OF_SIX'
            if timing['within_60s'] and timing['not_before_40s']
            else 'NO_GO_TIMING_NOT_WITHIN_40_TO_60S')
    return status,timing

def fixed_source_preflight():
    need(os.geteuid()==0, 'ROOT_REQUIRED')
    for p in (Path('/'),Path('/var'),Path('/var/lib'),ROOT):directory(p)
    need(REPO.is_dir() and not REPO.is_symlink(), 'WRONG_REPO')
    need(git('branch','--show-current').strip()==BRANCH.encode(),'WRONG_BRANCH')
    need(git('status','--porcelain=v1','--untracked-files=all')==b'', 'DIRTY_WORKTREE')
    need(git('log','-1','--format=%G?').strip()==b'G','SOURCE_NOT_SIGNED')
    git('merge-base','--is-ancestor',PREVIOUS_HEAD,'HEAD')
    head=git('rev-parse','HEAD').decode().strip()
    need(re.fullmatch('[0-9a-f]{40}',head),'HEAD_INVALID')
    own=Path(__file__)
    need(not own.is_symlink() and own.resolve()==REPO/SOURCE and
         root_source_ok(own.read_bytes(),git('show','HEAD:'+SOURCE)),
         'F2_SIGNED_SCRIPT_NOT_PINNED')
    return head

def root_source_ok(actual, committed):
    return actual == committed and 0 < len(actual) < 100000

def physical_preflight(mode):
    head=fixed_source_preflight()
    for d in (F1,F3, F3/'authority',ARCHIVE,
              ARCHIVE/'previous-f8-f1',ARCHIVE/'previous-f8-f3',R114):
        directory(d,0o700)
    need(digest(root_file(F1/'root-guard.py'))==F1_SHA,'F12_F1_SOURCE_DRIFT')
    need(digest(root_file(F3/'root-pilot.py'))==F3_SHA,'F12_F3_SOURCE_DRIFT')
    # Verify manifest source-lock and all 33 files, not merely the root executable.
    lock=strict_obj(git('show','HEAD:lab/operational-controller/r116-f3-root-source-lock-v1.json'))
    manifest=strict_obj(root_file(F3/'manifest.json',limit=16384))
    need(manifest.get('head')==PREVIOUS_HEAD and
         manifest.get('source_sha256')==lock.get('files') and
         manifest.get('catalog_sha256')==lock.get('catalog_sha256') and
         manifest.get('p8')=='NO-GO' and
         manifest.get('window_seconds')==60 and
         manifest.get('network_automatic') is False,
         'F3_ROOT_MANIFEST_DRIFT')
    l=lock.get('files',{})
    need(type(l) is dict and len(l)==33 and l.get('root-pilot.py')==F3_SHA,
         'ROOT_F3_SOURCE_LOCK_COUNT')
    for name, expected in l.items():
        need(re.fullmatch(r'(root-pilot\.py|runtime/ardrec/(?:coordination|evidence)/[a-z0-9_]+\.py)',name) is not None and
             type(expected) is str and re.fullmatch('[0-9a-f]{64}',expected) is not None,
             'ROOT_F3_SOURCE_LIST_UNSAFE')
        need(digest(root_file(F3/name))==expected,'ROOT_F3_SOURCE_DRIFT_'+name)
    need(not any((F3/'authority').iterdir()),'EXTERNAL_AUTHORITY_PRESENT')
    need(not (F1/'arm-consumed.once').exists() and
         not (F3/'pilot-attempted.once').exists(), 'REAL_ATTEMPT_MARKER_PRESENT')
    need(digest(root_file(F11))==F11_SHA,'F11_EVIDENCE_DRIFT')
    need(digest(root_file(ARCHIVE/'previous-f8-f1'/ARCHIVED_RECEIPT))==ARCHIVED_F1_RECEIPT_SHA,
         'F11_ARCHIVED_RESTORE_DRIFT')
    need(digest(root_file(R114/'window-46ebd6a6'/'receipt.json',limit=524288))==R114_RECEIPT_SHA,
         'R114_HISTORICAL_EVIDENCE_DRIFT')
    migration=strict_obj(root_file(ARCHIVE/'result.json'))
    need(migration.get('result')=='PASS' and migration.get('source_head')==PREVIOUS_HEAD
         and migration.get('f3_sources')==33 and migration.get('old_preserved') is True
         and migration.get('nft_changes')==0 and migration.get('guest_starts')==0 and
         migration.get('network_connections')==0 and migration.get('p8')=='NO-GO',
         'R117_F1_MIGRATION_RECORD_DRIFT')
    f1_manifest=strict_obj(root_file(F1/'manifest.json',limit=8192))
    need(f1_manifest.get('guard_sha256')==F1_SHA and
         f1_manifest.get('window_seconds')==60 and
         f1_manifest.get('p8')=='NO-GO' and f1_manifest.get('opens_ports') is False,
         'F1_MANIFEST_INVALID')
    f1_names={p.name for p in F1.iterdir()}
    need('arm-consumed.once' not in f1_names,'F1_ARM_CONSUMED')
    if mode == '--run' or mode == '--inspect':
        need(f1_names=={'root-guard.py','manifest.json'},'F1_UNEXPECTED_ROOT_RECEIPT_BEFORE_TIMER')
    else:
        need({'root-guard.py','manifest.json'} <= f1_names and
             all(x in {'root-guard.py','manifest.json'} or
                 re.fullmatch(r'restore-[0-9a-f]{16}\.json',x) for x in f1_names),
             'F1_ROOT_SCOPE_DRIFT_AFTER_TIMER')
    # Read-only guest and firewall assertion using actual deployed root guard.
    report=strict_obj(command(['/usr/bin/python3','-I','-B',str(F1/'root-guard.py'),'--check'],
                              timeout=40).stdout)
    need(report.get('deny')=='MATCH' and report.get('host_writes')==0 and
         report.get('p8')=='NO-GO' and
         report.get('states')=={'ssh':'OFF','runner':'OFF','ftp':'OFF','smb':'OFF'} and
         report.get('policy',{}).get('active_count')==0 and
         report.get('policy',{}).get('absent_count')==6,
         'HOST_NOT_DENY_0_6')
    timers=command(['/usr/bin/systemctl','list-timers','--all','--no-legend','--no-pager']).stdout
    for line in timers.decode('utf-8','replace').splitlines():
        if ('ardrec-r116-f1-deny-' in line or 'ardrec-r116-f3-' in line or
            'ardrec-r117-' in line):
            if mode=='--finalize' and BASE.exists() and 'ardrec-r117-f2-deny-' in line:
                continue
            # Historical *inactive* units appear in --all. Only ones marked pending matter.
            if not re.search(r'^\s*n/a\s',line,re.I):
                raise Stop('OTHER_LIVE_ARDREC_TIMER_PRESENT')
    emit('SOURCE','PASS_SIGNED_F2_AND_PINNED_F12_F1_F3_33')
    emit('SOURCE_HEAD',head)
    emit('R117_F1_ARCHIVE','PASS_F8_RECEIPT_PRESERVED')
    emit('R114_HISTORY','PASS_CONSUMED_NOT_REPLAYED')
    emit('DENY_BEFORE_OR_AFTER','PASS_R34_0_ACTIVE_6_OFF')
    emit('INDEPENDENT_AUTHORITY','NOT_PROVISIONED')
    emit('P7','DRAFT');emit('A6','ND');emit('P8','NO-GO')
    return head

def write_once(name, value):
    need(name in ('attempt.json','result.json'),'UNSAFE_RECEIPT_NAME')
    raw=canonical(value)
    fd=os.open(BASE/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    fd=os.open(BASE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally:os.close(fd)

def read_attempt():
    directory(BASE,0o700)
    d=strict_obj(root_file(BASE/'attempt.json',limit=8192))
    need(d.get('schema')==SCHEMA+'-attempt' and
         re.fullmatch(r'ardrec-r117-f2-deny-[0-9a-f]{12}',d.get('unit','')) is not None and
         d.get('source_head')==git('rev-parse','HEAD').decode().strip() and
         d.get('delay_seconds')==45 and d.get('max_window_seconds')==60 and
         d.get('mode')=='IDEMPOTENT_ZERO_OF_SIX_DENY_ONLY' and
         type(d.get('armed_clock_monotonic')) is float,
         'ATTEMPT_RECORD_INVALID')
    return d

def service_receipt(unit):
    p=get_props(unit+'.service')
    need(p.get('LoadState')=='loaded','F2_SERVICE_NOT_LOADED')
    need(p.get('Result')!='failed' and p.get('ActiveState')!='failed',
         'F2_SERVICE_FAILED')
    if (p.get('ActiveState')!='active' or p.get('SubState')!='exited' or
        p.get('Result')!='success' or p.get('ExecMainStatus')!='0'):
        return None
    raw=command(['/usr/bin/journalctl','--system','--unit='+unit+'.service',
                 '--no-pager','--output=cat','-n','100'],timeout=20).stdout
    matches=[]
    for line in raw.splitlines():
        try:d=strict_obj(line)
        except (ValueError,Stop,TypeError,UnicodeDecodeError): continue
        if type(d) is dict and d.get('schema')=='ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-restore' and d.get('status')=='DENY_RESTORED':
            matches.append(d)
    need(len(matches)==1,'F1_RESTORE_SERVICE_JOURNAL_NOT_EXACTLY_ONE')
    doc=matches[0]
    need(doc.get('traffic_allowed') is False and doc.get('p8')=='NO-GO' and
         doc.get('states')=={'ssh':'OFF','runner':'OFF','ftp':'OFF','smb':'OFF'} and
         doc.get('policy',{}).get('active_count')==0 and
         doc.get('policy',{}).get('absent_count')==6 and
         doc.get('host_writes')=='NFT_DENY_AND_KNOWN_BINDING_RESTORE_ONLY',
         'F1_RESTORE_SERVICE_JOURNAL_SEMANTICS_INVALID')
    receipt_raw=canonical(doc)
    receipt=F1/('restore-'+digest(receipt_raw)[:16]+'.json')
    need(digest(root_file(receipt,limit=8192))==digest(receipt_raw) and
         root_file(receipt,limit=8192)==receipt_raw,'F1_NEW_RESTORE_RECEIPT_MISSING')
    return p,doc,digest(receipt_raw)

def finalize():
    need(BASE.exists(),'NO_PRIOR_ATTEMPT')
    att=read_attempt()
    if (BASE/'result.json').exists():
        saved=strict_obj(root_file(BASE/'result.json',limit=8192))
        need(saved.get('source_head')==att['source_head'] and
             saved.get('unit')==att['unit'] and saved.get('schema')==SCHEMA+'-result',
             'SAVED_RESULT_INVALID')
        physical_preflight('--finalize')
        emit('RESULT','PASS_ALREADY_FINALIZED_NO_RESCHEDULE' if saved.get('status')=='PASS_45S_DENY_ZERO_OF_SIX'
             else 'NO_GO_ALREADY_FINALIZED_NO_RESCHEDULE')
        emit('RECEIPT',BASE/'result.json')
        emit('RECEIPT_SHA256',digest(root_file(BASE/'result.json',limit=8192)))
        return 0 if saved.get('status')=='PASS_45S_DENY_ZERO_OF_SIX' else 23
    service=service_receipt(att['unit'])
    need(service is not None,'SERVICE_NOT_COMPLETED_FINALIZE_ONLY')
    props,doc,f1_receipt_sha=service
    physical_preflight('--finalize')
    status,timing=timing_assessment(att['armed_clock_monotonic'],props)
    result={'schema':SCHEMA+'-result','source_head':att['source_head'],
        'unit':att['unit'],'status':status, 'configured_delay_seconds':45,
        'max_nominal_window_seconds':60,'timing':timing,'systemd_result':'success',
        'f1_restore_sha256':f1_receipt_sha,'f1_sha256':F1_SHA,'f3_sha256':F3_SHA,
        'root_f1_f12':True,'root_f3_f12_sources':33,'deny_before':'MATCH',
        'deny_after':'MATCH','guest_starts':0,'network_connections':0,
        'restore_from_allow_proven':False,'restore_5_1_proven':False,
        'pilot_authorized':False,'p7':'DRAFT','a6':'ND','p8':'NO-GO'}
    write_once('result.json',result)
    emit('UNIT',att['unit'])
    emit('MONOTONIC_START_SECONDS',timing.get('start_seconds','ND'))
    emit('MONOTONIC_RESTORE_EXIT_SECONDS',timing.get('restore_exit_seconds','ND'))
    emit('MONOTONIC_SERVICE_DURATION',timing.get('duration_seconds','ND'))
    emit('RECEIPT',BASE/'result.json')
    emit('RECEIPT_SHA256',digest(canonical(result)))
    emit('RESTORE_FROM_ALLOW_PROOF','NOT_PERFORMED')
    emit('RESTORE_5_1_PROOF','NOT_PERFORMED')
    emit('VM_STARTS',0);emit('NETWORK_CONNECTIONS',0)
    emit('RESULT',status)
    return 0 if status=='PASS_45S_DENY_ZERO_OF_SIX' else 23

def main(argv=None):
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--inspect',action='store_true')
    group.add_argument('--run',action='store_true')
    group.add_argument('--finalize',action='store_true')
    opts=parser.parse_args(argv)
    os.umask(0o077)
    mode='--inspect' if opts.inspect else '--run' if opts.run else '--finalize'
    if mode=='--finalize':return finalize()
    physical_preflight(mode)
    if mode=='--inspect':
        emit('PREVIOUS_ATTEMPT','PRESENT' if BASE.exists() else 'NONE')
        emit('MODE','READONLY_NO_WRITES')
        emit('RESULT','PASS_READONLY_READY_FOR_EXPLICIT_DENY_RESTORE'
             if not BASE.exists() else 'NO_GO_PRIOR_ATTEMPT_EXISTS')
        return 0 if not BASE.exists() else 23
    need(not BASE.exists() and not BASE.is_symlink(),'PRIOR_ATTEMPT_EXISTS_NO_RETRY')
    BASE.mkdir(mode=0o700)
    directory(BASE,0o700)
    unit='ardrec-r117-f2-deny-'+secrets.token_hex(6)
    attempt={'schema':SCHEMA+'-attempt','source_head':git('rev-parse','HEAD').decode().strip(),
        'unit':unit,'delay_seconds':45,'max_window_seconds':60,
        'mode':'IDEMPOTENT_ZERO_OF_SIX_DENY_ONLY',
        'armed_clock_monotonic':time.monotonic()}
    write_once('attempt.json',attempt) # one-shot consumed BEFORE invoking systemd
    emit('ONE_SHOT','CONSUMED_BEFORE_TIMER')
    emit('UNIT',unit)
    command(['/usr/bin/systemd-run','--system','--unit='+unit,
             '--on-active=45s','--timer-property=AccuracySec=1s',
             '--property=Type=oneshot','--property=RemainAfterExit=yes',
             '/usr/bin/python3','-I','-B',str(F1/'root-guard.py'),'--restore-deny'],timeout=20)
    emit('TIMER','ARMED_SIGNED_F12_F1_RESTORE_DENY_45S')
    emit('NFTP_FIREWALL_ACTION','IDEMPOTENT_DENY_WRITE_ONLY_AT_TIMER')
    emit('NOT_A_RECOVERY_FROM_ALLOW_OR_5_1','TRUE')
    deadline=time.monotonic()+85
    while time.monotonic()<deadline:
        if service_receipt(unit) is not None:return finalize()
        time.sleep(2)
    raise Stop('SERVICE_NOT_COMPLETED_WITHIN_85S_USE_FINALIZE_NO_RETRY')

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (Stop, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired,
            json.JSONDecodeError) as exc:
        emit('STOP',type(exc).__name__+':'+str(exc)[:160].replace('\n','_'))
        emit('RESULT','NO_GO_PRESERVE_ONE_SHOT_USE_FINALIZE_OR_REVIEW')
        emit('P8','NO-GO')
        raise SystemExit(23)
