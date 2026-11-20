#!/usr/bin/env python3
"""ARDREC F7: independent root systemd timer rehearsal, never opens networking.

Physical mode is exactly-once, never automatically retried. Replay touches no
host device and verifies the archived F6 check, timer, service and attestation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import time

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
from ardrec.coordination import r113_f7_timer_guard as g

EVIDENCE=Path('/home/cicada/ardrec-lab/r113-f7-deny-timer-v1')
LOGS=('root_check','before_attest','schedule','timer_armed',
      'service_done','after_attest','journal')


def save(path:Path, raw:bytes) -> None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())


def require_dir(folder:Path) -> None:
    for target in (EVIDENCE, folder):
        s=target.lstat()
        g.need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and
               stat.S_IMODE(s.st_mode)==0o700 and not target.is_symlink(),
               'EVIDENCE_DIR_UNSAFE_'+str(target))


def load(path:Path, allow_zero=False) -> bytes:
    s=path.lstat()
    g.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and
           s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and
           (s.st_size>=0 if allow_zero else s.st_size>0) and s.st_size<65536,
           'RECEIPT_FILE_INVALID_'+path.name)
    return path.read_bytes()


def run(name:str, argv:list[str], folder:Path, *, privileged=True, timeout=30, required=True) -> tuple[int,bytes]:
    g.need(name in (*LOGS,'timer_status_early','service_status_early'), 'PROBE_NAME_INVALID')
    command=(['/usr/bin/sudo','-n'] if privileged else [])+argv
    p=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,
                     check=False,timeout=timeout,close_fds=True)
    g.need(len(p.stdout)<65536 and len(p.stderr)<16384,'HOST_COMMAND_OUTPUT_TOO_LARGE')
    save(folder/(name+'.stdout'),p.stdout)
    save(folder/(name+'.stderr'),p.stderr)
    if required:
        g.need(p.returncode==0,'HOST_COMMAND_FAILED_'+name+'_'+str(p.returncode))
    return p.returncode,p.stdout


def start_folder() -> tuple[Path,str]:
    os.umask(0o077)
    if not EVIDENCE.exists():
        EVIDENCE.mkdir(mode=0o700)
    require_dir(EVIDENCE)
    folder=Path(tempfile.mkdtemp(dir=EVIDENCE,prefix='smoke-'))
    require_dir(folder)
    token=secrets.token_hex(6)
    intent={'schema':g.SCHEMA,'token':token,'action':'DENY_ONLY_SMOKE',
            'schedule_seconds':g.INTERVAL,'allow_traffic':False,'p8':'NO-GO'}
    save(folder/'intent.json',g.canonical(intent))
    return folder,token


def replay(folder:Path) -> dict:
    g.need(folder.is_absolute() and folder.parent==EVIDENCE and
           folder.name.startswith('smoke-'),'REPLAY_PATH_NOT_F7')
    require_dir(folder)
    intent=json.loads(load(folder/'intent.json'))
    g.need(set(intent)=={'schema','token','action','schedule_seconds','allow_traffic','p8'}
           and intent['schedule_seconds']==g.INTERVAL,'INTENT_SHAPE_DRIFT')
    outputs={k:load(folder/(k+'.stdout'),True) for k in LOGS}
    aux={k:load(folder/k,True) for k in g.AUX_NAMES}
    result=g.receipt(intent,outputs,aux)
    manifest=json.loads(load(folder/'manifest.json'))
    g.need(load(folder/'manifest.json')==g.canonical(result), 'MANIFEST_TAMPER_OR_NONCANONICAL')
    g.need(g.sha(load(folder/'intent.json'))==result['intent_sha256'],'INTENT_TAMPER')
    g.need(set(p.name for p in folder.iterdir())==
           {'intent.json','armed.once','manifest.json'} |
           {k+suffix for k in (*LOGS,'timer_status_early','service_status_early')
            for suffix in ('.stdout','.stderr')},
           'RECEIPT_FILE_SCOPE_DRIFT')
    g.need(load(folder/'armed.once')==b'SYSTEMD_TIMER_ARM_ATTEMPTED\n',
           'TIMER_ARM_MARKER_CHANGED')
    for name in (*LOGS,'timer_status_early','service_status_early'):
        load(folder/(name+'.stderr'),True)
    for name,digest in result['stdout_sha256'].items():
        g.need(g.sha(outputs[name])==digest,'RECEIPT_HASH_CHANGED_'+name)
    for name,digest in result['aux_sha256'].items():
        g.need(g.sha(aux[name])==digest,'RECEIPT_AUX_HASH_CHANGED_'+name)
    return result


def smoke() -> int:
    folder,token=start_folder()
    print('R113_F7_SESSION='+str(folder),flush=True)
    run('root_check',g.check_command(),folder)
    g.checked_root_result(load(folder/'root_check.stdout'),g.F6_CHECK)
    run('before_attest',g.attest_command(),folder)
    g.checked_root_result(load(folder/'before_attest.stdout'),g.F6_ATTESTED)
    # One-time intent is durably persisted BEFORE asking systemd to arm the
    # independent service. Never retry if subsequent host responses are lost.
    save(folder/'armed.once',b'SYSTEMD_TIMER_ARM_ATTEMPTED\n')
    run('schedule',g.schedule(token),folder,timeout=30)
    run('timer_armed',g.show_timer(token),folder)
    g.armed(load(folder/'timer_armed.stdout'),token)
    # Earliest service state. Log once, even if it has not run yet.
    run('service_status_early',g.show_service(token),folder,required=False)
    run('timer_status_early',g.show_timer(token),folder,required=False)
    deadline=time.monotonic()+55
    final=None
    while time.monotonic()<deadline:
        p=subprocess.run(['/usr/bin/sudo','-n']+g.show_service(token),
                         stdin=subprocess.DEVNULL,capture_output=True,
                         check=False,timeout=10,close_fds=True)
        if p.returncode==0 and p.stdout:
            try:
                if g.triggered_success(p.stdout):
                    final=p.stdout
                    break
            except g.GuardError as exc:
                raise g.GuardError('SYSTEMD_TRIGGER_FAILED_'+str(exc)) from exc
        time.sleep(0.5)
    g.need(final is not None,'SYSTEMD_TIMER_DID_NOT_COMPLETE_IN_BOUNDED_WAIT')
    save(folder/'service_done.stdout',final)
    save(folder/'service_done.stderr',b'')
    run('after_attest',g.attest_command(),folder)
    g.checked_root_result(load(folder/'after_attest.stdout'),g.F6_ATTESTED)
    # Journal output is informational; it may be empty on restrictive hosts.
    run('journal',g.journal(token),folder,required=False)
    intent=json.loads(load(folder/'intent.json'))
    raw={key:load(folder/(key+'.stdout'),True) for key in LOGS}
    aux={key:load(folder/key,True) for key in g.AUX_NAMES}
    report=g.receipt(intent,raw,aux)
    save(folder/'manifest.json',g.canonical(report))
    g.need(replay(folder)==report,'REPLAY_AT_CREATION_FAILED')
    print('R113_F7_TIMER=PASS_INDEPENDENT_ROOT_TRIGGER',flush=True)
    print('R113_F7_DENY_AFTER_TIMER=PASS_SIX_BINDINGS',flush=True)
    print('R113_F7_MANIFEST_SHA256='+g.sha(load(folder/'manifest.json')),flush=True)
    print('R113_F7_REPLAY=PASS',flush=True)
    print('R113_F7_TRAFFIC_OPENED=NO',flush=True)
    print('R113_F7_P8=NO-GO',flush=True)
    return 0


def main():
    parser=argparse.ArgumentParser()
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--smoke',action='store_true')
    modes.add_argument('--replay',type=Path)
    modes.add_argument('--contract',action='store_true')
    parser.add_argument('--i-authorize-one-independent-root-deny-timer',action='store_true')
    args=parser.parse_args()
    try:
        if args.contract:
            g.need(not args.i_authorize_one_independent_root_deny_timer,'CONTRACT_NO_AUTH')
            print('R113_F7_CONTRACT=PASS_DENY_ONLY')
            print('R113_F7_SCHEDULE_SECONDS='+str(g.INTERVAL))
            print('R113_F7_P8=NO-GO')
            return 0
        if args.replay:
            g.need(not args.i_authorize_one_independent_root_deny_timer,'REPLAY_NO_AUTH')
            report=replay(args.replay)
            print('R113_F7_REPLAY=PASS')
            print('R113_F7_RECEIPT_SHA256='+g.sha(g.canonical(report)))
            print('R113_F7_P8=NO-GO')
            return 0
        g.need(args.i_authorize_one_independent_root_deny_timer,'PHYSICAL_AUTH_REQUIRED')
        return smoke()
    except Exception as exc:
        print('R113_F7_STOP='+type(exc).__name__+':'+str(exc)[:180],flush=True)
        print('R113_F7_NO_AUTOMATIC_RETRY=TRUE',flush=True)
        print('R113_F7_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
