#!/usr/bin/env python3
"""Read-only plan, then individually authorized three isolated network starts.

No VM boot, no firewall/hook or F11 lease mutation, no retry, no automatic cleanup.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r112_f11_postreboot_network as core
from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_runner_nic_definition as nic
import ardrec_p14_r112_f5_scoped_hook as f5
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r111_legacy_host_snapshot as legacy

ROOT=Path('/home/cicada/ardrec-lab/r112-f11n-postreboot-networks-v1')
BRANCH='feat/p14-r111-r114-real-lab'
LEASE_ROOT='/run/ardrec-f11-boot-v1'
PRIOR_F9=Path('/home/cicada/ardrec-lab/r112-f9-real-runner-boot-v1/boot-cx9ri8bs/receipt.json')
PRIOR_F9_SHA='88bda990407c0902ff44c731ed8333a52e0adeca533f5d6f93348b2412d9af36'
PLAN_SET={'before.json','plan.json','manifest.json'}
APPLY_SET={'intent.json','receipt.json'} | {name+'-'+r+'.json' for r in ('ssh','ftp','smb') for name in ('command','after','step')}


def need(ok,reason): core.need(ok,reason)

def cmd(argv,timeout=30):
    try:
        p=subprocess.run(tuple(argv),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,check=False,timeout=timeout)
        return {'rc':p.returncode,'stdout':p.stdout.decode('utf-8','replace'),
                'stderr':p.stderr[:2048].decode('utf-8','replace'),
                'timeout':False,'truncated':len(p.stderr)>2048 or len(p.stdout)>200000}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'rc':None,'stdout':'','stderr':type(e).__name__,
                'timeout':isinstance(e,subprocess.TimeoutExpired),'truncated':False}

def ok(argv,reason):
    r=cmd(argv)
    need(r['rc']==0 and not r['timeout'] and not r['truncated'],reason)
    return r['stdout'].strip()

def source():
    need(Path.cwd().resolve()==REPO,'REPOSITORY_CWD')
    need(ok(('git','rev-parse','--show-toplevel'),'REPO_ROOT')==str(REPO),'ROOT_DRIFT')
    need(ok(('git','branch','--show-current'),'GIT_BRANCH')==BRANCH,'BRANCH_DRIFT')
    need(cmd(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'))['rc']==0,
         'F10_PARENT_NOT_ANCESTOR')
    need(ok(('git','status','--porcelain=v1','-uall'),'GIT_STATUS')=='',
         'WORKTREE_NOT_CLEAN')
    pins={
        'src/ardrec/coordination/r112_f8_ssh_positive_boot.py':'514a2a6e7b749b5b400553bced11308cbfb2aa9431fe480d69a0618ddea7f485',
        'src/ardrec/coordination/r112_f10_targets_boot.py':'1137c75d181d8130a88b830553cf701e3fe0e77a9e8751a6b63648cb38cb8100',
        'lab/f11-runtime-v3/00-ardrec-r33-admission':core.HOOK_SHA,
    }
    for rel,expected in pins.items():
        path=REPO/rel
        need(path.is_file() and not path.is_symlink() and
             hashlib.sha256(path.read_bytes()).hexdigest()==expected,'PINNED_SOURCE_DRIFT_'+rel)
    need(PRIOR_F9.is_file() and not PRIOR_F9.is_symlink() and
         hashlib.sha256(PRIOR_F9.read_bytes()).hexdigest()==PRIOR_F9_SHA,
         'PRE_REBOOT_F9_PROVENANCE_CHANGED')

def no_leases():
    for argv in (('sudo','-n','test','!','-e',LEASE_ROOT),
                 ('sudo','-n','test','!','-L',LEASE_ROOT)):
        need(cmd(argv)['rc']==0,'POST_REBOOT_F11_LEASE_OR_SYMLINK_EXISTS')

def read_host():
    return f5._measurement(unpinned=True)  # 29 real host probes; no mutations

def private_root():
    if not ROOT.exists():
        ROOT.mkdir(mode=0o700,parents=False)
    need(ROOT.is_dir() and not ROOT.is_symlink() and
         ROOT.stat().st_uid==os.getuid() and
         stat.S_IMODE(ROOT.stat().st_mode)==0o700,'PRIVATE_ROOT_INVALID')

def private(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         re.fullmatch(prefix+r'-[a-zA-Z0-9_\-]+',path.name) is not None and
         path.is_dir() and not path.is_symlink() and
         path.stat().st_uid==os.getuid() and
         stat.S_IMODE(path.stat().st_mode)==0o700,'PRIVATE_SESSION_INVALID')

def store(path,obj):
    raw=obj if isinstance(obj,bytes) else core.canon(obj)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())

def read(path):
    s=path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
         s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600
         and s.st_size<3_000_000,'PRIVATE_FILE_INVALID_'+path.name)
    raw=path.read_bytes()
    obj=json.loads(raw)
    need(core.canon(obj)==raw,'NONCANONICAL_PRIVATE_JSON_'+path.name)
    return obj

def verify_plan(plan):
    private(plan,'plan')
    names={p.name for p in plan.iterdir()}
    need(names-{'apply.once'}==PLAN_SET,'PLAN_FILE_SET')
    if 'apply.once' in names:
        need((plan/'apply.once').read_bytes()==b'ATTEMPTED\n', 'ONCE_MARKER_TAMPER')
    before=read(plan/'before.json')
    doc=read(plan/'plan.json')
    manifest=read(plan/'manifest.json')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                    'before_sha256':core.sha(before),
                    'plan_sha256':core.sha(doc)},'PLAN_MANIFEST_INVALID')
    need(doc=={'schema':core.SCHEMA+'-plan','base_commit':core.PARENT,
               'prior_f9_receipt_sha256':PRIOR_F9_SHA,
               'before_sha256':core.sha(before),
               'network_start_order':list(core.NETWORKS),
               'command_allowlist':[['sudo','-n','virsh','-c','qemu:///system',
                                     'net-start','ardrec-r33-dev-net-'+r]
                                    for r in core.NETWORKS],
               'guest_starts':0,'traffic_authorized':False,'p8_operational':'NO-GO'},
         'PLAN_DRIFT')
    need(core.network_states(before,legacy,f4)==dict.fromkeys(core.NETWORKS,'INACTIVE'),
         'PLAN_BEFORE_NOT_INACTIVE')
    return before,doc

def plan():
    source();no_leases()
    before=read_host()
    need(core.network_states(before,legacy,f4)==dict.fromkeys(core.NETWORKS,'INACTIVE'),
         'NETWORKS_NOT_ALL_INACTIVE')
    private_root()
    doc={'schema':core.SCHEMA+'-plan','base_commit':core.PARENT,
         'prior_f9_receipt_sha256':PRIOR_F9_SHA,'before_sha256':core.sha(before),
         'network_start_order':list(core.NETWORKS),
         'command_allowlist':[['sudo','-n','virsh','-c','qemu:///system','net-start',
                               'ardrec-r33-dev-net-'+r] for r in core.NETWORKS],
         'guest_starts':0,'traffic_authorized':False,'p8_operational':'NO-GO'}
    path=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT));private(path,'plan')
    store(path/'before.json',before)
    store(path/'plan.json',doc)
    store(path/'manifest.json',{'schema':core.SCHEMA+'-manifest',
                               'before_sha256':core.sha(before),'plan_sha256':core.sha(doc)})
    verify_plan(path)
    print('R112_F11N_PLAN=READY_POST_REBOOT_THREE_NETWORKS_R34_DENY')
    print('R112_F11N_PLAN_SESSION='+str(path))
    print('R112_F11N_PLAN_SHA256='+core.sha(doc))
    print('R112_F11N_VM_STARTS=0')
    print('R112_F11N_P8=NO-GO')
    return 0

def replay(plan_path,attempt):
    before,doc=verify_plan(plan_path)
    private(attempt,'apply')
    need({p.name for p in attempt.iterdir()}==APPLY_SET,'RECEIPT_FILE_SET')
    intent=read(attempt/'intent.json')
    need(intent=={'schema':core.SCHEMA+'-intent','plan_sha256':core.sha(doc),
                  'authorized_exactly_three_net_starts':True,
                  'guest_starts':0,'traffic_authorized':False,'p8_operational':'NO-GO'},
         'INTENT_DRIFT')
    steps=[]
    for role in core.NETWORKS:
        cmd_record=read(attempt/('command-'+role+'.json'))
        after_record=read(attempt/('after-'+role+'.json'))
        step=read(attempt/('step-'+role+'.json'))
        need(step=={'role':role,'command':cmd_record,'after':after_record},
             'STEP_PROVENANCE_DRIFT_'+role)
        steps.append(step)
    receipt=read(attempt/'receipt.json')
    need(receipt==core.verify_steps(before,steps,legacy,f4),'RECEIPT_DRIFT')
    need((plan_path/'apply.once').read_bytes()==b'ATTEMPTED\n','ONCE_MARKER_MISSING')
    return receipt

def activate(path):
    source();no_leases()
    before,doc=verify_plan(path)
    need(not (path/'apply.once').exists(),'NETWORK_ACTIVATION_ALREADY_ATTEMPTED')
    fresh=read_host()
    core.compare(before,fresh,(),legacy,f4)
    attempt=Path(tempfile.mkdtemp(prefix='apply-',dir=ROOT));private(attempt,'apply')
    store(attempt/'intent.json',{'schema':core.SCHEMA+'-intent',
          'plan_sha256':core.sha(doc),'authorized_exactly_three_net_starts':True,
          'guest_starts':0,'traffic_authorized':False,'p8_operational':'NO-GO'})
    store(path/'apply.once',b'ATTEMPTED\n')
    steps=[]
    for index,role in enumerate(core.NETWORKS,1):
        allowed=tuple(doc['command_allowlist'][index-1])
        need(allowed==('sudo','-n','virsh','-c','qemu:///system','net-start',
                        'ardrec-r33-dev-net-'+role),'START_ALLOWLIST')
        result=cmd(allowed,timeout=90)
        store(attempt/('command-'+role+'.json'),result)
        need(result['rc']==0 and not result['timeout'] and not result['truncated'],
             'NETWORK_START_FAILED_OR_UNCERTAIN_'+role)
        observed=read_host()
        store(attempt/('after-'+role+'.json'),observed)
        core.compare(before,observed,core.NETWORKS[:index],legacy,f4)
        step={'role':role,'command':result,'after':observed}
        store(attempt/('step-'+role+'.json'),step)
        steps.append(step)
    receipt=core.verify_steps(before,steps,legacy,f4)
    store(attempt/'receipt.json',receipt)
    # Persistent audit files command and after included; replay expects them too.
    replay(path,attempt)
    print('R112_F11N_NETWORKS=SSH_ACTIVE_FTP_ACTIVE_SMB_ACTIVE')
    print('R112_F11N_R34=DENY_PRESERVED')
    print('R112_F11N_PHYSICAL_RECEIPT='+str(attempt/'receipt.json'))
    print('R112_F11N_RECEIPT_SHA256='+hashlib.sha256((attempt/'receipt.json').read_bytes()).hexdigest())
    print('R112_F11N_GUEST_STARTS=0')
    print('R112_F11N_P8=NO-GO')
    print('R112_F11N_RESULT=THREE_REAL_NETWORKS_REACTIVATED_DENY_ONLY')
    return 0

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    g=parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--plan',action='store_true')
    g.add_argument('--activate',type=Path)
    g.add_argument('--replay',type=Path)
    parser.add_argument('--plan-session',type=Path)
    parser.add_argument('--i-authorize-three-isolated-net-starts',action='store_true')
    a=parser.parse_args()
    try:
        if a.plan:return plan()
        if a.activate:
            need(a.i_authorize_three_isolated_net_starts,'EXPLICIT_AUTHORIZATION_REQUIRED')
            return activate(a.activate)
        need(a.plan_session is not None,'PLAN_REQUIRED_FOR_REPLAY')
        source()
        receipt=replay(a.plan_session,a.replay)
        print('R112_F11N_REPLAY=PASS')
        print('R112_F11N_RECEIPT_SHA256='+core.sha(receipt))
        print('R112_F11N_P8=NO-GO')
        return 0
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as exc:
        print('R112_F11N_STOP='+type(exc).__name__+':'+str(exc)[:200])
        print('R112_F11N_ACTION=NO_RETRY_NO_ROLLBACK_NO_HOST_CLEANUP')
        print('R112_F11N_P8=NO-GO')
        return 23

if __name__=='__main__':raise SystemExit(main())
