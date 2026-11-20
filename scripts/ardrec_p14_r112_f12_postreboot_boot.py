#!/usr/bin/env python3
"""R112-F12: new one-use SSH then runner boots after a host reboot.

--plan and --replay are read-only on the host. --boot performs a root F11
lease install and exactly ONE virsh start after an explicit human approval.
Never retry, remove a marker, restore, destroy, shutdown or open traffic.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO/'src'), str(REPO/'scripts')]
from ardrec.coordination import r112_f12_postreboot_boot as core
from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_f9_runner_boot as f9
from ardrec.coordination import r112_runner_nic_definition as nic
import ardrec_p14_r112_f11n_postreboot_network as f11ncli
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as prior

ROOT = Path('/home/cicada/ardrec-lab/r112-f12-postreboot-ssh-runner-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
F11N_PLAN = Path('/home/cicada/ardrec-lab/r112-f11n-postreboot-networks-v1/plan-1kz5tzac')
F11N_ATTEMPT = Path('/home/cicada/ardrec-lab/r112-f11n-postreboot-networks-v1/apply-pz3g35by')
F11N_SHA = '9eea08bfb68a80af06b360d029c7b7912cddf659a307df7129f72740d406f427'
PINS = {
 'src/ardrec/coordination/r112_f8_ssh_positive_boot.py':
     '514a2a6e7b749b5b400553bced11308cbfb2aa9431fe480d69a0618ddea7f485',
 'src/ardrec/coordination/r112_f9_runner_boot.py':
     '523a84db936010dbc96f8d5b419f152f5d25bc7316dff32d1da7a8070b80e189',
 'src/ardrec/coordination/r112_f10_targets_boot.py':
     '1137c75d181d8130a88b830553cf701e3fe0e77a9e8751a6b63648cb38cb8100',
 'src/ardrec/coordination/r112_f11_postreboot_network.py':
     '72bec1e6723a15bbfbe48855f786818a955ce806ff2e0a9a0805d82096cdc586',
 'lab/f11-runtime-v3/00-ardrec-r33-admission': f8.HOOK_SHA,
}
PLAN_FILES = {'before.json','plan.json','manifest.json'}
BOOT_FILES = {'intent.json','ticket.json','grant-dir-command.json',
              'grant-file-command.json','grant-readback.json',
              'start-command.json','after.json','live-xml.json',
              'claim-readback.json','receipt.json'}

def need(ok,why): core.need(ok,why)

def host(argv,timeout=22):
    try:
        p=subprocess.run(tuple(argv),stdin=subprocess.DEVNULL,capture_output=True,
                         check=False,timeout=timeout)
        stdout=p.stdout[:legacy.MAX_CAPTURE]
        stderr=p.stderr[:2048]
        return {'rc':p.returncode,'stdout':stdout.decode('utf8','replace'),
                'stderr':stderr.decode('utf8','replace'),'timeout':False,
                'truncated':len(stdout)!=len(p.stdout) or len(stderr)!=len(p.stderr)}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {'rc':None,'stdout':'','stderr':type(exc).__name__,
                'timeout':isinstance(exc,subprocess.TimeoutExpired),'truncated':False}

def query(argv,code):
    r=host(argv)
    need(r['rc']==0 and r['timeout'] is False and r['truncated'] is False,code)
    return r['stdout'].strip()

def source():
    need(Path.cwd().resolve()==REPO,'REPO_CWD_CHANGED')
    need(query(('git','rev-parse','--show-toplevel'),'GIT_ROOT')==str(REPO),'ROOT_CHANGED')
    need(query(('git','branch','--show-current'),'BRANCH')==BRANCH,'BRANCH_CHANGED')
    need(host(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'))['rc']==0,
         'F11N_ANCESTRY_NOT_PRESENT')
    need(query(('git','status','--porcelain=v1','-uall'),'STATUS')=='',
         'WORKTREE_NOT_CLEAN')
    for path,digest in PINS.items():
        p=REPO/path
        need(p.is_file() and not p.is_symlink() and
             hashlib.sha256(p.read_bytes()).hexdigest()==digest,
             'SOURCE_PIN_DRIFT_'+path)
    for path in ('src/ardrec/coordination/r112_f12_postreboot_boot.py',
                 'scripts/ardrec_p14_r112_f12_postreboot_boot.py'):
        need(host(('git','ls-files','--error-unmatch',path))['rc']==0 and
             host(('git','diff','--quiet','HEAD','--',path))['rc']==0,
             'F12_FILE_NOT_TRACKED_OR_CHANGED_'+path)

def previous_f11n():
    p=F11N_ATTEMPT/'receipt.json'
    need(p.is_file() and not p.is_symlink() and
         core.digest(p.read_bytes())==F11N_SHA, 'F11N_RECEIPT_CHANGED')
    receipt=f11ncli.replay(F11N_PLAN,F11N_ATTEMPT)
    need(receipt==json.loads(p.read_bytes()) and
         receipt['network_start_count']==3 and receipt['guest_start_count']==0 and
         receipt['traffic_authorized'] is False and receipt['p8_operational']=='NO-GO',
         'F11N_PHYSICAL_REPLAY_INVALID')
    return {'type':'F11N_NETWORKS','plan':str(F11N_PLAN),
            'receipt':str(p),'sha256':F11N_SHA}

def private(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         path.name.startswith(prefix+'-') and not path.is_symlink(),
         'PRIVATE_SESSION_INVALID')
    prior.directory(path)

def write(path,obj):
    prior.store(path,core.canon(obj) if type(obj) is dict else obj)

def read(path): return prior.read_json(path)

def previous_ssh(plan_dir,receipt_path):
    need(isinstance(plan_dir, Path) and isinstance(receipt_path, Path),
         'SSH_PREDECESSOR_REQUIRED')
    need(receipt_path.name=='receipt.json','SSH_RECEIPT_FILE_NAME')
    private(plan_dir,'plan');private(receipt_path.parent,'boot')
    rec=replay(plan_dir,receipt_path.parent,expected_role='ssh')
    need(rec['role']=='ssh' and rec['guest_states']==core.expected('ssh',True)
         and rec['traffic_authorized'] is False and rec['p8_operational']=='NO-GO',
         'SSH_PREDECESSOR_REPLAY_FAILED')
    return {'type':'F12_SSH','plan':str(plan_dir),
            'receipt':str(receipt_path),'sha256':core.digest(receipt_path.read_bytes())}

def previous(role,ssh_plan=None,ssh_receipt=None):
    core.allowed(role)
    if role=='ssh':
        need(ssh_plan is None and ssh_receipt is None,'SSH_PREDECESSOR_SCOPE')
        return previous_f11n()
    return previous_ssh(ssh_plan,ssh_receipt)

def no_markers(role):
    for path in (core.lease(role),*core.markers(role).values()):
        for args in (( 'sudo','-n','test','!','-e',path),
                     ( 'sudo','-n','test','!','-L',path)):
            answer=host(args)
            need(answer['rc']==0 and answer['timeout'] is False,
                 'F11_STALE_LEASE_OR_MARKER_'+role)

def snapshot(role):
    record=f6.capture()
    core.audited(record,role,False,legacy,f4,f6)
    no_markers(role)
    return record

def verify_plan(path,role):
    private(path,'plan')
    files={p.name for p in path.iterdir()}
    need(files-{'boot.once'}==PLAN_FILES,'PLAN_FILE_SET_CHANGED')
    if 'boot.once' in files:
        need(prior.private_bytes(path/'boot.once')==b'ATTEMPTED\n',
             'BOOT_ONCE_TAMPER')
    before,document,manifest=(read(path/x) for x in
                              ('before.json','plan.json','manifest.json'))
    core.audited(before,role,False,legacy,f4,f6)
    need(document['role']==role,'PLAN_ROLE_CHANGED')
    pred=document['previous']
    need(type(pred) is dict and
         set(pred)=={'type','plan','receipt','sha256'},'PREDECESSOR_SCOPE')
    if role=='ssh':
        expected=previous('ssh')
    else:
        expected=previous('runner',Path(pred['plan']),Path(pred['receipt']))
    need(pred==expected,'PREDECESSOR_CHANGED')
    want={'schema':core.SCHEMA+'-plan',
          'parent':core.PARENT,'role':role,'guest':core.guest(role),
          'start_command':list(core.command(role)),'permit_seconds':core.TTL,
          'expected_before':core.expected(role,False),
          'expected_after':core.expected(role,True),
          'before_sha256':core.sha(before),'previous':pred,
          'traffic_authorized':False,'p8_operational':'NO-GO'}
    need(document==want,'PLAN_CONTENT_CHANGED')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                    'before_sha256':core.sha(before),
                    'plan_sha256':core.sha(want),'p8_operational':'NO-GO'},
         'MANIFEST_CHANGED')
    return before,document

def plan(role,ssh_plan=None,ssh_receipt=None):
    source()
    pred=previous(role,ssh_plan,ssh_receipt)
    before=snapshot(role)
    document={'schema':core.SCHEMA+'-plan','parent':core.PARENT,'role':role,
              'guest':core.guest(role),'start_command':list(core.command(role)),
              'permit_seconds':core.TTL,'expected_before':core.expected(role,False),
              'expected_after':core.expected(role,True),
              'before_sha256':core.sha(before),'previous':pred,
              'traffic_authorized':False,'p8_operational':'NO-GO'}
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    private(folder,'plan')
    write(folder/'before.json',before)
    write(folder/'plan.json',document)
    write(folder/'manifest.json',{
        'schema':core.SCHEMA+'-manifest','before_sha256':core.sha(before),
        'plan_sha256':core.sha(document),'p8_operational':'NO-GO'})
    verify_plan(folder,role)
    print('R112_F12_ROLE='+role.upper())
    print('R112_F12_PLAN=READY_NEW_POSTREBOOT_ONE_START_DENY_ONLY')
    print('R112_F12_PLAN_SESSION='+str(folder))
    print('R112_F12_PLAN_SHA256='+core.sha(document))
    print('R112_F12_VM_STARTS=0')
    print('R112_F12_P8=NO-GO')
    return 0

def grant_readback(role):
    l=core.lease(role)
    d=query(('sudo','-n','stat','-Lc','%u:%g %a %n',core.ROOT_LEASE),
            'ROOT_LEASE_DIRECTORY')
    s=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',l),
            'ROOT_LEASE_STAT')
    h=query(('sudo','-n','sha256sum',l),'ROOT_LEASE_SHA').split()
    need(len(h)==2 and h[1]==l,'ROOT_LEASE_SHA_FORMAT')
    return {'directory_stat':d,'lease_stat':s,'lease_sha256':h[0]}

def claim_readback(role):
    out={}
    for kind,path in core.markers(role).items():
        text=query(('sudo','-n','cat',path),'ROOT_CLAIM_CONTENT')+'\n'
        stat=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path),
                   'ROOT_CLAIM_STAT')
        out[kind]={'stat':stat,'content':text}
    return out

def replay(plan_path,boot_path,expected_role=None):
    private(plan_path,'plan')
    role=read(plan_path/'plan.json')['role']
    if expected_role is not None:
        need(role==expected_role,'REPLAY_ROLE_CHANGED')
    before,proposal=verify_plan(plan_path,role)
    private(boot_path,'boot')
    need({p.name for p in boot_path.iterdir()}==BOOT_FILES,
         'BOOT_RECEIPT_FILE_SET_CHANGED')
    intent=read(boot_path/'intent.json')
    need(intent=={'schema':core.SCHEMA+'-intent','plan_sha256':core.sha(proposal),
                 'role':role,'guest':core.guest(role),
                 'start_command':list(core.command(role)),
                 'one_physical_boot':True,'traffic_authorized':False,
                 'p8_operational':'NO-GO'},'BOOT_INTENT_CHANGED')
    for name in ('grant-dir-command.json','grant-file-command.json'):
        item=read(boot_path/name)
        need(item['rc']==0 and item['timeout'] is False and
             item['truncated'] is False,'ROOT_GRANT_NOT_ATTESTED_'+name)
    live=read(boot_path/'live-xml.json')
    need(live['rc']==0 and live['timeout'] is False and
         live['truncated'] is False,'LIVE_XML_NOT_ATTESTED')
    receipt=core.classify(before,read(boot_path/'after.json'),
             read(boot_path/'start-command.json'),live['stdout'],
             read(boot_path/'ticket.json'),read(boot_path/'grant-readback.json'),
             read(boot_path/'claim-readback.json'),role,proposal['previous'],
             legacy,f4,f6)
    need(receipt==read(boot_path/'receipt.json'),'RECEIPT_REPLAY_DRIFT')
    need(prior.private_bytes(plan_path/'boot.once')==b'ATTEMPTED\n',
         'BOOT_ONCE_MARKER_MISSING')
    return receipt

def boot(path,role):
    source()
    before,proposal=verify_plan(path,role)
    need(not (path/'boot.once').exists(),'BOOT_ALREADY_ATTEMPTED')
    fresh=snapshot(role)
    core.boundary(before,fresh,role,legacy,f4,f6)
    folder=Path(tempfile.mkdtemp(prefix='boot-',dir=ROOT))
    private(folder,'boot')
    write(folder/'intent.json',{
        'schema':core.SCHEMA+'-intent','plan_sha256':core.sha(proposal),
        'role':role,'guest':core.guest(role),
        'start_command':list(core.command(role)),
        'one_physical_boot':True,'traffic_authorized':False,
        'p8_operational':'NO-GO'})
    # Durable one-use record BEFORE any privileged operation or virsh start.
    write(path/'boot.once',b'ATTEMPTED\n')
    ticket_doc=core.ticket(role,int(time.time()),secrets.token_hex(32))
    write(folder/'ticket.json',ticket_doc)
    try:
        d=host(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',
                core.ROOT_LEASE))
        write(folder/'grant-dir-command.json',d)
        need(d['rc']==0 and not d['timeout'] and not d['truncated'],
             'ROOT_LEASE_DIRECTORY_UNCERTAIN')
        install=host(('sudo','-n','install','-o','root','-g','root','-m','0600',
                      str(folder/'ticket.json'),core.lease(role)))
        write(folder/'grant-file-command.json',install)
        need(install['rc']==0 and not install['timeout'] and not install['truncated'],
             'ROOT_LEASE_FILE_UNCERTAIN')
        grant=grant_readback(role)
        need(grant['lease_sha256']==core.digest(core.canon(ticket_doc)),
             'ROOT_LEASE_SHA_CHANGED')
        write(folder/'grant-readback.json',grant)
        need(int(time.time()) < ticket_doc['expires_at'] - 30,
             'ROOT_LEASE_TIME_BUDGET_EXCEEDED')
        # SINGLE physical start. No retry after any kind of uncertainty.
        started=host(core.command(role),timeout=90)
        write(folder/'start-command.json',started)
        after=f6.capture()
        write(folder/'after.json',after)
        need(started['rc']==0 and started['timeout'] is False and
             started['truncated'] is False,'PHYSICAL_VM_START_UNCERTAIN')
        live=host(('virsh','--readonly','-c','qemu:///system','dumpxml',core.guest(role)))
        write(folder/'live-xml.json',live)
        need(live['rc']==0 and live['timeout'] is False and
             live['truncated'] is False,'LIVE_VM_XML_UNCERTAIN')
        claims=claim_readback(role)
        write(folder/'claim-readback.json',claims)
        receipt=core.classify(before,after,started,live['stdout'],ticket_doc,
                              grant,claims,role,proposal['previous'],legacy,f4,f6)
        write(folder/'receipt.json',receipt)
        replay(path,folder,expected_role=role)
    except (OSError,ValueError,TypeError,KeyError,OverflowError) as exc:
        print('R112_F12_INCIDENT='+str(folder))
        print('R112_F12_STOP=PHYSICAL_BOOT_NOT_ATTESTED')
        print('R112_F12_REASON='+type(exc).__name__+':'+str(exc)[:190])
        print('R112_F12_ACTION=NO_RETRY_NO_AUTO_SHUTDOWN_NO_LEASE_CLEANUP')
        print('R112_F12_P8=NO-GO')
        return 24
    print('R112_F12_ROLE='+role.upper())
    print('R112_F12_QEMU=RUNNING_ATTESTED')
    print('R112_F12_R34=DENY_PRESERVED')
    print('R112_F12_F11=PREPARE_START_STARTED')
    print('R112_F12_RECEIPT='+str(folder/'receipt.json'))
    print('R112_F12_RECEIPT_SHA256='+core.digest((folder/'receipt.json').read_bytes()))
    print('R112_F12_PROTOCOL=NOT_TESTED')
    print('R112_F12_P8=NO-GO')
    print('R112_F12_RESULT=POSTREBOOT_BOOT_ONLY_ATTESTED')
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan',action='store_true')
    group.add_argument('--boot',action='store_true')
    group.add_argument('--replay',action='store_true')
    p.add_argument('--role',required=True,choices=core.ROLES)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--receipt',type=Path)
    p.add_argument('--previous-ssh-plan',type=Path)
    p.add_argument('--previous-ssh-receipt',type=Path)
    p.add_argument('--i-authorize-one-real-postreboot-boot-r34-deny',action='store_true')
    a=p.parse_args()
    try:
        if a.plan:
            return plan(a.role,a.previous_ssh_plan,a.previous_ssh_receipt)
        source()
        if a.boot:
            need(a.i_authorize_one_real_postreboot_boot_r34_deny,
                 'EXPLICIT_PHYSICAL_AUTHORIZATION_REQUIRED')
            need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
            return boot(a.plan_session,a.role)
        need(a.plan_session is not None and a.receipt is not None,
             'PLAN_AND_RECEIPT_REQUIRED')
        need(a.receipt.name=='receipt.json','RECEIPT_FILE_NAME')
        result=replay(a.plan_session,a.receipt.parent,expected_role=a.role)
        print('R112_F12_REPLAY=PASS')
        print('R112_F12_ROLE='+a.role.upper())
        print('R112_F12_RECEIPT_SHA256='+core.sha(result))
        print('R112_F12_P8=NO-GO')
        return 0
    except (OSError,ValueError,TypeError,KeyError,OverflowError) as exc:
        print('R112_F12_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R112_F12_ACTION=NO_RETRY_NO_AUTO_CLEANUP')
        print('R112_F12_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
