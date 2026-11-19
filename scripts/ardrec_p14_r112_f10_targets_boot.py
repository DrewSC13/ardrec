#!/usr/bin/env python3
"""R112-F10: plan/replay or explicitly authorize one FTP / SMB boot, no traffic.

FTP must be physically attested before planning SMB. No retry/cleanup on failure.
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

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r112_f10_targets_boot as core
from ardrec.coordination import r112_f9_runner_boot as f9
from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_runner_nic_definition as nic
import ardrec_p14_r112_f12_postreboot_boot as f12cli
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_runner_nic_definition as prior

ROOT=Path('/home/cicada/ardrec-lab/r112-f10-real-ftp-smb-boot-v1')
BRANCH='feat/p14-r111-r114-real-lab'
F12_BASE=Path('/home/cicada/ardrec-lab/r112-f12-postreboot-ssh-runner-v1')
F12_SSH_PLAN=F12_BASE/'plan-p_d18xuz'
F12_SSH_BOOT=F12_BASE/'boot-z87d2uaq'
F12_SSH_RECEIPT_SHA='3a19519eadb17120a473247f3aedc6e232de56026da3b6048cf1cbe017ad3924'
F12_RUNNER_PLAN=F12_BASE/'plan-c_9jb1os'
F12_RUNNER_BOOT=F12_BASE/'boot-1_efqr9q'
F12_RUNNER_RECEIPT_SHA='7c18d2e07710e92d8f37bdd214a68c84c0004f0d84e333202f099618562a80b5'
SOURCE_PIN={
  'src/ardrec/coordination/r112_f10_targets_boot.py':
    '1137c75d181d8130a88b830553cf701e3fe0e77a9e8751a6b63648cb38cb8100',
  'src/ardrec/coordination/r112_f9_runner_boot.py':
    '523a84db936010dbc96f8d5b419f152f5d25bc7316dff32d1da7a8070b80e189',
  'scripts/ardrec_p14_r112_f9_runner_boot.py':
    '0a1c9fc668e05614787d5fd1d7dd76609f64693c8704246cda76281e9c04070a',
  'src/ardrec/coordination/r112_f8_ssh_positive_boot.py':
    '514a2a6e7b749b5b400553bced11308cbfb2aa9431fe480d69a0618ddea7f485',
}
PLAN_FILES={'before.json','plan.json','manifest.json'}
BOOT_FILES={'intent.json','ticket.json','grant-dir-command.json',
            'grant-file-command.json','grant-readback.json',
            'start-command.json','after.json','live-xml.json',
            'claim-readback.json','receipt.json'}


def need(ok,reason): core.need(ok,reason)

def host(cmd,timeout=20):
    try:
        p=subprocess.run(tuple(cmd),stdin=subprocess.DEVNULL,
                         capture_output=True,timeout=timeout,check=False)
        stdout=p.stdout[:legacy.MAX_CAPTURE];stderr=p.stderr[:2048]
        return {'rc':p.returncode,'stdout':stdout.decode('utf-8','replace'),
                'stderr':stderr.decode('utf-8','replace'),'timeout':False,
                'truncated':len(p.stdout)>len(stdout) or len(p.stderr)>len(stderr)}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {'rc':None,'stdout':'','stderr':type(exc).__name__,
                'timeout':isinstance(exc,subprocess.TimeoutExpired),'truncated':False}

def query(command,reason):
    result=host(command)
    need(result['rc']==0 and result['timeout'] is False and
         result['truncated'] is False,reason)
    return result['stdout'].strip()

def source(descendant=False):
    need(Path.cwd().resolve()==REPO,'REPO_CWD_CHANGED')
    need(query(('git','branch','--show-current'),'BRANCH_READ')==BRANCH,
         'WRONG_BRANCH')
    current=query(('git','rev-parse','HEAD'),'HEAD_READ')
    if descendant:
        need(host(('git','merge-base','--is-ancestor',core.PARENT,current))['rc']==0,
             'BASE_COMMIT_NOT_ANCESTOR')
        need(query(('git','status','--porcelain=v1','-uall'),'GIT_STATUS')=='',
             'WORKTREE_NOT_CLEAN')
        for rel in ('src/ardrec/coordination/r112_f10_targets_boot.py',
                    'scripts/ardrec_p14_r112_f10_targets_boot.py'):
            need(host(('git','ls-files','--error-unmatch',rel))['rc']==0 and
                 host(('git','diff','--quiet','HEAD','--',rel))['rc']==0,
                 'F10_SOURCE_NOT_TRACKED_OR_MODIFIED_'+rel)
    else:
        need(current==core.PARENT,'HEAD_CHANGED_BEFORE_COMMIT')
    for rel,digest in SOURCE_PIN.items():
        path=REPO/rel
        need(path.is_file() and not path.is_symlink() and
             hashlib.sha256(path.read_bytes()).hexdigest()==digest,
             'PINNED_SOURCE_CHANGED_'+rel)

def previous_runner():
    # Both reboots are durable physical records. Never substitute historical F9.
    ssh_receipt=F12_SSH_BOOT/'receipt.json'
    runner_receipt=F12_RUNNER_BOOT/'receipt.json'
    need(all(p.is_dir() and not p.is_symlink() for p in
             (F12_SSH_PLAN,F12_RUNNER_PLAN,F12_SSH_BOOT,F12_RUNNER_BOOT)),
         'F12_PRIVATE_PREDECESSOR_MISSING')
    for path,digest in ((ssh_receipt,F12_SSH_RECEIPT_SHA),
                        (runner_receipt,F12_RUNNER_RECEIPT_SHA)):
        need(path.is_file() and not path.is_symlink() and
             core.digest(path.read_bytes())==digest,
             'F12_PHYSICAL_PREDECESSOR_CHANGED')
    ssh=f12cli.replay(F12_SSH_PLAN,F12_SSH_BOOT,expected_role='ssh')
    runner=f12cli.replay(F12_RUNNER_PLAN,F12_RUNNER_BOOT,expected_role='runner')
    from ardrec.coordination import r112_f12_postreboot_boot as f12core
    need(ssh==json.loads(ssh_receipt.read_bytes()) and
         runner==json.loads(runner_receipt.read_bytes()) and
         ssh['guest_states']==f12core.expected('ssh',True) and
         runner['guest_states']==f12core.expected('runner',True) and
         runner['predecessor_sha256']==F12_SSH_RECEIPT_SHA and
         ssh['traffic_authorized'] is False and
         runner['traffic_authorized'] is False and
         ssh['p8_operational']=='NO-GO' and
         runner['p8_operational']=='NO-GO' and
         runner['protocol_tested'] is False,
         'F12_PHYSICAL_PREDECESSOR_REPLAY_INVALID')
    return core.digest(runner_receipt.read_bytes())

def private(folder,prefix):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith(prefix) and not folder.is_symlink(),
         'PRIVATE_SCOPE')
    prior.directory(folder)

def store(path,obj):
    prior.store(path,core.canon(obj) if isinstance(obj,dict) else obj)

def read(path):
    return prior.read_json(path)

def previous_receipt(role,ftp_plan=None,ftp_receipt=None):
    core.target_ok(role)
    anchor=previous_runner()
    if role=='ftp':
        need(ftp_plan is None and ftp_receipt is None,'FTP_MUST_LINK_F12_ONLY')
        return {'type':'F12_RUNNER','plan':str(F12_RUNNER_PLAN),
                'receipt':str(F12_RUNNER_BOOT/'receipt.json'),
                'receipt_sha256':anchor}
    need(isinstance(ftp_plan, Path) and isinstance(ftp_receipt, Path),
         'SMB_REQUIRES_FTP_PLAN_AND_RECEIPT')
    private(ftp_plan,'plan-')
    need(ftp_receipt.name=='receipt.json','FTP_RECEIPT_FILENAME')
    boot_dir=ftp_receipt.parent
    private(boot_dir,'boot-')
    result=replay(ftp_plan,boot_dir,expected_role='ftp')
    need(result['target']=='ftp' and result['ftp_running'] is True and
         result['smb_running'] is False and result['traffic_authorized'] is False,
         'FTP_PREDECESSOR_NOT_ACREDITED')
    return {'type':'F10_FTP','plan':str(ftp_plan),'receipt':str(ftp_receipt),
            'receipt_sha256':core.digest(ftp_receipt.read_bytes())}

def preboot(role):
    core.target_ok(role)
    snapshot=f6.capture()
    core.audited(snapshot,role,after=False,legacy=legacy,f4=f4)
    # A stale grant/marker cannot be replaced; intentional no recovery here.
    for path in (core.lease(role),*core.markers(role).values()):
        for option in ('!','-L'):
            cmd=('sudo','-n','test','!','-e',path) if option=='!' else (
                'sudo','-n','test','!','-L',path)
            result=host(cmd)
            need(result['rc']==0 and result['timeout'] is False,
                 'TARGET_LEASE_MARKER_OR_SYMLINK_PRESENT')
    return snapshot

def verify_plan(path,role):
    core.target_ok(role)
    private(path,'plan-')
    actual={p.name for p in path.iterdir()}
    need(actual-{'boot.once'}==PLAN_FILES,'PLAN_FILE_SET_CHANGED')
    if 'boot.once' in actual:
        need(prior.private_bytes(path/'boot.once')==b'ATTEMPTED\n',
             'BOOT_ONCE_MARKER_INVALID')
    before,plan_doc,manifest=(read(path/name) for name in
                              ('before.json','plan.json','manifest.json'))
    core.audited(before,role,after=False,legacy=legacy,f4=f4)
    need(plan_doc['schema']==core.SCHEMA+'-plan' and
         plan_doc['parent']==core.PARENT and plan_doc['target']==role and
         plan_doc['guest']==core.guest(role) and
         plan_doc['command']==list(core.start(role)) and
         plan_doc['permit_seconds']==core.TTL and
         plan_doc['expected_before']==core.expected(role,False) and
         plan_doc['expected_after']==core.expected(role,True) and
         plan_doc['physical_before_sha256']==core.sha(before) and
         plan_doc['traffic_authorized'] is False and
         plan_doc['p8_operational']=='NO-GO' and
         set(plan_doc)=={'schema','parent','target','guest','command',
                         'permit_seconds','expected_before','expected_after',
                         'physical_before_sha256','previous','traffic_authorized',
                         'p8_operational'},'PLAN_CONTRACT_CHANGED')
    predecessor=plan_doc['previous']
    need(type(predecessor) is dict and
         set(predecessor)=={'type','plan','receipt','receipt_sha256'},
         'PREDECESSOR_SCHEMA')
    # Replay the predecessor rather than accept a mutable string or arbitrary file.
    if role=='ftp':
        expected_prev=previous_receipt('ftp')
    else:
        expected_prev=previous_receipt('smb',Path(predecessor['plan']),
                                        Path(predecessor['receipt']))
    need(predecessor==expected_prev,'PREDECESSOR_DRIFT')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                   'before_sha256':core.sha(before),
                   'plan_sha256':core.sha(plan_doc),'p8_operational':'NO-GO'},
         'PLAN_MANIFEST_CHANGED')
    return before,plan_doc

def plan(role,ftp_plan=None,ftp_receipt=None):
    source(descendant=True)
    previous=previous_receipt(role,ftp_plan,ftp_receipt)
    before=preboot(role)
    proposal={'schema':core.SCHEMA+'-plan','parent':core.PARENT,
              'target':role,'guest':core.guest(role),
              'command':list(core.start(role)),
              'permit_seconds':core.TTL,
              'expected_before':core.expected(role,False),
              'expected_after':core.expected(role,True),
              'physical_before_sha256':core.sha(before),
              'previous':previous,'traffic_authorized':False,
              'p8_operational':'NO-GO'}
    manifest={'schema':core.SCHEMA+'-manifest',
              'before_sha256':core.sha(before),
              'plan_sha256':core.sha(proposal),'p8_operational':'NO-GO'}
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    private(folder,'plan-')
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',manifest)):
        store(folder/name,obj)
    verify_plan(folder,role)
    print('R112_F10_TARGET='+role.upper())
    print('R112_F10_PLAN=READY_ONE_TARGET_BOOT_NO_TRAFFIC')
    print('R112_F10_PLAN_SESSION='+str(folder))
    print('R112_F10_PLAN_SHA256='+core.sha(proposal))
    print('R112_F10_REAL_STARTS=0')
    print('R112_F10_P8=NO-GO')
    return 0

def grant_readback(role):
    path=core.lease(role)
    directory=query(('sudo','-n','stat','-Lc','%u:%g %a %n',core.LEASE_ROOT),
                    'ROOT_LEASE_DIR_READ')
    filestat=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path),
                   'ROOT_LEASE_STAT_READ')
    out=query(('sudo','-n','sha256sum',path),'ROOT_LEASE_SHA_READ')
    parts=out.split()
    need(len(parts)==2 and parts[1]==path,'LEASE_SHA_OUTPUT_INVALID')
    return {'directory_stat':directory,'lease_stat':filestat,'lease_sha256':parts[0]}

def claim_readback(role):
    claims={}
    for kind,path in core.markers(role).items():
        content=query(('sudo','-n','cat',path),'ROOT_CLAIM_READ')+'\n'
        stat=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path),
                   'ROOT_CLAIM_STAT_READ')
        claims[kind]={'stat':stat,'content':content}
    return claims

def verify_boundary(before,now,role):
    core.audited(now,role,after=False,legacy=legacy,f4=f4)
    a,b=before['snapshot']['probes'],now['snapshot']['probes']
    for key in ([f'vm-{r}-{field}' for r in core.ROLES
                 for field in ('inactive-xml','block','state')]
                +['f11-hook-stat','f11-hook-hash','deny-nwfilter-xml']):
        need(a[key]['stdout']==b[key]['stdout'],'PLAN_TO_BOOT_DRIFT_'+key)
    for r in core.NETWORKS:
        key='net-'+r+'-xml'
        need(f8._r112_f8_static_network_xml(a[key]['stdout'])==
             f8._r112_f8_static_network_xml(b[key]['stdout']),
             'PLAN_TO_BOOT_NETWORK_DRIFT_'+r)
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),
         'PLAN_TO_BOOT_R34_DRIFT')
    need(before['other_domains']==now['other_domains'] and
         before['english_info']==now['english_info'],
         'PLAN_TO_BOOT_SCOPE_DRIFT')
    return True

def boot(path,role):
    source(descendant=True)
    before,proposal=verify_plan(path,role)
    need(not (path/'boot.once').exists(),'TARGET_BOOT_ALREADY_ATTEMPTED')
    now=preboot(role)
    verify_boundary(before,now,role)
    folder=Path(tempfile.mkdtemp(prefix='boot-',dir=ROOT))
    private(folder,'boot-')
    store(folder/'intent.json',{'schema':core.SCHEMA+'-intent',
          'plan_sha256':core.sha(proposal),'target':role,'guest':core.guest(role),
          'command':list(core.start(role)),'one_real_boot':True,
          'authorized_network_traffic':False,'p8_operational':'NO-GO'})
    # Durable one-use token before *any* root action or physical start.
    store(path/'boot.once',b'ATTEMPTED\n')
    token=core.ticket(role,int(time.time()),secrets.token_hex(32))
    store(folder/'ticket.json',token)
    try:
        cmd=host(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',
                  core.LEASE_ROOT))
        store(folder/'grant-dir-command.json',cmd)
        need(cmd['rc']==0 and not cmd['timeout'] and not cmd['truncated'],
             'LEASE_DIRECTORY_UNCERTAIN')
        cmd=host(('sudo','-n','install','-o','root','-g','root','-m','0600',
                  str(folder/'ticket.json'),core.lease(role)))
        store(folder/'grant-file-command.json',cmd)
        need(cmd['rc']==0 and not cmd['timeout'] and not cmd['truncated'],
             'LEASE_INSTALL_UNCERTAIN')
        grant=grant_readback(role)
        need(grant['lease_sha256']==core.digest(core.canon(token)),
             'LEASE_HASH_MISMATCH')
        store(folder/'grant-readback.json',grant)
        need(int(time.time())<token['expires_at']-30,'LEASE_TIME_BUDGET_EXHAUSTED')
        started=host(core.start(role),timeout=90)
        store(folder/'start-command.json',started)
        after=f6.capture()
        store(folder/'after.json',after)
        need(started['rc']==0 and not started['timeout'] and
             not started['truncated'],'TARGET_START_UNCERTAIN')
        live=host(('virsh','--readonly','-c','qemu:///system','dumpxml',core.guest(role)))
        store(folder/'live-xml.json',live)
        need(live['rc']==0 and not live['timeout'] and not live['truncated'],
             'TARGET_LIVE_XML_UNCERTAIN')
        claims=claim_readback(role)
        store(folder/'claim-readback.json',claims)
        rec=core.classify(before,after,started,live['stdout'],token,grant,claims,
                          role,legacy=legacy,f4=f4)
        store(folder/'receipt.json',rec)
        replay(path,folder,expected_role=role)
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as exc:
        print('R112_F10_INCIDENT_RECEIPT='+str(folder))
        print('R112_F10_STOP=TARGET_BOOT_NOT_ATTESTED')
        print('R112_F10_REASON='+type(exc).__name__+':'+str(exc)[:180])
        print('R112_F10_ACTION=NO_RETRY_NO_AUTO_SHUTDOWN_NO_LEASE_CLEANUP')
        print('R112_F10_P8=NO-GO')
        return 24
    print('R112_F10_TARGET='+role.upper())
    print('R112_F10_TARGET_QEMU=RUNNING_VERIFIED')
    print('R112_F10_SSH_RUNNER_QEMU=STILL_RUNNING_VERIFIED')
    print('R112_F10_R34=DENY_PRESERVED')
    print('R112_F10_F11=PREPARE_START_STARTED')
    print('R112_F10_RECEIPT='+str(folder/'receipt.json'))
    print('R112_F10_RECEIPT_SHA256='+core.digest((folder/'receipt.json').read_bytes()))
    print('R112_F10_REAL_PROTOCOL_OBSERVATIONS=NONE')
    print('R112_F10_A5_A6_A7_A9=NOT_ATTESTED')
    print('R112_F10_P8=NO-GO')
    print('R112_F10_RESULT=TARGET_BOOT_ATTESTED_DENY_ONLY')
    return 0

def replay(plan_dir,boot_dir,expected_role=None):
    private(plan_dir,'plan-')
    role=read(plan_dir/'plan.json')['target']
    if expected_role is not None:
        need(role==expected_role,'WRONG_REPLAY_TARGET')
    before,proposal=verify_plan(plan_dir,role)
    private(boot_dir,'boot-')
    need({p.name for p in boot_dir.iterdir()}==BOOT_FILES,
         'BOOT_RECEIPT_FILES_CHANGED')
    intent=read(boot_dir/'intent.json')
    need(intent=={'schema':core.SCHEMA+'-intent',
                 'plan_sha256':core.sha(proposal),'target':role,'guest':core.guest(role),
                 'command':list(core.start(role)),'one_real_boot':True,
                 'authorized_network_traffic':False,'p8_operational':'NO-GO'},
         'INTENT_CHANGED')
    for name in ('grant-dir-command.json','grant-file-command.json'):
        result=read(boot_dir/name)
        need(result['rc']==0 and result['timeout'] is False and
             result['truncated'] is False,'ROOT_GRANT_UNATTESTED_'+name)
    live=read(boot_dir/'live-xml.json')
    need(live['rc']==0 and live['timeout'] is False and
         live['truncated'] is False,'LIVE_XML_UNATTESTED')
    rec=core.classify(before,read(boot_dir/'after.json'),
         read(boot_dir/'start-command.json'),live['stdout'],
         read(boot_dir/'ticket.json'),read(boot_dir/'grant-readback.json'),
         read(boot_dir/'claim-readback.json'),role,legacy=legacy,f4=f4)
    need(rec==read(boot_dir/'receipt.json'),'RECEIPT_REPLAY_DRIFT')
    need(prior.private_bytes(plan_dir/'boot.once')==b'ATTEMPTED\n',
         'BOOT_ONCE_MARKER_MISSING')
    return rec

def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan',action='store_true')
    group.add_argument('--boot',action='store_true')
    group.add_argument('--replay',action='store_true')
    p.add_argument('--target',choices=core.TARGETS,required=True)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--receipt',type=Path)
    p.add_argument('--previous-ftp-plan',type=Path)
    p.add_argument('--previous-ftp-receipt',type=Path)
    p.add_argument('--i-authorize-one-real-target-boot-under-r34-deny',
                   action='store_true')
    a=p.parse_args()
    try:
        if a.plan:
            need(a.plan_session is None and a.receipt is None,
                 'PLAN_MODE_EXTRANEOUS_ARGS')
            return plan(a.target,a.previous_ftp_plan,a.previous_ftp_receipt)
        source(descendant=True)
        need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
        if a.boot:
            need(a.i_authorize_one_real_target_boot_under_r34_deny,
                 'EXPLICIT_OPERATOR_CONSENT_REQUIRED')
            need(a.receipt is None,'UNEXPECTED_RECEIPT_ARG')
            return boot(a.plan_session,a.target)
        need(a.receipt is not None,'REPLAY_REQUIRES_RECEIPT')
        rec=replay(a.plan_session,a.receipt.parent,expected_role=a.target)
        need(a.receipt.name=='receipt.json','REPLAY_RECEIPT_NAME')
        print('R112_F10_REPLAY=PASS_'+a.target.upper())
        print('R112_F10_RECEIPT_SHA256='+core.digest(a.receipt.read_bytes()))
        print('R112_F10_P8=NO-GO')
        return 0
    except (OSError,ValueError,KeyError,TypeError,OverflowError,
            subprocess.TimeoutExpired) as exc:
        print('R112_F10_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R112_F10_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
