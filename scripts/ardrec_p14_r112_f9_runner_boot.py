#!/usr/bin/env python3
"""R112-F9: plan or explicitly authorize ONE runner boot under R34 DENY.

Only the --boot-runner mode changes host state: root-scoped runner lease and one
virsh start. Never retry, destroy, reboot, change networks/firewall or clear markers.
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
from ardrec.coordination import r112_f9_runner_boot as core
from ardrec.coordination import r112_f8_ssh_positive_boot as f8
import ardrec_p14_r112_f8s_reconcile as f8s
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_runner_nic_definition as prior

ROOT=Path('/home/cicada/ardrec-lab/r112-f9-real-runner-boot-v1')
PRIOR_RECEIPT=Path('/home/cicada/ardrec-lab/r112-f8s-reconciliation-v1/reconcile-x8d4l0tu/receipt.json')
PRIOR_RECEIPT_SHA='c03816343ced7bd471a7f7c62a0295176d8d23c67e67d8b52668c19dff5bee36'
BRANCH='feat/p14-r111-r114-real-lab'
F8_SOURCE_SHA='514a2a6e7b749b5b400553bced11308cbfb2aa9431fe480d69a0618ddea7f485'
PLAN_FILES={'before.json','plan.json','manifest.json'}
RECEIPT_FILES={'intent.json','ticket.json','grant-dir-command.json',
               'grant-file-command.json','grant-readback.json',
               'start-command.json','after.json','live-xml.json',
               'claim-readback.json','receipt.json'}


def need(ok,reason): core.need(ok,reason)

def host(cmd,timeout=16):
    try:
        p=subprocess.run(tuple(cmd),stdin=subprocess.DEVNULL,
                         capture_output=True,timeout=timeout,check=False)
        stdout=p.stdout[:legacy.MAX_CAPTURE]
        stderr=p.stderr[:2048]
        return {'rc':p.returncode,'stdout':stdout.decode('utf-8','replace'),
                'stderr':stderr.decode('utf-8','replace'),
                'timeout':False,
                'truncated':len(p.stdout)>len(stdout) or len(p.stderr)>len(stderr)}
    except (OSError,subprocess.TimeoutExpired) as exc:
        return {'rc':None,'stdout':'','stderr':type(exc).__name__,
                'timeout':isinstance(exc,subprocess.TimeoutExpired),'truncated':False}

def query(cmd,reason):
    r=host(cmd)
    need(r['rc']==0 and not r['timeout'] and not r['truncated'],reason)
    return r['stdout'].strip()

def source(*, descendant=False):
    need(Path.cwd().resolve()==REPO,'REPO_CWD_CHANGED')
    need(query(('git','branch','--show-current'),'GIT_BRANCH')==BRANCH,'BRANCH_CHANGED')
    head=query(('git','rev-parse','HEAD'),'GIT_HEAD')
    if descendant:
        need(host(('git','merge-base','--is-ancestor',core.PARENT,head))['rc']==0,
             'BASE_COMMIT_NOT_ANCESTOR')
        need(query(('git','status','--porcelain=v1','-uall'),'GIT_STATUS')=='',
             'WORKTREE_NOT_CLEAN')
        for rel in ('src/ardrec/coordination/r112_f9_runner_boot.py',
                    'scripts/ardrec_p14_r112_f9_runner_boot.py'):
            need(host(('git','diff','--quiet','HEAD','--',rel))['rc']==0 and
                 host(('git','ls-files','--error-unmatch',rel))['rc']==0,
                 'F9_SOURCE_NOT_TRACKED_OR_MODIFIED_'+rel)
    else:
        need(head==core.PARENT,'HEAD_CHANGED')
    for rel,digest in (
        ('src/ardrec/coordination/r112_f8_ssh_positive_boot.py',F8_SOURCE_SHA),
        ('lab/f11-runtime-v3/00-ardrec-r33-admission',f8.HOOK_SHA),
    ):
        path=REPO/rel
        need(path.is_file() and not path.is_symlink() and
             hashlib.sha256(path.read_bytes()).hexdigest()==digest,
             'PINNED_SOURCE_DRIFT_'+rel)

def prior_receipt():
    need(PRIOR_RECEIPT.is_file() and not PRIOR_RECEIPT.is_symlink(),
         'F8S_PRIOR_RECEIPT_MISSING')
    raw=PRIOR_RECEIPT.read_bytes()
    need(core.digest(raw)==PRIOR_RECEIPT_SHA,'F8S_PRIOR_RECEIPT_HASH_CHANGED')
    rec=json.loads(raw)
    need(rec['schema']=='ardrec-r112-f8s-original-incident-reconciliation-v1' and
         rec['original_outcome']=='POSITIVE_BOOT_NOT_ATTESTED_PRESERVED' and
         rec['reason_original']=='STATIC_RESOURCE_CHANGED_net-ssh-xml' and
         rec['reclassified_original_event']['guest_running'] is True and
         rec['reclassified_original_event']['traffic_granted'] is False and
         rec['repeated_start'] is False and rec['host_mutations'] is False and
         rec['p8_operational']=='NO-GO' and rec['permit_traffic'] is False,
         'F8S_PRIOR_RECEIPT_SEMANTICS_CHANGED')
    # Validate chain back to physical original, including all F11 claims.
    records=f8s.read_original()
    f8s.validate_historical(f8,legacy,f4,f6,records)
    return rec

def private(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         path.name.startswith(prefix) and not path.is_symlink(),
         'PRIVATE_SCOPE')
    prior.directory(path)

def write(path,obj):
    prior.store(path,core.canon(obj) if isinstance(obj,dict) else obj)

def read(path): return prior.read_json(path)

def preboot():
    # F8S proved host SSH RUNNING, runner/ftp/smb OFF; repeat read at this instant.
    before=f6.capture()
    f8.audited(before,ssh_running=True,legacy=legacy,f4=f4,f6=f6)
    core.audited(before,runner_running=False,legacy=legacy,f4=f4)
    # No runner grant or claim may preexist; never replace stale lease or markers.
    for path in [core.LEASE,*core.MARKERS.values()]:
        result=host(('sudo','-n','test','!','-e',path))
        need(result['rc']==0 and not result['timeout'],
             'RUNNER_LEASE_OR_MARKER_ALREADY_EXISTS')
        result=host(('sudo','-n','test','!','-L',path))
        need(result['rc']==0 and not result['timeout'],
             'RUNNER_LEASE_SYMLINK_PRESENT')
    return before

def verify_plan(plan_dir):
    private(plan_dir,'plan-')
    items={p.name for p in plan_dir.iterdir()}
    need(items-{'boot.once'}==PLAN_FILES,'PLAN_FILE_SET_DRIFT')
    if 'boot.once' in items:
        need(prior.private_bytes(plan_dir/'boot.once')==b'ATTEMPTED\n',
             'BOOT_ONCE_MARKER_CHANGED')
    before,proposal,manifest=(read(plan_dir/f) for f in
                              ('before.json','plan.json','manifest.json'))
    core.audited(before,runner_running=False,legacy=legacy,f4=f4)
    need(proposal=={'schema':core.SCHEMA+'-plan',
                   'parent':core.PARENT,'prior_f8s_receipt_sha256':PRIOR_RECEIPT_SHA,
                   'physical_before_sha256':core.sha(before),'guest':core.GUEST,
                   'command':list(core.START),'permit_seconds':core.TTL,
                   'expected_before':{'ssh':'RUNNING','runner':'SHUTOFF',
                                      'ftp':'SHUTOFF','smb':'SHUTOFF'},
                   'expected_after':{'ssh':'RUNNING','runner':'RUNNING',
                                     'ftp':'SHUTOFF','smb':'SHUTOFF'},
                   'authorize_network_traffic':False,'p8_operational':'NO-GO'},
         'PLAN_CONTENT_DRIFT')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                   'before_sha256':core.sha(before),
                   'plan_sha256':core.sha(proposal),'p8_operational':'NO-GO'},
         'PLAN_MANIFEST_DRIFT')
    return before,proposal

def plan():
    source();prior_receipt()
    before=preboot()
    proposal={'schema':core.SCHEMA+'-plan',
              'parent':core.PARENT,'prior_f8s_receipt_sha256':PRIOR_RECEIPT_SHA,
              'physical_before_sha256':core.sha(before),'guest':core.GUEST,
              'command':list(core.START),'permit_seconds':core.TTL,
              'expected_before':{'ssh':'RUNNING','runner':'SHUTOFF',
                                 'ftp':'SHUTOFF','smb':'SHUTOFF'},
              'expected_after':{'ssh':'RUNNING','runner':'RUNNING',
                                'ftp':'SHUTOFF','smb':'SHUTOFF'},
              'authorize_network_traffic':False,'p8_operational':'NO-GO'}
    manifest={'schema':core.SCHEMA+'-manifest',
              'before_sha256':core.sha(before),
              'plan_sha256':core.sha(proposal),'p8_operational':'NO-GO'}
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    private(folder,'plan-')
    for file,obj in [('before.json',before),('plan.json',proposal),
                     ('manifest.json',manifest)]:write(folder/file,obj)
    verify_plan(folder)
    print('R112_F9_PLAN=READY_ONE_RUNNER_BOOT_NO_TRAFFIC')
    print('R112_F9_PLAN_SESSION='+str(folder))
    print('R112_F9_PLAN_SHA256='+core.sha(proposal))
    print('R112_F9_SSH_RUNNING=ATTESTED')
    print('R112_F9_RUNNER_STARTS=0')
    print('R112_F9_P8=NO-GO')
    return 0

def grant_readback():
    directory=query(('sudo','-n','stat','-Lc','%u:%g %a %n',core.ROOT),
                    'ROOT_LEASE_DIR_STAT')
    filestat=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',core.LEASE),
                   'ROOT_LEASE_FILE_STAT')
    output=query(('sudo','-n','sha256sum',core.LEASE),'ROOT_LEASE_SHA')
    fields=output.split()
    need(len(fields)==2 and fields[1]==core.LEASE,'ROOT_LEASE_SHA_FORMAT')
    return {'directory_stat':directory,'lease_stat':filestat,'lease_sha256':fields[0]}

def claim_readback():
    result={}
    for kind,path in core.MARKERS.items():
        body=query(('sudo','-n','cat',path),'ROOT_CLAIM_CONTENT')+'\n'
        info=query(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path),
                   'ROOT_CLAIM_STAT')
        result[kind]={'stat':info,'content':body}
    return result

def boot(plan_dir):
    source(descendant=True);prior_receipt()
    before,proposal=verify_plan(plan_dir)
    need(not (plan_dir/'boot.once').exists(), 'RUNNER_BOOT_ALREADY_ATTEMPTED')
    now=preboot()
    # Strong same-state check prior to any write; root dynamic counters tolerated.
    core.audited(now,runner_running=False,legacy=legacy,f4=f4)
    a,b=before['snapshot']['probes'],now['snapshot']['probes']
    for key in ([f'vm-{r}-{field}' for r in core.ROLES
                 for field in ('inactive-xml','block','state')]
                +['f11-hook-stat','f11-hook-hash','deny-nwfilter-xml']):
        need(a[key]['stdout']==b[key]['stdout'],'PLAN_TO_BOOT_DRIFT_'+key)
    for role in core.NETWORKS:
        key='net-'+role+'-xml'
        need(f8._r112_f8_static_network_xml(a[key]['stdout'])==
             f8._r112_f8_static_network_xml(b[key]['stdout']),
             'PLAN_TO_BOOT_NETWORK_DRIFT_'+role)
    from ardrec.coordination import r112_runner_nic_definition as nic
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),
         'PLAN_TO_BOOT_R34_DRIFT')
    need(before['other_domains']==now['other_domains'],
         'PLAN_TO_BOOT_UNRELATED_VM_SCOPE_DRIFT')
    need(before['english_info']==now['english_info'],
         'PLAN_TO_BOOT_NETWORK_STATE_DRIFT')
    folder=Path(tempfile.mkdtemp(prefix='boot-',dir=ROOT))
    private(folder,'boot-')
    write(folder/'intent.json',{'schema':core.SCHEMA+'-intent',
          'plan_sha256':core.sha(proposal),'guest':core.GUEST,
          'command':list(core.START),'one_real_runner_boot':True,
          'authorized_network_traffic':False,'p8_operational':'NO-GO'})
    # Durable marker BEFORE *any* root write, and before one virsh start.
    write(plan_dir/'boot.once',b'ATTEMPTED\n')
    now_seconds=int(time.time())
    token=core.ticket(now_seconds,secrets.token_hex(32))
    write(folder/'ticket.json',token)
    try:
        cmd=host(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',core.ROOT))
        write(folder/'grant-dir-command.json',cmd)
        need(cmd['rc']==0 and not cmd['timeout'] and not cmd['truncated'],
             'ROOT_LEASE_DIR_INSTALL_UNCERTAIN')
        cmd=host(('sudo','-n','install','-o','root','-g','root','-m','0600',
                  str(folder/'ticket.json'),core.LEASE))
        write(folder/'grant-file-command.json',cmd)
        need(cmd['rc']==0 and not cmd['timeout'] and not cmd['truncated'],
             'ROOT_LEASE_INSTALL_UNCERTAIN')
        grant=grant_readback()
        need(grant['lease_sha256']==core.digest(core.canon(token)),
             'ROOT_LEASE_NOT_PINNED')
        write(folder/'grant-readback.json',grant)
        need(int(time.time())<token['expires_at']-30,'LEASE_TIME_BUDGET_EXHAUSTED')
        result=host(core.START,timeout=90)
        write(folder/'start-command.json',result)
        after=f6.capture()
        write(folder/'after.json',after)
        need(result['rc']==0 and not result['timeout'] and not result['truncated'],
             'RUNNER_START_UNCERTAIN')
        live=host(('virsh','--readonly','-c','qemu:///system','dumpxml',core.GUEST))
        write(folder/'live-xml.json',live)
        need(live['rc']==0 and not live['timeout'] and not live['truncated'],
             'RUNNER_LIVE_XML_READ_FAILED')
        claims=claim_readback()
        write(folder/'claim-readback.json',claims)
        receipt=core.classify(before,after,result,live['stdout'],token,grant,claims,
                              legacy=legacy,f4=f4)
        write(folder/'receipt.json',receipt)
        replay(plan_dir,folder)
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as exc:
        print('R112_F9_INCIDENT_RECEIPT='+str(folder))
        print('R112_F9_STOP=RUNNER_BOOT_NOT_ATTESTED')
        print('R112_F9_REASON='+type(exc).__name__+':'+str(exc)[:180])
        print('R112_F9_ACTION=NO_RETRY_NO_AUTO_SHUTDOWN_NO_LEASE_CLEANUP')
        print('R112_F9_P8=NO-GO')
        return 24
    print('R112_F9_RUNNER_QEMU=RUNNING_VERIFIED')
    print('R112_F9_SSH_QEMU=STILL_RUNNING_VERIFIED')
    print('R112_F9_F11_PHASES=PREPARE_START_STARTED')
    print('R112_F9_R34=DENY_PRESERVED')
    print('R112_F9_RECEIPT='+str(folder/'receipt.json'))
    print('R112_F9_RECEIPT_SHA256='+core.digest((folder/'receipt.json').read_bytes()))
    print('R112_F9_SSH_FTP_SMB_PROTOCOL=NOT_TESTED')
    print('R112_F9_A5_A6_A7_A9=NOT_ATTESTED')
    print('R112_F9_P8=NO-GO')
    print('R112_F9_RESULT=RUNNER_BOOT_ATTESTED_DENY_ONLY')
    return 0

def replay(plan_dir,boot_dir):
    before,proposal=verify_plan(plan_dir)
    private(boot_dir,'boot-')
    need({p.name for p in boot_dir.iterdir()}==RECEIPT_FILES,
         'BOOT_RECEIPT_FILE_SET_CHANGED')
    intent=read(boot_dir/'intent.json')
    need(intent=={'schema':core.SCHEMA+'-intent',
                 'plan_sha256':core.sha(proposal),'guest':core.GUEST,
                 'command':list(core.START),'one_real_runner_boot':True,
                 'authorized_network_traffic':False,'p8_operational':'NO-GO'},
         'BOOT_INTENT_CHANGED')
    for key in ('grant-dir-command.json','grant-file-command.json'):
        result=read(boot_dir/key)
        need(result['rc']==0 and not result['timeout'] and not result['truncated'],
             'GRANT_COMMAND_NOT_ATTESTED_'+key)
    live=read(boot_dir/'live-xml.json')
    need(live['rc']==0 and not live['timeout'] and not live['truncated'],
         'RUNNER_LIVE_XML_NOT_ATTESTED')
    result=core.classify(before,read(boot_dir/'after.json'),
                         read(boot_dir/'start-command.json'),live['stdout'],
                         read(boot_dir/'ticket.json'),
                         read(boot_dir/'grant-readback.json'),
                         read(boot_dir/'claim-readback.json'),legacy=legacy,f4=f4)
    need(result==read(boot_dir/'receipt.json'),'F9_RECEIPT_REPLAY_DRIFT')
    need(prior.private_bytes(plan_dir/'boot.once')==b'ATTEMPTED\n',
         'ORIGINAL_ATTEMPT_MARKER_MISSING')
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--plan',action='store_true')
    g.add_argument('--verify-plan',type=Path)
    g.add_argument('--boot-runner',type=Path)
    g.add_argument('--replay-receipt',type=Path)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--i-authorize-one-real-runner-boot-under-r34-deny',
                   action='store_true')
    a=p.parse_args()
    try:
        if a.plan:return plan()
        source(descendant=True)
        if a.verify_plan:
            prior_receipt()
            before,proposal=verify_plan(a.verify_plan)
            print('R112_F9_PLAN_REPLAY=PASS')
            print('R112_F9_PLAN_SHA256='+core.sha(proposal))
            return 0
        if a.boot_runner:
            need(a.i_authorize_one_real_runner_boot_under_r34_deny,
                 'EXPLICIT_OPERATOR_AUTHORIZATION_REQUIRED')
            return boot(a.boot_runner)
        need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
        prior_receipt()
        value=replay(a.plan_session,a.replay_receipt)
        print('R112_F9_RECEIPT_REPLAY=PASS')
        print('R112_F9_RECEIPT_SHA256='+core.sha(value))
        print('R112_F9_P8=NO-GO')
        return 0
    except (OSError,ValueError,TypeError,KeyError,OverflowError,subprocess.TimeoutExpired) as exc:
        print('R112_F9_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R112_F9_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
