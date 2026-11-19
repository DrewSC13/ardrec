#!/usr/bin/env python3
"""R112-F8: one *real* libvirt SSH QEMU boot under preserved F11/R34 DENY.

Physical boot is optional and requires an exact explicit flag. Plan/replay are
host-readonly. One attempt; uncertain results never retry, shutdown, clean up
root marks, or grant any network traffic automatically.
"""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r112_f8_ssh_positive_boot as core
from ardrec.coordination import r112_f7_libvirt_negative as f7_core
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as prior
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f5_scoped_hook as f5
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r112_f7_libvirt_negative as f7

ROOT=Path('/home/cicada/ardrec-lab/r112-f8-real-ssh-boot-v1')
BRANCH='feat/p14-r111-r114-real-lab'
PLAN_FILES={'before.json','plan.json','manifest.json'}
RECEIPT_FILES={'intent.json','ticket.json','grant-dir-command.json',
               'grant-file-command.json','grant-readback.json',
               'start-command.json','after.json','live-xml.json',
               'claim-readback.json','receipt.json'}


def need(ok,code):
    core.need(ok,code)

def host(cmd,*,timeout=16):
    """Never use the shell. The QEMU start alone has a longer deadline."""
    try:
        p=subprocess.run(tuple(cmd),capture_output=True,stdin=subprocess.DEVNULL,
                         check=False,timeout=timeout)
        return {'rc':p.returncode,'stdout':p.stdout[:legacy.MAX_CAPTURE].decode('utf-8','replace'),
                'stderr':p.stderr[:2048].decode('utf-8','replace'),
                'timeout':False,'truncated':len(p.stdout)>legacy.MAX_CAPTURE or
                                       len(p.stderr)>2048}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'rc':None,'stdout':'','stderr':type(error).__name__,
                'timeout':isinstance(error,subprocess.TimeoutExpired),
                'truncated':False}

def checked(cmd, code):
    result=host(cmd)
    need(result['rc']==0 and result['timeout'] is False and
         result['truncated'] is False, code)
    return result['stdout']

def source(*,descendant=False):
    need(Path.cwd().resolve()==REPO,'MAIN_REPO_REQUIRED')
    need(checked(('git','branch','--show-current'),'GIT_BRANCH').strip()==BRANCH,
         'BRANCH_IDENTITY_CHANGED')
    if descendant:
        checked(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'),
                'SOURCE_NOT_DESCENDANT')
    else:
        need(checked(('git','rev-parse','HEAD'),'SOURCE_SHA').strip()==core.PARENT,
             'SOURCE_PARENT_CHANGED')
    candidate=REPO/'lab/f11-runtime-v3/00-ardrec-r33-admission'
    need(candidate.is_file() and not candidate.is_symlink() and
         hashlib.sha256(candidate.read_bytes()).hexdigest()==core.HOOK_SHA,
         'HOOK_CANDIDATE_CHANGED')

def private(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         path.name.startswith(prefix) and not path.is_symlink(),
         'PRIVATE_PATH_SCOPE')
    prior.directory(path)

def write(path,obj):
    prior.store(path,core.canon(obj) if type(obj) is dict else obj)

def read(path):
    return prior.read_json(path)

def provenance(f7plan,f7receipt,f6plan,f6receipt):
    verified=f7.verify_probe(f7plan,f7receipt,f6plan,f6receipt)
    need(verified['libvirt_denied_with_exact_hook_marker'] is True and
         verified['guest_remained_shutoff'] is True and
         verified['hook_sha256']==core.HOOK_SHA and
         verified['physical_guest_starts']==0,
         'F7_REAL_NEGATIVE_EVIDENCE_NOT_AUTHENTIC')
    return core.sha(verified)

def host_preflight():
    snapshot=f7.admit_current()  # F11 pinned, 0 grants, no running guests.
    core.audited(snapshot,ssh_running=False,legacy=legacy,f4=f4,f6=f6)
    return snapshot

def verify_plan(path,f7plan,f7receipt,f6plan,f6receipt):
    private(path,'plan-')
    items={p.name for p in path.iterdir()}
    need(items-{'boot.once'}==PLAN_FILES,'PLAN_FILE_SET')
    if 'boot.once' in items:
        need(prior.private_bytes(path/'boot.once')==b'ATTEMPTED\n',
             'BOOT_ONCE_MARKER_CHANGED')
    before,proposal,manifest=(read(path/name) for name in
                               ('before.json','plan.json','manifest.json'))
    core.audited(before,ssh_running=False,legacy=legacy,f4=f4,f6=f6)
    digest=provenance(f7plan,f7receipt,f6plan,f6receipt)
    need(proposal=={
        'schema':core.SCHEMA+'-plan',
        'source_parent':core.PARENT,
        'source_f7_physical_negative_sha256':digest,
        'physical_host_before_sha256':core.sha(before),
        'guest':core.GUEST,'command':list(core.START),
        'r34_policy':'DENY_ALL_TRAFFIC_PRESERVED',
        'permit_lifetime_seconds':core.TTL,
        'expected_running_after':core.GUEST,
        'other_three_guest_states':'SHUTOFF',
        'real_ssh_protocol_test':False,
        'operator_consent_required':True,
        'p8_operational':'NO-GO'},'PLAN_DRIFT')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                   'before_sha256':core.sha(before),
                   'plan_sha256':core.sha(proposal),
                   'p8_operational':'NO-GO'},'PLAN_MANIFEST_DRIFT')
    return before,proposal

def plan(f7plan,f7receipt,f6plan,f6receipt):
    source()
    digest=provenance(f7plan,f7receipt,f6plan,f6receipt)
    before=host_preflight()
    proposal={'schema':core.SCHEMA+'-plan',
              'source_parent':core.PARENT,
              'source_f7_physical_negative_sha256':digest,
              'physical_host_before_sha256':core.sha(before),
              'guest':core.GUEST,'command':list(core.START),
              'r34_policy':'DENY_ALL_TRAFFIC_PRESERVED',
              'permit_lifetime_seconds':core.TTL,
              'expected_running_after':core.GUEST,
              'other_three_guest_states':'SHUTOFF',
              'real_ssh_protocol_test':False,
              'operator_consent_required':True,
              'p8_operational':'NO-GO'}
    manifest={'schema':core.SCHEMA+'-manifest',
              'before_sha256':core.sha(before),
              'plan_sha256':core.sha(proposal),
              'p8_operational':'NO-GO'}
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    path=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    private(path,'plan-')
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',manifest)):
        write(path/name,obj)
    verify_plan(path,f7plan,f7receipt,f6plan,f6receipt)
    print('R112_F8_PLAN=ONE_REAL_SSH_BOOT_WITH_R34_DENY_READY')
    print('R112_F8_SSH_PRESTART=SHUTOFF')
    print('R112_F8_NETWORKS=ACTIVE_3')
    print('R112_F8_F7_PHYSICAL_DENIAL=VERIFIED')
    print('R112_F8_PLAN_SESSION='+str(path))
    print('R112_F8_VM_STARTS=0')
    print('R112_F8_P8=NO-GO')
    return 0

def _one(cmd):
    r=host(cmd)
    need(r['rc']==0 and r['timeout'] is False and r['truncated'] is False,
         'ROOT_PROOF_READ_FAILED')
    return r['stdout'].strip()

def grant_readback():
    directory=_one(('sudo','-n','stat','-Lc','%u:%g %a %n',core.LEASE_ROOT))
    file_stat=_one(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',core.LEASE_PATH))
    file_sha=_one(('sudo','-n','sha256sum',core.LEASE_PATH)).split()
    need(len(file_sha)==2 and file_sha[1]==core.LEASE_PATH,
         'ROOT_LEASE_HASH_FORMAT')
    return {'directory_stat':directory,'lease_stat':file_stat,
            'lease_sha256':file_sha[0]}

def claim_readback():
    result={}
    for kind,path in core.MARKERS.items():
        content=_one(('sudo','-n','cat',path))+'\n'
        stat=_one(('sudo','-n','stat','-Lc','%u:%g %a %h %s %n',path))
        result[kind]={'stat':stat,'content':content}
    return result

def verify_boot(plan_path,receipt_dir,f7plan,f7receipt,f6plan,f6receipt):
    before,proposal=verify_plan(plan_path,f7plan,f7receipt,f6plan,f6receipt)
    private(receipt_dir,'boot-')
    need({p.name for p in receipt_dir.iterdir()}==RECEIPT_FILES,
         'BOOT_RECEIPT_FILE_SET')
    intent=read(receipt_dir/'intent.json')
    ticket_doc=read(receipt_dir/'ticket.json')
    dir_cmd=read(receipt_dir/'grant-dir-command.json')
    file_cmd=read(receipt_dir/'grant-file-command.json')
    grant=read(receipt_dir/'grant-readback.json')
    started=read(receipt_dir/'start-command.json')
    after=read(receipt_dir/'after.json')
    live=read(receipt_dir/'live-xml.json')
    claims=read(receipt_dir/'claim-readback.json')
    rec=read(receipt_dir/'receipt.json')
    need(intent=={'schema':core.SCHEMA+'-intent',
                  'plan_sha256':core.sha(proposal),
                  'guest':core.GUEST,'one_real_qemu_start':True,
                  'command':list(core.START),
                  'network_opening_authorized':False,
                  'p8_operational':'NO-GO'},'BOOT_INTENT_CHANGED')
    need(ticket_doc==core.ticket(ticket_doc['issued_at'],ticket_doc['nonce']),
         'TICKET_SCHEMA_CHANGED')
    need(all(result['rc']==0 and result['timeout'] is False and
             result['truncated'] is False for result in (dir_cmd,file_cmd)),
         'ROOT_GRANT_COMMAND_UNCERTAIN')
    need(live['rc']==0 and live['timeout'] is False and
         live['truncated'] is False,'LIVE_XML_COMMAND_FAILED')
    expected=core.classify(before,after,started,live['stdout'],ticket_doc,
                           grant,claims,legacy,f4,f6)
    need(rec==expected,'BOOT_RECEIPT_TAMPER_OR_DRIFT')
    need((plan_path/'boot.once').is_file(),'BOOT_ONCE_MARKER_MISSING')
    return rec

def boot(plan_path,f7plan,f7receipt,f6plan,f6receipt):
    source()
    before,proposal=verify_plan(plan_path,f7plan,f7receipt,f6plan,f6receipt)
    need(not (plan_path/'boot.once').exists(),'POSITIVE_START_ALREADY_ATTEMPTED')
    current=host_preflight()
    f7_core.same(before,current,legacy,f4,f6.core)
    run_dir=Path(tempfile.mkdtemp(prefix='boot-',dir=ROOT))
    private(run_dir,'boot-')
    write(run_dir/'intent.json',{'schema':core.SCHEMA+'-intent',
          'plan_sha256':core.sha(proposal),'guest':core.GUEST,
          'one_real_qemu_start':True,'command':list(core.START),
          'network_opening_authorized':False,'p8_operational':'NO-GO'})
    # Mandatory durable marker, BEFORE the first state-changing command.
    write(plan_path/'boot.once',b'ATTEMPTED\n')
    now=int(time.time())
    ticket_doc=core.ticket(now,secrets.token_hex(32))
    write(run_dir/'ticket.json',ticket_doc)
    try:
        r=host(('sudo','-n','install','-d','-o','root','-g','root','-m','0700',
                core.LEASE_ROOT))
        write(run_dir/'grant-dir-command.json',r)
        need(r['rc']==0 and r['timeout'] is False and r['truncated'] is False,
             'ROOT_GRANT_DIR_UNCERTAIN')
        r=host(('sudo','-n','install','-o','root','-g','root','-m','0600',
                str(run_dir/'ticket.json'),core.LEASE_PATH))
        write(run_dir/'grant-file-command.json',r)
        need(r['rc']==0 and r['timeout'] is False and r['truncated'] is False,
             'ROOT_LEASE_INSTALL_UNCERTAIN')
        grant=grant_readback()
        need(grant['lease_sha256']==core.raw_sha(core.canon(ticket_doc)),
             'ROOT_LEASE_BYTES_NOT_PINNED')
        write(run_dir/'grant-readback.json',grant)
        need(int(time.time())<ticket_doc['expires_at']-30,
             'LEASE_TIME_BUDGET_TOO_SHORT')
        # The ONLY VM boot command. A timeout is an INCIDENT, not a retry.
        started=host(core.START,timeout=90)
        write(run_dir/'start-command.json',started)
        # Measure the actual host after the attempt, even if virsh returns error.
        after=f6.capture()
        write(run_dir/'after.json',after)
        need(started['rc']==0 and started['timeout'] is False and
             started['truncated'] is False,'SSH_VM_START_UNCERTAIN')
        live=host(('virsh','--readonly','-c','qemu:///system','dumpxml',core.GUEST))
        write(run_dir/'live-xml.json',live)
        need(live['rc']==0 and live['timeout'] is False and
             live['truncated'] is False,'LIVE_SSH_XML_READ_FAILED')
        claims=claim_readback()
        write(run_dir/'claim-readback.json',claims)
        receipt=core.classify(before,after,started,live['stdout'],ticket_doc,
                              grant,claims,legacy,f4,f6)
        write(run_dir/'receipt.json',receipt)
        verify_boot(plan_path,run_dir,f7plan,f7receipt,f6plan,f6receipt)
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as err:
        print('R112_F8_INCIDENT_RECEIPT='+str(run_dir))
        print('R112_F8_STOP=POSITIVE_BOOT_NOT_ATTESTED')
        print('R112_F8_REASON='+type(err).__name__+':'+str(err)[:160])
        print('R112_F8_ACTION=NO_RETRY_NO_AUTOMATIC_SHUTDOWN_REVIEW_LIVE_HOST')
        print('R112_F8_P8=NO-GO')
        return 24
    print('R112_F8_SSH_QEMU=RUNNING_VERIFIED')
    print('R112_F8_F11_PHASES=PREPARE_START_STARTED_CLAIMED')
    print('R112_F8_OTHER_VMS=SHUTOFF_3')
    print('R112_F8_NETWORKS=ACTIVE_3_R34_DENY')
    print('R112_F8_PHYSICAL_RECEIPT='+str(run_dir))
    print('R112_F8_RECEIPT_SHA256='+core.sha(receipt))
    print('R112_F8_REAL_SSH_PROTOCOL=NOT_TESTED')
    print('R112_F8_A6=ND')
    print('R112_F8_P8=NO-GO')
    print('R112_F8_RESULT=ONE_REAL_SSH_QEMU_BOOT_ATTESTED_DENY_ONLY')
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan',action='store_true')
    group.add_argument('--verify-plan',type=Path)
    group.add_argument('--boot-ssh',type=Path)
    group.add_argument('--verify-boot',type=Path)
    p.add_argument('--f7-plan',required=True,type=Path)
    p.add_argument('--f7-receipt',required=True,type=Path)
    p.add_argument('--f6-plan',required=True,type=Path)
    p.add_argument('--f6-receipt',required=True,type=Path)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--i-authorize-one-real-ssh-boot-under-r34-deny',action='store_true')
    a=p.parse_args()
    try:
        if a.plan:
            return plan(a.f7_plan,a.f7_receipt,a.f6_plan,a.f6_receipt)
        source(descendant=True)
        if a.verify_plan:
            _before,proposal=verify_plan(a.verify_plan,a.f7_plan,a.f7_receipt,
                                         a.f6_plan,a.f6_receipt)
            print('R112_F8_PLAN_REPLAY=PASS')
            print('R112_F8_PLAN_SHA256='+core.sha(proposal))
            return 0
        if a.boot_ssh:
            need(a.i_authorize_one_real_ssh_boot_under_r34_deny,
                 'EXPLICIT_REAL_SSH_BOOT_AUTHORIZATION_REQUIRED')
            return boot(a.boot_ssh,a.f7_plan,a.f7_receipt,a.f6_plan,a.f6_receipt)
        need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
        verified=verify_boot(a.plan_session,a.verify_boot,a.f7_plan,a.f7_receipt,
                             a.f6_plan,a.f6_receipt)
        print('R112_F8_PHYSICAL_REPLAY=PASS')
        print('R112_F8_RECEIPT_SHA256='+core.sha(verified))
        print('R112_F8_P8=NO-GO')
        return 0
    except (OSError,ValueError,KeyError,TypeError,OverflowError) as err:
        print('R112_F8_STOP='+type(err).__name__+':'+str(err)[:170])
        print('R112_F8_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
