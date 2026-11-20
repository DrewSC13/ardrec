#!/usr/bin/env python3
"""R112-F7: controlled one-time physical libvirt start DENIAL, no lease, no traffic.

--plan and --verify are read-only; --negative-probe executes ONE specific
`sudo -n virsh ... start ardrec-r33-dev-ssh` after explicit operator choice.
An unexpected start is an INCIDENT; never retry or shut down automatically.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
import tempfile

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r112_f7_libvirt_negative as core
from ardrec.coordination import r112_f6_hook_lifecycle as c6
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f5_scoped_hook as f5
import ardrec_p14_r112_f6_hook_lifecycle as f6

ROOT=Path('/home/cicada/ardrec-lab/r112-f7-libvirt-deny-v1')
BRANCH='feat/p14-r111-r114-real-lab'
PLAN_FILES={'before.json','plan.json','manifest.json'}
RECEIPT_FILES={'intent.json','command.json','after.json','receipt.json'}


def need(ok, code):
    core.need(ok,code)

def host(cmd):
    r=legacy.run(tuple(cmd))
    need(type(r) is dict and r.get('timeout') is False and
         r.get('truncated') is False,'HOST_COMMAND_UNCERTAIN')
    return r

def readok(cmd,code):
    r=host(cmd)
    need(r['rc']==0,code)
    return r['stdout']

def source(descendant=False):
    need(Path.cwd().resolve()==REPO,'MAIN_REPO_REQUIRED')
    need(readok(('git','branch','--show-current'),'GIT_BRANCH_READ').strip()==BRANCH,
         'BRANCH_DRIFT')
    if descendant:
        readok(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'),
               'ANCESTRY_DRIFT')
    else:
        need(readok(('git','rev-parse','HEAD'),'GIT_HEAD_READ').strip()==core.PARENT,
             'PARENT_SHA_DRIFT')
    need(f6.CANDIDATE.is_file() and not f6.CANDIDATE.is_symlink() and
         c6.hashlib.sha256(f6.CANDIDATE.read_bytes()).hexdigest()==core.HOOK_SHA,
         'F6_HOOK_SOURCE_DRIFT')

def saved(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         path.name.startswith(prefix) and not path.is_symlink(),
         'PRIVATE_PATH_OUT_OF_SCOPE')
    f5.prior.directory(path)

def write(path,obj):
    f5.write(path,obj)

def read(path):
    return f5.read(path)

def verify_f6(plan,apply):
    rec=f6.verify_apply(plan,apply)
    need(rec['attested_readback']['new_hook_sha256']==core.HOOK_SHA and
         rec['vm_starts']==0 and rec['permits_issued']==0,
         'F6_RECEIPT_NOT_DENY_ONLY')
    return c6.digest(rec)

def admit_current():
    # Hook must be present, executable, root-owned and with exact SHA.
    f5.inspect_scope(core.HOOK_SHA)
    # No /run lease directory and thus no root grants or reusable markers.
    need(host(('sudo','-n','test','!','-e','/run/ardrec-f11-boot-v1'))['rc']==0,
         'F11_LEASE_ROOT_EXISTS')
    # No running guests, including unrelated libvirt domains, while testing.
    running=readok(('virsh','--readonly','-c','qemu:///system','list','--name'),
                   'RUNNING_VM_INVENTORY_UNAVAILABLE')
    need(not running.strip(),'RUNNING_VM_PRESENT')
    # Direct negative test is necessary, but not proof of libvirt integration.
    direct=host(('sudo','-n',c6.HOST_HOOK,core.DOMAIN,'prepare','begin','-'))
    need(direct['rc']==79 and core.DENIAL in direct['stderr'],
         'DIRECT_HOOK_DENY_NOT_PINNED')
    observed=f6.capture()
    core.boundary(observed,legacy,f4,c6)
    return observed

def verify_plan(plan,f6plan,f6receipt):
    saved(plan,'plan-')
    items={p.name for p in plan.iterdir()}
    need(items-{'probe.once'}==PLAN_FILES,'PLAN_FILE_SET')
    if 'probe.once' in items:
        need(f5.prior.private_bytes(plan/'probe.once')==b'ATTEMPTED\n',
             'PROBE_ONCE_MARKER_DRIFT')
    before=read(plan/'before.json')
    proposal=read(plan/'plan.json')
    manifest=read(plan/'manifest.json')
    core.boundary(before,legacy,f4,c6)
    digest=verify_f6(f6plan,f6receipt)
    need(proposal=={'schema':core.SCHEMA+'-plan',
                    'source_parent':core.PARENT,
                    'source_f6_receipt_sha256':digest,
                    'before_sha256':core.sha(before),
                    'single_domain':core.DOMAIN,
                    'physical_command':list(core.START),
                    'consent_required':True,
                    'expected_outcome':'LIBVIRT_HOOK_DENIED_NO_GUEST_START',
                    'no_lease':True,'no_network_policy_change':True,
                    'p8_operational':'NO-GO'},
         'PLAN_IDENTITY_CHANGED')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                    'before_sha256':core.sha(before),
                    'plan_sha256':core.sha(proposal)},
         'PLAN_MANIFEST_CHANGED')
    return before,proposal

def plan(f6plan,f6receipt):
    source()
    digest=verify_f6(f6plan,f6receipt)
    before=admit_current()
    proposal={'schema':core.SCHEMA+'-plan','source_parent':core.PARENT,
              'source_f6_receipt_sha256':digest,
              'before_sha256':core.sha(before),'single_domain':core.DOMAIN,
              'physical_command':list(core.START),'consent_required':True,
              'expected_outcome':'LIBVIRT_HOOK_DENIED_NO_GUEST_START',
              'no_lease':True,'no_network_policy_change':True,'p8_operational':'NO-GO'}
    manifest={'schema':core.SCHEMA+'-manifest',
              'before_sha256':core.sha(before),
              'plan_sha256':core.sha(proposal)}
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    f5.prior.directory(ROOT)
    path=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    saved(path,'plan-')
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',manifest)):
        write(path/name,obj)
    verify_plan(path,f6plan,f6receipt)
    print('R112_F7_PLAN=ONE_SSH_LIBVIRT_NEGATIVE_PROBE_READY')
    print('R112_F7_HOOK_SHA256='+core.HOOK_SHA)
    print('R112_F7_PLAN_SESSION='+str(path))
    print('R112_F7_VM_STARTS=0')
    print('R112_F7_P8=NO-GO')
    return 0

def verify_probe(plan_path, attempt, f6plan, f6receipt):
    before,proposal=verify_plan(plan_path,f6plan,f6receipt)
    saved(attempt,'probe-')
    need({p.name for p in attempt.iterdir()}==RECEIPT_FILES,
         'PROBE_RECEIPT_FILE_SET')
    need(read(attempt/'intent.json')=={
        'schema':core.SCHEMA+'-intent','plan_sha256':core.sha(proposal),
        'command':list(core.START),'one_attempt_only':True,
        'no_lease':True,'p8_operational':'NO-GO'},'INTENT_DRIFT')
    command=read(attempt/'command.json')
    after=read(attempt/'after.json')
    receipt=read(attempt/'receipt.json')
    expected=core.classify(before,after,command,legacy,f4,c6)
    need(receipt==expected,'RECEIPT_REPLAY_MISMATCH')
    need((plan_path/'probe.once').is_file(),'PROBE_INTENT_MARKER_MISSING')
    return receipt

def negative_probe(plan_path,f6plan,f6receipt):
    source()
    before,proposal=verify_plan(plan_path,f6plan,f6receipt)
    need(not (plan_path/'probe.once').exists(),'NEGATIVE_PROBE_ALREADY_ATTEMPTED')
    fresh=admit_current()
    core.same(before,fresh,legacy,f4,c6)
    attempt=Path(tempfile.mkdtemp(prefix='probe-',dir=ROOT))
    saved(attempt,'probe-')
    write(attempt/'intent.json',{
        'schema':core.SCHEMA+'-intent','plan_sha256':core.sha(proposal),
        'command':list(core.START),'one_attempt_only':True,'no_lease':True,
        'p8_operational':'NO-GO'})
    # Durable once marker before one potentially state-changing libvirt call.
    write(plan_path/'probe.once',b'ATTEMPTED\n')
    command=legacy.run(core.START)
    write(attempt/'command.json',command)
    # A post-check is mandatory EVEN when virsh reports a start error.
    try:
        after=f6.capture()
        write(attempt/'after.json',after)
        receipt=core.classify(before,after,command,legacy,f4,c6)
        write(attempt/'receipt.json',receipt)
        verify_probe(plan_path,attempt,f6plan,f6receipt)
    except (OSError,ValueError,KeyError,TypeError) as error:
        print('R112_F7_INCIDENT_RECEIPT='+str(attempt))
        print('R112_F7_STOP=HOOK_DENIAL_NOT_PHYSICALLY_ATTESTED')
        print('R112_F7_REASON='+type(error).__name__+':'+str(error)[:140])
        print('R112_F7_ACTION=DO_NOT_RETRY_CHECK_VM_AND_R34_BEFORE_RECOVERY')
        print('R112_F7_P8=NO-GO')
        return 24
    print('R112_F7_PHYSICAL_HOOK_ENFORCEMENT=PASS_DENIED_BY_LIBVIRT')
    print('R112_F7_VM_SSH=SHUTOFF')
    print('R112_F7_NO_LEASE=TRUE')
    print('R112_F7_PHYSICAL_RECEIPT='+str(attempt))
    print('R112_F7_RECEIPT_SHA256='+core.sha(receipt))
    print('R112_F7_VM_STARTS=0')
    print('R112_F7_P8=NO-GO')
    print('R112_F7_RESULT=REAL_LIBVIRT_HOOK_DENIAL_REPLAY_VERIFIED')
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--plan',action='store_true')
    g.add_argument('--verify-plan',type=Path)
    g.add_argument('--negative-probe',type=Path)
    g.add_argument('--verify-probe',type=Path)
    p.add_argument('--f6-plan',type=Path,required=True)
    p.add_argument('--f6-receipt',type=Path,required=True)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--i-authorize-one-ssh-start-denial-test',action='store_true')
    a=p.parse_args()
    try:
        if a.plan:
            return plan(a.f6_plan,a.f6_receipt)
        source(descendant=True)
        if a.verify_plan:
            _before, proposal=verify_plan(a.verify_plan,a.f6_plan,a.f6_receipt)
            print('R112_F7_PLAN_REPLAY=PASS')
            print('R112_F7_PLAN_SHA256='+core.sha(proposal))
            return 0
        if a.negative_probe:
            need(a.i_authorize_one_ssh_start_denial_test,
                 'EXPLICIT_SINGLE_NEGATIVE_PROBE_AUTH_REQUIRED')
            return negative_probe(a.negative_probe,a.f6_plan,a.f6_receipt)
        need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
        receipt=verify_probe(a.plan_session,a.verify_probe,a.f6_plan,a.f6_receipt)
        print('R112_F7_PHYSICAL_REPLAY=PASS')
        print('R112_F7_RECEIPT_SHA256='+core.sha(receipt))
        print('R112_F7_P8=NO-GO')
        return 0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as e:
        print('R112_F7_STOP='+type(e).__name__+':'+str(e)[:170])
        print('R112_F7_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
