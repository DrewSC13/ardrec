#!/usr/bin/env python3
"""R112-F6: repair F11 QEMU hook shutdown/reconnect lifecycle, without boot.

A separate physical authorization is required. No runtime lease or virsh start.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
import tempfile

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r112_f6_hook_lifecycle as core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r112_f5_scoped_hook as f5
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4

ROOT=Path('/home/cicada/ardrec-lab/r112-f6-f11-lifecycle-v1')
BRANCH='feat/p14-r111-r114-real-lab'
CANDIDATE=REPO/'lab/f11-runtime-v3/00-ardrec-r33-admission'
PLAN_FILES={'before.json','plan.json','manifest.json'}
APPLY_FILES={'intent.json','stage.json','replace.json','after.json',
             'controls.json','receipt.json'}


def need(ok,code):
    core.need(ok,code)


def probe(command):
    item=legacy.run(tuple(command))
    need(type(item) is dict and item.get('timeout') is False and
         item.get('truncated') is False,'HOST_COMMAND_UNCERTAIN')
    return item


def result_ok(cmd,code):
    res=probe(cmd)
    need(res['rc']==0,code)
    return res


def source(descendant=False):
    need(Path.cwd().resolve()==REPO,'MAIN_REPO_REQUIRED')
    name=result_ok(('git','branch','--show-current'),'BRANCH_READ')['stdout'].strip()
    need(name==BRANCH,'BRANCH_CHANGED')
    if descendant:
        result_ok(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'),
                  'SOURCE_PARENT_NOT_ANCESTOR')
    else:
        head=result_ok(('git','rev-parse','HEAD'),'HEAD_READ')['stdout'].strip()
        need(head==core.PARENT,'SOURCE_COMMIT_CHANGED')
    need(CANDIDATE.is_file() and not CANDIDATE.is_symlink() and
         core.hashlib.sha256(CANDIDATE.read_bytes()).hexdigest()==
         core.NEW_HOOK_SHA256,'CANDIDATE_HASH_CHANGED')


def read_private(path):
    return f5.read(path)


def write_private(path,obj):
    f5.write(path,obj)


def private(path,prefix):
    need(path.is_absolute() and path.parent==ROOT and
         path.name.startswith(prefix) and not path.is_symlink(),
         'PRIVATE_DIRECTORY_SCOPE')
    f5.prior.directory(path)


def original_receipt(f5_plan,f5_apply):
    receipt=f5.verify_apply(f5_plan,f5_apply)
    historical=f5.verify_plan(f5_plan)[0]
    need(receipt['hook_sha256']==core.OLD_HOOK_SHA256,
         'PRIOR_HOOK_RECEIPT_INVALID')
    return historical, core.digest(receipt)


def inspect_host(expected):
    f5.inspect_scope(expected)
    res=probe(('sudo','-n','test','!','-e',core.STAGE))
    need(res['rc']==0,'F6_STAGE_PREEXISTING')
    res=probe(('sudo','-n','test','!','-L',core.STAGE))
    need(res['rc']==0,'F6_STAGE_SYMLINK')


def capture():
    return f5._measurement(unpinned=True)


def historical_check(historical,observation):
    f5.core.check_post(historical,observation,legacy,f4,r112)


def verify_plan(path):
    private(path,'plan-')
    items={p.name for p in path.iterdir()}
    need(items-{'install.once'}==PLAN_FILES,'PLAN_FILE_SCOPE')
    if 'install.once' in items:
        need(f5.prior.private_bytes(path/'install.once')==b'ATTEMPTED\n',
             'ATTEMPT_MARKER_MODIFIED')
    before=read_private(path/'before.json')
    proposal=read_private(path/'plan.json')
    manifest=read_private(path/'manifest.json')
    need(proposal==core.proposal(before,proposal['source_f5_receipt_sha256'],legacy,f4),
         'PLAN_REPLAY_FAILURE')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                   'files':{'before.json':core.digest(before),
                            'plan.json':core.digest(proposal)},
                   'p8_operational':'NO-GO'},'MANIFEST_DRIFT')
    return before,proposal


def plan(f5_plan,f5_apply):
    source()
    historical,receipt_sha=original_receipt(f5_plan,f5_apply)
    inspect_host(core.OLD_HOOK_SHA256)
    before=capture()
    historical_check(historical,before)
    proposal=core.proposal(before,receipt_sha,legacy,f4)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    f5.prior.directory(ROOT)
    directory=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    private(directory,'plan-')
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',{'schema':core.SCHEMA+'-manifest',
                      'files':{'before.json':core.digest(before),
                               'plan.json':core.digest(proposal)},
                      'p8_operational':'NO-GO'})):
        write_private(directory/name,obj)
    verify_plan(directory)
    print('R112_F6_PLAN=READY_DENY_DEFAULT_LIFECYCLE_REPAIR')
    print('R112_F6_PLAN_SESSION='+str(directory))
    print('R112_F6_PLAN_SHA256='+core.digest(proposal))
    print('R112_F6_VM_STARTS=0')
    print('R112_F6_P8=NO-GO')
    return 0


def controls():
    report={}
    for role in core.GUESTS:
        guest='ardrec-r33-dev-'+role
        res=probe(('sudo','-n',core.HOST_HOOK,guest,'prepare','begin','-'))
        need(res['rc']==79 and 'DENY_UNATTESTED_OR_ALREADY_USED_LEASE' in
             res['stderr'],'NEGATIVE_PREPARE_'+role)
        report[role]={'prepare_denied':True,'rc':79}
    res=probe(('sudo','-n',core.HOST_HOOK,'ardrec-r33-dev-runner',
               'reconnect','begin','-'))
    need(res['rc']==79 and 'DENY_RECONNECT_WITHOUT_COMPLETED_BOOT' in
         res['stderr'],'NEGATIVE_RECONNECT')
    report['reconnect']={'denied_without_completed_boot':True,'rc':79}
    for operation,extra in (('stopped','-'),('release','shutdown'),
                            ('release','destroyed')):
        res=probe(('sudo','-n',core.HOST_HOOK,'ardrec-r33-dev-runner',
                   operation,'end',extra))
        need(res['rc']==0,'SHUTDOWN_REASON_REJECTED')
    report['shutdown']={'stopped':True,'release_shutdown':True,
                        'release_destroyed':True}
    return report


def verify_apply(plan_path,attempt):
    before,proposal=verify_plan(plan_path)
    private(attempt,'apply-')
    need({p.name for p in attempt.iterdir()}==APPLY_FILES,'APPLY_FILE_SCOPE')
    intent=read_private(attempt/'intent.json')
    stage=read_private(attempt/'stage.json')
    replace=read_private(attempt/'replace.json')
    after=read_private(attempt/'after.json')
    control=read_private(attempt/'controls.json')
    receipt=read_private(attempt/'receipt.json')
    need(intent=={'schema':core.SCHEMA+'-intent','plan_sha256':core.digest(proposal),
                  'action':'ATOMIC_ROOT_HOOK_REPLACEMENT_DENY_NO_LEASES',
                  'vm_starts':0,'p8_operational':'NO-GO'},'INTENT_DRIFT')
    for command in (stage,replace):
        need(command['rc']==0 and command['timeout'] is False and
             command['truncated'] is False,'HOST_REPLACEMENT_NOT_SUCCESSFUL')
    checked=core.result(before,after,legacy,f4,r112)
    need(control=={**{r:{'prepare_denied':True,'rc':79} for r in core.GUESTS},
                   'reconnect':{'denied_without_completed_boot':True,'rc':79},
                   'shutdown':{'stopped':True,'release_shutdown':True,
                               'release_destroyed':True}}, 'CONTROL_DRIFT')
    need(receipt=={'schema':core.SCHEMA+'-physical-receipt',
                   'plan_sha256':core.digest(proposal),
                   'attested_readback':checked,'negative_controls':5,
                   'shutdown_controls':3,'vm_starts':0,'permits_issued':0,
                   'p8_operational':'NO-GO'},'RECEIPT_INVALID')
    need((plan_path/'install.once').is_file(),'ATTEMPT_MARKER_MISSING')
    return receipt


def install(plan_path):
    source()
    before,proposal=verify_plan(plan_path)
    need('install.once' not in {p.name for p in plan_path.iterdir()},
         'INSTALL_RETRY_FORBIDDEN')
    inspect_host(core.OLD_HOOK_SHA256)
    fresh=capture()
    core.same_boundary(before,fresh,legacy,f4,r112,new_hook=False)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    f5.prior.directory(ROOT)
    attempt=Path(tempfile.mkdtemp(prefix='apply-',dir=ROOT))
    private(attempt,'apply-')
    write_private(attempt/'intent.json',{'schema':core.SCHEMA+'-intent',
        'plan_sha256':core.digest(proposal),
        'action':'ATOMIC_ROOT_HOOK_REPLACEMENT_DENY_NO_LEASES',
        'vm_starts':0,'p8_operational':'NO-GO'})
    write_private(plan_path/'install.once',b'ATTEMPTED\n')
    stage=probe(('sudo','-n','install','-o','root','-g','root','-m','0755',
                 str(CANDIDATE),core.STAGE))
    write_private(attempt/'stage.json',stage)
    need(stage['rc']==0,'STAGING_FAILED_NO_RETRY')
    got=f5.get_hash(core.STAGE)
    need(got==core.NEW_HOOK_SHA256,'STAGE_HASH_DRIFT')
    replace=probe(('sudo','-n','mv','-T','--',core.STAGE,core.HOST_HOOK))
    write_private(attempt/'replace.json',replace)
    need(replace['rc']==0,'REPLACEMENT_UNCERTAIN_NO_RETRY')
    inspect_host(core.NEW_HOOK_SHA256)
    observed=controls()
    write_private(attempt/'controls.json',observed)
    after=capture()
    checked=core.result(before,after,legacy,f4,r112)
    write_private(attempt/'after.json',after)
    receipt={'schema':core.SCHEMA+'-physical-receipt',
             'plan_sha256':core.digest(proposal),
             'attested_readback':checked,'negative_controls':5,
             'shutdown_controls':3,'vm_starts':0,'permits_issued':0,
             'p8_operational':'NO-GO'}
    write_private(attempt/'receipt.json',receipt)
    verify_apply(plan_path,attempt)
    print('R112_F6_INSTALLED=DENY_DEFAULT_LIFECYCLE_FIXED')
    print('R112_F6_NEGATIVE_CONTROLS=PASS_5')
    print('R112_F6_SHUTDOWN_CONTROLS=PASS_3')
    print('R112_F6_HOOK_SHA256='+core.NEW_HOOK_SHA256)
    print('R112_F6_PHYSICAL_RECEIPT='+str(attempt))
    print('R112_F6_RECEIPT_SHA256='+core.digest(receipt))
    print('R112_F6_VM_STARTS=0')
    print('R112_F6_P8=NO-GO')
    print('R112_F6_RESULT=ROOT_HOOK_LIFECYCLE_REPAIRED_DENY_ONLY')
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--plan',action='store_true')
    g.add_argument('--verify-plan',type=Path)
    g.add_argument('--install-deny-repair',type=Path)
    g.add_argument('--verify-install',type=Path)
    p.add_argument('--f5-plan',type=Path)
    p.add_argument('--f5-receipt',type=Path)
    p.add_argument('--plan-session',type=Path)
    p.add_argument('--i-authorize-f11-lifecycle-deny-repair',action='store_true')
    a=p.parse_args()
    try:
        if a.plan:
            need(a.f5_plan is not None and a.f5_receipt is not None,
                 'F5_PROVENANCE_REQUIRED')
            return plan(a.f5_plan,a.f5_receipt)
        source(descendant=True)
        if a.verify_plan is not None:
            before,proposal=verify_plan(a.verify_plan)
            print('R112_F6_PLAN_REPLAY=PASS')
            print('R112_F6_PLAN_SHA256='+core.digest(proposal))
            return 0
        if a.install_deny_repair is not None:
            need(a.i_authorize_f11_lifecycle_deny_repair,
                 'EXPLICIT_ROOT_HOOK_AUTHORIZATION_REQUIRED')
            return install(a.install_deny_repair)
        need(a.plan_session is not None,'PLAN_SESSION_REQUIRED')
        verified=verify_apply(a.plan_session,a.verify_install)
        print('R112_F6_PHYSICAL_REPLAY=PASS')
        print('R112_F6_RECEIPT_SHA256='+core.digest(verified))
        print('R112_F6_P8=NO-GO')
        return 0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as err:
        print('R112_F6_STOP='+type(err).__name__+':'+str(err)[:180])
        print('R112_F6_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
