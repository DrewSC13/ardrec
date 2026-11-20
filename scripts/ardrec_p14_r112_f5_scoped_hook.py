#!/usr/bin/env python3
"""R112-F5: physically install a deny-default, one-boot-capable F11 hook.

Only installs a pinned candidate *without any lease*; does not start a VM,
create root grants, open traffic, restart libvirt or modify the watchdog.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO/'src'),str(REPO/'scripts')]

from ardrec.coordination import r112_f5_scoped_hook as core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as prior
import ardrec_p14_r112_f4_isolated_networks as f4

ROOT=Path('/home/cicada/ardrec-lab/r112-f5-f11-scoped-hook-v1')
CANDIDATE=REPO/'lab/f11-runtime-v2/00-ardrec-r33-admission'
BRANCH='feat/p14-r111-r114-real-lab'
PLAN_FILES={'before.json','plan.json','manifest.json'}
APPLY_FILES={'intent.json','stage-result.json','stage-hash.json',
             'replace-result.json','after.json','deny-tests.json','receipt.json'}


def need(condition, code):
    core.need(condition,code)


def probe(command):
    res=legacy.run(tuple(command))
    need(type(res) is dict and res.get('timeout') is False and
         res.get('truncated') is False, 'PROBE_UNCERTAIN')
    return res


def read_ok(command, code):
    res=probe(command)
    need(res['rc']==0,code)
    return res['stdout']


def source(*,descendant=False):
    need(Path.cwd().resolve()==REPO,'REPOSITORY_REQUIRED')
    branch=read_ok(('git','branch','--show-current'),'BRANCH_READ')
    need(branch.strip()==BRANCH,'BRANCH_DRIFT')
    if descendant:
        read_ok(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'),
                'SOURCE_NOT_DESCENDANT')
    else:
        need(read_ok(('git','rev-parse','HEAD'),'HEAD_READ').strip()==core.PARENT,
             'SOURCE_HEAD_DRIFT')
    need(CANDIDATE.is_file() and not CANDIDATE.is_symlink() and
         core.sha(CANDIDATE.read_bytes())==core.CANDIDATE,
         'NEW_HOOK_SOURCE_HASH_DRIFT')
    need(core.sha((REPO/'lab/f11-runtime-v1/00-ardrec-r33-deny').read_bytes())==
         core.ORIGINAL,'OLD_HOOK_SOURCE_HASH_DRIFT')


def get_hash(host_path):
    text=read_ok(('sudo','-n','sha256sum',host_path),'HOST_HOOK_HASH_READ')
    parts=text.split()
    need(len(parts)==2 and len(parts[0])==64 and parts[1]==host_path,
         'HOST_HOOK_HASH_FORMAT')
    return parts[0]


def inspect_scope(expected_hook):
    actual=get_hash(core.HOST_HOOK)
    need(actual==expected_hook,'INSTALLED_HOOK_SOURCE_DRIFT')
    stat=read_ok(('sudo','-n','stat','-Lc','%u:%g %a %h %n',core.HOST_HOOK),
                 'HOOK_STAT_FAILURE').strip()
    need(stat==f'0:0 755 1 {core.HOST_HOOK}','HOOK_MODE_OR_OWNER')
    need(probe(('sudo','-n','test','!','-L',core.HOST_HOOK))['rc']==0,
         'INSTALLED_HOOK_SYMLINK_REJECTED')
    names=read_ok(('sudo','-n','find','/etc/libvirt/hooks','-maxdepth','4',
                   '-type','f','-print'),'HOOK_INVENTORY_FAILURE')
    need([s.strip() for s in names.splitlines() if s.strip()]==[core.HOST_HOOK],
         'HOOK_INVENTORY_CHANGED')
    for path in (core.STAGING,core.LEASE_DIR):
        need(probe(('sudo','-n','test','!','-e',path))['rc']==0 and
             probe(('sudo','-n','test','!','-L',path))['rc']==0,
             'STALE_STAGE_OR_OLD_LEASE_ROOT')
    return True


def _measurement(unpinned=False):
    if not unpinned:
        return f4.measure()
    commands=legacy.command_list()
    checks={key:probe(command) for key,command in commands.items()}
    snapshot={'schema':legacy.SCHEMA,
              'commands':{k:list(v) for k,v in commands.items()},
              'probes':checks,'summary':legacy.summarize(checks)}
    info={role:probe(('env','LC_ALL=C','LANG=C','LANGUAGE=C','virsh',
                      '--readonly','-c','qemu:///system','net-info',
                      'ardrec-r33-dev-net-'+role)) for role in core.NETWORKS}
    return {'snapshot':snapshot,'english_info':info,
            'other_domains':f4._readonly_names()}


def private(p, prefix):
    need(p.is_absolute() and p.parent==ROOT and p.name.startswith(prefix)
         and not p.is_symlink(),'PRIVATE_PATH_DRIFT')
    prior.directory(p)


def write(path,obj):
    prior.store(path, core.canonical(obj) if type(obj) is dict else obj)


def read(path):
    return prior.read_json(path)


def verify_plan(path):
    private(path,'plan-')
    actual={p.name for p in path.iterdir()}
    need(actual-{'install.once'}==PLAN_FILES and
         ('install.once' not in actual or
          prior.private_bytes(path/'install.once')==b'ATTEMPTED\n'),
         'PLAN_INVENTORY_OR_MARKER')
    before=read(path/'before.json')
    plan=read(path/'plan.json')
    manifest=read(path/'manifest.json')
    need(manifest=={'schema':core.SCHEMA+'-manifest',
                    'files':{'before.json':core.digest(before),
                             'plan.json':core.digest(plan)},
                    'p8_operational':'NO-GO'}, 'MANIFEST_REPLAY_FAILED')
    need(core.plan_for(before,core.CANDIDATE,legacy,f4)==plan,
         'PLAN_NOT_REPRODUCIBLE')
    return before,plan


def plan():
    source()
    inspect_scope(core.ORIGINAL)
    before=_measurement()
    proposal=core.plan_for(before,core.CANDIDATE,legacy,f4)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    directory=Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    prior.directory(directory)
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',{'schema':core.SCHEMA+'-manifest',
                         'files':{'before.json':core.digest(before),
                                  'plan.json':core.digest(proposal)},
                         'p8_operational':'NO-GO'})):
        write(directory/name,obj)
    verify_plan(directory)
    print('R112_F5_PLAN=READY_TO_INSTALL_DENY_DEFAULT_HOOK_ONLY')
    print('R112_F5_PLAN_SESSION='+str(directory))
    print('R112_F5_ORIGINAL_HOOK_SHA256='+core.ORIGINAL)
    print('R112_F5_CANDIDATE_HOOK_SHA256='+core.CANDIDATE)
    print('R112_F5_PLAN_SHA256='+core.digest(proposal))
    print('R112_F5_VM_STARTS=0')
    print('R112_F5_P8=NO-GO')
    return 0


def negative_tests():
    results={}
    for role in core.GUESTS:
        command=('sudo','-n',core.HOST_HOOK,'ardrec-r33-dev-'+role,
                 'prepare','begin','-')
        result=probe(command)
        need(result['rc']==79 and
             'DENY_UNATTESTED_OR_ALREADY_USED_LEASE' in result['stderr'],
             'F11_NOT_DENYING_'+role)
        results[role]={'returncode':79,'deny':True}
    # Reject reconnect (not an invitation to reconnect an already running VM).
    reconnect=probe(('sudo','-n',core.HOST_HOOK,'ardrec-r33-dev-runner',
                     'reconnect','begin','-'))
    need(reconnect['rc']==79 and 'DENY_OPERATION_OR_RECONNECT' in
         reconnect['stderr'],'RECONNECT_NOT_DENIED')
    results['reconnect']={'returncode':79,'deny':True}
    return results


def verify_apply(path, attempt):
    before,proposal=verify_plan(path)
    private(attempt,'apply-')
    need({p.name for p in attempt.iterdir()}==APPLY_FILES,
         'APPLY_FILE_INVENTORY_DRIFT')
    intent=read(attempt/'intent.json')
    stage=read(attempt/'stage-result.json')
    stage_hash=read(attempt/'stage-hash.json')
    replace=read(attempt/'replace-result.json')
    after=read(attempt/'after.json')
    negative=read(attempt/'deny-tests.json')
    receipt=read(attempt/'receipt.json')
    need(intent=={'schema':core.SCHEMA+'-intent',
                  'plan_sha256':core.digest(proposal),
                  'operation':'INSTALL_NEW_ROOT_HOOK_NO_LEASES',
                  'vm_starts':0,'root_grants_created':0,
                  'p8_operational':'NO-GO'},'INTENT_DRIFT')
    for result in (stage,replace):
        need(result['rc']==0 and result['timeout'] is False
             and result['truncated'] is False,'HOST_INSTALL_UNCERTAIN')
    need(stage_hash['observed_sha256']==core.CANDIDATE,
         'STAGED_HOOK_HASH_DRIFT')
    verified=core.check_post(before,after,legacy,f4,r112)
    need(negative=={r:{'returncode':79,'deny':True} for r in
                    (*core.GUESTS,'reconnect')},'NEGATIVE_TEST_REPLAY_DRIFT')
    need(receipt=={'schema':core.SCHEMA+'-physical-receipt',
                   'plan_sha256':core.digest(proposal),
                   'attested_readback':verified,
                   'hook_sha256':core.CANDIDATE,
                   'deny_control_count':5,'new_permits':0,'vm_starts':0,
                   'network_policy_mutations':0,
                   'p8_operational':'NO-GO'}, 'RECEIPT_REPLAY_DRIFT')
    need((path/'install.once').is_file(),'MISSING_ONCE_MARKER')
    return receipt


def install(plan_path):
    source()
    before,proposal=verify_plan(plan_path)
    need('install.once' not in {p.name for p in plan_path.iterdir()},
         'INSTALL_ALREADY_ATTEMPTED')
    inspect_scope(core.ORIGINAL)
    fresh=_measurement()
    f4.core.compare(before,fresh,legacy,active=core.NETWORKS)
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    attempt=Path(tempfile.mkdtemp(prefix='apply-',dir=ROOT))
    prior.directory(attempt)
    write(attempt/'intent.json',{'schema':core.SCHEMA+'-intent',
        'plan_sha256':core.digest(proposal),
        'operation':'INSTALL_NEW_ROOT_HOOK_NO_LEASES','vm_starts':0,
        'root_grants_created':0,'p8_operational':'NO-GO'})
    write(plan_path/'install.once',b'ATTEMPTED\n')
    # Stage outside hooks directory so it is never prematurely discovered.
    cmd=('sudo','-n','install','-o','root','-g','root','-m','0755',
         str(CANDIDATE),core.STAGING)
    result=probe(cmd)
    write(attempt/'stage-result.json',result)
    need(result['rc']==0,'ROOT_STAGE_FAILED_NO_RETRY')
    staged=get_hash(core.STAGING)
    write(attempt/'stage-hash.json',{'observed_sha256':staged})
    need(staged==core.CANDIDATE,'ROOT_STAGE_SOURCE_NOT_PINNED')
    replace=probe(('sudo','-n','mv','-T','--',core.STAGING,core.HOST_HOOK))
    write(attempt/'replace-result.json',replace)
    need(replace['rc']==0,'ATOMIC_HOOK_REPLACEMENT_UNCERTAIN')
    # No VM or network actions. Current hook MUST still DENY all four boots.
    need(get_hash(core.HOST_HOOK)==core.CANDIDATE,
         'POST_REPLACEMENT_HOOK_HASH_DRIFT')
    inspect_scope(core.CANDIDATE)
    deny=negative_tests()
    write(attempt/'deny-tests.json',deny)
    after=_measurement(unpinned=True)
    validated=core.check_post(before,after,legacy,f4,r112)
    write(attempt/'after.json',after)
    receipt={'schema':core.SCHEMA+'-physical-receipt',
             'plan_sha256':core.digest(proposal),
             'attested_readback':validated,
             'hook_sha256':core.CANDIDATE,'deny_control_count':5,
             'new_permits':0,'vm_starts':0,'network_policy_mutations':0,
             'p8_operational':'NO-GO'}
    write(attempt/'receipt.json',receipt)
    verify_apply(plan_path,attempt)
    print('R112_F5_INSTALLED=DENY_DEFAULT_NO_PERMITS')
    print('R112_F5_HOOK_SHA256='+core.CANDIDATE)
    print('R112_F5_NEGATIVE_CONTROLS=PASS_5')
    print('R112_F5_PHYSICAL_RECEIPT='+str(attempt))
    print('R112_F5_RECEIPT_SHA256='+core.digest(receipt))
    print('R112_F5_VM_STARTS=0')
    print('R112_F5_P8=NO-GO')
    print('R112_F5_RESULT=ROOT_SCOPED_HOOK_INSTALLED_DENY_ONLY')
    return 0


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--plan',action='store_true')
    group.add_argument('--verify-plan',type=Path)
    group.add_argument('--install-deny-default',type=Path)
    group.add_argument('--verify-install',type=Path)
    parser.add_argument('--plan-session',type=Path)
    parser.add_argument('--i-authorize-install-root-hook-deny-only',
                        action='store_true')
    args=parser.parse_args()
    try:
        if args.plan:
            return plan()
        source(descendant=True)
        if args.verify_plan is not None:
            before,proposal=verify_plan(args.verify_plan)
            print('R112_F5_PLAN_REPLAY=PASS')
            print('R112_F5_PLAN_SHA256='+core.digest(proposal))
            return 0
        if args.install_deny_default is not None:
            need(args.i_authorize_install_root_hook_deny_only,
                 'EXPLICIT_ROOT_HOOK_INSTALL_AUTHORITY_REQUIRED')
            return install(args.install_deny_default)
        need(args.plan_session is not None,'PLAN_SESSION_REQUIRED')
        receipt=verify_apply(args.plan_session,args.verify_install)
        print('R112_F5_PHYSICAL_REPLAY=PASS')
        print('R112_F5_RECEIPT_SHA256='+core.digest(receipt))
        print('R112_F5_P8=NO-GO')
        return 0
    except (ValueError,KeyError,TypeError,OSError,RuntimeError) as err:
        print('R112_F5_STOP='+type(err).__name__+':'+str(err)[:180])
        print('R112_F5_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
