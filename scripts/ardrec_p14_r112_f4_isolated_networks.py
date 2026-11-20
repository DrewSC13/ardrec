#!/usr/bin/env python3
"""R112-F4: start only three isolated R33 libvirt networks under intact DENY.

Requires explicit operator choice for physical mutation. No domain start,
no network NAT/IP/DHCP, no firewall/hook change, and no A5 execution.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO/'src'), str(REPO/'scripts')]
from ardrec.coordination import r112_f4_isolated_networks as core
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as prior

ROOT = Path('/home/cicada/ardrec-lab/r112-f4-real-isolated-networks-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
PLAN_FILES = {'before.json','plan.json','manifest.json'}
ROLES = core.ROLES


def need(ok: bool, code: str) -> None:
    core.need(ok,code)


def source(*, descendant: bool = False) -> None:
    need(Path.cwd().resolve() == REPO, 'REPOSITORY_ROOT_REQUIRED')
    b = legacy.run(('git','branch','--show-current'))
    need(b['rc'] == 0 and b['stdout'].strip() == BRANCH, 'BRANCH_DRIFT')
    if descendant:
        p = legacy.run(('git','merge-base','--is-ancestor',core.PARENT,'HEAD'))
        need(p['rc'] == 0, 'SOURCE_ANCESTRY_DRIFT')
    else:
        h = legacy.run(('git','rev-parse','HEAD'))
        need(h['rc'] == 0 and h['stdout'].strip() == core.PARENT, 'SOURCE_COMMIT_DRIFT')


def _result_valid(value: dict, code: str) -> None:
    need(type(value) is dict and value.get('rc') == 0 and
         value.get('timeout') is False and value.get('truncated') is False and
         type(value.get('stdout')) is str, code)


def _readonly_names() -> dict:
    result = legacy.run(('virsh','--readonly','-c','qemu:///system',
                         'list','--all','--name'))
    _result_valid(result, 'DOMAIN_INVENTORY_UNAVAILABLE')
    names = [s.strip() for s in result['stdout'].splitlines() if s.strip()]
    need(len(names) <= 128 and len(set(names)) == len(names) and
         all(re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', name) for name in names),
         'DOMAIN_NAME_OR_COUNT_INVALID')
    expected = {'ardrec-r33-dev-'+role for role in ('runner',*ROLES)}
    need(expected <= set(names), 'R33_DOMAIN_NOT_REGISTERED')
    observed = []
    for name in sorted(set(names)-expected):
        for mode in ('inactive','effective'):
            command = ('virsh','--readonly','-c','qemu:///system',
                       'dumpxml', '--inactive',name) if mode == 'inactive' else (
                       'virsh','--readonly','-c','qemu:///system','dumpxml',name)
            result = legacy.run(command)
            _result_valid(result,'UNRELATED_DOMAIN_XML_UNAVAILABLE')
            doc = ET.fromstring(result['stdout'])
            need(doc.tag == 'domain' and doc.findtext('name') == name,
                 'UNRELATED_DOMAIN_IDENTITY')
            srcs = [source.get('network') for source in
                    doc.findall('devices/interface/source') if source.get('network')]
            need(not any(x.startswith('ardrec-r33-dev-net-') for x in srcs),
                 'UNRELATED_GUEST_R33_NET_ATTACHMENT')
            observed.append((name, mode,
                hashlib.sha256(result['stdout'].encode()).hexdigest()))
    return {'status':'NO_UNRELATED_R33_NET_ATTACHMENTS','inspected':True,
            'count':len(observed),'xml_inventory_sha256':core.digest(observed)}


def measure() -> dict:
    snapshot = prior.capture()  # 29 pinned read-only host checks.
    info = {role:legacy.run(('env','LC_ALL=C','LANG=C','LANGUAGE=C',
         'virsh','--readonly','-c','qemu:///system',
         'net-info','ardrec-r33-dev-net-'+role)) for role in ROLES}
    result = {'snapshot':snapshot,'english_info':info,
              'other_domains':_readonly_names()}
    core.inspect(result,legacy)
    return result


def private_path(root: Path, prefix: str) -> None:
    need(root.is_absolute() and root.parent == ROOT and
         root.name.startswith(prefix) and not root.is_symlink(),
         'PRIVATE_SESSION_PATH_INVALID')
    prior.directory(root)


def write(path: Path, value: dict | bytes) -> None:
    prior.store(path, core.canonical(value) if type(value) is dict else value)


def read(path: Path) -> dict:
    return prior.read_json(path)


def verify_plan(path: Path) -> tuple[dict,dict]:
    private_path(path,'plan-')
    actual = {p.name for p in path.iterdir()}
    markers = {'apply.once','restore.once'}
    need(actual - markers == PLAN_FILES, 'PLAN_FILE_SET')
    for name in markers & actual:
        need(prior.private_bytes(path/name) == b'ATTEMPTED\n',
             'PLAN_ONCE_MARKER_DRIFT')
    need('restore.once' not in actual or 'apply.once' in actual,
         'RESTORE_WITHOUT_APPLY')
    before, plan, manifest = (read(path/k) for k in
                             ('before.json','plan.json','manifest.json'))
    need(manifest.get('schema') == core.SCHEMA+'-manifest'
         and manifest.get('files') == {
             'before.json':core.digest(before),'plan.json':core.digest(plan)}
         and manifest.get('sha256') == core.digest({k:v for k,v in manifest.items()
                                                   if k != 'sha256'}),
         'PLAN_MANIFEST_DRIFT')
    need(plan == core.plan_for(before,legacy), 'PLAN_CANNOT_BE_REPLAYED')
    return plan,before


def plan() -> int:
    source()
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    prior.directory(ROOT)
    before = measure()
    proposal = core.plan_for(before,legacy)
    manifest = {'schema':core.SCHEMA+'-manifest',
                'files':{'before.json':core.digest(before),
                         'plan.json':core.digest(proposal)},
                'authority': 'PENDING_EXPLICIT_OPERATOR_NET_START',
                'vm_starts':0,'nft_changed':False,'p8_operational':'NO-GO'}
    manifest['sha256'] = core.digest(manifest)
    directory = Path(tempfile.mkdtemp(prefix='plan-',dir=ROOT))
    prior.directory(directory)
    for name,obj in (('before.json',before),('plan.json',proposal),
                     ('manifest.json',manifest)):
        write(directory/name,obj)
    verify_plan(directory)
    print('R112_F4_PLAN=THREE_ISOLATED_NET_STARTS_READY_DENY_PRESERVED')
    print('R112_F4_NETWORKS_BEFORE=SSH_INACTIVE_FTP_INACTIVE_SMB_INACTIVE')
    print('R112_F4_PLAN_SHA256='+core.digest(proposal))
    print('R112_F4_PLAN_SESSION='+str(directory))
    print('R112_F4_VM_STARTS=0')
    print('R112_F4_P8=NO-GO')
    return 0


def verify_apply(plan_path: Path, attempt: Path) -> dict:
    _, before = verify_plan(plan_path)
    private_path(attempt,'apply-')
    names = {'intent.json','receipt.json'}
    for role in ROLES:
        names.update({'intent-'+role+'.json','result-'+role+'.json',
                      'readback-'+role+'.json'})
    need({p.name for p in attempt.iterdir()} == names,
         'APPLY_INVENTORY_CHANGED')
    first = read(attempt/'intent.json')
    need(first == {'schema':core.SCHEMA+'-intent','plan_sha256':
          core.digest(core.plan_for(before,legacy)),
          'start_order':list(ROLES),'physical_host_changes_authorized':3,
          'guest_starts':0,'host_policy_changes':0,'p8_operational':'NO-GO'},
         'APPLY_INTENT_MISMATCH')
    steps = []
    for role in ROLES:
        op = read(attempt/('intent-'+role+'.json'))
        need(op.get('schema') == core.SCHEMA+'-network-intent'
             and op.get('role') == role
             and op.get('command') == ['sudo','-n','virsh','-c','qemu:///system',
                                      'net-start','ardrec-r33-dev-net-'+role],
             'START_COMMAND_NOT_ALLOWLISTED')
        steps.append({'role':role,'command':read(attempt/('result-'+role+'.json')),
                      'readback':read(attempt/('readback-'+role+'.json'))})
    receipt = read(attempt/'receipt.json')
    expected = core.verify_success(before,steps,legacy)
    need(receipt == expected, 'NETWORK_RECEIPT_REPLAY_DRIFT')
    need((plan_path/'apply.once').is_file(), 'MISSING_ONCE_MARKER')
    return receipt


def activate(path: Path) -> int:
    source()
    proposal, before = verify_plan(path)
    # Validate *fresh* host state, not merely the prior capture.
    fresh = measure()
    core.compare(before,fresh,legacy,active=())
    need(not (path/'apply.once').exists(), 'NETWORK_START_ALREADY_ATTEMPTED')
    attempt = Path(tempfile.mkdtemp(prefix='apply-',dir=ROOT))
    prior.directory(attempt)
    intent = {'schema':core.SCHEMA+'-intent',
              'plan_sha256':core.digest(proposal),
              'start_order':list(ROLES),'physical_host_changes_authorized':3,
              'guest_starts':0,'host_policy_changes':0,'p8_operational':'NO-GO'}
    write(attempt/'intent.json', intent)
    # The durable once marker prevents an automatic second run after partial failure.
    write(path/'apply.once',b'ATTEMPTED\n')
    for index,role in enumerate(ROLES,1):
        command = ('sudo','-n','virsh','-c','qemu:///system',
                   'net-start','ardrec-r33-dev-net-'+role)
        write(attempt/('intent-'+role+'.json'),{
            'schema':core.SCHEMA+'-network-intent','role':role,
            'command':list(command),'ordinal':index})
        outcome = legacy.run(command)
        write(attempt/('result-'+role+'.json'),outcome)
        need(outcome['rc'] == 0 and outcome['timeout'] is False
             and outcome['truncated'] is False,
             'NETWORK_START_FAILED_OR_UNCERTAIN_'+role.upper())
        actual = measure()
        write(attempt/('readback-'+role+'.json'),actual)
        core.compare(before,actual,legacy,active=ROLES[:index])
    steps = [{'role':role,'command':read(attempt/('result-'+role+'.json')),
              'readback':read(attempt/('readback-'+role+'.json'))}
             for role in ROLES]
    receipt = core.verify_success(before,steps,legacy)
    write(attempt/'receipt.json',receipt)
    verify_apply(path,attempt)
    print('R112_F4_NETWORKS=SSH_ACTIVE_FTP_ACTIVE_SMB_ACTIVE')
    print('R112_F4_RUNNER_NICS=3')
    print('R112_F4_GUESTS_SHUTOFF=4')
    print('R112_F4_F11_R34=DENY_PRESERVED')
    print('R112_F4_RECEIPT_SHA256='+core.digest(receipt))
    print('R112_F4_PHYSICAL_RECEIPT='+str(attempt))
    print('R112_F4_VM_STARTS=0')
    print('R112_F4_P8=NO-GO')
    print('R112_F4_RESULT=THREE_REAL_NETWORKS_STARTED_WITH_DENY_AND_REPLAY')
    return 0



def verify_restore(plan_path: Path, attempt: Path) -> dict:
    _, before = verify_plan(plan_path)
    private_path(attempt,'restore-')
    order = tuple(reversed(ROLES))
    names={'intent.json','receipt.json'}
    for role in order:
        names.update({'intent-'+role+'.json','result-'+role+'.json',
                      'readback-'+role+'.json'})
    need({p.name for p in attempt.iterdir()} == names,
         'RESTORE_INVENTORY_CHANGED')
    intent=read(attempt/'intent.json')
    need(intent == {'schema':core.SCHEMA+'-restore-intent',
                    'plan_sha256':core.digest(core.plan_for(before,legacy)),
                    'stop_order':list(order),
                    'physical_network_stops_authorized':3,
                    'vm_starts':0,'host_policy_changes':0,'p8_operational':'NO-GO'},
         'RESTORE_INTENT_MISMATCH')
    steps=[]
    for role in order:
        op=read(attempt/('intent-'+role+'.json'))
        need(op.get('schema') == core.SCHEMA+'-network-restore-intent'
             and op.get('role') == role
             and op.get('command') == ['sudo','-n','virsh','-c','qemu:///system',
                                      'net-destroy','ardrec-r33-dev-net-'+role],
             'NET_STOP_NOT_ALLOWLISTED')
        steps.append({'role':role,'command':read(attempt/('result-'+role+'.json')),
                      'readback':read(attempt/('readback-'+role+'.json'))})
    receipt=read(attempt/'receipt.json')
    need(receipt == core.verify_restoration(before,steps,legacy),
         'RESTORE_RECEIPT_REPLAY_DRIFT')
    need((plan_path/'restore.once').is_file(),'RESTORE_ONCE_MARKER_MISSING')
    return receipt


def restore(plan_path: Path, apply_path: Path) -> int:
    source(descendant=True)
    need(isinstance(apply_path, Path), 'APPLY_RECEIPT_REQUIRED')
    verify_apply(plan_path,apply_path)
    _,before=verify_plan(plan_path)
    need(not (plan_path/'restore.once').exists(),'RESTORE_ALREADY_ATTEMPTED')
    fresh=measure()
    core.compare(before,fresh,legacy,active=ROLES)
    attempt=Path(tempfile.mkdtemp(prefix='restore-',dir=ROOT))
    prior.directory(attempt)
    order=tuple(reversed(ROLES))
    write(attempt/'intent.json',{
        'schema':core.SCHEMA+'-restore-intent',
        'plan_sha256':core.digest(core.plan_for(before,legacy)),
        'stop_order':list(order),'physical_network_stops_authorized':3,
        'vm_starts':0,'host_policy_changes':0,'p8_operational':'NO-GO'})
    write(plan_path/'restore.once',b'ATTEMPTED\n')
    for idx,role in enumerate(order,1):
        command=('sudo','-n','virsh','-c','qemu:///system',
                 'net-destroy','ardrec-r33-dev-net-'+role)
        write(attempt/('intent-'+role+'.json'),{
            'schema':core.SCHEMA+'-network-restore-intent',
            'role':role,'command':list(command),'ordinal':idx})
        outcome=legacy.run(command)
        write(attempt/('result-'+role+'.json'),outcome)
        need(outcome['rc'] == 0 and outcome['timeout'] is False
             and outcome['truncated'] is False,
             'NETWORK_STOP_FAILED_OR_UNCERTAIN_'+role.upper())
        actual=measure()
        write(attempt/('readback-'+role+'.json'),actual)
        core.compare(before,actual,legacy,active=ROLES[:3-idx])
    steps=[{'role':role,'command':read(attempt/('result-'+role+'.json')),
            'readback':read(attempt/('readback-'+role+'.json'))}
           for role in order]
    receipt=core.verify_restoration(before,steps,legacy)
    write(attempt/'receipt.json',receipt)
    verify_restore(plan_path,attempt)
    print('R112_F4_NETWORKS=SSH_INACTIVE_FTP_INACTIVE_SMB_INACTIVE')
    print('R112_F4_RESTORE_RECEIPT='+str(attempt))
    print('R112_F4_RESTORED=PASS')
    print('R112_F4_P8=NO-GO')
    return 0

def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan',action='store_true')
    modes.add_argument('--verify-plan',type=Path)
    modes.add_argument('--apply',type=Path)
    modes.add_argument('--verify-physical',type=Path)
    modes.add_argument('--restore',type=Path)
    modes.add_argument('--verify-restored',type=Path)
    parser.add_argument('--plan-session',type=Path)
    parser.add_argument('--apply-session',type=Path)
    parser.add_argument('--i-authorize-three-deny-isolated-network-starts',action='store_true')
    parser.add_argument('--i-authorize-three-network-stops-after-vms-shutoff',action='store_true')
    args=parser.parse_args()
    try:
        if args.plan:
            need(not args.i_authorize_three_deny_isolated_network_starts,'PLAN_MUST_NOT_AUTHORIZE')
            return plan()
        if args.verify_plan is not None:
            source(descendant=True)
            proposal,_=verify_plan(args.verify_plan)
            print('R112_F4_PLAN_REPLAY=PASS')
            print('R112_F4_PLAN_SHA256='+core.digest(proposal))
            return 0
        if args.verify_physical is not None:
            source(descendant=True)
            need(args.plan_session is not None,'PLAN_PATH_REQUIRED')
            result=verify_apply(args.plan_session,args.verify_physical)
            print('R112_F4_PHYSICAL_REPLAY=PASS')
            print('R112_F4_RECEIPT_SHA256='+core.digest(result))
            print('R112_F4_P8=NO-GO')
            return 0
        if args.verify_restored is not None:
            source(descendant=True)
            need(args.plan_session is not None,'PLAN_PATH_REQUIRED')
            receipt=verify_restore(args.plan_session,args.verify_restored)
            print('R112_F4_RESTORATION_REPLAY=PASS')
            print('R112_F4_RESTORE_SHA256='+core.digest(receipt))
            return 0
        if args.restore is not None:
            need(args.i_authorize_three_network_stops_after_vms_shutoff and
                 not args.i_authorize_three_deny_isolated_network_starts,
                 'EXPLICIT_NETWORK_RESTORE_AUTHORIZATION_REQUIRED')
            return restore(args.restore,args.apply_session)
        need(args.i_authorize_three_deny_isolated_network_starts and
             not args.i_authorize_three_network_stops_after_vms_shutoff,
             'EXPLICIT_NETWORK_START_AUTHORIZATION_REQUIRED')
        return activate(args.apply)
    except (ValueError,OSError,TypeError,KeyError,IndexError,RecursionError,ET.ParseError) as error:
        print('R112_F4_STOP='+type(error).__name__+':'+str(error)[:180])
        print('R112_F4_ACTION=NO_RETRY_OR_AUTOMATIC_ROLLBACK_AFTER_PARTIAL_CHANGE')
        print('R112_F4_P8=NO-GO')
        return 23

if __name__=='__main__':
    raise SystemExit(main())
