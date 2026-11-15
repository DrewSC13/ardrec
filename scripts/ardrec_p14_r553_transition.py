#!/usr/bin/env python3
"""R55.3: authenticated transition plan and physical READ-ONLY readiness.

This executable deliberately has no apply/enable/rollback mode. In particular
no virsh nwfilter-binding-delete/create, nft -f or guest commands are issued.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.coordination import r33_offline_topology as r33
from ardrec.coordination import r34_containment as r34
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r45_ssh_positive_candidate as r45
from ardrec.coordination import r47_filter_stage as r47
from ardrec.coordination import r49_runner_first_boot as r49
from ardrec.coordination import r553_transition_guard as g

DEFAULT_PLAN = Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')
SAFE_VERBS = frozenset({'list', 'net-list', 'dumpxml', 'nwfilter-dumpxml',
                       'nwfilter-binding-dumpxml', 'domstate', 'net-info',
                       'dominfo', 'net-dumpxml'})
ENV = {**os.environ, 'LC_ALL': 'C', 'LANG': 'C'}
COMMANDS = []


def call(argv: list[str], *, input_bytes: bytes | None = None) -> bytes:
    if argv[:5] == ['/usr/bin/sudo','-n','--','/usr/bin/virsh','--readonly']:
        g.require(len(argv) >= 9 and argv[5:7] == ['-c','qemu:///system'] and
                  argv[7] in SAFE_VERBS, 'host_command_not_readonly_virsh')
    elif argv[:4] == ['/usr/bin/sudo','-n','--','/usr/sbin/nft']:
        g.require(argv[4:8] in (['-j','-a','list','table'],
                ['-j','list','tables'], ['-c','-f','-']), 'nft_command_not_safe')
    elif argv[:4] == ['/usr/bin/sudo','-n','--','/usr/sbin/ip']:
        g.require(argv[4:] == ['-j','link','show'] or
                  argv[4:] == ['-o','-4','addr','show','dev','br33d30'],
                  'ip_command_not_safe')
    else:
        g.require(False, 'unapproved_host_executable')
    cmd = argv[-1]
    try:
        cp = subprocess.run(argv, input=input_bytes, stdin=subprocess.DEVNULL if input_bytes is None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, close_fds=True, timeout=40, env=ENV)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise g.TransitionGuardError('host_command_unavailable_' + cmd[:50]) from exc
    COMMANDS.append({'argv':argv,'rc':cp.returncode,
                     'stdout_sha256':g.digest(cp.stdout),
                     'stderr_sha256':g.digest(cp.stderr)})
    g.require(cp.returncode == 0 and len(cp.stdout) <= 512000 and
              len(cp.stderr) <= 16000, 'host_query_failed_' + cmd[:50])
    return cp.stdout


def virsh(*args: str) -> bytes:
    return call(['/usr/bin/sudo','-n','--','/usr/bin/virsh','--readonly','-c',
                 'qemu:///system',*args])


def nft(*args: str, input_bytes=None) -> bytes:
    return call(['/usr/bin/sudo','-n','--','/usr/sbin/nft',*args],input_bytes=input_bytes)


def exact_names(raw: bytes) -> set[str]:
    return {s.strip() for s in raw.decode('utf-8').splitlines() if s.strip()}


def live_readonly(files: dict[str,bytes]) -> dict:
    # Validate existing authoritative R34 deny table and R33 shared filter.
    r35._verify_nft_json(nft('-j','-a','list','table','bridge',g.TABLE))
    r34.verify_filter(virsh('nwfilter-dumpxml',g.DENY))
    all_names = exact_names(virsh('list','--all','--name'))
    active = exact_names(virsh('list','--name'))
    net_names = exact_names(virsh('net-list','--all','--name'))
    net_active = exact_names(virsh('net-list','--name'))
    expected_domains = {r33.DOMAIN_PREFIX + role for role in r33.ROLES}
    expected_networks = {r33.NETWORK_PREFIX + role for role in r33.NET_BRIDGE}
    g.require({x for x in all_names if x.startswith('ardrec-')} == expected_domains,
              'domain_inventory_changed')
    g.require({x for x in net_names if x.startswith('ardrec-')} == expected_networks,
              'network_inventory_changed')
    g.require(active & expected_domains == {g.GUESTS[r][0] for r in g.GUESTS},
              'vm_state_changed')
    g.require(net_active & expected_networks == {g.NETWORK},
              'network_state_changed')
    xmls = {}
    filters = {}
    for role, (domain,tap,mac,ip,candidate) in g.GUESTS.items():
        live = virsh('dumpxml',domain)
        inactive = virsh('dumpxml',domain,'--inactive')
        if role == 'ssh':
            r49._check_ssh_live(live)
        else:
            r49._check_runner_domain(live)
        if role == 'runner':
            r49._check_runner_domain(inactive)
        g.require(ET.fromstring(files[f'{role}-binding-original.xml']).findtext('owner/uuid')
                  == ET.fromstring(live).findtext('uuid'), 'binding_owner_uuid_not_live_' + role)
        g.require(virsh('nwfilter-binding-dumpxml',tap) == files[f'{role}-binding-original.xml'],
                  'binding_changed_' + role)
        expected_filter = r45.filter_candidate(runner=role=='runner')
        current_filter = virsh('nwfilter-dumpxml',candidate)
        r47._check_definition(current_filter, expected_filter)
        filters[role] = g.digest(current_filter)
        xmls[role] = {'live_sha256':g.digest(live),'inactive_sha256':g.digest(inactive)}
    for role in ('ftp','smb'):
        r35._verify_inactive_info(virsh('domstate',r33.DOMAIN_PREFIX+role),kind='domain')
        r35._verify_inactive_info(virsh('net-info',r33.NETWORK_PREFIX+role),kind='network')
    expected_links = {'br33d30','a33d30t','a33d30r'}
    links = json.loads(call(['/usr/bin/sudo','-n','--','/usr/sbin/ip','-j','link','show']))
    observed_links = {x['ifname'] for x in links} & (set(r34.TAPS) | set(r34.BRIDGES))
    g.require(observed_links == expected_links, 'reserved_links_changed')
    addr = call(['/usr/bin/sudo','-n','--','/usr/sbin/ip','-o','-4','addr','show','dev','br33d30'])
    g.require(not addr.strip(), 'host_bridge_ipv4_unexpected')
    # Check syntax again; this is NOT a deployment of either policy.
    nft('-c','-f','-',input_bytes=files['nft-arp-icmp-NOT-AUTHORIZED.nft'])
    nft('-c','-f','-',input_bytes=files['nft-deny-restore-NOT-EXECUTED.nft'])
    # Second before/after readback catches incidental drift during inspection.
    r35._verify_nft_json(nft('-j','-a','list','table','bridge',g.TABLE))
    for role, (domain,tap,mac,ip,candidate) in g.GUESTS.items():
        g.require(virsh('nwfilter-binding-dumpxml',tap) == files[f'{role}-binding-original.xml'],
                  'binding_drift_during_snapshot_' + role)
    return {'status':'LIVE_DENY_READONLY_VERIFIED',
            'domains': sorted(active & expected_domains),
            'networks': sorted(net_active & expected_networks),
            'reserved_links':sorted(observed_links), 'filters_sha256':filters,
            'domain_xml_sha256':xmls, 'active_guest_packets_generated':False,
            'policy_applied':False,'p8_operational':'NO-GO'}


def save(root: Path, data: dict) -> None:
    g.require(root.is_absolute() and not root.exists() and not root.is_symlink(),
              'new_private_receipt_required')
    parent = root.parent
    g.require(parent.is_dir() and parent.stat().st_uid == os.getuid() and
              stat.S_IMODE(parent.stat().st_mode) == 0o700 and
              not any(p.is_symlink() for p in root.parents), 'private_parent_required')
    root.mkdir(mode=0o700)
    blobs = {'r553_report.json':g.canonical(data), 'commands.json':g.canonical(COMMANDS)}
    for name, body in blobs.items():
        fd = os.open(root/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
    sums = ''.join(f'{g.digest(body)}  {name}\n' for name,body in sorted(blobs.items()))
    fd = os.open(root/'SHA256SUMS',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(sums.encode('ascii'))
    print('R553_RECEIPT='+str(root))
    print('R553_REPORT_SHA256='+g.digest(blobs['r553_report.json']))


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description='ARDREC R55.3 source+physical readiness; NO HOST WRITES')
    parser.add_argument('--r552-plan',type=Path,default=DEFAULT_PLAN)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--verify-offline',action='store_true')
    modes.add_argument('--live-readonly',action='store_true')
    parser.add_argument('--receipt-dir',type=Path)
    args=parser.parse_args(argv)
    try:
        g.require(not args.verify_offline or args.receipt_dir is None,
                  'offline_receipt_dir_not_allowed')
        files=g.verify_private_receipt(args.r552_plan)
        contract=g.plan_contract(files)
        try:
            g.simulate(gate_verified=False)
        except g.TransitionGuardError as ex:
            g.require(str(ex) == 'independent_watchdog_missing',
                      'independent_watchdog_gate_drift')
        else:
            g.require(False, 'watchdog_gate_unexpectedly_open')
    except (OSError, ValueError) as ex:
        print('R553_STATUS=BLOCKED:'+str(ex)[:180])
        print('R553_P8=NO-GO')
        return 2
    try:
        offline=g.plan_contract(files)
        if args.verify_offline:
            print('R553_SOURCE_PLAN=VERIFIED')
            print('R553_SYNTHETIC_GUARD=BLOCKS_WITHOUT_WATCHDOG')
            print('R553_R552_SHA256='+g.PLAN_SHA256)
            print('R553_HOST_MUTATIONS=0')
        else:
            g.require(args.receipt_dir is not None, 'receipt_directory_required')
            current=live_readonly(files)
            report={**offline,'live_readonly':current,'status':'R553_OFFLINE_AND_LIVE_READONLY_VERIFIED_NO_GO'}
            save(args.receipt_dir,report)
            print('R553_LIVE_PAIR=RUNNING_DENY_FIRST')
            print('R553_BINDINGS=R33_DENY_VERIFIED')
            print('R553_R45_FILTERS=UNUSED_VERIFIED')
            print('R553_NFT_ALLOW_RESTORE_SYNTAX=PASS')
            print('R553_HOST_MUTATIONS=0')
        print('R553_RESULT=PASS_READONLY_NO_PHYSICAL_AUTHORITY')
        print('R553_WATCHDOG=NOT_IMPLEMENTED')
        print('R553_TRAFFIC=NOT_EXECUTED')
        print('R553_P8=NO-GO')
        return 0
    except (OSError,ValueError,RuntimeError) as ex:
        print('R553_STATUS=BLOCKED:'+str(ex)[:180])
        print('R553_HOST_MUTATIONS=0')
        print('R553_P8=NO-GO')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
