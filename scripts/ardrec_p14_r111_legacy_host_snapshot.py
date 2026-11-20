#!/usr/bin/env python3
"""ARDREC R111 P0: actual HOST read-only libvirt/F11/NFT inventory.

This program DOES NOT start guests or networks; modify policies or guest data;
execute protocol probes; or grant P8 permissions. Private host data stays local.
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
import xml.etree.ElementTree as ET

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/home/cicada/ardrec-lab/r111-real-host-readiness-v1')
BASE = '4d01b095771079e7e778b9b3c3f4640296191117'
ROLES = ('runner', 'ssh', 'ftp', 'smb')
NETWORKS = ('ssh', 'ftp', 'smb')
PREFIX = 'ardrec-r33-dev-'
NETWORK_PREFIX = 'ardrec-r33-dev-net-'
FILTER = 'ardrec-r33-block-until-containment'
HOOK = '/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'
MAX_CAPTURE = 256_000
SCHEMA = 'ardrec-r111-real-host-readonly-inventory-v1'


def require(v: bool, code: str):
    if not v:
        raise ValueError(code)


def canonical(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii') + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command_list():
    common = ('virsh', '--readonly', '-c', 'qemu:///system')
    out = {
        'domains': (*common, 'list', '--all'),
        'networks': (*common, 'net-list', '--all'),
        'filters': (*common, 'nwfilter-list'),
        'libvirt-daemon': ('systemctl', 'show', 'libvirtd.service',
                          '--property=LoadState,ActiveState,SubState,Requires,After,DropInPaths'),
        'f11-boot-unit': ('systemctl', 'show', 'ardrec-r34-boot-deny.service',
                          '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus'),
        'f11-watchdog-unit': ('systemctl', 'show', 'ardrec-r34-deny-watchdog.service',
                              '--property=LoadState,ActiveState,SubState,Result'),
        'f11-watchdog-timer': ('systemctl', 'show', 'ardrec-r34-deny-watchdog.timer',
                              '--property=LoadState,ActiveState,SubState,Unit,NextElapseUSecRealtime'),
        'f11-hook-stat': ('sudo', '-n', 'stat', '-Lc', '%u:%g %a %s %n', HOOK),
        'f11-hook-hash': ('sudo', '-n', 'sha256sum', HOOK),
        'r34-nft': ('sudo', '-n', 'nft', '-j', '-a', 'list', 'table', 'bridge', 'ardrec_r34_guard'),
    }
    for role in ROLES:
        dom = PREFIX + role
        out[f'vm-{role}-state'] = (*common, 'domstate', dom)
        out[f'vm-{role}-inactive-xml'] = (*common, 'dumpxml', '--inactive', dom)
        out[f'vm-{role}-block'] = (*common, 'domblklist', dom)
    for role in NETWORKS:
        net = NETWORK_PREFIX + role
        out[f'net-{role}-info'] = (*common, 'net-info', net)
        out[f'net-{role}-xml'] = (*common, 'net-dumpxml', net)
    out['deny-nwfilter-xml'] = (*common, 'nwfilter-dumpxml', FILTER)
    return out


def run(args):
    try:
        p = subprocess.run(args, capture_output=True, timeout=16,
                           stdin=subprocess.DEVNULL, check=False)
        out, err = p.stdout, p.stderr
        return {'rc': p.returncode, 'timeout': False,
                'stdout': out[:MAX_CAPTURE].decode('utf-8', 'replace'),
                'stderr': err[:2048].decode('utf-8', 'replace'),
                'truncated': len(out) > MAX_CAPTURE or len(err) > 2048}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'rc': None, 'timeout': isinstance(error, subprocess.TimeoutExpired),
                'stdout': '', 'stderr': type(error).__name__, 'truncated': False}


def xml_diagnostics(probes):
    states, links, nets = {}, {}, {}
    for role in ROLES:
        obs = probes[f'vm-{role}-state']
        states[role] = obs['stdout'].strip().upper() if obs['rc'] == 0 else 'UNKNOWN'
        xml = probes[f'vm-{role}-inactive-xml']
        if xml['rc'] != 0 or xml['truncated']:
            links[role] = {'error': 'INACTIVE_XML_UNAVAILABLE'}
            continue
        try:
            root = ET.fromstring(xml['stdout'])
            interfaces = []
            for n in root.findall('devices/interface'):
                src, target, mac, flt = (n.find(part) for part in ('source','target','mac','filterref'))
                interfaces.append({
                    'network': src.get('network') if src is not None else None,
                    'tap': target.get('dev') if target is not None else None,
                    'mac': mac.get('address') if mac is not None else None,
                    'filter': flt.get('filter') if flt is not None else None,
                })
            disks = root.findall('devices/disk')
            links[role] = {'name': root.findtext('name'), 'interfaces': interfaces,
                           'disks': len(disks), 'hostdevs': len(root.findall('devices/hostdev')),
                           'host_filesystem_mounts': len(root.findall('devices/filesystem'))}
        except ET.ParseError:
            links[role] = {'error': 'INACTIVE_XML_PARSE_FAILURE'}
    for role in NETWORKS:
        xml = probes[f'net-{role}-xml']
        if xml['rc'] != 0 or xml['truncated']:
            nets[role] = {'error': 'NETWORK_XML_UNAVAILABLE'}
            continue
        try:
            root = ET.fromstring(xml['stdout'])
            bridge = root.find('bridge')
            nets[role] = {'name': root.findtext('name'),
                          'bridge': bridge.get('name') if bridge is not None else None,
                          'no_forward': root.find('forward') is None,
                          'no_l3': root.find('ip') is None,
                          'dns_disabled': root.find('dns') is not None
                          and root.find('dns').get('enable') == 'no',
                          'ipv6_attribute': root.get('ipv6')}
        except ET.ParseError:
            nets[role] = {'error': 'NETWORK_XML_PARSE_FAILURE'}
    return states, links, nets


def summarize(probes):
    states, links, nets = xml_diagnostics(probes)
    missing = []
    for role in ROLES:
        if states[role] != 'SHUT OFF' and states[role] != 'SHUTOFF':
            missing.append('VM_' + role.upper() + '_NOT_CONFIRMED_SHUTOFF')
        if 'error' in links[role]:
            missing.append('VM_' + role.upper() + '_XML_UNAVAILABLE')
    expected_if = {'ssh': (NETWORK_PREFIX+'ssh',),
                   'ftp': (NETWORK_PREFIX+'ftp',),
                   'smb': (NETWORK_PREFIX+'smb',),
                   'runner': tuple(NETWORK_PREFIX+r for r in NETWORKS)}
    for role in ROLES:
        if 'error' in links[role]:
            continue
        actual = tuple(row['network'] for row in links[role]['interfaces'])
        if actual != expected_if[role]:
            missing.append('VM_'+role.upper()+'_NIC_TOPOLOGY_INCOMPLETE')
        if not all(row['filter'] == FILTER for row in links[role]['interfaces']):
            missing.append('VM_'+role.upper()+'_FILTER_BINDING_DRIFT')
    for role in NETWORKS:
        n = nets[role]
        if 'error' in n:
            missing.append('NETWORK_'+role.upper()+'_XML_UNAVAILABLE')
        elif not (n['name'] == NETWORK_PREFIX+role and
                  n['no_forward'] and n['no_l3'] and n['dns_disabled']):
            missing.append('NETWORK_'+role.upper()+'_ISOLATION_DRIFT')
    for key in ('f11-hook-stat', 'f11-hook-hash', 'r34-nft', 'deny-nwfilter-xml'):
        if probes[key]['rc'] != 0:
            missing.append(key.replace('-', '_').upper()+'_NOT_READABLE')
    if probes['deny-nwfilter-xml']['rc'] == 0:
        try:
            xml = ET.fromstring(probes['deny-nwfilter-xml']['stdout'])
            rules = xml.findall('rule')
            if (xml.get('name') != FILTER or len(rules) != 1
                    or rules[0].get('action') != 'drop'
                    or rules[0].get('direction') != 'inout'):
                missing.append('NWFILTER_NOT_EXACT_DROP')
        except ET.ParseError:
            missing.append('NWFILTER_XML_INVALID')
    nft_count = None
    if probes['r34-nft']['rc'] == 0:
        try:
            nft = json.loads(probes['r34-nft']['stdout'])
            rules = [row['rule'] for row in nft.get('nftables', []) if 'rule' in row]
            nft_count = len(rules)
            if nft_count < 4:
                missing.append('NFT_R34_LESS_THAN_FOUR_RULES')
        except (ValueError, TypeError, KeyError):
            missing.append('NFT_R34_PARSE_FAILURE')
    systemd = {}
    for key in ('libvirt-daemon', 'f11-boot-unit', 'f11-watchdog-unit', 'f11-watchdog-timer'):
        p = probes[key]
        entries = dict(line.split('=', 1) for line in p['stdout'].splitlines() if '=' in line)
        systemd[key] = {k: entries.get(k, 'UNKNOWN') for k in
                        ('LoadState', 'ActiveState', 'SubState', 'Result', 'Requires')}
        if p['rc'] != 0 or entries.get('LoadState') != 'loaded':
            missing.append(key.replace('-', '_').upper()+'_UNKNOWN_OR_UNLOADED')
    hook_hash = probes['f11-hook-hash']['stdout'].split()[:1] if probes['f11-hook-hash']['rc'] == 0 else []
    return {'schema': SCHEMA, 'read_only': True,
            'source_main_sha': BASE, 'domains': states, 'domain_inventory': links,
            'isolated_networks': nets, 'nft_rule_count': nft_count,
            'systemd': systemd, 'hook_sha256': hook_hash[0] if hook_hash else None,
            'failed_readonly_probes': sorted(k for k,v in probes.items() if v['rc'] != 0),
            'readiness_findings': sorted(set(missing)),
            'physical_admission': 'DENIED_F11_NOT_CHANGED',
            'vm_starts': 0, 'host_policy_mutations': 0, 'protocol_connections': 0,
            'a6_technical_truth': 'ND', 'p8_operational': 'NO-GO'}


def secure_write(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _private_directory(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'PRIVATE_DIR_INVALID')
    st = directory.stat()
    require(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
            'PRIVATE_DIR_MODE_OR_OWNER')


def collect():
    require(Path.cwd().resolve() == REPO, 'REPOSITORY_ROOT_REQUIRED')
    current = run(('git', 'rev-parse', 'HEAD'))
    branch = run(('git', 'branch', '--show-current'))
    status = run(('git', 'status', '--porcelain', '--untracked-files=all'))
    require(current['rc'] == branch['rc'] == status['rc'] == 0 and
            current['stdout'].strip() == BASE and branch['stdout'].strip() == 'main'
            and not status['stdout'].strip(), 'MAIN_OR_WORKTREE_DRIFT')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(ROOT)
    probes = {key: run(command) for key, command in command_list().items()}
    summary = summarize(probes)
    record = {'schema': SCHEMA, 'commands': {k:list(v) for k,v in command_list().items()},
              'probes': probes, 'summary': summary}
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=ROOT))
    _private_directory(directory)
    raw = canonical(record)
    secure_write(directory / 'snapshot.json', raw)
    manifest = {'schema': SCHEMA+'-manifest', 'snapshot_sha256': sha(raw),
                'source_main_sha': BASE, 'read_only': True,
                'vm_starts': 0, 'host_policy_mutations': 0,
                'p8_operational': 'NO-GO'}
    secure_write(directory / 'manifest.json', canonical(manifest))
    verify(directory)
    print('R111_REAL_HOST_SNAPSHOT=RECORDED_READONLY')
    print('R111_PROBE_COUNT='+str(len(probes)))
    print('R111_FAILED_PROBES='+str(len(summary['failed_readonly_probes'])))
    for role in ROLES:
        print('R111_VM_'+role.upper()+'_STATE='+summary['domains'][role])
        interfaces = summary['domain_inventory'][role].get('interfaces', [])
        print('R111_VM_'+role.upper()+'_NICS='+(','.join((i['network'] or '?') for i in interfaces) or 'UNKNOWN'))
    for role in NETWORKS:
        n = summary['isolated_networks'][role]
        print('R111_NET_'+role.upper()+'='+str(n.get('bridge', n.get('error', 'UNKNOWN'))))
    for k in ('f11-boot-unit', 'f11-watchdog-unit', 'f11-watchdog-timer'):
        st = summary['systemd'][k]
        print('R111_'+k.replace('-', '_').upper()+'='+st['LoadState']+'/'+st['ActiveState'])
    print('R111_F11_HOOK_SHA256='+str(summary['hook_sha256']))
    print('R111_R34_NFT_RULES='+str(summary['nft_rule_count']))
    print('R111_FINDINGS='+','.join(summary['readiness_findings']))
    print('R111_SNAPSHOT_SHA256='+sha(raw))
    print('R111_SESSION='+str(directory))
    print('R111_VM_STARTS=0')
    print('R111_PHYSICAL_ADMISSION=DENIED_F11_NOT_CHANGED')
    print('R111_P8=NO-GO')
    print('R111_RESULT=REAL_HOST_READONLY_INVENTORY_RECORDED')
    return 0


def verify(directory):
    require(directory.is_absolute() and directory.parent == ROOT
            and re.fullmatch(r'run-[A-Za-z0-9_\-]+', directory.name) is not None,
            'REPLAY_PATH_INVALID')
    _private_directory(directory)
    require({p.name for p in directory.iterdir()} == {'snapshot.json','manifest.json'},
            'REPLAY_FILE_SET_DRIFT')
    for name in ('snapshot.json','manifest.json'):
        st = (directory / name).lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600
                and st.st_size <= 3_000_000, 'REPLAY_MODE_OR_SIZE')
    raw = (directory / 'snapshot.json').read_bytes()
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    record = json.loads(raw)
    require(raw == canonical(record) and
            canonical(manifest) == (directory / 'manifest.json').read_bytes(),
            'REPLAY_CANONICAL')
    require(manifest['snapshot_sha256'] == sha(raw) and
            manifest['source_main_sha'] == BASE and
            manifest['p8_operational'] == 'NO-GO' and
            manifest['read_only'] is True and
            manifest['vm_starts'] == 0 and
            manifest['host_policy_mutations'] == 0,
            'REPLAY_MANIFEST_INTEGRITY')
    require(record['commands'] == {k:list(v) for k,v in command_list().items()}
            and record['summary'] == summarize(record['probes']),
            'REPLAY_SOURCE_OR_SUMMARY_DRIFT')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--real-host-readonly', action='store_true')
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args()
    try:
        if args.real_host_readonly:
            return collect()
        result = verify(args.verify)
        print('R111_REPLAY_SHA256='+result['snapshot_sha256'])
        print('R111_REPLAY=PASS')
        print('R111_P8=NO-GO')
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('R111_STOP='+type(error).__name__+':'+str(error)[:140])
        print('R111_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
