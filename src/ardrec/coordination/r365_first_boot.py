"""R36.5: single-segment SSH first boot, fail-closed and receipt-bound.

Only physical writes: `virsh net-start ardrec-r33-dev-net-ssh`, then
`virsh start ardrec-r33-dev-ssh`. No guest probes, network policy changes,
shutdown, cleanup, rollback, unrelated service access or pentesting.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any
import xml.etree.ElementTree as ET

from ardrec.coordination import r33_offline_topology as t33
from ardrec.coordination import r34_containment as t34
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination.r36_readonly_dashboard import (
    EXPECTED_R35_FILES, EXPECTED_R36_FILES, EXPECTED_R361_FILES,
    load_sources, verified_directory,
)

SCHEMA = 'ardrec-p14-r365-first-boot-ssh-v1'
RECEIPT_SCHEMA = 'ardrec-p14-r365-preflight-receipt-v1'
EXPECTED_MAIN = 'a161cb625ed48d0a35251e3976f79f196b6fd039'
SSH_NETWORK = t33.NETWORK_PREFIX + 'ssh'
SSH_DOMAIN = t33.DOMAIN_PREFIX + 'ssh'
R363_FILES = frozenset({
    'capabilities.xml', 'domains_active.txt', 'domains_all.txt',
    'interfaces.json', 'networks_active.txt', 'networks_all.txt',
    'nft.json', 'nwfilter.xml', 'r363_report.json',
    *(f'network_{r}.xml' for r in t33.NET_BRIDGE),
    *(f'network_{r}_info.txt' for r in t33.NET_BRIDGE),
    *(f'domain_{r}.xml' for r in t33.ROLES),
    *(f'domain_{r}_info.txt' for r in t33.ROLES),
    *(f'domain_{r}_state.txt' for r in t33.ROLES),
})
R364_FILES = frozenset({'r364_report.json'})
READ_ONLY = 'NO_OPERATIONAL_AUTHORITY'

class BootError(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise BootError(reason)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_json(raw: bytes) -> dict[str, Any]:
    require(len(raw) < 262144, 'json_too_large')
    pairs = []
    def unique(items):
        keys = [k for k, _ in items]
        require(len(keys) == len(set(keys)), 'duplicate_json_key')
        return dict(items)
    obj = json.loads(raw, object_pairs_hook=unique,
                     parse_constant=lambda _: (_ for _ in ()).throw(BootError('nonfinite_json')))
    require(type(obj) is dict, 'json_object_expected')
    return obj


def check_digest(doc: dict[str, Any], schema: str) -> None:
    require(doc.get('schema') == schema and type(doc.get('sha256')) is str and
            len(doc['sha256']) == 64 and
            sha(canonical({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
            'report_schema_or_digest_invalid')


def verify_prior(r35_dir: Path, r36_dir: Path, r361_dir: Path,
                 r363_dir: Path, r364_dir: Path) -> dict[str, Any]:
    # R36.2 verifies R35/R36/R36.1 semantically, not just their SHA256SUMS.
    view = load_sources(r35_dir=r35_dir, r36_dir=r36_dir, r361_dir=r361_dir)
    r363 = verified_directory(r363_dir, R363_FILES)
    r364 = verified_directory(r364_dir, R364_FILES)
    p3 = read_json(r363['r363_report.json'])
    p4 = read_json(r364['r364_report.json'])
    check_digest(p3, 'ardrec-r363-preboot-readonly-v1')
    check_digest(p4, 'ardrec-r364-boot-readiness-v1')
    require(p3.get('source_main') == EXPECTED_MAIN and
            p3.get('source_r35_sha256') == view['host_evidence']['r35_file_sha256'] and
            p3.get('source_r36_sha256') == view['host_evidence']['r36_file_sha256'] and
            p3.get('source_r361_sha256') == view['algorithm_evidence']['r361_file_sha256'] and
            p3.get('nft_verified') is True and
            p3.get('nwfilter_verified') is True and
            p3.get('active_ardrec_resources') == 0 and
            p3.get('protected_interfaces') == 6 and
            p3.get('kvm_x86_64_available') is True and
            p3.get('guest_traffic_isolation_tested') is False and
            p3.get('vm_activated') is False and
            p3.get('network_activated') is False and
            p3.get('p8_operational') == 'NO-GO', 'r363_state_invalid')
    require(p4.get('main') == EXPECTED_MAIN and
            p4.get('source_r363_sha256') == p3['sha256'] and
            p4.get('nft_verified') is True and
            p4.get('networks_inactive') == list(r35.NETWORKS) and
            p4.get('domains_shut_off') == list(r35.DOMAINS) and
            p4.get('reserved_interfaces_absent') is True and
            p4.get('vm_memory_mib') == 6144 and
            p4.get('host_reserve_mib') == 2048 and
            p4.get('guest_isolation_tested') is False and
            p4.get('network_started') is False and
            p4.get('vm_started') is False and
            p4.get('physical_authorization_granted') is False and
            p4.get('p8_operational') == 'NO-GO', 'r364_state_invalid')
    return {'r363_sha256': p3['sha256'], 'r364_sha256': p4['sha256'],
            'r35_file_sha256': view['host_evidence']['r35_file_sha256'],
            'r36_file_sha256': view['host_evidence']['r36_file_sha256'],
            'r361_file_sha256': view['algorithm_evidence']['r361_file_sha256']}


def _names(raw: bytes) -> set[str]:
    values = raw.decode('utf-8').splitlines()
    require(len(values) == len(set(values)), 'duplicate_resource_in_inventory')
    return {x for x in values if x}


def _interfaces(host: 'FirstBootHost') -> set[str]:
    data = read_json(b'{"items":' + host.run([host.bin['ip'], '-j', 'link', 'show']) + b'}')
    values = data['items']
    require(type(values) is list and all(type(x) is dict and
            type(x.get('ifname')) is str for x in values), 'ip_link_json_invalid')
    names = [x['ifname'] for x in values]
    require(len(names) == len(set(names)), 'duplicate_link_name')
    return set(names)


def memory_available_mib() -> int:
    values = {}
    for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            bits = v.split()
            if k in ('MemAvailable', 'MemTotal') and len(bits) == 2 and bits[0].isdigit() and bits[1] == 'kB':
                values[k] = int(bits[0]) // 1024
    require('MemAvailable' in values and 'MemTotal' in values and
            0 < values['MemAvailable'] <= values['MemTotal'], 'memory_read_invalid')
    return values['MemAvailable']


class FirstBootHost(r35.Host):
    """R35's allowlisted read-only boundary plus two exact activation argv."""
    def activate_ssh_network(self) -> None:
        self.run([self.bin['sudo'], '-n', '--', self.bin['virsh'],
                  '-c', 'qemu:///system', 'net-start', SSH_NETWORK], timeout=120)

    def activate_ssh_domain(self) -> None:
        self.run([self.bin['sudo'], '-n', '--', self.bin['virsh'],
                  '-c', 'qemu:///system', 'start', SSH_DOMAIN], timeout=180)


def current(host: FirstBootHost, *, phase: str) -> dict[str, Any]:
    require(phase in ('BEFORE', 'NETWORK_ONLY', 'SSH_RUNNING'), 'invalid_phase')
    r35._verify_installed_nft(host)
    t34.verify_filter(host.virsh_ro(['nwfilter-dumpxml', t33.DENY_FILTER]))
    exp = t33.render_xml(t33.R32_RECEIPT_FILE_SHA256)
    macs = {}
    for role in t33.NET_BRIDGE:
        name = t33.NETWORK_PREFIX + role
        xml = host.virsh_ro(['net-dumpxml', name, '--inactive'])
        macs[role] = r35._network_bridge_mac(xml, exp[f'network-{role}.xml'], role)
        if phase == 'BEFORE' or role != 'ssh':
            r35._verify_inactive_info(host.virsh_ro(['net-info', name]), kind='network')
    r35._verify_network_mac_inventory(macs, prior_ssh=True)
    require(macs == r35.R354_EXISTING_BRIDGE_MACS, 'network_mac_drift')
    for role in t33.ROLES:
        name = t33.DOMAIN_PREFIX + role
        r35._verify_domain_dump(host.virsh_ro(['dumpxml', name, '--inactive']),
                                exp[f'domain-{role}.xml'], role)
        if phase != 'SSH_RUNNING' or role != 'ssh':
            r35._verify_inactive_info(host.virsh_ro(['domstate', name]), kind='domain')
        r35._verify_domain_autostart(host.virsh_ro(['dominfo', name]))
    all_net = _names(host.virsh_ro(['net-list', '--all', '--name']))
    all_dom = _names(host.virsh_ro(['list', '--all', '--name']))
    active_net = _names(host.virsh_ro(['net-list', '--name']))
    active_dom = _names(host.virsh_ro(['list', '--name']))
    require((all_net & {x for x in all_net if x.startswith(t33.NETWORK_PREFIX)}) == set(r35.NETWORKS) and
            (all_dom & {x for x in all_dom if x.startswith(t33.DOMAIN_PREFIX)}) == set(r35.DOMAINS),
            'resource_inventory_drift')
    expected_net = set() if phase == 'BEFORE' else {SSH_NETWORK}
    expected_dom = {SSH_DOMAIN} if phase == 'SSH_RUNNING' else set()
    require(active_net.intersection(r35.NETWORKS) == expected_net,
            'network_activation_drift')
    require(active_dom.intersection(r35.DOMAINS) == expected_dom,
            'domain_activation_drift')
    present = _interfaces(host)
    reserved = present.intersection(set(r35.TAPS) | set(r35.BRIDGES))
    expected_links = {
        'BEFORE': set(),
        'NETWORK_ONLY': {t33.NET_BRIDGE['ssh']},
        'SSH_RUNNING': {t33.NET_BRIDGE['ssh'], 'a33d30t'},
    }[phase]
    require(reserved == expected_links, 'reserved_interface_scope_changed')
    # Before any boot all 4 runtime overlays must match authenticated R32 bytes.
    return {'phase': phase, 'active_networks': sorted(expected_net),
            'active_domains': sorted(expected_dom), 'reserved_links': sorted(reserved),
            'bridge_macs': macs, 'deny_first_still_verified': True}


def verify_storage(host: FirstBootHost, r32: dict[str, Any]) -> None:
    d = r35._verify_storage(host, r32)
    require(d['verified_roles'] == 4 and not d['source_images_mutated'],
            'storage_drift')


def verify_preflight_receipt(directory: Path, sources: dict[str, Any]) -> dict[str, Any]:
    docs = verified_directory(directory, frozenset({'r365_report.json', 'commands.jsonl'}))
    report = read_json(docs['r365_report.json'])
    check_digest(report, SCHEMA)
    require(report.get('status') == 'READY_FOR_EXPLICIT_FIRST_BOOT' and
            report.get('mode') == 'PREFLIGHT_ONLY' and
            report.get('source_evidence') == sources and
            report.get('host_state', {}).get('phase') == 'BEFORE' and
            report.get('storage_verified') is True and
            report.get('host_mutations') == [] and
            report.get('attempted_mutations') == [] and
            report.get('network_started') is False and
            report.get('vm_started') is False and
            report.get('operational_dispatch') is False and
            report.get('failure_code') is None and
            report.get('guest_isolation_tested') is False and
            report.get('p8_operational') == 'NO-GO', 'preflight_receipt_not_ready')
    lines = docs['commands.jsonl'].splitlines()
    for raw in lines:
        row = read_json(raw)
        argv = row.get('argv')
        require(type(argv) is list and argv and
                all(type(x) is str for x in argv), 'preflight_command_invalid')
        argv = argv[3:] if argv[:3] == ['/usr/bin/sudo','-n','--'] else argv
        exe = argv[0]
        if exe == '/usr/bin/virsh':
            require(argv[1:4] == ['--readonly', '-c', 'qemu:///system'] and
                    argv[4] in ('nwfilter-dumpxml','net-dumpxml','net-info','dumpxml',
                                'domstate','dominfo','net-list','list'),
                    'preflight_receipt_contains_write')
        elif exe in ('/usr/bin/nft','/usr/sbin/nft'):
            require(argv[1:] == ['-j','-a','list','table','bridge',t34.NFT_TABLE],
                    'preflight_receipt_contains_write')
        elif exe in ('/usr/bin/ip','/usr/sbin/ip'):
            require(argv[1:] == ['-j','link','show'],
                    'preflight_receipt_contains_write')
        elif exe == '/usr/bin/stat':
            require(argv[1] == '--printf=%F|%u|%g|%h|%a|%s|%i|%Y|%Z',
                    'preflight_receipt_contains_write')
        elif exe == '/usr/bin/sha256sum':
            require(argv[1:3] == ['--binary', '--'],
                    'preflight_receipt_contains_write')
        elif exe == '/usr/bin/qemu-img':
            require(argv[1:5] == ['info','--output=json','-f','qcow2'],
                    'preflight_receipt_contains_write')
        else:
            raise BootError('preflight_receipt_contains_write')
    return report


def _receipt_directory(path: Path) -> None:
    require(isinstance(path, Path) and path.is_absolute() and
            not path.exists() and not path.is_symlink(), 'receipt_destination_invalid')
    require(not any(x.is_symlink() for x in path.parents), 'receipt_parent_symlink')
    parent = path.parent
    s = parent.stat()
    require(parent.is_dir() and s.st_uid == os.geteuid() and
            stat.S_IMODE(s.st_mode) == 0o700, 'receipt_parent_not_private')
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'receipt_dir_mode_wrong')


def _write(path: Path, body: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(body)
        file.flush()
        os.fsync(file.fileno())


def seal_receipts(directory: Path, report: dict[str, Any], commands: list[dict[str, Any]]) -> None:
    report['sha256'] = sha(canonical({k: v for k, v in report.items() if k != 'sha256'}))
    _write(directory / 'r365_report.json', canonical(report) + b'\n')
    _write(directory / 'commands.jsonl', b''.join(canonical(x) + b'\n' for x in commands))
    files = ('commands.jsonl', 'r365_report.json')
    _write(directory / 'SHA256SUMS', b''.join(
        sha((directory / name).read_bytes()).encode() + b'  ' + name.encode() + b'\n'
        for name in files))


def perform(*, archive: Path, receipt_dir: Path, r35_dir: Path,
            r36_dir: Path, r361_dir: Path, r363_dir: Path, r364_dir: Path,
            preflight_dir: Path | None = None, authorized: bool = False,
            host: FirstBootHost | None = None) -> dict[str, Any]:
    """No mutation unless both authorized AND prior preflight receipt verified."""
    require(not authorized or preflight_dir is not None, 'authorization_requires_preflight')
    _receipt_directory(receipt_dir)
    h = host if host is not None else FirstBootHost()
    mode = 'FIRST_BOOT_AUTHORIZED' if authorized else 'PREFLIGHT_ONLY'
    report: dict[str, Any] = {
        'schema': SCHEMA, 'mode': mode, 'status': 'BLOCKED_NO_CHANGE',
        'failure_code': None, 'source_main': EXPECTED_MAIN,
        'source_evidence': None, 'source_archive_sha256': r35.ARCHIVE_SHA256,
        'host_state': None, 'storage_verified': False,
        'host_mutations': [], 'network_started': False, 'vm_started': False,
        'guest_isolation_tested': False, 'real_service_testing': 'NOT_EXECUTED',
        'operational_dispatch': False, 'final_risk': None,
        'experimental_validation': 'NOT_RUN', 'p8_operational': 'NO-GO',
        'automatic_rollback': False,
    }
    report['attempted_mutations'] = []
    try:
        source = verify_prior(r35_dir, r36_dir, r361_dir, r363_dir, r364_dir)
        report['source_evidence'] = source
        if authorized:
            prior_receipt = verify_preflight_receipt(preflight_dir, source)
            report['source_preflight_sha256'] = prior_receipt['sha256']
        # The source TAR has a pinned SHA and exact inventory; extraction is local only.
        with tempfile.TemporaryDirectory(prefix='r365-source-') as root:
            temp = Path(root)
            bundle = r35.verify_source_bundle(archive, temp)
            current_memory = memory_available_mib()
            report['memory_available_mib_before'] = current_memory
            require(current_memory >= t33.RESOURCE['ssh']['ram_mib'] + 2048,
                    'host_memory_insufficient_for_single_ssh')
            verify_storage(h, bundle['r32'])
            report['storage_verified'] = True
            state = current(h, phase='BEFORE')
            report['host_state'] = state
            if not authorized:
                report['status'] = 'READY_FOR_EXPLICIT_FIRST_BOOT'
            else:
                # A second readback immediately before each of two ONLY permitted writes.
                current(h, phase='BEFORE')
                report['attempted_mutations'].append('virsh net-start ' + SSH_NETWORK)
                h.activate_ssh_network()
                report['host_mutations'].append('virsh net-start ' + SSH_NETWORK)
                report['network_started'] = True
                mid = current(h, phase='NETWORK_ONLY')
                report['network_phase_readback'] = mid
                # Only the SSH runtime overlay can be changed by a VM boot.
                report['attempted_mutations'].append('virsh start ' + SSH_DOMAIN)
                h.activate_ssh_domain()
                report['host_mutations'].append('virsh start ' + SSH_DOMAIN)
                report['vm_started'] = True
                after = current(h, phase='SSH_RUNNING')
                report['final_readback'] = after
                report['status'] = 'FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED'
    except Exception as exc:
        report['failure_code'] = str(exc)[:220]
        report['status'] = 'PARTIAL_NO_GO_REVIEW_REQUIRED' if report['attempted_mutations'] else 'BLOCKED_NO_CHANGE'
    finally:
        seal_receipts(receipt_dir, report, h.commands)
    return report
