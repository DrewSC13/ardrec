"""R112-F1: validated real libvirt runner NIC definition, never traffic admission.

All observations originate on Prometheus; pure helpers cannot access the host.
This transition adds FTP/SMB NICs to the *inactive* runner definition only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import xml.etree.ElementTree as ET
from typing import Any

from ardrec.coordination import r111_real_host_reconciliation as r111

SCHEMA = 'ardrec-r112-runner-inactive-nic-definition-v1'
HOST_HOOK_PIN = '8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38'
RUNNER = 'ardrec-r33-dev-runner'
PREFIX = 'ardrec-r33-dev-'
NETPREFIX = 'ardrec-r33-dev-net-'
FILTER = 'ardrec-r33-block-until-containment'
NIC = {
    'runner': [('ssh', '52:54:00:ad:30:01', 'a33d30r')],
    'ssh': [('ssh', '52:54:00:ad:30:02', 'a33d30t')],
    'ftp': [('ftp', '52:54:00:ad:31:02', 'a33d31t')],
    'smb': [('smb', '52:54:00:ad:32:02', 'a33d32t')],
}
ADDED = [('ftp', '52:54:00:ad:31:01', 'a33d31r'),
         ('smb', '52:54:00:ad:32:01', 'a33d32r')]
BRIDGES = {'ssh': 'br33d30', 'ftp': 'br33d31', 'smb': 'br33d32'}


class AdmissionError(ValueError):
    """No automatic privilege escalation, retry, rollback, or P8 authorization."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise AdmissionError(code)


def canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'),
                      allow_nan=False, ensure_ascii=True).encode('ascii') + b'\n'


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def normalized_xml(raw: bytes | str) -> bytes:
    """Ignore only formatting whitespace and attribute insertion order."""
    root = ET.fromstring(raw)
    for element in root.iter():
        if element.text is not None and not element.text.strip():
            element.text = None
        if element.tail is not None and not element.tail.strip():
            element.tail = None
    return ET.canonicalize(ET.tostring(root, encoding='unicode')).encode('utf-8')


def _ifaces(xml: ET.Element) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for interface in xml.findall('devices/interface'):
        net = interface.find('source')
        mac = interface.find('mac')
        tap = interface.find('target')
        filt = interface.find('filterref')
        model = interface.find('model')
        need(interface.get('type') == 'network'
             and all(x is not None for x in (net, mac, tap, filt, model)),
             'INTERFACE_SCHEMA')
        rows.append((net.get('network'), mac.get('address'), tap.get('dev'),
                     filt.get('filter'), model.get('type')))
    return rows


def validate_domain(raw: str, role: str, *, configured: bool = False) -> None:
    need(role in NIC, 'ROLE_UNKNOWN')
    root = ET.fromstring(raw)
    need(root.tag == 'domain' and root.get('type') == 'kvm'
         and root.findtext('name') == PREFIX + role
         and root.find('devices') is not None,
         'DOMAIN_IDENTITY_DRIFT')
    need(not root.findall('devices/hostdev')
         and not root.findall('devices/filesystem')
         and not root.findall('devices/interface[@type="bridge"]')
         and not root.findall('devices/interface[@type="direct"]'),
         'DOMAIN_EXTRA_EGRESS')
    need(len(root.findall('devices/disk[@device="disk"]')) == 1,
         'DOMAIN_DISK_COUNT_DRIFT')
    expected = NIC[role] + (ADDED if role == 'runner' and configured else [])
    actual = _ifaces(root)
    desired = [(NETPREFIX + net, mac, tap, FILTER, 'virtio')
               for net, mac, tap in expected]
    need(actual == desired, 'DOMAIN_NIC_MAC_TAP_OR_FILTER_DRIFT')


def make_candidate(runner_raw: str) -> str:
    validate_domain(runner_raw, 'runner', configured=False)
    root = ET.fromstring(runner_raw)
    devices = root.find('devices')
    need(devices is not None, 'RUNNER_DEVICES_MISSING')
    for role, mac, tap in ADDED:
        iface = ET.SubElement(devices, 'interface', {'type': 'network'})
        ET.SubElement(iface, 'mac', {'address': mac})
        ET.SubElement(iface, 'source', {'network': NETPREFIX + role})
        ET.SubElement(iface, 'target', {'dev': tap})
        ET.SubElement(iface, 'model', {'type': 'virtio'})
        ET.SubElement(iface, 'filterref', {'filter': FILTER})
    candidate = ET.tostring(root, encoding='unicode')
    validate_domain(candidate, 'runner', configured=True)
    return candidate


def validate_candidate(original: str, candidate: str) -> None:
    """No other change permitted: strip exactly the two added NICs."""
    validate_domain(original, 'runner', configured=False)
    validate_domain(candidate, 'runner', configured=True)
    root = ET.fromstring(candidate)
    devices = root.find('devices')
    assert devices is not None
    for element in root.findall('devices/interface')[1:]:
        devices.remove(element)
    need(normalized_xml(ET.tostring(root, encoding='unicode')) ==
         normalized_xml(original), 'CANDIDATE_NON_NIC_MUTATION')


def _nft_structure(raw: str) -> dict:
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise AdmissionError('R34_JSON_INVALID') from exc
    rows = [x['rule'] for x in doc.get('nftables', []) if 'rule' in x]
    need(len(rows) == 4, 'R34_EXACT_RULES_REQUIRED')
    result = []
    for row in rows:
        need(row.get('family') == 'bridge'
             and row.get('table') == 'ardrec_r34_guard'
             and row.get('chain') in ('input', 'output', 'forward')
             and type(row.get('expr')) is list
             and sum('drop' in expr for expr in row['expr']) == 1,
             'R34_DENY_ACTION_DRIFT')
        normalized = copy.deepcopy(row)
        for key in ('handle', 'index', 'comment'):
            normalized.pop(key, None)
        for item in normalized['expr']:
            if type(item) is dict and 'counter' in item:
                item['counter'] = {'packets': 0, 'bytes': 0}
        result.append(normalized)
    need(sorted(x['chain'] for x in result) ==
         ['forward', 'forward', 'input', 'output'], 'R34_CHAIN_COVERAGE')
    return {'rules': sorted(result, key=lambda x: (x['chain'], canonical(x)))}


def _safe_net(xml: str, role: str) -> None:
    root = ET.fromstring(xml)
    bridge = root.find('bridge')
    dns = root.find('dns')
    need(root.tag == 'network' and root.findtext('name') == NETPREFIX + role
         and bridge is not None and bridge.get('name') == BRIDGES[role]
         and root.find('forward') is None and root.find('ip') is None
         and root.find('dhcp') is None and dns is not None
         and dns.get('enable') == 'no', 'NETWORK_ISOLATION_DRIFT')


def audit(record: dict, legacy) -> dict:
    """Validate newly measured physical snapshot and exact persistent scope."""
    need(type(record) is dict and set(record) ==
         {'schema', 'commands', 'probes', 'summary'}, 'SNAPSHOT_SCHEMA')
    probes = record['probes']
    need(record['commands'] == {k: list(v) for k, v in legacy.command_list().items()}
         and len(probes) == 29
         and record['summary'] == legacy.summarize(probes), 'SNAPSHOT_UNREPRODUCIBLE')
    for entry in probes.values():
        need(type(entry) is dict and type(entry.get('rc')) is int
             and entry['rc'] == 0 and entry['timeout'] is False
             and entry['truncated'] is False, 'PROBE_FAILED')
    summary = record['summary']
    need(summary['hook_sha256'] == HOST_HOOK_PIN
         and summary['nft_rule_count'] == 4
         and summary['p8_operational'] == 'NO-GO'
         and summary['physical_admission'] == 'DENIED_F11_NOT_CHANGED',
         'F11_OR_R34_ANCHOR_DRIFT')
    for role in NIC:
        state = summary['domains'][role]
        need(r111.normalize_state(state) == 'SHUTOFF', 'VM_NOT_SHUTOFF')
        validate_domain(probes['vm-' + role + '-inactive-xml']['stdout'], role,
                        configured=(role == 'runner' and len(summary['domain_inventory']['runner']['interfaces']) == 3))
    for role in BRIDGES:
        _safe_net(probes['net-' + role + '-xml']['stdout'], role)
    filt = ET.fromstring(probes['deny-nwfilter-xml']['stdout'])
    rules = filt.findall('rule')
    need(filt.tag == 'filter' and filt.get('name') == FILTER
         and len(rules) == 1 and rules[0].get('action') == 'drop'
         and rules[0].get('direction') == 'inout'
         and rules[0].find('all') is not None, 'NWFILTER_DENY_DRIFT')
    systemd = summary['systemd']
    need(systemd['libvirt-daemon']['ActiveState'] == 'active'
         and systemd['f11-boot-unit']['ActiveState'] == 'active'
         and systemd['f11-watchdog-timer']['ActiveState'] == 'active',
         'F11_RUNTIME_NOT_ACTIVE')
    nft = _nft_structure(probes['r34-nft']['stdout'])
    nic_count = len(summary['domain_inventory']['runner']['interfaces'])
    need(nic_count in (1, 3), 'RUNNER_NIC_COUNT_INVALID')
    return {'runner_nics': nic_count, 'all_shutoff': True,
            'nft_structure_sha256': sha(canonical(nft)),
            'f11_hook_sha256': HOST_HOOK_PIN,
            'runner_xml_sha256': sha(normalized_xml(probes['vm-runner-inactive-xml']['stdout']))}


def snapshot_equivalent(before: dict, now: dict, legacy, *, after_definition: bool) -> None:
    base = audit(before, legacy)
    target = audit(now, legacy)
    need(base['runner_nics'] == 1, 'PLAN_NOT_SSH_ONLY')
    need(target['runner_nics'] == (3 if after_definition else 1),
         'RUNNER_NIC_COUNT_NOT_EXPECTED')
    b, n = before['probes'], now['probes']
    # Ignore monotonically changing nft counters and timer timestamps only.
    need(base['nft_structure_sha256'] == target['nft_structure_sha256'],
         'R34_STRUCTURE_CHANGED')
    stable_keys = ([f'vm-{role}-state' for role in NIC]
                   + [f'vm-{role}-block' for role in NIC]
                   + [f'vm-{role}-inactive-xml' for role in NIC if role != 'runner']
                   + [f'net-{role}-{kind}' for role in BRIDGES
                      for kind in ('xml', 'info')]
                   + ['deny-nwfilter-xml', 'f11-hook-hash', 'f11-hook-stat'])
    for key in stable_keys:
        need(b[key]['stdout'] == n[key]['stdout'], 'HOST_SOURCE_DRIFT_' + key)
    old_runner = b['vm-runner-inactive-xml']['stdout']
    new_runner = n['vm-runner-inactive-xml']['stdout']
    if after_definition:
        validate_candidate(old_runner, new_runner)
    else:
        need(normalized_xml(old_runner) == normalized_xml(new_runner),
             'RUNNER_CHANGED_SINCE_PLAN')
