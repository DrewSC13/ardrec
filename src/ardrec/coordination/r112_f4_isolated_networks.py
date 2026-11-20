"""R112-F4: strict admission for activating three no-forward R33 virtual bridges.

Network activation is a real host mutation, NOT guest boot or traffic authority.
All snapshots and network states are measured, not assumed or simulated.
"""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ardrec.coordination import r112_runner_nic_definition as r112

SCHEMA = 'ardrec-r112-f4-real-isolated-network-activation-v1'
ROLES = ('ssh', 'ftp', 'smb')
PARENT = '1cc6db8e8b0ee19ad9f3474a062ad933430eb8f2'
UUIDS = {
    'ssh': '81661f30-4bf2-513b-a384-c5066d407548',
    'ftp': 'a301f714-46b9-5987-ba85-492edd9e65b8',
    'smb': '0d20eab3-1838-5c18-b182-73ae90f5fa9c',
}
MAX_DOC = 3_000_000

class NetworkGateError(ValueError):
    """Refuse a changed target, unverified isolation, or repeated operation."""


def need(predicate: bool, reason: str) -> None:
    if not predicate:
        raise NetworkGateError(reason)


def canonical(obj: Any) -> bytes:
    raw = json.dumps(obj, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
    need(len(raw) <= MAX_DOC, 'NETWORK_REPORT_TOO_LARGE')
    return raw


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def parse_net_info(raw: str, role: str) -> str:
    """Parse locale-pinned virsh net-info; reject duplicate/unknown/mismatched fields."""
    need(role in ROLES and type(raw) is str and 20 < len(raw) < 8192,
         'NET_INFO_BOUNDS')
    found: dict[str,str] = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        need(':' in line, 'NET_INFO_LINE')
        k, v = (x.strip() for x in line.split(':', 1))
        need(k in {'Name','UUID','Active','Persistent','Autostart','Bridge'}
             and k not in found and v, 'NET_INFO_KEY')
        found[k] = v
    need(set(found) == {'Name','UUID','Active','Persistent','Autostart','Bridge'}
         and found['Name'] == 'ardrec-r33-dev-net-' + role
         and found['UUID'] == UUIDS[role]
         and found['Persistent'] == 'yes'
         and found['Autostart'] == 'no'
         and found['Bridge'] == r112.BRIDGES[role]
         and found['Active'] in ('yes', 'no'), 'NET_INFO_IDENTITY_OR_STATE')
    return 'ACTIVE' if found['Active'] == 'yes' else 'INACTIVE'


def inspect(measurement: dict, legacy) -> dict[str,str]:
    """Check all host policy boundaries and measured, C-locale network state."""
    need(type(measurement) is dict and set(measurement) ==
         {'snapshot', 'english_info', 'other_domains'}, 'MEASUREMENT_SCHEMA')
    snapshot = measurement['snapshot']
    verified = r112.audit(snapshot, legacy)
    need(verified['runner_nics'] == 3 and verified['all_shutoff'] is True,
         'RUNNER_OR_GUESTS_NOT_READY')
    extra = measurement['english_info']
    need(type(extra) is dict and set(extra) == set(ROLES), 'NETWORK_INFO_SET')
    status = {}
    for role in ROLES:
        read = extra[role]
        need(type(read) is dict and read.get('rc') == 0 and
             read.get('timeout') is False and read.get('truncated') is False,
             'NET_INFO_PROBE_FAILURE')
        status[role] = parse_net_info(read['stdout'], role)
        xml = ET.fromstring(snapshot['probes']['net-'+role+'-xml']['stdout'])
        need(xml.get('ipv6') in (None, 'no') and
             xml.find('forward') is None and xml.find('ip') is None and
             xml.find('dhcp') is None, 'NETWORK_COULD_ROUTE')
    extra_guests = measurement['other_domains']
    need(type(extra_guests) is dict
         and extra_guests.get('status') == 'NO_UNRELATED_R33_NET_ATTACHMENTS'
         and extra_guests.get('inspected') is True
         and type(extra_guests.get('count')) is int
         and 0 <= extra_guests['count'] <= 128
         and type(extra_guests.get('xml_inventory_sha256')) is str
         and re.fullmatch(r'[0-9a-f]{64}', extra_guests['xml_inventory_sha256']),
         'UNRELATED_GUEST_NETWORK_SCOPE_UNCHECKED')
    return status


def compare(before: dict, after: dict, legacy,
            *, active: tuple[str,...]) -> None:
    """Require no changed XML, VM state, F11 hook, filter, or R34 structure."""
    original, current = inspect(before, legacy), inspect(after, legacy)
    need(original is not None and
         current == {role: ('ACTIVE' if role in active else 'INACTIVE')
                     for role in ROLES}, 'NETWORK_ACTIVATION_STATE_DRIFT')
    b, a = before['snapshot'], after['snapshot']
    b_check, a_check = r112.audit(b, legacy), r112.audit(a, legacy)
    need(b_check['nft_structure_sha256'] == a_check['nft_structure_sha256'],
         'R34_POLICY_CHANGED')
    need(before['other_domains'] == after['other_domains'],
         'UNRELATED_GUEST_INVENTORY_CHANGED')
    # Exclude net-info (expected activity changes) and watchdog time/counters.
    for key in ([f'vm-{role}-{field}' for role in r112.NIC
                 for field in ('state','inactive-xml','block')]
                + [f'net-{role}-xml' for role in ROLES]
                + ['deny-nwfilter-xml','f11-hook-hash','f11-hook-stat']):
        need(b['probes'][key]['stdout'] == a['probes'][key]['stdout'],
             'UNEXPECTED_DOMAIN_NET_OR_HOOK_DRIFT_' + key)


def plan_for(before: dict, legacy) -> dict:
    states = inspect(before, legacy)
    need(states == dict.fromkeys(ROLES, 'INACTIVE'),
         'NETWORK_ALREADY_ACTIVE_OR_DRIFT')
    return {'schema': SCHEMA+'-plan',
            'source_commit': PARENT,
            'mode': 'THREE_REAL_L2_BRIDGES_UNDER_EXISTING_DENY',
            'before_sha256': digest(before),
            'network_names': ['ardrec-r33-dev-net-'+r for r in ROLES],
            'startup_order': list(ROLES),
            'expected_bridges': dict(r112.BRIDGES),
            'unrelated_attachments': 0,
            'guest_boots': 0, 'host_policy_changes': 0,
            'f11_hook_changes': 0, 'protocol_connections': 0,
            'operational_dispatch': False, 'p8_operational': 'NO-GO'}


def verify_success(before: dict, steps: list[dict], legacy) -> dict:
    need(type(steps) is list and len(steps) == len(ROLES), 'STEP_COUNT')
    prior = before
    for idx, (step, role) in enumerate(zip(steps, ROLES), 1):
        need(type(step) is dict and set(step) == {'role','command','readback'}
             and step['role'] == role, 'STEP_SCHEMA')
        result = step['command']
        need(type(result) is dict and result.get('rc') == 0 and
             result.get('timeout') is False and result.get('truncated') is False,
             'NET_START_RESULT_NOT_SUCCESS')
        compare(before, step['readback'], legacy, active=ROLES[:idx])
        prior = step['readback']
    return {'schema': SCHEMA+'-receipt', 'mode': 'REAL_LIBVIRT_NETWORKS_STARTED_NO_GUEST_TRAFFIC',
            'before_sha256': digest(before), 'last_snapshot_sha256': digest(prior),
            'network_start_count': 3, 'network_states': dict.fromkeys(ROLES,'ACTIVE'),
            'vm_starts': 0, 'f11_changed': False, 'nft_changed': False,
            'protocol_connections': 0, 'admission': 'BLOCKED_F11_DENY_PRESERVED',
            'a6_classification': 'ND', 'p8_operational': 'NO-GO'}


def verify_restoration(before: dict, steps: list[dict], legacy) -> dict:
    """Three deliberate net-destroy readbacks, only with all R33 VMs off."""
    order = tuple(reversed(ROLES))
    need(type(steps) is list and len(steps) == 3, 'RESTORE_STEP_COUNT')
    for idx,(step,role) in enumerate(zip(steps,order),1):
        need(type(step) is dict and set(step) == {'role','command','readback'}
             and step['role'] == role, 'RESTORE_STEP_SCHEMA')
        result = step['command']
        need(type(result) is dict and result.get('rc') == 0 and
             result.get('timeout') is False and result.get('truncated') is False,
             'NET_STOP_RESULT_UNCERTAIN')
        compare(before, step['readback'], legacy, active=ROLES[:3-idx])
    return {'schema': SCHEMA+'-restore-receipt',
            'mode':'REAL_LIBVIRT_ISOLATED_NETWORKS_DEACTIVATED',
            'source_before_sha256':digest(before),
            'network_stop_count':3,
            'network_states':dict.fromkeys(ROLES,'INACTIVE'),
            'vm_starts':0,'f11_changed':False,'nft_changed':False,
            'p8_operational':'NO-GO'}
