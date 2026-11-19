"""R113-F1: lectura tipada de topología y candidatos IP; jamás habilita tráfico."""
from __future__ import annotations
import ipaddress
import json
import re
from typing import Any

SCHEMA = 'ardrec-p14-r113-f1-readonly-network-audit-v1'
ROLES = ('ssh', 'runner', 'ftp', 'smb')
NETWORKS = ('ssh', 'ftp', 'smb')
BRIDGES = {'ssh': 'br33d30', 'ftp': 'br33d31', 'smb': 'br33d32'}

class AuditError(ValueError):
    pass

def need(value: bool, reason: str) -> None:
    if not value:
        raise AuditError(reason)

def valid_capture(record: dict[str, Any]) -> bool:
    return (type(record) is dict
            and set(record) == {'rc', 'stdout', 'stderr', 'timeout', 'truncated'}
            and record['rc'] == 0 and record['timeout'] is False
            and record['truncated'] is False and type(record['stdout']) is str)

def agent_addresses(raw: str, expected: dict[str, str]) -> dict[str, list[str]]:
    """Solo candidatos informativos del agente, con MAC de NIC ancladas."""
    need(type(raw) is str and len(raw) < 20000, 'AGENT_OUTPUT_INVALID')
    found = {role: [] for role in expected}
    for line in raw.splitlines():
        m = re.fullmatch(
            r'\s*(\S+)\s+([0-9a-fA-F:]{17})\s+(ipv4|ipv6)\s+(\S+)\s*', line
        )
        if not m:
            continue
        _, mac, family, address = m.groups()
        matched = [role for role, value in expected.items() if mac.lower() == value.lower()]
        if len(matched) != 1:
            continue
        try:
            net = ipaddress.ip_interface(address)
        except ValueError:
            continue
        if net.version != (4 if family == 'ipv4' else 6):
            continue
        ip = net.ip
        if (not ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified):
            continue
        addr = str(net)
        if addr not in found[matched[0]]:
            found[matched[0]].append(addr)
    return {key: sorted(value) for key, value in found.items()}

def classify_live(snapshot: dict, guest: dict[str, dict], bridge: dict[str, dict],
                  *, f10, legacy, f4, nic, f9) -> dict:
    # Reutilizar el clasificador final R112: cuatro VM encendidas + R34 intacta.
    f10.audited(snapshot, 'smb', after=True, legacy=legacy, f4=f4)
    expected = set(ROLES)
    need(type(guest) is dict and set(guest) == expected, 'GUEST_INVENTORY_SCOPE')
    need(type(bridge) is dict and set(bridge) == set(NETWORKS), 'BRIDGE_INVENTORY_SCOPE')
    inventory = snapshot['snapshot']['summary']['domain_inventory']
    topology = {}
    candidate_complete = True
    for role in ROLES:
        entry = guest[role]
        need(set(entry) == {'live_xml', 'agent', 'domiflist'}, 'GUEST_FIELDS_INVALID')
        xml = entry['live_xml']
        need(valid_capture(xml), 'LIVE_XML_UNAVAILABLE_'+role)
        if role == 'runner':
            f9.live_runner(xml['stdout'])
        else:
            nic.validate_domain(xml['stdout'], role)
        interfaces = inventory[role]['interfaces']
        macs = {item['network'].split('-')[-1]: item['mac'] for item in interfaces}
        need(len(macs) == (3 if role == 'runner' else 1),
             'INTERFACE_COUNT_CHANGED_'+role)
        agent = entry['agent']
        addresses = (agent_addresses(agent['stdout'], macs)
                     if valid_capture(agent) else {key: [] for key in macs})
        if any(not value for value in addresses.values()):
            candidate_complete = False
        topology[role] = {
            'interfaces': interfaces, 'agent_rc': agent['rc'],
            'agent_ipv4_ipv6_candidates': addresses,
            'agent_verified_available': valid_capture(agent),
            'domiflist_rc': entry['domiflist']['rc'],
            'ip_source': 'libvirt-agent-only-not-service-proof',
        }
    for role, item in bridge.items():
        need(set(item) == {'link', 'addresses'}, 'BRIDGE_FIELDS_INVALID')
        need(valid_capture(item['link']), 'BRIDGE_LINK_MISSING_'+role)
        try:
            decoded = json.loads(item['link']['stdout'])
        except (TypeError, ValueError) as exc:
            raise AuditError('BRIDGE_LINK_JSON_INVALID_'+role) from exc
        need(type(decoded) is list and len(decoded) == 1 and
             decoded[0]['ifname'] == BRIDGES[role],
             'BRIDGE_IFNAME_CHANGED_'+role)
    return {
        'schema': SCHEMA + '-classification',
        'guest_states': {role: 'RUNNING' for role in ROLES},
        'networks': {role: 'ACTIVE_DENY' for role in NETWORKS},
        'R34': 'DENY_PRESERVED',
        'F11': 'HOOK_AND_FILTER_VERIFIED',
        'agent_ip_discovery': 'CANDIDATES_AVAILABLE' if candidate_complete else 'INCOMPLETE',
        'guest_network_inventory': topology,
        'traffic_authorized': False,
        'protocol_connections': 0,
        'a5_dispatched': False,
        'a6': 'ND',
        'p8_operational': 'NO-GO',
    }
