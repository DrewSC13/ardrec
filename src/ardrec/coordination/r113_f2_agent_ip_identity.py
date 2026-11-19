"""R113-F2: identidad IPv4 real de las 3 redes libvirt, sin abrir tráfico."""
from __future__ import annotations

SCHEMA = 'ardrec-p14-r113-f2-agent-ip-identity-v1'

EXPECTED = {
    'ssh': {'ssh': ('52:54:00:ad:30:02', '10.203.30.2/28')},
    'runner': {
        'ssh': ('52:54:00:ad:30:01', '10.203.30.1/28'),
        'ftp': ('52:54:00:ad:31:01', '10.203.31.1/28'),
        'smb': ('52:54:00:ad:32:01', '10.203.32.1/28'),
    },
    'ftp': {'ftp': ('52:54:00:ad:31:02', '10.203.31.2/28')},
    'smb': {'smb': ('52:54:00:ad:32:02', '10.203.32.2/28')},
}

BRIDGES = {'ssh': 'br33d30', 'ftp': 'br33d31', 'smb': 'br33d32'}

class IdentityError(ValueError):
    pass

def need(test, reason):
    if not test:
        raise IdentityError(reason)

def verify_classification(classified: dict) -> dict:
    """Fail-closed: IP+MAC+red exacta; información operacional, NO permiso P8."""
    need(type(classified) is dict, 'CLASSIFICATION_NOT_OBJECT')
    need(classified.get('agent_ip_discovery') == 'CANDIDATES_AVAILABLE', 'AGENT_NOT_AVAILABLE')
    need(classified.get('R34') == 'DENY_PRESERVED', 'R34_NOT_DENY')
    need(classified.get('F11') == 'HOOK_AND_FILTER_VERIFIED', 'F11_NOT_VERIFIED')
    need(classified.get('traffic_authorized') is False, 'TRAFFIC_STATUS_DRIFT')
    need(classified.get('protocol_connections') == 0, 'PROTOCOL_TEST_ALREADY_RECORDED')
    need(classified.get('p8_operational') == 'NO-GO', 'P8_NOT_NO_GO')
    need(classified.get('guest_states') == dict.fromkeys(EXPECTED, 'RUNNING'), 'GUEST_STATES_DRIFT')
    need(classified.get('networks') == dict.fromkeys(BRIDGES, 'ACTIVE_DENY'), 'NETWORK_STATES_DRIFT')
    guest = classified.get('guest_network_inventory')
    need(type(guest) is dict and set(guest) == set(EXPECTED), 'GUEST_SCOPE_CHANGED')
    output = {}
    for role, targets in EXPECTED.items():
        item = guest[role]
        need(type(item) is dict and item.get('agent_rc') == 0
             and item.get('agent_verified_available') is True, 'AGENT_RESULT_INVALID_'+role)
        observed = item.get('agent_ipv4_ipv6_candidates')
        need(type(observed) is dict and set(observed) == set(targets), 'AGENT_IP_SCOPE_'+role)
        interfaces = item.get('interfaces')
        need(type(interfaces) is list and len(interfaces) == len(targets), 'NIC_COUNT_DRIFT_'+role)
        mapped = {}
        for iface in interfaces:
            need(type(iface) is dict, 'NIC_OBJECT_INVALID_'+role)
            network = iface.get('network')
            mac = iface.get('mac')
            need(type(network) is str and network.startswith('ardrec-r33-dev-net-'),
                 'NIC_NETWORK_UNRECOGNIZED_'+role)
            short = network.removeprefix('ardrec-r33-dev-net-')
            need(short in targets and short not in mapped, 'NIC_SCOPE_DRIFT_'+role)
            need(mac == targets[short][0], 'NIC_MAC_DRIFT_'+role+'_'+short)
            mapped[short] = mac
        need(set(mapped) == set(targets), 'NIC_MISSING_'+role)
        for network, (mac, address) in targets.items():
            need(observed[network] == [address], 'IP_NOT_EXACT_'+role+'_'+network)
        output[role] = {network: {'mac': mac, 'ipv4_cidr': cidr, 'bridge': BRIDGES[network]}
                        for network, (mac, cidr) in targets.items()}
    return {
        'schema': SCHEMA,
        'verified_interface_count': sum(map(len, EXPECTED.values())),
        'verified_network_count': len(BRIDGES),
        'endpoints': output,
        'source': 'real_qemu_guest_agent_mac_bound',
        'services_tested': False,
        'traffic_authorized': False,
        'p8_operational': 'NO-GO',
    }
