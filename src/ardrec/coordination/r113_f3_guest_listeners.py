"""R113-F3: clasificación sin tráfico de puertos en escucha reportados por ss en VM."""
from __future__ import annotations
import base64
import binascii
import ipaddress
import re

SCHEMA = 'ardrec-p14-r113-f3-guest-listeners-v2'
TARGETS = {
    'ssh': ('10.203.30.2',22),
    'ftp': ('10.203.31.2',21),
    'smb': ('10.203.32.2',445),
}

class GuardError(ValueError):
    pass

def need(condition: bool, reason: str) -> None:
    if not condition:
        raise GuardError(reason)

def agent_info(reply: dict) -> bool:
    need(type(reply) is dict and set(reply) == {'return'}, 'QGA_INFO_STRUCTURE')
    entry = reply['return']
    need(type(entry) is dict and type(entry.get('supported_commands')) is list,
         'QGA_INFO_MISSING_COMMANDS')
    found = {}
    for cmd in entry['supported_commands']:
        need(type(cmd) is dict and type(cmd.get('name')) is str
             and type(cmd.get('enabled')) is bool, 'QGA_COMMAND_INVALID')
        need(cmd['name'] not in found, 'QGA_DUPLICATE_COMMAND')
        found[cmd['name']] = cmd['enabled']
    need(found.get('guest-exec') is True and
         found.get('guest-exec-status') is True, 'QGA_GUEST_EXEC_DISABLED')
    return True

def started(reply: dict) -> int:
    need(type(reply) is dict and set(reply) == {'return'} and
         type(reply['return']) is dict, 'GUEST_EXEC_START_INVALID')
    pid = reply['return'].get('pid')
    need(type(pid) is int and 0 < pid < (1 << 32), 'GUEST_EXEC_PID_INVALID')
    return pid

def status(reply: dict) -> tuple[bool, int | None, bytes | None, bytes | None]:
    need(type(reply) is dict and set(reply) == {'return'} and
         type(reply['return']) is dict, 'GUEST_EXEC_STATUS_INVALID')
    item = reply['return']
    need(type(item.get('exited')) is bool, 'GUEST_EXIT_FLAG_INVALID')
    if not item['exited']:
        return False, None, None, None
    need(type(item.get('exitcode')) is int and item['exitcode'] >= 0,
         'GUEST_EXIT_CODE_INVALID')
    results = []
    for name in ('out-data','err-data'):
        raw = item.get(name,'')
        need(type(raw) is str and len(raw) <= 64000, 'GUEST_OUTPUT_FIELD_INVALID')
        try:
            value = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise GuardError('GUEST_OUTPUT_BASE64_INVALID') from exc
        need(len(value) <= 48000, 'GUEST_OUTPUT_TOO_LARGE')
        results.append(value)
    return True, item['exitcode'], results[0], results[1]

def listening_sockets(raw: bytes) -> tuple[dict, ...]:
    need(type(raw) is bytes and len(raw) <= 48000, 'SS_CAPTURE_INVALID')
    try:
        text = raw.decode('utf-8','strict')
    except UnicodeDecodeError as exc:
        raise GuardError('SS_CAPTURE_ENCODING') from exc
    sockets = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        need(len(fields) >= 5 and fields[0] == 'LISTEN', 'SS_LINE_INVALID')
        local = fields[3]
        need(':' in local, 'SS_LOCAL_SOCKET_INVALID')
        host, port = local.rsplit(':', 1)
        need(re.fullmatch(r'\d{1,5}',port) is not None, 'SS_PORT_INVALID')
        port_int = int(port)
        need(1 <= port_int <= 65535, 'SS_PORT_RANGE')
        # Linux ss -4 puede añadir %interfaz a una dirección IPv4 concreta,
        # p. ej. 127.0.0.53%lo:53. El ámbito no transforma una dirección
        # de loopback en accesibilidad externa. Nunca se admite *%interfaz.
        if host == '*':
            address = ipaddress.IPv4Address('0.0.0.0')
        else:
            address_text = host
            if '%' in host:
                need(host.count('%') == 1, 'SS_IPV4_SCOPE_INVALID')
                address_text, iface = host.split('%', 1)
                need(re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,15}', iface)
                     is not None, 'SS_IPV4_SCOPE_INVALID')
            try:
                address = ipaddress.IPv4Address(address_text)
            except ipaddress.AddressValueError as exc:
                raise GuardError('SS_ADDRESS_NOT_IPV4') from exc
        sockets.append({'address':str(address),'port':port_int})
    return tuple(sockets)

def classify(role: str, result: dict) -> dict:
    need(role in TARGETS, 'ROLE_NOT_ALLOWED')
    need(type(result) is dict and set(result) ==
         {'pid','status','command','stdout_b64','stderr_b64'}, 'OBSERVATION_SCHEMA')
    need(result['command'] == ['/usr/bin/ss','-H','-ltn4'], 'COMMAND_NOT_ALLOWLISTED')
    need(type(result['pid']) is int and result['pid'] > 0, 'INVALID_PID')
    need(type(result['status']) is int and result['status'] == 0,
         'SS_EXECUTION_UNSUCCESSFUL')
    exited, code, stdout, stderr = status({'return': {
        'exited':True, 'exitcode':result['status'],
        'out-data':result['stdout_b64'], 'err-data':result['stderr_b64']
    }})
    need(exited and code == 0 and stderr == b'', 'SS_STDERR_NOT_EMPTY')
    sockets = listening_sockets(stdout)
    target, port = TARGETS[role]
    found = [sock['address'] for sock in sockets if sock['port'] == port]
    if target in found or '0.0.0.0' in found:
        state = 'LISTENING_ON_LAB_IPV4'
    elif found:
        state = 'LISTENING_ONLY_ON_OTHER_IPV4'
    else:
        state = 'NO_LISTENER_AT_EXPECTED_PORT'
    return {
        'role':role, 'address':target, 'expected_port':port,
        'local_listener_state':state, 'bound_ipv4':sorted(set(found)),
        'observed_ipv4_socket_count':len(sockets),
        'protocol_connection_attempted':False,
        'network_reachability_proven':False,
        'service_identity_proven':False,
        'p8_operational':'NO-GO',
    }
