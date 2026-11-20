"""R115-F2: medidas *actuales* de solo lectura para A3; nunca habilita P8.

Captura información local de libvirt, nftables y systemd; verifica contexto,
identidad y fallos observables. La telemetría local no es un permiso de prueba.
La autoridad independiente, el cliente y la preparación del servicio requieren
sus propios verificadores antes de considerar cualquier despacho.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from typing import Callable
import xml.etree.ElementTree as ET

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r112_runner_nic_definition as nic
from ardrec.coordination import r112_f4_isolated_networks as net4

BASE_COMMIT = 'a652195a544a549dbad6a44120e3d447cf4d4994'
SCHEMA = 'ARDREC-R115-F2-A3-CURRENT-READONLY-SOURCES-v1'
REPORT_SCHEMA = 'ARDREC-R115-F2-A3-READONLY-NEGATIVE-GATES-v1'
MANIFEST_SCHEMA = 'ARDREC-R115-F2-PRIVATE-RECEIPT-v1'
PREFIX = ('/usr/bin/virsh', '--readonly', '-c', 'qemu:///system')
TARGET_VM = 'ardrec-r33-dev-ftp'
RUNNER_VM = 'ardrec-r33-dev-runner'
TARGET_MAC = '52:54:00:ad:31:02'
RUNNER_MAC = '52:54:00:ad:31:01'
FTP_NET = 'ardrec-r33-dev-net-ftp'
NFT_TABLE = 'ardrec_r34_guard'
TIMER = 'ardrec-r34-deny-watchdog.timer'
PRIVATE_ROOT = Path('/home/cicada/ardrec-lab/r115-f2-a3-readonly-v1')
CONTRACT_MAX = 200_000
COMMAND_MAX = 192_000
MAX_DURATION = 150

# Absolute, immutable argument lists. No shell, QGA, VM start, network or nft mutation.
COMMANDS = {
    'ftp_state': PREFIX + ('domstate', TARGET_VM),
    'runner_state': PREFIX + ('domstate', RUNNER_VM),
    'ftp_xml': PREFIX + ('dumpxml', TARGET_VM),
    'runner_xml': PREFIX + ('dumpxml', RUNNER_VM),
    'ftp_net_info': PREFIX + ('net-info', FTP_NET),
    'ftp_net_xml': PREFIX + ('net-dumpxml', FTP_NET),
    'nft_r34': ('/usr/sbin/nft', '-j', 'list', 'table', 'bridge', NFT_TABLE),
    'watchdog_timer': ('/usr/bin/systemctl', 'show', TIMER,
                       '--property=ActiveState', '--property=LoadState'),
}

class Stop(ValueError):
    """Invalid, untrusted or inconsistent input; never a permission."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def canonical(doc) -> bytes:
    return f1.canonical(doc)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')


def capture_command(name: str, *, runner: Callable = subprocess.run,
                    clock: Callable = utcnow) -> dict:
    need(name in COMMANDS, 'COMMAND_NOT_ALLOWLISTED')
    argv = COMMANDS[name]
    start = clock()
    began = time.monotonic()
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                  timeout=8, check=False, shell=False,
                  env={'LC_ALL': 'C', 'LANG': 'C', 'PATH': '/usr/sbin:/usr/bin:/bin'})
    try:
        proc = runner(list(argv), **kwargs)
        out, err = proc.stdout, proc.stderr
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        out, err = exc.stdout or b'', exc.stderr or b''
        rc = None
        timed_out = True
    except (OSError, ValueError):
        out, err = b'', b''
        rc = None
        timed_out = False
    end = clock()
    need(type(out) is bytes and type(err) is bytes, 'COMMAND_OUTPUT_NOT_BYTES')
    truncated = len(out) > COMMAND_MAX or len(err) > COMMAND_MAX
    return {
        'rc': rc, 'timed_out': timed_out, 'truncated': truncated,
        'started_at': iso(start), 'completed_at': iso(end),
        'elapsed_ms': max(0, int((time.monotonic()-began)*1000)),
        'stdout_b64': base64.b64encode(out[:COMMAND_MAX]).decode('ascii'),
        'stderr_b64': base64.b64encode(err[:COMMAND_MAX]).decode('ascii'),
    }


def collect(*, runner: Callable = subprocess.run,
            clock: Callable = utcnow) -> dict:
    start = clock()
    probes = {key: capture_command(key, runner=runner, clock=clock)
              for key in COMMANDS}
    end = clock()
    return {'schema': SCHEMA, 'started_at': iso(start),
            'completed_at': iso(end), 'commands': probes,
            'source_kind': 'LOCAL_COMMANDS_READONLY_UNPRIVILEGED',
            'not_an_authority_or_traffic_grant': True}


def check_snapshot(doc: dict) -> dict:
    need(type(doc) is dict and set(doc) ==
         {'schema', 'started_at', 'completed_at', 'commands',
          'source_kind', 'not_an_authority_or_traffic_grant'}, 'SNAPSHOT_FIELDS')
    need(doc['schema'] == SCHEMA and
         doc['source_kind'] == 'LOCAL_COMMANDS_READONLY_UNPRIVILEGED' and
         doc['not_an_authority_or_traffic_grant'] is True, 'SNAPSHOT_UNTRUSTED_SHAPE')
    start = f1._instant(doc['started_at'], 'CAPTURE_START')
    end = f1._instant(doc['completed_at'], 'CAPTURE_END')
    need(start <= end and (end-start).total_seconds() <= MAX_DURATION, 'CAPTURE_INTERVAL')
    probes = doc['commands']
    need(type(probes) is dict and set(probes) == set(COMMANDS), 'COMMAND_SET')
    for key, record in probes.items():
        need(type(record) is dict and set(record) ==
             {'rc','timed_out','truncated','started_at','completed_at',
              'elapsed_ms','stdout_b64','stderr_b64'}, 'COMMAND_RECORD_'+key)
        need((record['rc'] is None or
              (type(record['rc']) is int and -128 <= record['rc'] <= 255)) and
             type(record['timed_out']) is bool and
             type(record['truncated']) is bool and
             type(record['elapsed_ms']) is int and
             0 <= record['elapsed_ms'] <= MAX_DURATION*1000,
             'COMMAND_STATUS_'+key)
        a = f1._instant(record['started_at'], 'COMMAND_START')
        b = f1._instant(record['completed_at'], 'COMMAND_END')
        need(start <= a <= b <= end, 'COMMAND_TIMELINE_'+key)
        for field in ('stdout_b64','stderr_b64'):
            value = record[field]
            need(type(value) is str and len(value) <= 4*((COMMAND_MAX+2)//3)+4,
                 'COMMAND_CONTENT_SIZE_'+key)
            try:
                raw = base64.b64decode(value, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise Stop('COMMAND_INVALID_BASE64_'+key) from exc
            need(len(raw) <= COMMAND_MAX, 'COMMAND_CONTENT_OVERFLOW_'+key)
    return doc


def output(snapshot: dict, key: str) -> bytes | None:
    p = snapshot['commands'][key]
    if p['rc'] != 0 or p['timed_out'] or p['truncated']:
        return None
    raw = base64.b64decode(p['stdout_b64'], validate=True)
    return raw if raw else None


def xml_root(raw: bytes | None) -> ET.Element | None:
    if raw is None or b'<!' in raw:
        return None
    try:
        return ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        return None


def vm_state(raw: bytes | None) -> str:
    if raw is None:
        return 'ND'
    # LC_ALL=C is pinned by collector; accept known older locale for replay.
    normalized = raw.decode('utf-8', errors='replace').strip().casefold()
    if normalized in ('shut off', 'apagado'):
        return 'OFF'
    if normalized in ('running', 'ejecutando'):
        return 'RUNNING'
    return 'ND'


def identities(snapshot: dict, contract: dict | None) -> tuple[str, str]:
    ftp_raw = output(snapshot, 'ftp_xml')
    runner_raw = output(snapshot, 'runner_xml')
    if ftp_raw is None or runner_raw is None:
        return 'ND', 'VM_DEFINITIONS_UNREADABLE'
    if b'<!' in ftp_raw or b'<!' in runner_raw:
        return 'DRIFT', 'VM_XML_DTD_FORBIDDEN'
    try:
        nic.validate_domain(ftp_raw.decode('utf-8'), 'ftp')
        nic.validate_domain(runner_raw.decode('utf-8'), 'runner', configured=True)
    except (UnicodeError, ET.ParseError, ValueError, KeyError, TypeError):
        return 'DRIFT', 'PINNED_VM_INTERFACE_DRIFT'
    if contract is not None and contract['target']['mac'] != TARGET_MAC:
        return 'DRIFT', 'CONTRACT_TARGET_MAC_NOT_PINNED'
    return 'MATCH', 'PINNED_VM_XML_MATCH_NO_AUTHORITY'


def isolated_network(snapshot: dict) -> tuple[str, str]:
    raw = output(snapshot, 'ftp_net_xml')
    if raw is None:
        return 'ND', 'NETWORK_DEFINITION_UNREADABLE'
    root = xml_root(raw)
    if root is None:
        return 'ND', 'NETWORK_XML_INVALID'
    bridge = root.find('bridge')
    if (root.tag != 'network' or root.findtext('name') != FTP_NET or
            bridge is None or bridge.get('name') != 'br33d31'):
        return 'DRIFT', 'FTP_NETWORK_IDENTITY_DRIFT'
    if (root.find('forward') is not None or root.find('ip') is not None or
            root.find('dhcp') is not None or root.get('ipv6') not in (None, 'no')):
        return 'DRIFT', 'FTP_NETWORK_ROUTING_OR_ADDRESSING_DRIFT'
    return 'MATCH', 'NO_FORWARD_IN_STATIC_NETWORK_XML'


def network_runtime(snapshot: dict) -> tuple[str,str]:
    raw = output(snapshot, 'ftp_net_info')
    if raw is None:
        return 'ND', 'NETWORK_RUNTIME_READ_FAILED'
    try:
        result = net4.parse_net_info(raw.decode('ascii'), 'ftp')
    except (UnicodeError, ValueError, TypeError, KeyError, ET.ParseError):
        return 'DRIFT', 'NETWORK_RUNTIME_IDENTITY_OR_CONFIG_DRIFT'
    return 'MATCH', 'ISOLATED_NETWORK_' + result + '_NO_AUTHORITY'


def deny_nft(snapshot: dict) -> tuple[str,str]:
    raw = output(snapshot, 'nft_r34')
    if raw is None:
        return 'ND', 'NFT_READ_FAILED_OR_INSUFFICIENT_PERMISSIONS'
    try:
        doc = f1.load(raw)
        rows = doc.get('nftables')
        need(type(rows) is list, 'NFT_ROWS')
        rules = [v['rule'] for v in rows if type(v) is dict and type(v.get('rule')) is dict]
        chains = [v['chain'] for v in rows if type(v) is dict and type(v.get('chain')) is dict]
        table = [v['table'] for v in rows if type(v) is dict and type(v.get('table')) is dict]
        need(len(table)==1 and table[0].get('name') == NFT_TABLE and
             table[0].get('family') == 'bridge', 'NFT_TABLE_DRIFT')
        need(len(chains)==3 and {x.get('name') for x in chains} ==
             {'input','output','forward'}, 'NFT_CHAINS_DRIFT')
        need(len(rules)==4 and
             {(r.get('chain'), next((k for x in r.get('expr', []) if
                              type(x) is dict and type(x.get('match')) is dict
                              for k in (x['match'].get('left', {}).get('meta', {}).get('key'),)),
                             None)) for r in rules} ==
             {('input','iifname'),('output','oifname'),
              ('forward','iifname'),('forward','oifname')}, 'NFT_DENY_RULE_SET')
        taps = {'a33d30r','a33d30t','a33d31r','a33d31t','a33d32r','a33d32t'}
        for r in rules:
            expr = r['expr']
            need(len(expr)==3 and type(expr[0]) is dict and
                 type(expr[0].get('match')) is dict and
                 type(expr[1]) is dict and 'counter' in expr[1] and
                 expr[2] == {'drop':None} and
                 r.get('family')=='bridge' and r.get('table')==NFT_TABLE,
                 'NFT_NOT_FOUR_EXACT_DROPS')
            match = expr[0]['match']
            need(match.get('op')=='==' and
                 set(match.get('right',{}).get('set',[]))==taps,
                 'NFT_EXTRA_OR_MISSING_TAPS')
    except (f1.Rejected, Stop, KeyError, TypeError, ValueError, AttributeError):
        return 'DRIFT', 'NFT_DENY_STRUCTURE_DRIFT'
    return 'MATCH', 'FOUR_EXACT_DROPS_OBSERVED_NO_TRAFFIC_GRANT'


def timer_state(snapshot: dict) -> tuple[str,str]:
    raw = output(snapshot, 'watchdog_timer')
    if raw is None:
        return 'ND', 'WATCHDOG_UNREADABLE'
    try:
        rows = raw.decode('ascii').splitlines()
        pairs = [line.split('=',1) for line in rows]
        data = dict(pairs)
        need(len(rows)==2 and len(data)==2 and
             set(data)=={'LoadState','ActiveState'}, 'WATCHDOG_FIELDS')
    except (UnicodeError, ValueError, Stop):
        return 'ND', 'WATCHDOG_PARSE_UNCERTAIN'
    if data=={'LoadState':'loaded','ActiveState':'active'}:
        return 'MATCH', 'WATCHDOG_TIMER_ACTIVE_NOT_RECOVERY_PROOF'
    return 'DRIFT', 'WATCHDOG_NOT_ACTIVE_OR_LOADED'


def report(snapshot: dict, *, contract: dict | None = None,
           catalogue: dict | None = None, catalog_raw: bytes | None = None) -> dict:
    check_snapshot(snapshot)
    current = f1._instant(snapshot['completed_at'], 'CAPTURE_END')
    contract_state = 'NOT_SUPPLIED'
    contract_digest = None
    if contract is not None:
        need(catalogue is not None and catalog_raw is not None, 'CATALOG_REQUIRED')
        f1.validate(contract, catalogue, catalog_raw)
        need(contract['source_commit']==BASE_COMMIT, 'CONTRACT_SOURCE_COMMIT_DRIFT')
        contract_digest = sha(canonical(contract))
        contract_state = 'STATIC_VALID_CURRENT_WINDOW'
        start = f1._instant(contract['valid_from'], 'CONTRACT_FROM')
        end = f1._instant(contract['valid_until'], 'CONTRACT_TO')
        if not start <= current < end:
            contract_state = 'STATIC_VALID_BUT_OUTSIDE_WINDOW'
    ftp = vm_state(output(snapshot, 'ftp_state'))
    runner = vm_state(output(snapshot, 'runner_state'))
    ident, ident_reason = identities(snapshot, contract)
    net, net_reason = isolated_network(snapshot)
    netlive, netlive_reason = network_runtime(snapshot)
    nft, nft_reason = deny_nft(snapshot)
    timer, timer_reason = timer_state(snapshot)
    source = {
        'ftp_vm_state': ftp, 'runner_vm_state': runner,
        'vm_definition': {'status': ident, 'reason': ident_reason},
        'ftp_network_definition': {'status': net, 'reason': net_reason},
        'ftp_network_runtime': {'status': netlive, 'reason': netlive_reason},
        'r34_nft': {'status': nft, 'reason': nft_reason},
        'r34_watchdog': {'status': timer, 'reason': timer_reason},
    }
    gates = {key: 'ND' for key in f1.GATES}
    reasons = {key: 'INDEPENDENT_AUTHORITY_AND_COMPLETE_CURRENT_PROOF_REQUIRED'
               for key in f1.GATES}
    if contract_state == 'STATIC_VALID_BUT_OUTSIDE_WINDOW':
        gates['SCOPE_APPROVED'] = 'FALSO'
        reasons['SCOPE_APPROVED'] = 'CONTRACT_TIME_WINDOW_NOT_CURRENT'
    else:
        reasons['SCOPE_APPROVED'] = 'NO_INDEPENDENT_AUTHORIZED_SIGNER_OR_REVOCATION_CHECK'
    if 'DRIFT' in (net, netlive, nft, timer):
        gates['LAB_ISOLATION_CONFIRMED'] = 'FALSO'
        reasons['LAB_ISOLATION_CONFIRMED'] = 'MEASURED_ISOLATION_CONTROL_DRIFT'
    else:
        reasons['LAB_ISOLATION_CONFIRMED'] = 'SIX_CURRENT_BINDINGS_AND_EFFECTIVE_POLICY_NOT_YET_ATTESTED'
    if ident == 'DRIFT':
        gates['DESTINATION_AUTHORIZED'] = 'FALSO'
        reasons['DESTINATION_AUTHORIZED'] = ident_reason
    else:
        reasons['DESTINATION_AUTHORIZED'] = 'VM_IDENTITY_IS_NOT_TARGET_AUTHORIZATION'
    reasons['CLIENT_COMPATIBLE'] = 'PROFILE_CLIENT_RUNTIME_NOT_ATTESTED'
    if ftp == 'OFF' or runner == 'OFF':
        gates['SERVICE_READY'] = 'FALSO'
        reasons['SERVICE_READY'] = 'RUNNER_OR_FTP_VM_SHUT_OFF'
    else:
        reasons['SERVICE_READY'] = 'NO_FRESH_EFFECTIVE_SERVICE_OR_PROTOCOL_READINESS_PROOF'
    return {
        'schema': REPORT_SCHEMA,
        'snapshot_sha256': sha(canonical(snapshot)),
        'capture_completed_at': snapshot['completed_at'],
        'contract_sha256': contract_digest,
        'contract_binding': contract_state,
        'source_checks': source,
        'a3_status': gates, 'a3_reasons': reasons,
        'a3_all_true': False, 'a5_executable': False,
        'a6_classification': 'ND', 'a7_final_risk': None,
        'a9_published_generation': None, 'p8': 'NO-GO',
        'dispatch_decision': 'NO-GO',
        'operational_authority_granted': False,
        'current_source_not_authorization': True,
        'no_network_probe': True, 'no_vm_start': True,
        'read_only_capture': True,
        'snapshot_not_a_live_lease': True,
    }


def private_parent(path: Path) -> None:
    need(path.is_absolute(), 'PRIVATE_PATH_NOT_ABSOLUTE')
    for parent in [path, *path.parents]:
        need(not parent.is_symlink(), 'PRIVATE_SYMLINK_COMPONENT')
    need(path.is_dir(), 'PRIVATE_DIRECTORY_MISSING')
    s = path.stat()
    need(s.st_uid == os.geteuid() and stat.S_IMODE(s.st_mode) == 0o700,
         'PRIVATE_DIRECTORY_MODE_OR_OWNER')


def private_read(path: Path) -> bytes:
    need(path.is_absolute(), 'INPUT_PATH_NOT_ABSOLUTE')
    for component in [path, *path.parents]:
        need(not component.is_symlink(), 'INPUT_SYMLINK')
    s = path.stat()
    need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
         s.st_uid==os.geteuid() and not (stat.S_IMODE(s.st_mode)&0o077) and
         0 < s.st_size <= CONTRACT_MAX, 'INPUT_OWNER_MODE_OR_SIZE')
    return path.read_bytes()


def exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    finally:
        os.close(fd)


def persist(snapshot: dict, classification: dict, root: Path = PRIVATE_ROOT) -> Path:
    need(os.geteuid()!=0, 'ROOT_EXECUTION_FORBIDDEN')
    if not root.exists():
        need(not root.is_symlink(), 'PRIVATE_ROOT_SYMLINK')
        need(root.parent.is_dir() and not root.parent.is_symlink(), 'PRIVATE_PARENT_MISSING')
        root.mkdir(mode=0o700)
    private_parent(root)
    folder = Path(tempfile.mkdtemp(prefix='capture-', dir=root))
    private_parent(folder)
    files = {'snapshot.json': canonical(snapshot), 'report.json': canonical(classification)}
    for filename, raw in files.items():
        exclusive(folder/filename, raw)
    manifest = {'schema': MANIFEST_SCHEMA,
                'files_sha256': {name: sha(raw) for name,raw in files.items()},
                'report_sha256': sha(files['report.json']),
                'mode': 'READONLY_CAPTURE_NO_DISPATCH'}
    exclusive(folder/'manifest.json', canonical(manifest))
    return folder


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description='R115-F2: host read-only A3 snapshot; NO-GO')
    parser.add_argument('--capture', action='store_true', required=True)
    parser.add_argument('--contract', type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        need(os.geteuid()!=0, 'NO_ROOT_EXECUTION')
        contract = None
        catalogue = raw = None
        if args.contract is not None:
            contract = f1.load(private_read(args.contract))
            raw = (Path(__file__).resolve().parents[3] / 'lab' /
                   'operational-catalog-v1' / 'catalog.json').read_bytes()
            catalogue = f1.load(raw)
            f1.validate(contract,catalogue,raw)
            need(contract['source_commit']==BASE_COMMIT, 'CONTRACT_SOURCE_COMMIT_DRIFT')
        snapshot = collect()
        result = report(snapshot, contract=contract, catalogue=catalogue, catalog_raw=raw)
        folder = persist(snapshot, result)
    except (OSError, Stop, f1.Rejected, UnicodeError, TypeError, ValueError) as exc:
        print('R115_F2_STOP=' + type(exc).__name__ + ':' + str(exc))
        return 2
    print('R115_F2_CAPTURE=PASS_PRIVATE_READONLY')
    print('R115_F2_PRIVATE_RECEIPT=' + str(folder))
    print('R115_F2_CAPTURE_SHA256=' + result['snapshot_sha256'])
    print('R115_F2_CONTRACT=' + result['contract_binding'])
    print('R115_F2_FTP_VM=' + result['source_checks']['ftp_vm_state'])
    print('R115_F2_RUNNER_VM=' + result['source_checks']['runner_vm_state'])
    for name in f1.GATES:
        print('R115_F2_A3_' + name + '=' + result['a3_status'][name])
        print('R115_F2_REASON_' + name + '=' + result['a3_reasons'][name])
    for name in ('vm_definition','ftp_network_definition','ftp_network_runtime','r34_nft','r34_watchdog'):
        print('R115_F2_CHECK_' + name.upper() + '=' + result['source_checks'][name]['status'])
    print('R115_F2_DISPATCH=NO-GO')
    print('R115_F2_A6=ND')
    print('R115_F2_P8=NO-GO')
    print('R115_F2_NETWORK_PROBES=0')
    print('R115_F2_VMS_STARTED=0')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
