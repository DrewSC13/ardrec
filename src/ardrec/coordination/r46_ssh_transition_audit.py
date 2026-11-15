"""P14-R46: host read-only evidence and rollback-baseline for R45 SSH candidates.

NO installation, nwfilter definition, domain redefinition, start/stop, or packets.
Host command output is never promoted into authority to test real SSH.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from typing import Any, Callable
from xml.etree import ElementTree as ET

from ardrec.coordination import r33_offline_topology as r33
from ardrec.coordination import r34_containment as r34
from ardrec.coordination import r45_ssh_positive_candidate as r45

SCHEMA = 'ardrec-p14-r46-ssh-transition-readonly-audit-v1'
BASE_MAIN = '20cb051262c0e556954e51a01e2089bab954100e'
R45_REPORT_PIN = '3ddca2761bd4ca2d4244afa962bec305e68985466687824fa6ddd9db93bdceb3'
EXPECTED_RESTORE_STATE = {'ssh': 'RUNNING', 'runner': 'SHUTOFF'}
SSH_DOMAIN = 'ardrec-r33-dev-ssh'
RUNNER_DOMAIN = 'ardrec-r33-dev-runner'
OLD_FILTER = 'ardrec-r33-block-until-containment'
GUARD_TABLE = 'ardrec_r34_guard'
MAX_RAW = 131072
SNAPSHOTS = ('ssh-inactive.xml', 'runner-inactive.xml', 'r33-deny-nwfilter.xml',
             'r34-bridge-deny.txt', 'nwfilter-list.txt', 'bridge-ipv4.txt', 'vm-states.json')
RECEIPT = 'r46_transition_audit.json'
SUMS = 'SHA256SUMS'


class R46AuditError(ValueError):
    pass


def need(ok: bool, msg: str) -> None:
    if not ok:
        raise R46AuditError(msg)


def canon(doc: Any) -> bytes:
    return json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _xml(data: bytes, code: str) -> ET.Element:
    need(type(data) is bytes and 0 < len(data) <= MAX_RAW, code + '_size')
    try:
        return ET.fromstring(data)
    except ET.ParseError as ex:
        raise R46AuditError(code + '_xml_invalid') from ex


def verify_domain(data: bytes, role: str) -> dict[str, Any]:
    """Validate concrete inactive host identity against immutable R33 baseline."""
    need(role in ('ssh', 'runner'), 'role_invalid')
    actual = _xml(data, 'domain')
    original = _xml(r33.render_xml(r33.R32_RECEIPT_FILE_SHA256)['domain-' + role + '.xml'], 'baseline')
    need(actual.tag == 'domain' and actual.get('type') == 'kvm', 'domain_type_drift')
    need(actual.findtext('name') == original.findtext('name') and
         actual.findtext('uuid') == original.findtext('uuid'), 'domain_identity_drift')
    actual_disk = actual.find('./devices/disk/source')
    original_disk = original.find('./devices/disk/source')
    need(actual_disk is not None and original_disk is not None and
         actual_disk.get('file') == original_disk.get('file') and
         actual.find('./devices/disk/driver') is not None and
         actual.find('./devices/disk/driver').get('type') == 'qcow2',
         'domain_disk_drift')
    need(actual.findtext('on_reboot') == 'destroy', 'domain_reboot_policy_drift')
    for forbidden in ('hostdev', 'filesystem', 'redirdev', 'vsock'):
        need(not actual.findall('./devices/' + forbidden), 'unapproved_device_' + forbidden)
    expected = r33.RESOURCE[role]['nics']
    interfaces = actual.findall('./devices/interface')
    need(len(interfaces) == len(expected), 'domain_nic_count_drift')
    rows = []
    for nic, (segment, address, mac, tap) in zip(interfaces, expected):
        source = nic.find('source'); target = nic.find('target')
        macel = nic.find('mac'); filt = nic.find('filterref')
        need(nic.get('type') == 'network' and source is not None and
             source.get('network') == r33.NETWORK_PREFIX + segment and
             target is not None and target.get('dev') == tap and
             macel is not None and macel.get('address') == mac and
             filt is not None and filt.get('filter') == OLD_FILTER,
             'domain_nic_or_filter_drift')
        rows.append({'network': segment, 'ip_design': address, 'mac': mac, 'tap': tap,
                     'filter': OLD_FILTER})
    return {'name': actual.findtext('name'), 'uuid': actual.findtext('uuid'),
            'disk': actual_disk.get('file'), 'nics': rows}


def verify_original_filter(data: bytes) -> None:
    actual = _xml(data, 'filter')
    baseline = _xml(r34.deny_filter_xml(), 'filter_baseline')
    need(actual.tag == 'filter' and actual.attrib == baseline.attrib and
         actual.findtext('uuid') == baseline.findtext('uuid'), 'nwfilter_identity_drift')
    rules = actual.findall('rule')
    need(len(actual) == 2 and len(rules) == 1 and
         rules[0].attrib == {'action': 'drop', 'direction': 'inout', 'priority': '1000'} and
         len(rules[0]) == 1 and rules[0][0].tag == 'all' and not rules[0][0].attrib,
         'nwfilter_not_deny_all')


def verify_nft_guard(data: bytes) -> None:
    """Fail closed on unknown live nft format; never infer containment from counters."""
    need(type(data) is bytes and len(data) <= MAX_RAW, 'nft_size')
    try:
        src = data.decode('ascii')
    except UnicodeError as ex:
        raise R46AuditError('nft_non_ascii') from ex
    need(src.strip().startswith('table bridge ' + GUARD_TABLE + ' {') and
         len(re.findall(r'\btable\b', src)) == 1, 'nft_table_drift')
    blocks = re.findall(r'(?ms)^\s*chain (input|output|forward) \{(.*?)^\s*\}', src)
    need(len(blocks) == 3 and [n for n, _ in blocks] == ['input','output','forward'],
         'nft_chain_drift')
    # Reject unattached lines/rules that a chain-only parser might overlook.
    leftover = re.sub(r'(?ms)^\s*chain (?:input|output|forward) \{.*?^\s*\}', '', src)
    leftover = re.sub(r'^\s*table bridge ' + GUARD_TABLE + r' \{(?: # handle \d+)?', '', leftover, count=1)
    leftover = re.sub(r'\}\s*$', '', leftover)
    need(not leftover.strip(), 'nft_unexpected_outside_chains')
    expected_names = set(r34.TAPS)
    expected_by_chain = {'input': ['iifname'], 'output': ['oifname'],
                         'forward': ['iifname', 'oifname']}
    total = 0
    for chain, body in blocks:
        lines = [line.strip() for line in body.strip().splitlines()
                 if line.strip() and not re.fullmatch(r'# handle \d+', line.strip())]
        need(lines and re.fullmatch(
            'type filter hook ' + chain + r' priority [a-zA-Z0-9_-]+; policy accept;',
            lines[0]) is not None, 'nft_hook_or_policy_drift')
        need(len(lines) == 1 + len(expected_by_chain[chain]), 'nft_rule_count_drift')
        for line, direction in zip(lines[1:], expected_by_chain[chain]):
            match = re.fullmatch(
                r'(iifname|oifname) \{\s*(.*?)\s*\} counter packets (\d+) bytes (\d+) drop(?: # handle \d+)?',
                line)
            need(match is not None and match.group(1) == direction, 'nft_drop_rule_invalid')
            names = re.findall(r'"([a-zA-Z0-9]+)"', match.group(2))
            need(len(names) == len(expected_names) and set(names) == expected_names and
                 match.group(2).replace(',', '').replace('"', '').split() == names,
                 'nft_tap_set_drift')
            total += 1
    need(total == 4, 'nft_rule_cardinality')


def normalize_state(value: bytes, role: str) -> str:
    need(type(value) is bytes and len(value) < 128, 'state_output_invalid')
    try:
        state = value.decode('utf-8').strip().casefold()
    except UnicodeError as ex:
        raise R46AuditError('state_encoding_invalid') from ex
    found = ('RUNNING' if state in ('running','ejecutando') else
             'SHUTOFF' if state in ('shut off','apagado') else 'UNKNOWN')
    need(found == EXPECTED_RESTORE_STATE[role], 'domain_runtime_state_drift_' + role)
    return found


def verify_live_observation(snapshot: dict[str, bytes], r45dir: Path) -> dict[str, Any]:
    need(set(snapshot) == set(SNAPSHOTS), 'snapshot_set_invalid')
    r45_receipt = r45.verify_directory(r45dir)
    need(r45_receipt['sha256'] == R45_REPORT_PIN and
         r45_receipt['p8_operational'] == 'NO-GO', 'r45_source_receipt_mismatch')
    states = json.loads(snapshot['vm-states.json'])
    need(states == EXPECTED_RESTORE_STATE, 'states_not_expected')
    ssh = verify_domain(snapshot['ssh-inactive.xml'], 'ssh')
    runner = verify_domain(snapshot['runner-inactive.xml'], 'runner')
    verify_original_filter(snapshot['r33-deny-nwfilter.xml'])
    verify_nft_guard(snapshot['r34-bridge-deny.txt'])
    inventory = snapshot['nwfilter-list.txt']
    need(type(inventory) is bytes and len(inventory) <= MAX_RAW, 'filter_inventory_size')
    try:
        inv = inventory.decode('utf-8')
    except UnicodeError as ex:
        raise R46AuditError('filter_inventory_encoding') from ex
    need(OLD_FILTER in inv and r45.FILTER_SSH not in inv and
         r45.FILTER_RUNNER not in inv, 'candidate_filter_already_defined')
    need(snapshot['bridge-ipv4.txt'].strip() == b'', 'bridge_has_ipv4_address')
    need(len(ssh['nics']) == 1 and len(runner['nics']) == 3 and
         ssh['nics'][0]['tap'] == r45.SSH_TAP and
         runner['nics'][0]['tap'] == r45.RUNNER_TAP,
         'topology_unexpected')
    # Candidate guard is independent of validation of inactive installed XML.
    for role in ('ssh','runner'):
        raw = r45.domain_candidate(runner=(role == 'runner'))
        r45.check_domain(raw, runner=(role == 'runner'))
    return {
        'schema': SCHEMA, 'source_main': BASE_MAIN,
        'source_r45_report_sha256': R45_REPORT_PIN,
        'mode': 'READONLY_LIVE_HOST_BASELINE_AND_ROLLBACK_SNAPSHOT',
        'domain_states': states,
        'observed_ssh': ssh, 'observed_runner': runner,
        'change_preview': [
            'SSH_INACTIVE_FILTER_REFERENCE_R33_TO_UNIQUE_R45_CANDIDATE',
            'RUNNER_INACTIVE_THREE_NICS_TO_SSH_ONLY_ONE_NIC',
            'RUNNER_INACTIVE_SSH_FILTER_REFERENCE_R33_TO_UNIQUE_R45_CANDIDATE',
            'FIREWALL_R34_CHANGE_NOT_DESIGNED_OR_AUTHORIZED',
            'RUNNING_SSH_REQUIRES_SEPARATE_MAINTENANCE_AND_ROLLBACK_AUTHORIZATION',
        ],
        'snapshot_files': [{'filename': x, 'sha256': sha(snapshot[x]),
                            'bytes': len(snapshot[x])} for x in SNAPSHOTS],
        'legacy_nwfilter_deny_all': True,
        'legacy_r34_nft_deny_all': True,
        'candidate_filters_installed': False,
        'bridge_ipv4_assigned': False,
        'rollback_baseline_captured': True,
        'rollback_tested': False,
        'restore_command_executed': False,
        'host_mutations': False,
        'vm_started_or_stopped': False,
        'packet_probes_executed': False,
        'positive_control_verified': False,
        'isolation_proven': False,
        'operational_dispatch': False,
        'real_pentesting': 'NOT_EXECUTED',
        'p8_operational': 'NO-GO',
        'final_risk': None, 'published_generation': None,
        'next_gate': 'INDEPENDENT_OFFLINE_RULE_AUDIT_ROLLBACK_PLAN_AND_OPERATOR_APPROVAL',
    }


def _which(name: str, allowed: tuple[str, ...]) -> str:
    value = shutil.which(name)
    need(value in allowed, 'executable_not_allowlisted_' + name)
    return value


def capture_host(run: Callable[..., Any] = subprocess.run) -> dict[str, bytes]:
    """Fixed read commands, never through a shell. No dynamic user commands."""
    sudo = _which('sudo', ('/usr/bin/sudo',))
    virsh = _which('virsh', ('/usr/bin/virsh',))
    nft = _which('nft', ('/usr/sbin/nft','/usr/bin/nft'))
    ip = _which('ip', ('/usr/sbin/ip','/usr/bin/ip'))
    vb = [sudo, '-n', '--', virsh, '--readonly', '-c', 'qemu:///system']
    commands = {
      'ssh-state': vb + ['domstate', SSH_DOMAIN],
      'runner-state': vb + ['domstate', RUNNER_DOMAIN],
      'ssh-inactive.xml': vb + ['dumpxml','--inactive', SSH_DOMAIN],
      'runner-inactive.xml': vb + ['dumpxml','--inactive', RUNNER_DOMAIN],
      'r33-deny-nwfilter.xml': vb + ['nwfilter-dumpxml', OLD_FILTER],
      'nwfilter-list.txt': vb + ['nwfilter-list'],
      'r34-bridge-deny.txt': [sudo, '-n', '--', nft, '-a','list','table','bridge',GUARD_TABLE],
      'bridge-ipv4.txt': [ip, '-o','-4','addr','show','dev','br33d30'],
    }
    outputs: dict[str, bytes] = {}
    for filename, command in commands.items():
        try:
            process = run(command, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=15, check=False, close_fds=True)
        except (OSError, subprocess.TimeoutExpired) as ex:
            raise R46AuditError('host_read_failed_' + filename) from ex
        need(type(process.returncode) is int and process.returncode == 0 and
             type(process.stdout) is bytes and type(process.stderr) is bytes and
             len(process.stdout) <= MAX_RAW and len(process.stderr) <= 4096,
             'host_read_unsuccessful_' + filename)
        outputs[filename] = process.stdout
    states = {role: normalize_state(outputs[role + '-state'], role)
              for role in ('ssh','runner')}
    del outputs['ssh-state']; del outputs['runner-state']
    outputs['vm-states.json'] = canon(states) + b'\n'
    need(set(outputs) == set(SNAPSHOTS), 'host_output_set_invalid')
    return outputs


def _private_root(path: Path, must_exist: bool) -> None:
    need(isinstance(path, Path) and path.is_absolute() and
         not any(x.is_symlink() for x in (path,*path.parents)), 'receipt_symlink_or_relative')
    parent = path.parent
    need(parent.is_dir() and parent.stat().st_uid == os.getuid() and
         stat.S_IMODE(parent.stat().st_mode) == 0o700, 'private_parent_required')
    need(re.fullmatch(r'r46-ssh-audit-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}', path.name) is not None,
         'receipt_name_invalid')
    if must_exist:
        need(path.is_dir() and path.stat().st_uid == os.getuid() and
             stat.S_IMODE(path.stat().st_mode) == 0o700,
             'private_receipt_invalid')
    else:
        need(not path.exists(), 'receipt_already_exists')


def _write(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as dest:
        dest.write(content); dest.flush(); os.fsync(dest.fileno())


def _report_with_digest(snap: dict[str, bytes], r45dir: Path) -> dict[str, Any]:
    report = verify_live_observation(snap, r45dir)
    report['sha256'] = sha(canon(report))
    return report


def prepare_receipt(root: Path, r45dir: Path, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    _private_root(root, False)
    source = r45.verify_directory(r45dir)
    need(source['sha256'] == R45_REPORT_PIN, 'r45_source_receipt_mismatch')
    # If the host drifted, refuse all writes and preserve existing state.
    snap = capture_host(run)
    report = _report_with_digest(snap, r45dir)
    records = {**snap, RECEIPT: canon(report) + b'\n'}
    sums = (''.join(f'{sha(records[n])}  {n}\n' for n in sorted(records))).encode('ascii')
    root.mkdir(mode=0o700)
    try:
        for name in sorted(records):
            _write(root/name, records[name])
        _write(root/SUMS, sums)
        dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except BaseException:
        # Keep incomplete/uncertain evidence for human investigation.
        raise
    verify_receipt(root, r45dir)
    return report


def verify_receipt(root: Path, r45dir: Path) -> dict[str, Any]:
    _private_root(root, True)
    names = set(SNAPSHOTS) | {RECEIPT, SUMS}
    need({x.name for x in root.iterdir()} == names, 'receipt_file_set_mismatch')
    raw: dict[str, bytes] = {}
    for name in sorted(names):
        file = root/name
        st = file.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= MAX_RAW,
             'receipt_file_permissions_or_size_' + name)
        raw[name] = file.read_bytes()
    expected_sums = ''.join(f'{sha(raw[n])}  {n}\n' for n in sorted(names - {SUMS})).encode('ascii')
    need(raw[SUMS] == expected_sums, 'receipt_checksums_invalid')
    expected = _report_with_digest({n: raw[n] for n in SNAPSHOTS}, r45dir)
    need(raw[RECEIPT] == canon(expected) + b'\n', 'receipt_tampered')
    return expected
