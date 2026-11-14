"""P14-R35: install scoped deny-first containment and define an inactive lab.

The only host firewall mutation is creation of bridge/ardrec_r34_guard.
The only libvirt mutations are one nwfilter, three inactive networks and four
shut-off domains. This module never starts or autostarts a network or VM, never
flushes/replaces the global ruleset, and never mutates QCOW2 assets.
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
import tarfile
import tempfile
from typing import Any, Callable
import xml.etree.ElementTree as ET

from ardrec.coordination import r33_offline_topology as t33
from ardrec.coordination import r34_containment as t34

SCHEMA = 'ardrec-p14-r35-inactive-deployment-v1'
BASE_MAIN = 'b9b52e6fc65415e939728b17366acb49d2551563'
ARCHIVE_SHA256 = '58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36'
R32_FILE_SHA256 = 'b032c35c5f9760b9b057b6bbc3e681fca82ff37532c897b37463a147b1cdaadf'
R33_FILE_SHA256 = '1b55caefef6808fbfddf32a66a19be7f23c3f63b226799b098380fd93627421c'
R34_FILE_SHA256 = '1b5c316566d9023ca25d5a89f324909bdc33c2f397ab5a418b65db402ebbcafc'
R34_HOST_FILE_SHA256 = 'd39a4e108c25851fa77dfa1538d62c6cdda8ffbc8fd83d81f4d220c8f12f8cdd'
R34_SHA256SUMS_SHA256 = 'ec9fd09b28365fbc0279e502e86088c5312f566a3399e80c78da6905816eaafa'
NFT_TABLE = 'ardrec_r34_guard'
R35_PARTIAL_REPORT_SHA256 = '8a082fc006c9a588c3d2063972221c953f4b264a4c6a277f14e750660e3123f1'
FILTER_NAME = 'ardrec-r33-block-until-containment'
QEMU_UID = 64055
QEMU_GID = 64055
ENV = {'LC_ALL': 'C', 'LANG': 'C', 'PATH': '/usr/sbin:/usr/bin'}
MAX_ARCHIVE_BYTES = 2_000_000
MAX_MEMBER_BYTES = 131_072
MAX_OUTPUT_BYTES = 131_072
DIGEST = re.compile(r'[0-9a-f]{64}\Z')

R32_DIR = 'recibos-r32-storage-OHOl9Crz'
R33_DIR = 'recibos-r33-xml-d9nAhhgU'
R34_DIR = 'recibos-r34-publicacion-fuYEDHUS'
R32_FILE = 'r32_staging.json'
R33_FILE = 'r33_topology_receipt.json'
R34_FILE = 'r34_containment_receipt.json'
R34_HOST_FILE = 'host_preflight.json'
R34_SUMS_FILE = 'SHA256SUMS'

EXPECTED_FILES = {
    f'{R32_DIR}/{R32_FILE}',
    *{f'{R33_DIR}/{x}' for x in (
        'domain-ftp.xml', 'domain-runner.xml', 'domain-smb.xml', 'domain-ssh.xml',
        'network-ftp.xml', 'network-smb.xml', 'network-ssh.xml', R33_FILE)},
    *{f'{R34_DIR}/{x}' for x in (
        'PR_BODY.md', 'SHA256SUMS', 'actual.txt', 'bridge-deny.nft', 'ci.log',
        'expected.txt', R34_HOST_FILE, 'nft_tables.json', 'nwfilter-deny.xml',
        'postmerge_runs.json', 'pr_files.txt', R34_FILE, 'staged.txt')},
}
EXPECTED_DIRS = {R33_DIR, R34_DIR}
EXPECTED_MEMBERS = EXPECTED_FILES | EXPECTED_DIRS

NETWORKS = tuple(t33.NETWORK_PREFIX + role for role in t33.NET_BRIDGE)
DOMAINS = tuple(t33.DOMAIN_PREFIX + role for role in t33.ROLES)
BRIDGES = tuple(t33.NET_BRIDGE[role] for role in t33.NET_BRIDGE)
TAPS = tuple(sorted(tap for role in t33.ROLES for _, _, _, tap in t33.RESOURCE[role]['nics']))


class R35Error(ValueError):
    """Fail-closed R35 source, host, or deployment error."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise R35Error(code)


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'duplicate_json_key')
        out[key] = value
    return out


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = t34.secure_file(path)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(R35Error('nonfinite_json')))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise R35Error('source_json_invalid') from exc
    need(type(value) is dict, 'source_json_not_object')
    return value, raw


def _safe_extract(archive: Path, destination: Path) -> None:
    need(archive.is_absolute() and not archive.is_symlink(), 'archive_path_invalid')
    for parent in archive.parents:
        need(not parent.is_symlink(), 'archive_parent_symlink')
    parent_stat = archive.parent.stat()
    need(stat.S_ISDIR(parent_stat.st_mode) and parent_stat.st_uid == os.geteuid() and
         (stat.S_IMODE(parent_stat.st_mode) & 0o022) == 0,
         'archive_parent_owner_or_mode_invalid')
    st = archive.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
         st.st_size <= MAX_ARCHIVE_BYTES and (stat.S_IMODE(st.st_mode) & 0o022) == 0,
         'archive_type_owner_or_mode_invalid')
    raw_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    need(raw_sha == ARCHIVE_SHA256, 'archive_sha256_mismatch')
    need(destination.is_dir() and not destination.is_symlink() and
         stat.S_IMODE(destination.stat().st_mode) == 0o700, 'private_extract_root_invalid')
    try:
        with tarfile.open(archive, 'r:gz') as tf:
            members = tf.getmembers()
            names = [m.name.rstrip('/') if m.isdir() else m.name for m in members]
            need(len(names) == len(set(names)), 'archive_duplicate_member')
            need(set(names) == EXPECTED_MEMBERS and len(members) == 24,
                 'archive_member_inventory_mismatch')
            for member in members:
                name = member.name.rstrip('/') if member.isdir() else member.name
                path = Path(name)
                need(not path.is_absolute() and '..' not in path.parts and '\\' not in name,
                     'archive_member_path_invalid')
                need(not (member.issym() or member.islnk() or member.isdev() or member.isfifo()),
                     'archive_link_or_special_file_rejected')
                target = destination / name
                need(destination.resolve() in target.resolve().parents,
                     'archive_path_escape')
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=False)
                    continue
                need(member.isfile() and 0 <= member.size <= MAX_MEMBER_BYTES,
                     'archive_member_type_or_size_invalid')
                parent = target.parent
                if not parent.exists():
                    parent.mkdir(mode=0o700, parents=True, exist_ok=False)
                need(parent.is_dir() and not parent.is_symlink(), 'archive_parent_invalid')
                stream = tf.extractfile(member)
                need(stream is not None, 'archive_member_unreadable')
                body = stream.read(MAX_MEMBER_BYTES + 1)
                need(len(body) == member.size and len(body) <= MAX_MEMBER_BYTES,
                     'archive_member_size_mismatch')
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(body)
                    output.flush()
                    os.fsync(output.fileno())
    except (tarfile.TarError, OSError) as exc:
        raise R35Error('archive_extraction_failed') from exc


def _verify_sha256sums(directory: Path) -> dict[str, str]:
    path = directory / R34_SUMS_FILE
    raw = t34.secure_file(path)
    need(sha(raw) == R34_SHA256SUMS_SHA256, 'r34_sha256sums_file_hash_mismatch')
    expected = {}
    for line in raw.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})\s+(.+)', line)
        need(match is not None, 'r34_sha256sums_line_invalid')
        digest, source_path = match.groups()
        name = Path(source_path).name
        need(name not in expected, 'r34_sha256sums_duplicate_name')
        expected[name] = digest
    required = {
        'actual.txt', 'bridge-deny.nft', 'ci.log', 'expected.txt', R34_HOST_FILE,
        'nft_tables.json', 'nwfilter-deny.xml', 'postmerge_runs.json', 'PR_BODY.md',
        'pr_files.txt', R34_FILE, 'staged.txt',
    }
    need(set(expected) == required and len(expected) == 12, 'r34_sha256sums_inventory_invalid')
    for name, digest in expected.items():
        body = t34.secure_file(directory / name)
        need(sha(body) == digest, 'r34_file_hash_mismatch_' + name)
    return expected


def verify_source_bundle(archive: Path, destination: Path) -> dict[str, Any]:
    """Authenticate the exact R32 -> R33 -> R34 chain and all bundled bytes."""
    _safe_extract(archive, destination)
    need(t34.NFT_TABLE == NFT_TABLE and t33.DENY_FILTER == FILTER_NAME,
         'r35_r33_r34_contract_drift')
    r32_path = destination / R32_DIR / R32_FILE
    r33_dir = destination / R33_DIR
    r34_dir = destination / R34_DIR

    r32, r32_file_sha = t33.read_r32(r32_path, R32_FILE_SHA256)
    r33, _ = t34.source_load(r33_dir / R33_FILE, R33_FILE_SHA256)
    r34, r34_raw = _read_json(r34_dir / R34_FILE)
    need(sha(r34_raw) == R34_FILE_SHA256, 'r34_receipt_file_hash_mismatch')
    t34.verify_report(r34)
    host, host_raw = _read_json(r34_dir / R34_HOST_FILE)
    need(sha(host_raw) == R34_HOST_FILE_SHA256, 'r34_host_file_hash_mismatch')
    t34.verify_host_report(host)
    sums = _verify_sha256sums(r34_dir)
    snapshot = json.loads(t34.secure_file(r34_dir / 'nft_tables.json'))
    snapshot_tables = _nft_table_names(canon(snapshot))
    need(('bridge', NFT_TABLE) not in snapshot_tables, 'r34_historical_nft_collision')
    expected_scope = {
        'docs/development/p14-r34-deny-first-containment-v1.md',
        'docs/traceability/p14-r34-containment-offline-v1.json',
        'lab/p14-r34-containment-v1/contract.json',
        'lab/tests/test_p14_r34_containment.py',
        'scripts/ardrec_p14_r34_containment.py',
        'src/ardrec/coordination/r34_containment.py',
    }
    inventories = [
        set(t34.secure_file(r34_dir / name).decode('utf-8').splitlines())
        for name in ('actual.txt', 'expected.txt', 'staged.txt', 'pr_files.txt')
    ]
    need(all(items == expected_scope for items in inventories) and
         all(items == inventories[0] for items in inventories[1:]),
         'r34_pr_file_scope_mismatch')

    need(r32_file_sha == r33.get('source_r32_file_sha256') == R32_FILE_SHA256 and
         r32['sha256'] == r33.get('source_r32_report_sha256'), 'r32_r33_chain_mismatch')
    need(sha(t34.secure_file(r33_dir / R33_FILE)) == R33_FILE_SHA256 and
         r33['sha256'] == r34.get('source_r33_report_sha256') and
         R33_FILE_SHA256 == r34.get('source_r33_file_sha256'), 'r33_r34_chain_mismatch')
    need(r34['sha256'] == host.get('source_r34_sha256') and
         r33['sha256'] == host.get('source_r33_report_sha256'), 'r34_host_chain_mismatch')
    need(r34.get('mode') == 'OFFLINE_PREPARED' and
         r34.get('offline_policies_prepared') is True and
         r34.get('host_containment_installed') is False and
         r34.get('libvirt_definitions_created') is False and
         r34.get('network_started') is False and r34.get('vm_started') is False and
         r34.get('p8_operational') == 'NO-GO', 'r34_source_not_offline_prepared')
    need(host.get('firewall_modified') is False and
         host.get('libvirt_definitions_created') is False and
         host.get('network_started') is False and host.get('vm_started') is False and
         host.get('p8_operational') == 'NO-GO', 'r34_host_receipt_overclaims')

    policy = t34.policy_files()
    for filename, expected in policy.items():
        actual = t34.secure_file(r34_dir / filename)
        need(actual == expected, 'r34_policy_bytes_mismatch_' + filename)
    t34.verify_nft(policy['bridge-deny.nft'])
    t34.verify_filter(policy['nwfilter-deny.xml'])

    postmerge = json.loads(t34.secure_file(r34_dir / 'postmerge_runs.json'))
    need(type(postmerge) is list and any(
        type(row) is dict and row.get('status') == 'completed' and
        row.get('conclusion') == 'success' and row.get('headBranch') == 'main'
        for row in postmerge), 'r34_postmerge_ci_not_successful')
    ci_log = t34.secure_file(r34_dir / 'ci.log').decode('utf-8')
    need('Python - empaquetado / packaging' in ci_log and
         'Rust - compilación / build' in ci_log and
         re.search(r'Python - empaquetado / packaging\s+pass', ci_log) is not None and
         re.search(r'Rust - compilación / build\s+pass', ci_log) is not None,
         'r34_pr_ci_not_successful')

    attestation = {
        'schema': 'ardrec-p14-r35-source-attestation-v1',
        'archive_sha256': ARCHIVE_SHA256,
        'archive_member_count': 24,
        'r32_file_sha256': R32_FILE_SHA256,
        'r32_report_sha256': r32['sha256'],
        'r33_file_sha256': R33_FILE_SHA256,
        'r33_report_sha256': r33['sha256'],
        'r33_xml_files': r33['files'],
        'r34_file_sha256': R34_FILE_SHA256,
        'r34_report_sha256': r34['sha256'],
        'r34_host_file_sha256': R34_HOST_FILE_SHA256,
        'r34_host_report_sha256': host['sha256'],
        'r34_sha256sums_file_sha256': R34_SHA256SUMS_SHA256,
        'r34_sha256sums_verified_files': len(sums),
        'r34_policy_files': r34['policy_files'],
        'source_chain': 'R32_TO_R33_TO_R34_VERIFIED',
        'historical_host_preflight': 'VERIFIED_NOT_CURRENT_STATE',
        'system_functional_acceptance': 'PENDING',
        'experimental_validation': 'NOT_RUN',
        'p8_operational': 'NO-GO',
    }
    attestation['sha256'] = sha(canon(attestation))
    return {'root': destination, 'r32': r32, 'r33': r33, 'r34': r34,
            'host': host, 'attestation': attestation}


def _xml_uuid(path: Path) -> str:
    root = ET.fromstring(path.read_bytes())
    value = root.findtext('uuid')
    need(type(value) is str and re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value),
        'xml_uuid_invalid')
    return value


def _xml_semantic(raw: bytes, kind: str, role: str | None = None) -> None:
    root = ET.fromstring(raw)
    if kind == 'nwfilter':
        t34.verify_filter(raw)
        return
    if kind == 'network':
        need(root.tag == 'network' and root.get('ipv6') == 'no' and
             root.findtext('name') == t33.NETWORK_PREFIX + str(role) and
             root.find('bridge') is not None and
             root.find('bridge').get('name') == t33.NET_BRIDGE[str(role)] and
             root.find('dns') is not None and root.find('dns').get('enable') == 'no' and
             root.find('forward') is None and root.find('ip') is None and
             root.find('dhcp') is None, 'network_xml_semantics_invalid')
        return
    need(kind == 'domain' and role in t33.ROLES, 'domain_kind_invalid')
    cfg = t33.RESOURCE[str(role)]
    need(root.tag == 'domain' and root.get('type') == 'kvm' and
         root.findtext('name') == t33.DOMAIN_PREFIX + str(role) and
         root.findtext('memory') == str(cfg['ram_mib']) and
         root.findtext('vcpu') == str(cfg['vcpus']), 'domain_identity_or_resources_invalid')
    disks = root.findall('devices/disk')
    need(len(disks) == 1 and disks[0].get('type') == 'file' and
         disks[0].find('driver').get('type') == 'qcow2' and
         disks[0].find('source').get('file') ==
         f'{t33.R32_STAGE}/{role}-runtime.qcow2', 'domain_disk_binding_invalid')
    interfaces = root.findall('devices/interface')
    need(len(interfaces) == len(cfg['nics']), 'domain_nic_count_invalid')
    for iface, (segment, _ip, mac, tap) in zip(interfaces, cfg['nics']):
        need(iface.get('type') == 'network' and
             iface.find('mac').get('address') == mac and
             iface.find('source').get('network') == t33.NETWORK_PREFIX + segment and
             iface.find('target').get('dev') == tap and
             iface.find('filterref').get('filter') == FILTER_NAME,
             'domain_nic_or_filter_binding_invalid')
    for forbidden in ('hostdev', 'filesystem', 'redirdev', 'vsock', 'graphics'):
        need(not root.findall('devices/' + forbidden), 'domain_forbidden_device_' + forbidden)
    need(root.findtext('on_poweroff') == 'destroy' and
         root.findtext('on_reboot') == 'destroy' and
         root.findtext('on_crash') == 'destroy', 'domain_lifecycle_invalid')


def _parse_stat(raw: bytes) -> dict[str, Any]:
    try:
        fields = raw.decode('ascii').rstrip('\n').split('|')
        need(len(fields) == 9, 'stat_field_count_invalid')
        mode = int(fields[4], 8)
        values = [int(value) for value in fields[1:4]]
        tail = [int(value) for value in fields[5:]]
        need(all(value >= 0 for value in values + tail), 'stat_negative_value')
        return {'kind': fields[0], 'uid': values[0], 'gid': values[1],
                'nlink': values[2], 'mode': mode, 'size': tail[0],
                'inode': tail[1], 'mtime': tail[2], 'ctime': tail[3]}
    except (ValueError, UnicodeError) as exc:
        raise R35Error('stat_output_invalid') from exc


def _parse_hash(raw: bytes, path: str) -> str:
    try:
        text = raw.decode('ascii').rstrip('\n')
    except UnicodeError as exc:
        raise R35Error('sha256sum_output_invalid') from exc
    match = re.fullmatch(r'([0-9a-f]{64}) \*' + re.escape(path), text)
    need(match is not None, 'sha256sum_output_path_mismatch')
    return match.group(1)


def _verify_qcow_info(raw: bytes, *, virtual_size: int, backing: str | None) -> None:
    try:
        info = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise R35Error('qemu_img_info_invalid_json') from exc
    need(type(info) is dict and info.get('format') == 'qcow2' and
         info.get('virtual-size') == virtual_size, 'qcow2_format_or_size_mismatch')
    actual_backing = info.get('backing-filename')
    need((actual_backing in (None, '') if backing is None else actual_backing == backing),
         'qcow2_backing_chain_mismatch')
    if backing is not None:
        need(info.get('backing-filename-format') in (None, 'qcow2'),
             'qcow2_backing_format_mismatch')


class Host:
    """Small command boundary: fixed executables, literal argv, no shell."""
    def __init__(self, runner: Callable[..., Any] = subprocess.run,
                 which: Callable[[str], str | None] = shutil.which):
        self.runner = runner
        self.which = which
        self.commands: list[dict[str, Any]] = []
        self.bin = {
            'sudo': self._exe('sudo', ('/usr/bin/sudo',)),
            'nft': self._exe('nft', ('/usr/sbin/nft', '/usr/bin/nft')),
            'ip': self._exe('ip', ('/usr/sbin/ip', '/usr/bin/ip')),
            'virsh': self._exe('virsh', ('/usr/bin/virsh',)),
            'qemu-img': self._exe('qemu-img', ('/usr/bin/qemu-img',)),
            'stat': self._exe('stat', ('/usr/bin/stat',)),
            'sha256sum': self._exe('sha256sum', ('/usr/bin/sha256sum',)),
            'virt-xml-validate': self._exe('virt-xml-validate', ('/usr/bin/virt-xml-validate',)),
        }

    def _exe(self, name: str, allowed: tuple[str, ...]) -> str:
        found = self.which(name)
        need(found in allowed, 'binary_unavailable_or_outside_scope_' + name)
        return str(found)

    def run(self, argv: list[str], *, input_bytes: bytes | None = None,
            timeout: int = 30) -> bytes:
        need(type(argv) is list and argv and all(type(x) is str for x in argv), 'argv_invalid')
        need(type(timeout) is int and 1 <= timeout <= 240, 'timeout_invalid')
        kwargs = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE,
                  'check': False, 'timeout': timeout, 'close_fds': True, 'env': ENV}
        if input_bytes is None:
            kwargs['stdin'] = subprocess.DEVNULL
        else:
            need(type(input_bytes) is bytes and len(input_bytes) <= MAX_MEMBER_BYTES,
                 'stdin_bytes_invalid')
            kwargs['input'] = input_bytes
        try:
            result = self.runner(argv, **kwargs)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise R35Error('command_unavailable_' + Path(argv[0]).name) from exc
        need(type(result.returncode) is int and type(result.stdout) is bytes and
             type(result.stderr) is bytes and len(result.stdout) <= MAX_OUTPUT_BYTES and
             len(result.stderr) <= MAX_OUTPUT_BYTES, 'command_output_invalid')
        record = {'argv': argv, 'returncode': result.returncode,
                  'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr),
                  'stdout': result.stdout.decode('utf-8', 'replace')[:4096],
                  'stderr': result.stderr.decode('utf-8', 'replace')[:2048]}
        self.commands.append(record)
        need(result.returncode == 0, 'command_failed_' + Path(argv[0]).name)
        return result.stdout

    def sudo(self, args: list[str], *, input_bytes: bytes | None = None,
             timeout: int = 30) -> bytes:
        need(type(args) is list and args and args[0] in set(self.bin.values()),
             'sudo_command_outside_allowlist')
        executable = args[0]
        storage_paths = {
            '/var', '/var/lib', '/var/lib/libvirt', '/var/lib/libvirt/images',
            t33.R32_STAGE,
        }
        for role in t33.ROLES:
            storage_paths.update({
                f'{t33.BASE_ROOT}/{role}-base.qcow2',
                f'{t33.PARENT_ROOT}/{role}-runtime.qcow2',
                f'{t33.R32_STAGE}/{role}-runtime.qcow2',
            })
        if executable == self.bin['nft']:
            valid = (args == [executable, '-j', 'list', 'tables'] or
                     args == [executable, 'list', 'table', 'bridge', NFT_TABLE] or
                     args == [executable, '-j', '-a', 'list', 'table', 'bridge', NFT_TABLE] or
                     args == [executable, '-c', '-f', '-'] or
                     args == [executable, '-f', '-'])
            if args in ([executable, '-c', '-f', '-'], [executable, '-f', '-']):
                valid = valid and input_bytes == t34.policy_files()['bridge-deny.nft']
            need(valid, 'sudo_nft_argv_outside_allowlist')
        elif executable == self.bin['stat']:
            valid = args == [executable, '--version'] or (
                len(args) == 4 and args[1] == '--printf=%F|%u|%g|%h|%a|%s|%i|%Y|%Z'
                and args[2] == '--' and args[3] in storage_paths)
            need(valid, 'sudo_stat_argv_outside_allowlist')
        elif executable == self.bin['sha256sum']:
            need(len(args) == 4 and args[1:3] == ['--binary', '--'] and
                 args[3] in storage_paths and args[3] not in {'/var', '/var/lib',
                 '/var/lib/libvirt', '/var/lib/libvirt/images', t33.R32_STAGE},
                 'sudo_sha256sum_argv_outside_allowlist')
        elif executable == self.bin['qemu-img']:
            need(len(args) == 6 and args[1:5] == ['info', '--output=json', '-f', 'qcow2']
                 and args[5] in storage_paths and args[5] not in {'/var', '/var/lib',
                 '/var/lib/libvirt', '/var/lib/libvirt/images', t33.R32_STAGE},
                 'sudo_qemu_img_argv_outside_allowlist')
        elif executable == self.bin['virsh']:
            valid = (len(args) == 5 and args[1:3] == ['-c', 'qemu:///system'] and
                     args[3] == 'nwfilter-define' and
                     Path(args[4]).name == 'nwfilter-deny.xml')
            valid = valid or (len(args) == 5 and args[1:3] == ['-c', 'qemu:///system'] and
                              args[3] == 'net-define' and
                              Path(args[4]).name in {f'network-{r}.xml' for r in t33.NET_BRIDGE})
            # The domain path follows --validate; exact role-specific basenames only.
            valid = valid or (len(args) == 6 and args[1:3] == ['-c', 'qemu:///system'] and
                              args[3:5] == ['define', '--validate'] and
                              Path(args[5]).name in {f'domain-{r}.xml' for r in t33.ROLES})
            need(valid, 'sudo_virsh_argv_outside_allowlist')
        else:
            raise R35Error('sudo_executable_not_permitted')
        return self.run([self.bin['sudo'], '-n', '--', *args],
                        input_bytes=input_bytes, timeout=timeout)

    def virsh_ro(self, args: list[str]) -> bytes:
        allowed = {
            ('list', '--all', '--name'), ('list', '--name'),
            ('list', '--all', '--uuid'), ('net-list', '--all', '--name'),
            ('net-list', '--name'), ('net-list', '--all', '--uuid'), ('nwfilter-list',),
        }
        # Post-deployment readback commands are added only from fixed call sites.
        post = (args[0] in {'nwfilter-dumpxml', 'net-dumpxml', 'net-info',
                            'dumpxml', 'domstate', 'dominfo'} and len(args) in (2, 3))
        need(tuple(args) in allowed or post, 'virsh_readonly_argv_outside_allowlist')
        return self.run([self.bin['virsh'], '--readonly', '-c', 'qemu:///system', *args])

    def virsh_write(self, args: list[str]) -> bytes:
        valid = (args[0] == 'nwfilter-define' and len(args) == 2) or \
                (args[0] == 'net-define' and len(args) == 2) or \
                (args[0] == 'define' and len(args) == 3 and args[1] == '--validate')
        need(valid, 'virsh_write_argv_outside_allowlist')
        return self.sudo([self.bin['virsh'], '-c', 'qemu:///system', *args])


def _lines(raw: bytes) -> set[str]:
    try:
        return {line.strip() for line in raw.decode('utf-8').splitlines() if line.strip()}
    except UnicodeError as exc:
        raise R35Error('libvirt_inventory_encoding_invalid') from exc



def _nwfilter_inventory(raw: bytes) -> tuple[set[str], set[str]]:
    """Parse virsh nwfilter-list's UUID/Name table, rejecting malformed rows.

    nwfilter-list has NO --name or --uuid flags; these are from other virsh
    list commands and must never be sent to a real libvirt host.
    """
    try:
        lines = [line.strip() for line in raw.decode('utf-8').splitlines()
                 if line.strip()]
    except UnicodeError as exc:
        raise R35Error('nwfilter_inventory_encoding_invalid') from exc
    need(len(lines) >= 2 and re.fullmatch(r'UUID\s+Name', lines[0]) is not None
         and re.fullmatch(r'-{5,}', lines[1]) is not None,
         'nwfilter_inventory_header_invalid')
    names: set[str] = set()
    uuids: set[str] = set()
    uuid_pattern = re.compile(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
        r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
    for line in lines[2:]:
        columns = line.split()
        need(len(columns) == 2 and
             uuid_pattern.fullmatch(columns[0]) is not None and
             re.fullmatch(r'[A-Za-z0-9_.-]+', columns[1]) is not None,
             'nwfilter_inventory_row_invalid')
        ident, name = columns
        ident = ident.lower()
        need(ident not in uuids and name not in names,
             'nwfilter_inventory_duplicate_identity')
        names.add(name)
        uuids.add(ident)
    return names, uuids


def _nft_table_names(raw: bytes) -> set[tuple[str, str]]:
    try:
        doc = json.loads(raw)
        rows = doc['nftables']
        need(type(rows) is list, 'nft_inventory_invalid')
        result = set()
        for row in rows:
            if type(row) is dict and type(row.get('table')) is dict:
                result.add((row['table'].get('family'), row['table'].get('name')))
        return result
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise R35Error('nft_inventory_invalid') from exc



def _verify_nft_json(raw: bytes) -> None:
    """Accept only the exact R34 table semantics from nft JSON readback.

    nft displays numeric -200 as the textual priority alias "filter" on some
    systems; this checker compares the *numeric* JSON priority. Handles,
    counters and metainfo are observational, never permission grants.
    """
    try:
        data = json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(R35Error('nft_nonfinite')))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise R35Error('nft_json_invalid') from exc
    need(type(data) is dict and set(data) == {'nftables'} and
         type(data['nftables']) is list, 'nft_json_shape_invalid')
    rows = data['nftables']
    # nft -j -a list table often includes a metainfo row. It is not a rule.
    structural = [row for row in rows if not (type(row) is dict and set(row) == {'metainfo'})]
    meta = [row for row in rows if type(row) is dict and set(row) == {'metainfo'}]
    need(len(meta) <= 1 and all(type(row['metainfo']) is dict for row in meta),
         'nft_metadata_invalid')
    need(len(structural) == 8, 'nft_object_count_invalid')
    actual_table = []
    chains = {}
    rules = {}
    targets = set(TAPS)
    expected_rules = {
        ('input', 'iifname'), ('output', 'oifname'),
        ('forward', 'iifname'), ('forward', 'oifname'),
    }
    for item in structural:
        need(type(item) is dict and len(item) == 1, 'nft_object_kind_invalid')
        kind, value = next(iter(item.items()))
        need(kind in ('table', 'chain', 'rule') and type(value) is dict,
             'nft_unexpected_object')
        if 'handle' in value:
            need(type(value['handle']) is int and value['handle'] >= 0,
                 'nft_handle_invalid')
        if kind == 'table':
            need(set(value) <= {'family', 'name', 'handle'} and
                 value.get('family') == 'bridge' and value.get('name') == NFT_TABLE,
                 'nft_table_scope_invalid')
            actual_table.append(value)
        elif kind == 'chain':
            need(set(value) <= {'family', 'table', 'name', 'type', 'hook',
                                'prio', 'policy', 'handle'}, 'nft_extra_chain_fields')
            name = value.get('name')
            need(name in ('input', 'output', 'forward') and name not in chains and
                 value.get('family') == 'bridge' and value.get('table') == NFT_TABLE and
                 value.get('hook') == name and value.get('type') == 'filter' and
                 type(value.get('prio')) is int and value['prio'] == -200 and
                 value.get('policy') == 'accept', 'nft_chain_contract_invalid')
            chains[name] = value
        else:
            need(set(value) <= {'family', 'table', 'chain', 'expr', 'handle'},
                 'nft_extra_rule_fields')
            need(value.get('family') == 'bridge' and value.get('table') == NFT_TABLE and
                 value.get('chain') in ('input', 'output', 'forward'),
                 'nft_rule_scope_invalid')
            expr = value.get('expr')
            need(type(expr) is list and len(expr) == 3 and
                 all(type(x) is dict and len(x) == 1 for x in expr),
                 'nft_expr_shape_invalid')
            match, counter, verdict = expr
            need(set(match) == {'match'} and type(match['match']) is dict and
                 set(match['match']) == {'left', 'op', 'right'} and
                 match['match']['op'] == '==', 'nft_match_invalid')
            left = match['match']['left']
            right = match['match']['right']
            need(type(left) is dict and set(left) == {'meta'} and
                 type(left['meta']) is dict and set(left['meta']) == {'key'} and
                 left['meta']['key'] in ('iifname', 'oifname') and
                 type(right) is dict and set(right) == {'set'} and
                 type(right['set']) is list and len(right['set']) == len(targets) and
                 all(type(x) is str for x in right['set']) and
                 set(right['set']) == targets, 'nft_interface_set_invalid')
            need(set(counter) == {'counter'} and type(counter['counter']) is dict and
                 set(counter['counter']) == {'packets', 'bytes'} and
                 all(type(n) is int and n >= 0 for n in counter['counter'].values()),
                 'nft_counter_invalid')
            need(verdict == {'drop': None}, 'nft_verdict_not_drop')
            identity = (value['chain'], left['meta']['key'])
            need(identity in expected_rules and identity not in rules,
                 'nft_extra_or_duplicate_rule')
            rules[identity] = value
    need(len(actual_table) == 1 and set(chains) == {'input', 'output', 'forward'} and
         set(rules) == expected_rules, 'nft_missing_or_extra_objects')


def _verify_installed_nft(host: 'Host') -> None:
    raw = host.sudo([host.bin['nft'], '-j', '-a', 'list', 'table',
                     'bridge', NFT_TABLE])
    _verify_nft_json(raw)


def _verify_nft_dump(raw: bytes, expected: bytes) -> None:
    try:
        actual = raw.decode('utf-8')
    except UnicodeError as exc:
        raise R35Error('nft_table_dump_encoding_invalid') from exc
    wanted = expected.decode('ascii')
    # nft list adds zero-valued packet/byte counters; normalize only that rendering.
    actual = re.sub(r'counter packets [0-9]+ bytes [0-9]+', 'counter', actual)
    normalize = lambda value: re.sub(r'\s+', '', value)
    need(normalize(actual) == normalize(wanted), 'installed_nft_table_semantics_mismatch')


def _verify_network_dump(raw: bytes, expected: bytes, role: str) -> None:
    got = ET.fromstring(raw)
    want = ET.fromstring(expected)
    bridge = got.find('bridge')
    expected_bridge = want.find('bridge')
    need(bridge is not None and expected_bridge is not None and
         all(bridge.get(key) == expected_bridge.get(key)
             for key in ('name', 'stp', 'delay')) and
         set(bridge.attrib) <= {'name', 'stp', 'delay', 'macTableManager'} and
         bridge.get('macTableManager') in (None, 'kernel', 'libvirt'),
         'defined_network_bridge_attributes_invalid_' + role)
    need(got.tag == 'network' and got.findtext('name') == want.findtext('name') and
         got.findtext('uuid') == want.findtext('uuid') and
         got.get('ipv6') == 'no' and
         got.find('dns') is not None and got.find('dns').attrib == {'enable': 'no'} and
         got.find('forward') is None and got.find('ip') is None and
         got.find('dhcp') is None and
         {child.tag for child in got} == {'name', 'uuid', 'bridge', 'dns'},
         'defined_network_xml_mismatch_' + role)


def _verify_domain_dump(raw: bytes, expected: bytes, role: str) -> None:
    got = ET.fromstring(raw)
    want = ET.fromstring(expected)
    need(got.tag == 'domain' and got.get('type') == 'kvm' and
         got.findtext('name') == want.findtext('name') and
         got.findtext('uuid') == want.findtext('uuid') and
         got.findtext('memory') == want.findtext('memory') and
         got.findtext('currentMemory') == want.findtext('currentMemory') and
         got.findtext('vcpu') == want.findtext('vcpu'), 'defined_domain_identity_mismatch_' + role)
    gd = got.findall('devices/disk')
    wd = want.findall('devices/disk')
    need(len(gd) == len(wd) == 1 and gd[0].find('source').attrib == wd[0].find('source').attrib and
         gd[0].find('driver').attrib == wd[0].find('driver').attrib,
         'defined_domain_disk_mismatch_' + role)
    gi = got.findall('devices/interface')
    wi = want.findall('devices/interface')
    need(len(gi) == len(wi), 'defined_domain_nic_count_mismatch_' + role)
    for left, right in zip(gi, wi):
        need(left.get('type') == 'network' and
             left.find('mac').attrib == right.find('mac').attrib and
             left.find('source').attrib == right.find('source').attrib and
             left.find('target').attrib == right.find('target').attrib and
             left.find('filterref').attrib == right.find('filterref').attrib,
             'defined_domain_nic_mismatch_' + role)
    for forbidden in ('hostdev', 'filesystem', 'redirdev', 'vsock', 'graphics'):
        need(not got.findall('devices/' + forbidden),
             'defined_domain_forbidden_device_' + role + '_' + forbidden)
    need(got.findtext('on_poweroff') == 'destroy' and
         got.findtext('on_reboot') == 'destroy' and
         got.findtext('on_crash') == 'destroy', 'defined_domain_lifecycle_mismatch_' + role)


def _verify_inactive_info(raw: bytes, *, kind: str) -> None:
    try:
        text = raw.decode('utf-8')
    except UnicodeError as exc:
        raise R35Error('libvirt_info_encoding_invalid') from exc
    if kind == 'network':
        need(re.search(r'^Active:\s+no$', text, re.M) is not None and
             re.search(r'^Autostart:\s+no$', text, re.M) is not None,
             'network_not_inactive_or_autostart_enabled')
    else:
        need(text.strip().lower() == 'shut off', 'domain_not_shut_off')


def _verify_domain_autostart(raw: bytes) -> None:
    text = raw.decode('utf-8', 'strict')
    need(re.search(r'^Autostart:\s+(?:disable|no)$', text, re.M) is not None,
         'domain_autostart_not_disabled')


def _stat_command(host: Host, path: str) -> dict[str, Any]:
    raw = host.sudo([host.bin['stat'], '--printf=%F|%u|%g|%h|%a|%s|%i|%Y|%Z', '--', path])
    return _parse_stat(raw)


def _hash_command(host: Host, path: str) -> str:
    raw = host.sudo([host.bin['sha256sum'], '--binary', '--', path], timeout=120)
    return _parse_hash(raw, path)


def _qemu_info(host: Host, path: str) -> dict[str, Any]:
    raw = host.sudo([host.bin['qemu-img'], 'info', '--output=json', '-f', 'qcow2', path], timeout=60)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise R35Error('qemu_img_info_invalid_json') from exc
    need(type(value) is dict, 'qemu_img_info_not_object')
    return value


def _verify_storage(host: Host, r32: dict[str, Any]) -> dict[str, Any]:
    for path in ('/var', '/var/lib', '/var/lib/libvirt', '/var/lib/libvirt/images'):
        item = _stat_command(host, path)
        need(item['kind'] == 'directory' and item['uid'] == 0 and
             (item['mode'] & 0o022) == 0, 'storage_parent_permission_drift')
    stage = _stat_command(host, t33.R32_STAGE)
    need(stage['kind'] == 'directory' and stage['uid'] == 0 and
         stage['gid'] == QEMU_GID and stage['mode'] == 0o750,
         'r32_stage_directory_permission_drift')

    verified = []
    for row, asset in zip(r32['roles'], r32['new_assets']):
        role = row['role']
        base = row['source_base']
        parent = row['parent_overlay']
        new = row['new_overlay']
        size = row['virtual_size']
        need(asset['role'] == role and asset['path'] == new and
             asset['backing_filename'] == parent and asset['virtual_size'] == size,
             'r32_asset_row_mismatch')
        base_stat = _stat_command(host, base)
        parent_stat = _stat_command(host, parent)
        new_stat = _stat_command(host, new)
        need(base_stat['kind'] == 'regular file' and base_stat['nlink'] == 1 and
             base_stat['uid'] in (0, QEMU_UID) and (base_stat['mode'] & 0o222) == 0,
             'base_file_permission_drift_' + role)
        need(parent_stat['kind'] == 'regular file' and parent_stat['nlink'] == 1 and
             parent_stat['uid'] in (0, QEMU_UID) and (parent_stat['mode'] & 0o077) == 0,
             'parent_overlay_permission_drift_' + role)
        need(new_stat['kind'] == 'regular file' and new_stat['uid'] == QEMU_UID and
             new_stat['gid'] == QEMU_GID and new_stat['nlink'] == 1 and
             new_stat['mode'] == 0o600, 'new_overlay_permission_drift_' + role)
        need(_hash_command(host, base) == row['source_base_sha256'],
             'base_sha256_drift_' + role)
        need(_hash_command(host, parent) == row['parent_overlay_sha256'],
             'parent_overlay_sha256_drift_' + role)
        need(_hash_command(host, new) == asset['sha256'],
             'new_overlay_sha256_drift_' + role)
        _verify_qcow_info(canon(_qemu_info(host, base)), virtual_size=size, backing=None)
        _verify_qcow_info(canon(_qemu_info(host, parent)), virtual_size=size, backing=base)
        _verify_qcow_info(canon(_qemu_info(host, new)), virtual_size=size, backing=parent)
        verified.append({'role': role, 'base': base, 'parent_overlay': parent,
                         'new_overlay': new, 'base_sha256': row['source_base_sha256'],
                         'parent_overlay_sha256': row['parent_overlay_sha256'],
                         'new_overlay_sha256': asset['sha256'], 'virtual_size': size})
    return {'verified_roles': len(verified), 'assets': verified,
            'source_images_mutated': False}



def _assert_resource_absent(host: Host, *, kind: str, name: str, uuid: str) -> None:
    if kind == 'domain':
        names = _lines(host.virsh_ro(['list', '--all', '--name']))
        uuids = _lines(host.virsh_ro(['list', '--all', '--uuid']))
    elif kind == 'network':
        names = _lines(host.virsh_ro(['net-list', '--all', '--name']))
        uuids = _lines(host.virsh_ro(['net-list', '--all', '--uuid']))
    elif kind == 'nwfilter':
        names, uuids = _nwfilter_inventory(host.virsh_ro(['nwfilter-list']))
    else:
        raise R35Error('libvirt_resource_kind_invalid')
    need(name not in names and uuid not in uuids,
         'libvirt_resource_collision_' + kind)


def _assert_reserved_interfaces_absent(host: Host) -> None:
    raw = host.run([host.bin['ip'], '-j', 'link', 'show'])
    try:
        rows = json.loads(raw)
        need(type(rows) is list and all(type(row) is dict and
             type(row.get('ifname')) is str for row in rows),
             'ip_link_inventory_invalid')
    except (ValueError, TypeError) as exc:
        raise R35Error('ip_link_inventory_invalid') from exc
    names = {row['ifname'] for row in rows}
    need(not (names & (set(TAPS) | set(BRIDGES))),
         'ardrec_interface_name_collision')


def host_preflight(bundle: dict[str, Any], *, runner: Callable[..., Any] = subprocess.run,
                   which: Callable[[str], str | None] = shutil.which,
                   existing_nft: bool = False) -> tuple[dict[str, Any], Host]:
    """Fresh, read-only host preflight. No nft/libvirt writes occur here."""
    host = Host(runner=runner, which=which)
    host.sudo([host.bin['stat'], '--version'])
    domains = _lines(host.virsh_ro(['list', '--all', '--name']))
    active_domains = _lines(host.virsh_ro(['list', '--name']))
    domain_uuids = _lines(host.virsh_ro(['list', '--all', '--uuid']))
    networks = _lines(host.virsh_ro(['net-list', '--all', '--name']))
    network_uuids = _lines(host.virsh_ro(['net-list', '--all', '--uuid']))
    filters, filter_uuids = _nwfilter_inventory(host.virsh_ro(['nwfilter-list']))

    need(not any(name.startswith(('ardrec-r33-', 'ardrec-dev-')) for name in domains | networks),
         'ardrec_domain_or_network_collision')
    need(not any(name.startswith('ardrec-r33-') for name in filters), 'ardrec_filter_collision')
    expected_domain_uuids = {_xml_uuid(bundle['root'] / R33_DIR / f'domain-{role}.xml')
                             for role in t33.ROLES}
    expected_network_uuids = {_xml_uuid(bundle['root'] / R33_DIR / f'network-{role}.xml')
                              for role in t33.NET_BRIDGE}
    expected_filter_uuid = _xml_uuid(bundle['root'] / R34_DIR / 'nwfilter-deny.xml')
    need(not (expected_domain_uuids & domain_uuids) and
         not (expected_network_uuids & network_uuids) and
         expected_filter_uuid not in filter_uuids, 'libvirt_uuid_collision')
    need(not (set(DOMAINS) & active_domains), 'ardrec_domain_already_active')

    links_raw = host.run([host.bin['ip'], '-j', 'link', 'show'])
    try:
        links = json.loads(links_raw)
        need(type(links) is list and all(type(row) is dict and
             type(row.get('ifname')) is str for row in links), 'ip_link_inventory_invalid')
    except (ValueError, TypeError) as exc:
        raise R35Error('ip_link_inventory_invalid') from exc
    link_names = {row['ifname'] for row in links}
    need(not (link_names & (set(TAPS) | set(BRIDGES))), 'ardrec_interface_name_collision')

    nft_tables = _nft_table_names(host.sudo([host.bin['nft'], '-j', 'list', 'tables']))
    if existing_nft:
        need(('bridge', NFT_TABLE) in nft_tables, 'r35_prior_nft_table_missing')
        _verify_installed_nft(host)
    else:
        need(('bridge', NFT_TABLE) not in nft_tables, 'nft_table_name_collision')
    policy = t34.policy_files()['bridge-deny.nft']
    host.sudo([host.bin['nft'], '-c', '-f', '-'], input_bytes=policy)

    xml_dir = bundle['root'] / R33_DIR
    for role in t33.NET_BRIDGE:
        host.run([host.bin['virt-xml-validate'], str(xml_dir / f'network-{role}.xml'), 'network'])
    for role in t33.ROLES:
        host.run([host.bin['virt-xml-validate'], str(xml_dir / f'domain-{role}.xml'), 'domain'])
    host.run([host.bin['virt-xml-validate'], str(bundle['root'] / R34_DIR / 'nwfilter-deny.xml'), 'nwfilter'])

    storage = _verify_storage(host, bundle['r32'])
    report = {
        'schema': ('ardrec-p14-r35-resume-host-preflight-v1' if existing_nft
                   else 'ardrec-p14-r35-host-preflight-v1'),
        'mode': ('READONLY_HOST_PREFLIGHT_EXISTING_NFT' if existing_nft
                 else 'READONLY_HOST_PREFLIGHT'),
        'source_archive_sha256': ARCHIVE_SHA256,
        'source_r32_report_sha256': bundle['r32']['sha256'],
        'source_r33_report_sha256': bundle['r33']['sha256'],
        'source_r34_report_sha256': bundle['r34']['sha256'],
        'libvirt_readonly_queries_pass': True,
        'name_collisions_absent': True,
        'uuid_collisions_absent': True,
        'tap_and_bridge_names_absent': True,
        'nft_table_absent': not existing_nft,
        'nft_existing_verified_json': existing_nft,
        'nft_syntax_validated': True,
        'libvirt_xml_schema_validated': 8,
        'qcow2_chain_verified_roles': storage['verified_roles'],
        'qcow2_assets_verified': 12,
        'storage_assets': storage['assets'],
        'firewall_modified': False,
        'libvirt_definitions_created': False,
        'network_started': False,
        'vm_started': False,
        'operational_dispatch': False,
        'can_restore': False,
        'p8_operational': 'NO-GO',
        'final_risk': None,
    }
    report['sha256'] = sha(canon(report))
    verify_host_report(report)
    return report, host


def verify_host_report(report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         DIGEST.fullmatch(report['sha256']) is not None and
         sha(canon({k: v for k, v in report.items() if k != 'sha256'})) == report['sha256'],
         'r35_host_report_digest_invalid')
    need( ( (report.get('schema') == 'ardrec-p14-r35-host-preflight-v1' and
              report.get('mode') == 'READONLY_HOST_PREFLIGHT' and
              report.get('nft_table_absent') is True and
              report.get('nft_existing_verified_json', False) is False) or
           (report.get('schema') == 'ardrec-p14-r35-resume-host-preflight-v1' and
              report.get('mode') == 'READONLY_HOST_PREFLIGHT_EXISTING_NFT' and
              report.get('nft_table_absent') is False and
              report.get('nft_existing_verified_json') is True) ) and
         report.get('source_archive_sha256') == ARCHIVE_SHA256 and
         all(type(report.get(key)) is str and DIGEST.fullmatch(report[key]) is not None
             for key in ('source_r32_report_sha256', 'source_r33_report_sha256',
                         'source_r34_report_sha256')) and
         all(report.get(key) is True for key in (
             'libvirt_readonly_queries_pass', 'name_collisions_absent',
             'uuid_collisions_absent', 'tap_and_bridge_names_absent',
             'nft_syntax_validated')) and
         report.get('libvirt_xml_schema_validated') == 8 and
         report.get('qcow2_chain_verified_roles') == 4 and
         report.get('qcow2_assets_verified') == 12 and
         all(report.get(key) is False for key in (
             'firewall_modified', 'libvirt_definitions_created',
             'network_started', 'vm_started', 'operational_dispatch', 'can_restore')) and
         report.get('p8_operational') == 'NO-GO' and report.get('final_risk') is None,
         'r35_host_report_semantics_invalid')
    assets = report.get('storage_assets')
    need(type(assets) is list and len(assets) == 4 and
         {row.get('role') for row in assets if type(row) is dict} == set(t33.ROLES),
         'r35_host_storage_inventory_invalid')
    for row in assets:
        role = row['role']
        need(row.get('base') == f'{t33.BASE_ROOT}/{role}-base.qcow2' and
             row.get('parent_overlay') == f'{t33.PARENT_ROOT}/{role}-runtime.qcow2' and
             row.get('new_overlay') == f'{t33.R32_STAGE}/{role}-runtime.qcow2' and
             all(type(row.get(key)) is str and DIGEST.fullmatch(row[key]) is not None
                 for key in ('base_sha256', 'parent_overlay_sha256', 'new_overlay_sha256')) and
             type(row.get('virtual_size')) is int and row['virtual_size'] > 0,
             'r35_host_storage_role_binding_invalid')
    return True


def _write_exclusive(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _receipt_dir(path: Path) -> None:
    need(path.is_absolute() and not path.exists() and not path.is_symlink(),
         'receipt_directory_must_be_new')
    for parent in path.parents:
        need(not parent.is_symlink(), 'receipt_parent_symlink')
    parent = path.parent
    need(parent.is_dir() and parent.stat().st_uid == os.geteuid() and
         (stat.S_IMODE(parent.stat().st_mode) & 0o022) == 0,
         'receipt_parent_owner_or_mode_invalid')
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    need(stat.S_IMODE(path.stat().st_mode) == 0o700 and
         path.stat().st_uid == os.geteuid(), 'receipt_directory_not_private')


def _write_receipts(directory: Path, records: dict[str, dict[str, Any]], commands: list[dict[str, Any]]) -> None:
    for name, doc in records.items():
        _write_exclusive(directory / name, canon(doc) + b'\n')
    command_bytes = b''.join(canon(row) + b'\n' for row in commands)
    _write_exclusive(directory / 'commands.jsonl', command_bytes)
    sums = []
    for path in sorted(directory.iterdir()):
        if path.name == 'SHA256SUMS':
            continue
        sums.append(f'{sha(path.read_bytes())}  {path.name}')
    _write_exclusive(directory / 'SHA256SUMS', ('\n'.join(sums) + '\n').encode('ascii'))


def deployment_report(source: dict[str, Any], preflight: dict[str, Any] | None,
                      *, status: str, failure: str | None = None,
                      nft_installed: bool = False, filter_defined: bool = False,
                      filter_verified: bool = False, networks_defined: list[str] | None = None,
                      domains_defined: list[str] | None = None,
                      networks_inactive: list[str] | None = None,
                      domains_shut_off: list[str] | None = None,
                      active_networks_observed: list[str] | None = None,
                      active_domains_observed: list[str] | None = None,
                      autostart_disabled: bool = False,
                      storage_revalidated: bool = False,
                      collision_rechecks: bool = False,
                      interfaces_absent_before_domains: bool = False,
                      table_verified: bool = False,
                      interfaces_absent_after: bool = False,
                      runtime_only: bool = True) -> dict[str, Any]:
    networks_defined = list(networks_defined or [])
    domains_defined = list(domains_defined or [])
    networks_inactive = list(networks_inactive or [])
    domains_shut_off = list(domains_shut_off or [])
    active_networks_observed = list(active_networks_observed or [])
    active_domains_observed = list(active_domains_observed or [])
    doc = {
        'schema': SCHEMA,
        'base_main': BASE_MAIN,
        'source_archive_sha256': ARCHIVE_SHA256,
        'source_attestation_sha256': source['attestation']['sha256'],
        'host_preflight_sha256': preflight['sha256'] if preflight else None,
        'mode': 'DENY_FIRST_AND_INACTIVE_LIBVIRT_DEPLOYMENT',
        'status': status,
        'nft_table': NFT_TABLE,
        'nft_table_installed': nft_installed,
        'nft_table_verified': table_verified,
        'nwfilter': FILTER_NAME,
        'nwfilter_defined': filter_defined,
        'nwfilter_verified': filter_verified,
        'network_names': list(NETWORKS),
        'networks_defined': networks_defined,
        'networks_verified_inactive': networks_inactive,
        'domain_names': list(DOMAINS),
        'domains_defined': domains_defined,
        'domains_verified_shut_off': domains_shut_off,
        'active_networks_observed': active_networks_observed,
        'active_domains_observed': active_domains_observed,
        'autostart_disabled_verified': autostart_disabled,
        'qcow2_revalidated_before_domain_definition': storage_revalidated,
        'libvirt_collisions_rechecked_before_each_definition': collision_rechecks,
        'tap_and_bridge_names_absent_before_domain_definition': interfaces_absent_before_domains,
        'tap_and_bridge_names_absent_after': interfaces_absent_after,
        'runtime_only_not_persistent_across_reboot': runtime_only,
        'global_ruleset_flushed': False,
        'non_ardrec_firewall_changed': False,
        'qcow2_assets_mutated': False,
        'network_started': False,
        'vm_started': False,
        'operational_dispatch': False,
        'can_restore': False,
        'technical_truth_accredited': False,
        'p8_operational': 'NO-GO',
        'final_risk': None,
        'published_generation': None,
        'experimental_validation': 'NOT_RUN',
        'system_functional_acceptance': 'PENDING',
        'open_findings': ['AL-06', 'AL-07'],
        'failure_code': failure,
        'automatic_rollback': False,
        'activation_commands_invoked': False,
    }
    doc['sha256'] = sha(canon(doc))
    verify_deployment_report(doc)
    return doc


def verify_deployment_report(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         DIGEST.fullmatch(doc['sha256']) is not None and
         sha(canon({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
         'r35_deployment_digest_invalid')
    need(doc.get('schema') == SCHEMA and doc.get('base_main') == BASE_MAIN and
         doc.get('source_archive_sha256') == ARCHIVE_SHA256 and
         type(doc.get('source_attestation_sha256')) is str and
         DIGEST.fullmatch(doc['source_attestation_sha256']) is not None and
         type(doc.get('host_preflight_sha256')) is str and
         DIGEST.fullmatch(doc['host_preflight_sha256']) is not None and
         doc.get('mode') == 'DENY_FIRST_AND_INACTIVE_LIBVIRT_DEPLOYMENT' and
         doc.get('network_names') == list(NETWORKS) and
         doc.get('domain_names') == list(DOMAINS) and
         doc.get('nft_table') == NFT_TABLE and doc.get('nwfilter') == FILTER_NAME and
         all(doc.get(key) is False for key in (
             'global_ruleset_flushed', 'non_ardrec_firewall_changed',
             'qcow2_assets_mutated', 'network_started', 'vm_started',
             'operational_dispatch', 'can_restore', 'technical_truth_accredited',
             'automatic_rollback', 'activation_commands_invoked')) and
         doc.get('runtime_only_not_persistent_across_reboot') is True and
         doc.get('p8_operational') == 'NO-GO' and doc.get('final_risk') is None and
         doc.get('published_generation') is None and
         doc.get('experimental_validation') == 'NOT_RUN' and
         doc.get('system_functional_acceptance') == 'PENDING' and
         doc.get('open_findings') == ['AL-06', 'AL-07'],
         'r35_deployment_semantics_invalid')
    need(len(doc.get('networks_defined', [])) == len(set(doc.get('networks_defined', []))) and
         len(doc.get('domains_defined', [])) == len(set(doc.get('domains_defined', []))) and
         len(doc.get('networks_verified_inactive', [])) == len(set(doc.get('networks_verified_inactive', []))) and
         len(doc.get('domains_verified_shut_off', [])) == len(set(doc.get('domains_verified_shut_off', []))) and
         set(doc.get('networks_defined', [])) <= set(NETWORKS) and
         set(doc.get('domains_defined', [])) <= set(DOMAINS) and
         set(doc.get('networks_verified_inactive', [])) <= set(doc.get('networks_defined', [])) and
         set(doc.get('domains_verified_shut_off', [])) <= set(doc.get('domains_defined', [])) and
         len(doc.get('active_networks_observed', [])) == len(set(doc.get('active_networks_observed', []))) and
         len(doc.get('active_domains_observed', [])) == len(set(doc.get('active_domains_observed', []))) and
         set(doc.get('active_networks_observed', [])) <= set(NETWORKS) and
         set(doc.get('active_domains_observed', [])) <= set(DOMAINS) and
         (not doc.get('nft_table_verified') or doc.get('nft_table_installed')) and
         (not doc.get('nwfilter_verified') or doc.get('nwfilter_defined')) and
         (not doc.get('autostart_disabled_verified') or
          (set(doc.get('networks_verified_inactive', [])) == set(NETWORKS) and
           set(doc.get('domains_verified_shut_off', [])) == set(DOMAINS))),
         'r35_resource_inventory_invalid')
    if 'recovery_mode' in doc:
        need(doc.get('recovery_mode') == 'EXISTING_NFT_VERIFIED_JSON' and
             type(doc.get('prior_partial_receipt_sha256')) is str and
             DIGEST.fullmatch(doc['prior_partial_receipt_sha256']) is not None and
             type(doc.get('resume_attestation_sha256')) is str and
             DIGEST.fullmatch(doc['resume_attestation_sha256']) is not None and
             doc.get('status') != 'PREFLIGHT_PASS_NOT_INSTALLED',
             'r35_resume_provenance_invalid')
    if doc['status'] == 'PREFLIGHT_PASS_NOT_INSTALLED':
        need(doc.get('nft_table_installed') is False and
             doc.get('nft_table_verified') is False and
             doc.get('nwfilter_defined') is False and
             doc.get('nwfilter_verified') is False and
             doc.get('networks_defined') == [] and doc.get('domains_defined') == [] and
             doc.get('failure_code') is None, 'r35_preflight_only_status_invalid')
    elif doc['status'] == 'BLOCKED_NO_CHANGE':
        need(doc.get('nft_table_installed') is False and
             doc.get('nft_table_verified') is False and
             doc.get('nwfilter_defined') is False and
             doc.get('nwfilter_verified') is False and
             doc.get('networks_defined') == [] and doc.get('domains_defined') == [] and
             type(doc.get('failure_code')) is str and bool(doc['failure_code']),
             'r35_blocked_status_invalid')
    elif doc['status'] == 'PARTIAL_NO_GO_REVIEW_REQUIRED':
        need(type(doc.get('failure_code')) is str and bool(doc['failure_code']),
             'r35_partial_status_missing_code')
    if doc['status'] == 'DEPLOYMENT_COMPLETE_INACTIVE':
        need(doc.get('nft_table_installed') is True and
             doc.get('nft_table_verified') is True and
             doc.get('nwfilter_defined') is True and
             doc.get('nwfilter_verified') is True and
             set(doc['networks_defined']) == set(NETWORKS) and
             set(doc['domains_defined']) == set(DOMAINS) and
             set(doc['networks_verified_inactive']) == set(NETWORKS) and
             set(doc['domains_verified_shut_off']) == set(DOMAINS) and
             doc.get('active_networks_observed') == [] and
             doc.get('active_domains_observed') == [] and
             doc.get('autostart_disabled_verified') is True and
             doc.get('qcow2_revalidated_before_domain_definition') is True and
             doc.get('libvirt_collisions_rechecked_before_each_definition') is True and
             doc.get('tap_and_bridge_names_absent_before_domain_definition') is True and
             doc.get('tap_and_bridge_names_absent_after') is True and
             doc.get('failure_code') is None, 'r35_success_claim_invalid')
    else:
        need(doc['status'] in ('PREFLIGHT_PASS_NOT_INSTALLED',
             'RESUME_PREFLIGHT_PASS_EXISTING_NFT', 'BLOCKED_NO_CHANGE', 'PARTIAL_NO_GO_REVIEW_REQUIRED'),
             'r35_status_invalid')
    return True


def _check_activation_absent(commands: list[dict[str, Any]]) -> None:
    forbidden = {'start', 'net-start', 'autostart', 'shutdown', 'destroy',
                 'net-destroy', 'undefine', 'net-undefine', 'nwfilter-undefine'}
    for record in commands:
        argv = record.get('argv', [])
        need(not any(token in forbidden for token in argv), 'activation_or_cleanup_command_detected')
        need(not (any(Path(token).name == 'nft' for token in argv) and 'flush' in argv),
             'global_nft_flush_command_detected')



def verify_prior_partial_receipt(directory: Path, bundle: dict[str, Any]) -> dict[str, Any]:
    """Pin exact R35 nft-only partial receipts before admitting a recovery.

    This evidence authorizes no write. The existing nft table must separately
    pass a fresh read-only structural JSON attestation.
    """
    need(isinstance(directory, Path) and directory.is_absolute() and
         directory.name.startswith('recibos-instalacion-') and
         not directory.is_symlink(), 'prior_receipt_directory_invalid')
    for parent in (directory, *directory.parents):
        need(not parent.is_symlink(), 'prior_receipt_symlink')
    dstat = directory.stat()
    need(stat.S_ISDIR(dstat.st_mode) and dstat.st_uid == os.geteuid() and
         stat.S_IMODE(dstat.st_mode) == 0o700,
         'prior_receipt_owner_or_mode_invalid')
    names = {'SHA256SUMS', 'commands.jsonl', 'r35_deployment.json',
             'r35_host_preflight.json', 'r35_source_attestation.json'}
    need({p.name for p in directory.iterdir()} == names,
         'prior_receipt_inventory_invalid')
    sums = t34.secure_file(directory / 'SHA256SUMS').decode('ascii')
    seen = set()
    for row in sums.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', row)
        need(match is not None, 'prior_sha256sum_row_invalid')
        digest, name = match.groups()
        need(name in names - {'SHA256SUMS'} and name not in seen,
             'prior_sha256sum_inventory_invalid')
        seen.add(name)
        need(sha(t34.secure_file(directory / name)) == digest,
             'prior_receipt_file_hash_invalid_' + name)
    need(seen == names - {'SHA256SUMS'}, 'prior_receipt_missing_hash')
    old, old_bytes = _read_json(directory / 'r35_deployment.json')
    verify_deployment_report(old)
    need(old.get('sha256') == R35_PARTIAL_REPORT_SHA256 and
         old['status'] == 'PARTIAL_NO_GO_REVIEW_REQUIRED' and
         old['failure_code'] == 'installed_nft_table_semantics_mismatch' and
         old['nft_table_installed'] is True and
         old['nft_table_verified'] is False and
         old['nwfilter_defined'] is False and old['nwfilter_verified'] is False and
         old['networks_defined'] == [] and old['domains_defined'] == [] and
         old['network_started'] is False and old['vm_started'] is False and
         old['source_archive_sha256'] == ARCHIVE_SHA256 and
         old['source_attestation_sha256'] == bundle['attestation']['sha256'],
         'prior_partial_state_invalid')
    old_host, _ = _read_json(directory / 'r35_host_preflight.json')
    verify_host_report(old_host)
    need(old['host_preflight_sha256'] == old_host['sha256'] and
         old_host['schema'] == 'ardrec-p14-r35-host-preflight-v1',
         'prior_host_preflight_not_original')
    old_source, _ = _read_json(directory / 'r35_source_attestation.json')
    need(old_source == bundle['attestation'], 'prior_source_attestation_mismatch')
    raw_commands = t34.secure_file(directory / 'commands.jsonl')
    need(len(raw_commands) > 0, 'prior_command_log_empty')
    commands = []
    for line in raw_commands.splitlines():
        try:
            cmd = json.loads(line, object_pairs_hook=_pairs)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise R35Error('prior_command_json_invalid') from exc
        need(type(cmd) is dict and type(cmd.get('argv')) is list and
             all(type(x) is str for x in cmd['argv']) and
             type(cmd.get('returncode')) is int and
             type(cmd.get('stdout_sha256')) is str and
             type(cmd.get('stderr_sha256')) is str,
             'prior_command_record_invalid')
        commands.append(cmd)
    _check_activation_absent(commands)
    nft = ['/usr/bin/sudo', '-n', '--', '/usr/sbin/nft']
    alternate = ['/usr/bin/sudo', '-n', '--', '/usr/bin/nft']
    writes = [c for c in commands if c['argv'][:4] in (nft, alternate) and
              c['argv'][4:] == ['-f', '-']]
    need(len(writes) == 1 and writes[0]['returncode'] == 0,
         'prior_nft_write_not_unique')
    reads = [c for c in commands if c['argv'][:4] in (nft, alternate) and
             c['argv'][4:] == ['list', 'table', 'bridge', NFT_TABLE]]
    need(len(reads) == 1 and reads[0]['returncode'] == 0 and
         type(reads[0].get('stdout')) is str and
         sha(reads[0]['stdout'].encode('utf-8')) == reads[0]['stdout_sha256'] and
         'table bridge ' + NFT_TABLE in reads[0]['stdout'],
         'prior_nft_readback_not_authenticated')
    need(not any(c['argv'][:4] in (nft, alternate) and
                 c['argv'][4:] in (['flush', 'ruleset'], ['delete', 'table', 'bridge', NFT_TABLE])
                 for c in commands), 'prior_firewall_write_outside_scope')
    need(not any(c['argv'][:4] in (
        ['/usr/bin/sudo', '-n', '--', '/usr/bin/virsh'],) for c in commands),
         'prior_libvirt_write_forbidden')
    return {
        'schema': 'ardrec-p14-r352-prior-partial-attestation-v1',
        'original_receipt_sha256': sha(old_bytes),
        'original_commands_sha256': sha(raw_commands),
        'original_sha256sums_sha256': sha((directory / 'SHA256SUMS').read_bytes()),
        'original_status': old['status'],
        'original_failure_code': old['failure_code'],
        'old_nft_installed': True,
        'old_libvirt_definitions_absent': True,
        'source_attestation_sha256': bundle['attestation']['sha256'],
        'p8_operational': 'NO-GO',
    }


def deploy(bundle: dict[str, Any], preflight: dict[str, Any], host: Host, *,
           reuse_verified_nft: bool = False) -> dict[str, Any]:
    """Install the exact R34 deny policy, then define filter/networks/domains inactive.

    No rollback is attempted after a partial write. Every next step is fail-closed.
    """
    policy = t34.policy_files()
    root = bundle['root']
    nft_installed = bool(reuse_verified_nft)
    filter_defined = filter_verified = table_verified = False
    networks_defined: list[str] = []
    domains_defined: list[str] = []
    networks_inactive: list[str] = []
    domains_shut_off: list[str] = []
    autostart_disabled = False
    storage_revalidated = False
    collision_rechecks = False
    interfaces_absent_before_domains = False
    interfaces_absent_after = False
    active_networks_observed: list[str] = []
    active_domains_observed: list[str] = []
    failure = None
    status = 'PARTIAL_NO_GO_REVIEW_REQUIRED'
    try:
        # 1. Install only the new bridge-family table; never flush or replace rulesets.
        if not reuse_verified_nft:
            host.sudo([host.bin['nft'], '-f', '-'], input_bytes=policy['bridge-deny.nft'])
            nft_installed = True
        # Re-read kernel state for both paths. No textual alias comparisons.
        _verify_installed_nft(host)
        table_verified = True

        # 2. Define the deny-all libvirt filter before any domain can reference it.
        filter_path = root / R34_DIR / 'nwfilter-deny.xml'
        _assert_resource_absent(host, kind='nwfilter', name=FILTER_NAME,
                                uuid=_xml_uuid(filter_path))
        host.virsh_write(['nwfilter-define', str(filter_path)])
        filter_defined = True
        filter_dump = host.virsh_ro(['nwfilter-dumpxml', FILTER_NAME])
        t34.verify_filter(filter_dump)
        filter_verified = True

        # 3. Define the three isolated networks. net-define never starts them.
        for role in t33.NET_BRIDGE:
            name = t33.NETWORK_PREFIX + role
            xml_path = root / R33_DIR / f'network-{role}.xml'
            expected = xml_path.read_bytes()
            _assert_resource_absent(host, kind='network', name=name,
                                    uuid=_xml_uuid(xml_path))
            host.virsh_write(['net-define', str(xml_path)])
            networks_defined.append(name)
            dump = host.virsh_ro(['net-dumpxml', name, '--inactive'])
            _verify_network_dump(dump, expected, role)
            info = host.virsh_ro(['net-info', name])
            _verify_inactive_info(info, kind='network')
            networks_inactive.append(name)

        # 4. Re-hash the complete QCOW2 chain immediately before domain definitions.
        storage_now = _verify_storage(host, bundle['r32'])
        need(storage_now['assets'] == preflight['storage_assets'],
             'qcow2_storage_changed_after_preflight')
        storage_revalidated = True
        _assert_reserved_interfaces_absent(host)
        interfaces_absent_before_domains = True

        # 5. Define four domains with the already-installed deny-all filter.
        for role in t33.ROLES:
            name = t33.DOMAIN_PREFIX + role
            xml_path = root / R33_DIR / f'domain-{role}.xml'
            expected = xml_path.read_bytes()
            _assert_resource_absent(host, kind='domain', name=name,
                                    uuid=_xml_uuid(xml_path))
            host.virsh_write(['define', '--validate', str(xml_path)])
            domains_defined.append(name)
            dump = host.virsh_ro(['dumpxml', name, '--inactive'])
            _verify_domain_dump(dump, expected, role)
            state = host.virsh_ro(['domstate', name])
            _verify_inactive_info(state, kind='domain')
            info = host.virsh_ro(['dominfo', name])
            _verify_domain_autostart(info)
            domains_shut_off.append(name)

        # 6. Final state: names exist, all inactive, no tap/bridge was created.
        current_domains = _lines(host.virsh_ro(['list', '--all', '--name']))
        current_active_domains = _lines(host.virsh_ro(['list', '--name']))
        current_networks = _lines(host.virsh_ro(['net-list', '--all', '--name']))
        current_active_networks = _lines(host.virsh_ro(['net-list', '--name']))
        current_filters, _ = _nwfilter_inventory(host.virsh_ro(['nwfilter-list']))
        active_domains_observed = sorted(set(DOMAINS) & current_active_domains)
        active_networks_observed = sorted(set(NETWORKS) & current_active_networks)
        need(set(DOMAINS) <= current_domains and
             not active_domains_observed,
             'final_domain_inventory_or_state_mismatch')
        need(set(NETWORKS) <= current_networks and
             not active_networks_observed and
             FILTER_NAME in current_filters,
             'final_network_or_filter_inventory_mismatch')

        # Final readback replaces the earlier per-resource observations.
        filter_verified = False
        t34.verify_filter(host.virsh_ro(['nwfilter-dumpxml', FILTER_NAME]))
        filter_verified = True
        networks_inactive = []
        for role in t33.NET_BRIDGE:
            name = t33.NETWORK_PREFIX + role
            _verify_inactive_info(host.virsh_ro(['net-info', name]), kind='network')
            networks_inactive.append(name)
        domains_shut_off = []
        for role in t33.ROLES:
            name = t33.DOMAIN_PREFIX + role
            _verify_inactive_info(host.virsh_ro(['domstate', name]), kind='domain')
            _verify_domain_autostart(host.virsh_ro(['dominfo', name]))
            domains_shut_off.append(name)
        autostart_disabled = True

        links_raw = host.run([host.bin['ip'], '-j', 'link', 'show'])
        try:
            links = json.loads(links_raw)
            need(type(links) is list and all(type(row) is dict and
                 type(row.get('ifname')) is str for row in links),
                 'final_ip_link_inventory_invalid')
        except (ValueError, TypeError) as exc:
            raise R35Error('final_ip_link_inventory_invalid') from exc
        link_names = {row['ifname'] for row in links}
        need(not (link_names & (set(TAPS) | set(BRIDGES))),
             'tap_or_bridge_appeared_without_activation')
        interfaces_absent_after = True

        table_verified = False
        _verify_installed_nft(host)
        table_verified = True
        collision_rechecks = True
        status = 'DEPLOYMENT_COMPLETE_INACTIVE'
    except (R35Error, OSError, ValueError, KeyError, TypeError) as exc:
        failure = str(exc)[:160] or type(exc).__name__
        status = 'PARTIAL_NO_GO_REVIEW_REQUIRED' if (
            nft_installed or filter_defined or networks_defined or domains_defined
        ) else 'BLOCKED_NO_CHANGE'
    _check_activation_absent(host.commands)
    report = deployment_report(bundle, preflight, status=status, failure=failure,
        nft_installed=nft_installed, filter_defined=filter_defined,
        filter_verified=filter_verified, networks_defined=networks_defined, domains_defined=domains_defined,
        networks_inactive=networks_inactive, domains_shut_off=domains_shut_off,
        active_networks_observed=active_networks_observed,
        active_domains_observed=active_domains_observed,
        autostart_disabled=autostart_disabled, storage_revalidated=storage_revalidated,
        collision_rechecks=collision_rechecks,
        interfaces_absent_before_domains=interfaces_absent_before_domains,
        table_verified=table_verified, interfaces_absent_after=interfaces_absent_after)
    return report


def run(archive: Path, receipt_dir: Path, *, install: bool,
        runner: Callable[..., Any] = subprocess.run,
        which: Callable[[str], str | None] = shutil.which,
        resume_partial_dir: Path | None = None) -> dict[str, Any]:
    _receipt_dir(receipt_dir)
    temp = tempfile.TemporaryDirectory(prefix='ardrec-r35-source-')
    try:
        root = Path(temp.name)
        root.chmod(0o700)
        bundle = verify_source_bundle(archive, root)
        prior = (verify_prior_partial_receipt(resume_partial_dir, bundle)
                 if resume_partial_dir is not None else None)
        preflight, host = host_preflight(bundle, runner=runner, which=which,
                                         existing_nft=prior is not None)
        records: dict[str, dict[str, Any]] = {
            'r35_source_attestation.json': bundle['attestation'],
            'r35_host_preflight.json': preflight,
        }
        if prior is not None:
            prior['current_host_preflight_sha256'] = preflight['sha256']
            prior['sha256'] = sha(canon(prior))
            records['r35_resume_attestation.json'] = prior
        if install:
            report = deploy(bundle, preflight, host,
                            reuse_verified_nft=prior is not None)
        elif prior is not None:
            report = deployment_report(bundle, preflight,
                status='RESUME_PREFLIGHT_PASS_EXISTING_NFT',
                nft_installed=True, table_verified=True)
        else:
            report = deployment_report(bundle, preflight,
                status='PREFLIGHT_PASS_NOT_INSTALLED')
        if prior is not None:
            report['recovery_mode'] = 'EXISTING_NFT_VERIFIED_JSON'
            report['prior_partial_receipt_sha256'] = prior['original_receipt_sha256']
            report['resume_attestation_sha256'] = prior['sha256']
            report['sha256'] = sha(canon({k: v for k, v in report.items() if k != 'sha256'}))
            verify_deployment_report(report)
        records['r35_deployment.json'] = report
        _write_receipts(receipt_dir, records, host.commands)
        return report
    finally:
        temp.cleanup()
