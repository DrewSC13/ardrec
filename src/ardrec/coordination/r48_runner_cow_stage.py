"""P14-R48: stage exactly one new runner COW layer; no domain/network mutation.

The historical R32 disk remains the backing image. The generated SSH-only
runner XML references the *new* COW, but still applies the R33 deny-all filter.
This module never defines a domain, starts a guest, alters nftables, or sends packets.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Callable
from xml.etree import ElementTree as ET

from ardrec.coordination import r33_offline_topology as r33
from ardrec.coordination import r45_ssh_positive_candidate as r45
from ardrec.coordination import r46_ssh_transition_audit as r46
from ardrec.coordination import r47_filter_stage as r47

SCHEMA = 'ardrec-p14-r48-runner-disposable-cow-stage-v1'
BASE_MAIN = '60c330e627d2822257d0f60de610b46c986538aa'
R45_PIN = '3ddca2761bd4ca2d4244afa962bec305e68985466687824fa6ddd9db93bdceb3'
R46_PIN = '6cbe72db1b93f6ce33b63d6337d808f583a30944fa327b1a46c9b01f18284abb'
R47_PIN = 'fc285dc12fbe0bad276ac3402f066d9c82f63357ad6b71adf0c400bc9ede677d'
TOP = '/var/lib/libvirt/images/ardrec-dev-point4-r32/runner-runtime.qcow2'
PARENT = '/var/lib/libvirt/images/ardrec-dev-point4-v6/runner-runtime.qcow2'
BASE = '/var/lib/libvirt/images/ardrec-dev-point4-v4/runner-base.qcow2'
NEW_DIR = '/var/lib/libvirt/images/ardrec-dev-point4-r48'
NEW_DISK = NEW_DIR + '/runner-ssh-isolated.qcow2'
VOL_BYTES = 24 * 1024**3
MIN_FREE = 2 * 1024**3
REC_FILES = ('r48-stage-intent.json', 'runner-ssh-only-deny-r48.xml', 'r48-stage-verified.json')
MAX_OUT = 131072

class R48Error(ValueError):
    pass

def need(ok: bool, msg: str) -> None:
    if not ok:
        raise R48Error(msg)

def canon(o: Any) -> bytes:
    return json.dumps(o, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _host(argv: list[str], *, run: Callable[..., Any] = subprocess.run, out_limit: int = MAX_OUT) -> bytes:
    need(argv and argv[0] == '/usr/bin/sudo' and argv[1] == '-n', 'command_not_sudo_noninteractive')
    try:
        result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, timeout=40, check=False, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise R48Error('host_command_unavailable') from ex
    need(type(result.returncode) is int and result.returncode == 0 and
         type(result.stdout) is bytes and len(result.stdout) <= out_limit and
         type(result.stderr) is bytes and len(result.stderr) <= 4096,
         'host_command_failed_' + argv[-1][-48:])
    return result.stdout

def _cmd(*args: str) -> list[str]:
    return ['/usr/bin/sudo', '-n', '--', *args]

def _sources(r45dir: Path, r46dir: Path, r47dir: Path) -> None:
    need(r45.verify_directory(r45dir)['sha256'] == R45_PIN, 'r45_pin_mismatch')
    need(r46.verify_receipt(r46dir, r45dir)['sha256'] == R46_PIN, 'r46_pin_mismatch')
    # R47 verifies actual live libvirt, including unused filter readback and R34.
    need(r47.verify_receipt(r45dir, r46dir, r47dir)['sha256'] == R47_PIN,
         'r47_live_filter_or_receipt_mismatch')

def _chain(data: bytes, expected: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as ex:
        raise R48Error('disk_chain_json_invalid') from ex
    need(type(value) is list and len(value) == len(expected), 'disk_chain_length')
    for i, (part, filename) in enumerate(zip(value, expected)):
        need(type(part) is dict and part.get('filename') == filename and
             part.get('format') == 'qcow2' and
             part.get('virtual-size') == VOL_BYTES,
             'disk_chain_identity_' + str(i))
        form = part.get('format-specific', {})
        if type(form) is dict and type(form.get('data')) is dict:
            need(form['data'].get('corrupt') is not True, 'disk_chain_corrupt')
        if i < len(expected) - 1:
            need(part.get('backing-filename') is not None and
                 (part.get('full-backing-filename', part.get('backing-filename')) == expected[i + 1]),
                 'disk_chain_backing_' + str(i))
        else:
            need(not part.get('backing-filename'), 'disk_base_has_unknown_backing')
    return tuple(value)

def _info(path: str, run: Callable[..., Any]) -> bytes:
    return _host(_cmd('/usr/bin/qemu-img', 'info', '--output=json', '--backing-chain', path), run=run)

def _top_hash(run: Callable[..., Any]) -> str:
    raw = _host(_cmd('/usr/bin/sha256sum', TOP), run=run)
    parts = raw.strip().split(maxsplit=1)
    need(len(parts) == 2 and parts[1].decode('utf-8') == TOP and
         re.fullmatch(rb'[0-9a-f]{64}', parts[0]) is not None,
         'top_hash_unexpected')
    return parts[0].decode('ascii')

def _stat_disk(path: str, run: Callable[..., Any]) -> dict[str, Any]:
    raw = _host(_cmd('/usr/bin/stat', '-c', '%s|%a|%U|%G|%h', path), run=run)
    try:
        length, mode, user, group, links = raw.decode().strip().split('|')
        result = {'bytes': int(length), 'mode': mode, 'user': user,
                  'group': group, 'links': int(links)}
    except (ValueError, UnicodeError) as ex:
        raise R48Error('disk_stat_invalid') from ex
    need(result['links'] == 1 and result['mode'] == '600' and
         result['user'] == result['group'] == 'libvirt-qemu', 'disk_mode_or_owner_invalid')
    return result

def _free_bytes(run: Callable[..., Any]) -> int:
    raw = _host(_cmd('/usr/bin/df', '-P', '-B1', '/var/lib/libvirt/images'), run=run)
    lines = raw.decode('utf-8').strip().splitlines()
    need(len(lines) == 2, 'df_output_invalid')
    fields = lines[1].split()
    need(len(fields) >= 6 and fields[3].isdigit(), 'df_free_invalid')
    avail = int(fields[3])
    need(avail >= MIN_FREE, 'disk_free_space_below_2gib')
    return avail

def runner_domain_candidate() -> bytes:
    original = r45.domain_candidate(runner=True)
    root = ET.fromstring(original)
    disk = root.find('./devices/disk/source')
    ref = root.find('./devices/interface/filterref')
    need(disk is not None and disk.get('file') == TOP and ref is not None and
         ref.get('filter') == r45.FILTER_RUNNER, 'runner_candidate_source_drift')
    disk.set('file', NEW_DISK)
    ref.set('filter', r33.DENY_FILTER)
    result = r45.xml_bytes(root)
    check_runner_candidate(result)
    return result

def check_runner_candidate(raw: bytes) -> None:
    root = ET.fromstring(raw)
    reference = ET.fromstring(r45.domain_candidate(runner=True))
    disk = reference.find('./devices/disk/source')
    filt = reference.find('./devices/interface/filterref')
    need(disk is not None and filt is not None, 'runner_reference_structure')
    disk.set('file', NEW_DISK)
    filt.set('filter', r33.DENY_FILTER)
    def semantic(el: ET.Element) -> Any:
        return el.tag, tuple(sorted(el.attrib.items())), (el.text or '').strip(), tuple(semantic(e) for e in el)
    need(semantic(root) == semantic(reference) and
         len(root.findall('./devices/interface')) == 1 and
         root.find('./devices/disk/source').get('file') == NEW_DISK and
         root.find('./devices/interface/filterref').get('filter') == r33.DENY_FILTER,
         'runner_isolation_or_identity_drift')

def _private_receipt_root(root: Path, *, exists: bool) -> None:
    need(isinstance(root, Path) and root.is_absolute() and
         re.fullmatch(r'r48-runner-overlay-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}', root.name) is not None and
         not any(p.is_symlink() for p in (root, *root.parents)), 'receipt_path_invalid')
    parent = root.parent
    need(parent.is_dir() and parent.stat().st_uid == os.getuid() and
         stat.S_IMODE(parent.stat().st_mode) == 0o700, 'receipt_parent_insecure')
    need(root.is_dir() if exists else not root.exists(), 'receipt_state_invalid')
    if exists:
        st = root.stat()
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700, 'receipt_root_insecure')

def _write(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def _preflight(r45dir: Path, r46dir: Path, r47dir: Path, *, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    _sources(r45dir, r46dir, r47dir)
    original_chain = _chain(_info(TOP, run), (TOP, PARENT, BASE))
    stat_top = _stat_disk(TOP, run)
    available = _free_bytes(run)
    top_sha = _top_hash(run)
    # Never overwrite a prior R48 physical staging attempt.
    exists = _host(_cmd('/usr/bin/test', '!', '-e', NEW_DIR), run=run)
    not_link = _host(_cmd('/usr/bin/test', '!', '-L', NEW_DIR), run=run)
    need(exists == b'' and not_link == b'', 'new_disk_directory_collision')
    cand = runner_domain_candidate()
    return {'schema': SCHEMA, 'source_main': BASE_MAIN,
            'r45_report_sha256': R45_PIN, 'r46_report_sha256': R46_PIN,
            'r47_report_sha256': R47_PIN,
            'mode': 'RUNNER_NEW_OVERLAY_PREFLIGHT',
            'base_chain_paths': [x['filename'] for x in original_chain],
            'base_top_sha256': top_sha, 'base_top_stat': stat_top,
            'storage_free_bytes': available,
            'new_disk': NEW_DISK, 'domain_candidate_sha256': sha(cand),
            'domain_candidate_filter': r33.DENY_FILTER,
            'physical_overlay_created': False, 'runner_redefined': False,
            'vm_started': False, 'network_or_firewall_modified': False,
            'packets_sent': False, 'rollback_tested': False,
            'p8_operational': 'NO-GO'}

def preflight(r45dir: Path, r46dir: Path, r47dir: Path) -> dict[str, Any]:
    result = _preflight(r45dir, r46dir, r47dir)
    result['sha256'] = sha(canon(result))
    return result

def stage(r45dir: Path, r46dir: Path, r47dir: Path, root: Path,
          *, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    _private_receipt_root(root, exists=False)
    plan = _preflight(r45dir, r46dir, r47dir, run=run)
    domain = runner_domain_candidate()
    root.mkdir(mode=0o700)
    _write(root/'r48-stage-intent.json', canon(plan) + b'\n')
    _write(root/'runner-ssh-only-deny-r48.xml', domain)
    # The first host mutation is restricted to a newly named directory.
    _host(_cmd('/usr/bin/install', '-d', '-m', '0700', '-o', 'libvirt-qemu',
               '-g', 'libvirt-qemu', '--', NEW_DIR), run=run)
    _host(['/usr/bin/sudo', '-n', '-u', 'libvirt-qemu', '-g', 'libvirt-qemu',
           '--', '/usr/bin/qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
           '-b', TOP, NEW_DISK], run=run)
    _host(_cmd('/usr/bin/chmod', '0600', '--', NEW_DISK), run=run)
    _chain(_info(NEW_DISK, run), (NEW_DISK, TOP, PARENT, BASE))
    disk_stat = _stat_disk(NEW_DISK, run)
    need(_top_hash(run) == plan['base_top_sha256'], 'original_r32_top_changed')
    # The existing R47 host checks must still pass after disk-only creation.
    _sources(r45dir, r46dir, r47dir)
    report = {**plan, 'mode': 'RUNNER_DISPOSABLE_COW_STAGED_NO_GO',
              'physical_overlay_created': True, 'new_overlay_stat': disk_stat,
              'storage_free_bytes_after': _free_bytes(run),
              'original_r32_sha256_verified_unchanged': True,
              'runner_redefined': False, 'vm_started': False,
              'network_or_firewall_modified': False, 'packets_sent': False,
              'rollback_tested': False, 'p8_operational': 'NO-GO'}
    report['sha256'] = sha(canon(report))
    _write(root/'r48-stage-verified.json', canon(report)+b'\n')
    sums = ''.join(f'{sha((root / name).read_bytes())}  {name}\n' for name in sorted(REC_FILES))
    _write(root/'SHA256SUMS', sums.encode('ascii'))
    return report

def verify(r45dir: Path, r46dir: Path, r47dir: Path, root: Path,
           *, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    _private_receipt_root(root, exists=True)
    need({p.name for p in root.iterdir()} == set(REC_FILES) | {'SHA256SUMS'}, 'receipt_files_unexpected')
    contents: dict[str, bytes] = {}
    for name in (*REC_FILES, 'SHA256SUMS'):
        p = root / name
        st = p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o600,
             'receipt_file_insecure_'+name)
        contents[name] = p.read_bytes()
    expected = ''.join(f'{sha(contents[name])}  {name}\n' for name in sorted(REC_FILES)).encode('ascii')
    need(contents['SHA256SUMS'] == expected, 'receipt_hashes_invalid')
    need(contents['runner-ssh-only-deny-r48.xml'] == runner_domain_candidate(), 'domain_candidate_changed')
    original = json.loads(contents['r48-stage-intent.json'])
    report = json.loads(contents['r48-stage-verified.json'])
    need(type(original) is dict and original.get('schema') == SCHEMA and
         original.get('source_main') == BASE_MAIN and
         original.get('mode') == 'RUNNER_NEW_OVERLAY_PREFLIGHT' and
         original.get('r45_report_sha256') == R45_PIN and
         original.get('r46_report_sha256') == R46_PIN and
         original.get('r47_report_sha256') == R47_PIN and
         original.get('base_chain_paths') == [TOP, PARENT, BASE] and
         original.get('new_disk') == NEW_DISK and
         original.get('storage_free_bytes', 0) >= MIN_FREE and
         original.get('physical_overlay_created') is False and
         all(original.get(k) is False for k in ('runner_redefined','vm_started',
                             'network_or_firewall_modified','packets_sent','rollback_tested')) and
         original.get('p8_operational') == 'NO-GO' and
         original.get('domain_candidate_sha256') == sha(contents['runner-ssh-only-deny-r48.xml']),
         'intent_source_invalid')
    additions = {'mode': 'RUNNER_DISPOSABLE_COW_STAGED_NO_GO',
                 'physical_overlay_created': True,
                 'new_overlay_stat': report.get('new_overlay_stat'),
                 'storage_free_bytes_after': report.get('storage_free_bytes_after'),
                 'original_r32_sha256_verified_unchanged': True}
    expected_report = {**original, **additions}
    expected_report['sha256'] = sha(canon(expected_report))
    need(report == expected_report and
         type(report.get('storage_free_bytes_after')) is int and
         report['storage_free_bytes_after'] >= MIN_FREE,
         'receipt_report_invalid')
    _sources(r45dir, r46dir, r47dir)
    _chain(_info(NEW_DISK, run), (NEW_DISK, TOP, PARENT, BASE))
    need(_stat_disk(NEW_DISK, run) == report['new_overlay_stat'], 'new_disk_stat_drift')
    need(_stat_disk(TOP, run) == original['base_top_stat'], 'original_r32_stat_changed')
    need(_top_hash(run) == original['base_top_sha256'], 'original_r32_top_changed')
    return report
