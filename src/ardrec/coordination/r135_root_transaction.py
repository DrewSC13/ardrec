"""R135: durable, resumable two-destination publication core (source only).

This module has no command-line installer and cannot establish operational
trust. A separately provisioned, root-owned agent MUST authenticate the
release, trust anchors, source bytes, boot identity, and fresh revocation
before supplying the authorize callback. Never import from a mutable checkout
in privileged execution. No network or VM operations are implemented.
"""
from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = 'ARDREC-R135-ROOT-PAIR-TRANSACTION-v1'
B4_SHA = 'f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8'
B9_SHA = 'c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3'
GUARD_SHA = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
F3_SHA = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
B4 = frozenset({'manifest.json', 'root-controller.py', 'grant.json',
                'contract.json', 'scope-authorization.json', 'pilot-permit.json',
                'traffic-window.json'})
B9 = frozenset({'root-executor.py', 'manifest.json', 'release.json',
                'traffic-grant.json', 'f13-handoff.json', 'lock'})
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
TARGETS = ('/var/lib/ardrec/r126-ftp-session-guard-v1',
           '/var/lib/ardrec/r128-one-session-v2')
NAMES = frozenset({'.r135.lock', 'journal.json', 'receipt.json',
                   '.pending-b4', '.pending-b9', 'published-b4', 'published-b9'})


class Refusal(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def parse_json(blob: bytes) -> dict:
    require(type(blob) is bytes and 0 < len(blob) <= 200000, 'JSON_SIZE')

    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'JSON_DUPLICATE_KEY')
            out[key] = value
        return out

    try:
        obj = json.loads(blob, object_pairs_hook=pairs,
                         parse_constant=lambda _: require(False, 'JSON_NONFINITE'))
    except (ValueError, UnicodeError, TypeError) as exc:
        if isinstance(exc, Refusal):
            raise
        raise Refusal('JSON_SYNTAX') from exc
    require(type(obj) is dict and canonical(obj) == blob, 'JSON_NONCANONICAL')
    return obj


def validate_payload(payload: dict, head: str) -> dict:
    """Validate complete source identity and exact V2 manifest semantics.

    All other operational JSON remains untrusted pending independent semantic
    review. A successful return is NOT permission to install.
    """
    require(type(head) is str and HEX40.fullmatch(head) is not None,
            'HEAD_INVALID')
    expected = {f'B4/{name}' for name in B4} | {f'B9/{name}' for name in B9}
    require(type(payload) is dict and set(payload) == expected,
            'FILE_SET_INVALID')
    require(all(type(v) is bytes and 0 < len(v) <= 200000
                for v in payload.values()) and sum(map(len, payload.values())) <= 1_000_000,
            'FILE_SIZE_INVALID')
    require(digest(payload['B4/root-controller.py']) == B4_SHA, 'B4_PIN_INVALID')
    require(digest(payload['B9/root-executor.py']) == B9_SHA, 'B9_PIN_INVALID')
    require(payload['B9/lock'] == b'ARDREC-R128-B9-ROOT-LOCK\n', 'LOCK_INVALID')
    for name, data in payload.items():
        if name.endswith('.json'):
            parse_json(data)
    b4 = parse_json(payload['B4/manifest.json'])
    b9 = parse_json(payload['B9/manifest.json'])
    require(b4 == {
        'schema': 'ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle',
        'script_sha256': B4_SHA, 'guard_sha256': GUARD_SHA,
        'approved_head': head, 'deny_only': True,
        'root_install_independent': True,
    }, 'B4_MANIFEST_INVALID')
    require(b9 == {
        'schema': 'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle',
        'approved_head': head, 'script_sha256': B9_SHA,
        'r126_deny_controller_sha256': B4_SHA, 'legacy_f3_sha256': F3_SHA,
        'guard_sha256': GUARD_SHA, 'root_staged_independently': True,
        'automatic_network': False, 'p8': 'NO-GO',
    }, 'B9_MANIFEST_INVALID')
    hashes = {name: digest(raw) for name, raw in sorted(payload.items())}
    return {
        'schema': SCHEMA + '-plan', 'head': head,
        'b4_target': TARGETS[0], 'b9_target': TARGETS[1],
        'files': hashes, 'inventory_sha256': digest(canonical(hashes)),
        'signed_release_verified': False,
        'independent_trust_confirmed': False,
        'operational_semantics_verified': False,
        'physical_execution': False, 'root_install_authorized': False,
        'p8': 'NO-GO',
    }


def check_directory(path: Path, owner: int) -> None:
    require(isinstance(path, Path) and path.is_absolute(), 'PATH_INVALID')
    require(not path.is_symlink(), 'SYMLINK_DIRECTORY')
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == owner
            and stat.S_IMODE(st.st_mode) == 0o700,
            'PRIVATE_DIRECTORY_REQUIRED')


def sync_folder(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_exact(path: Path, expected: bytes, owner: int) -> None:
    require(not path.is_symlink(), 'FILE_SYMLINK')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        meta = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner
                and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_nlink == 1 and before.st_size == len(expected),
                'FILE_METADATA_INVALID')
        data = bytearray()
        while len(data) <= len(expected):
            chunk = os.read(fd, len(expected) + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        meta_after = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                      after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        require(meta == meta_after and bytes(data) == expected,
                'FILE_CHANGED_OR_CONTENT_MISMATCH')
    finally:
        os.close(fd)


def exclusive_file(path: Path, body: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def rename_noreplace(source: Path, target: Path) -> None:
    """Linux renameat2(RENAME_NOREPLACE): never overwrite an existing target."""
    libc = ctypes.CDLL(None, use_errno=True)
    operation = libc.renameat2
    operation.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    operation.restype = ctypes.c_int
    result = operation(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    if result != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number), str(target))


def children(folder: Path) -> set[str]:
    return {p.name for p in folder.iterdir()}


def verify_published(folder: Path, contents: dict[str, bytes], owner: int) -> None:
    require(folder.exists() and not folder.is_symlink(), 'PUBLISHED_DIRECTORY_MISSING')
    check_directory(folder, owner)
    require(children(folder) == set(contents), 'PUBLISHED_FILE_SET_CHANGED')
    for name, raw in sorted(contents.items()):
        read_exact(folder / name, raw, owner)


def stage_pending(parent: Path, pending: str, contents: dict[str, bytes], owner: int):
    folder = parent / pending
    if not folder.exists() and not folder.is_symlink():
        folder.mkdir(mode=0o700)
        sync_folder(parent)
    check_directory(folder, owner)
    require(children(folder) <= set(contents), 'PENDING_UNEXPECTED_ENTRY')
    for name, data in sorted(contents.items()):
        dst = folder / name
        if not dst.exists() and not dst.is_symlink():
            exclusive_file(dst, data)
        read_exact(dst, data, owner)
    sync_folder(folder)


def authorize_phase(authorize, phase: str, plan: dict):
    """The upstream *independent agent* supplies this trusted callback.

    A callback from a checkout is NOT operational authentication. This core
    performs no real root action by itself and exposes no install CLI.
    """
    require(callable(authorize), 'INDEPENDENT_AUTHORIZER_MISSING')
    result = authorize(phase, plan)
    require(result is True, 'FRESH_AUTHORIZATION_REQUIRED:' + phase)


def publish_pair(*, parent: Path, payload: dict, head: str,
                 authorize, fault: str | None = None) -> dict:
    """Two durable publications and explicit recovery. No auto-removal.

    parent MUST be a separately authenticated private root-owned transaction
    directory in production. This function cannot prove root provenance.
    Tests use disposable, user-owned temporary directories only.
    """
    require(fault in (None, 'before_b4', 'after_b4', 'after_b9',
                      'before_receipt', 'after_stage'), 'UNKNOWN_FAULT')
    owner = os.geteuid()
    check_directory(parent, owner)
    plan = validate_payload(payload, head)
    b4_data = {n.split('/', 1)[1]: raw for n, raw in payload.items() if n.startswith('B4/')}
    b9_data = {n.split('/', 1)[1]: raw for n, raw in payload.items() if n.startswith('B9/')}
    journal = {'schema': SCHEMA + '-journal', 'plan_sha256': digest(canonical(plan)),
               'inventory_sha256': plan['inventory_sha256'],
               'head': head, 'targets': list(TARGETS), 'p8': 'NO-GO'}
    journal_raw = canonical(journal)
    receipt = {'schema': SCHEMA + '-receipt', 'journal_sha256': digest(journal_raw),
               'inventory_sha256': plan['inventory_sha256'], 'b4_sha256': B4_SHA,
               'b9_sha256': B9_SHA, 'root_trust_independent': False,
               'physical_execution': False, 'traffic_enabled': False, 'p8': 'NO-GO'}
    receipt_raw = canonical(receipt)
    lock = parent / '.r135.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size == 0, 'TRANSACTION_LOCK_UNSAFE')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refusal('CONCURRENT_TRANSACTION_DENIED') from exc
        require(children(parent) <= NAMES, 'UNEXPECTED_TRANSACTION_ENTRY')
        b4 = parent / 'published-b4'
        b9 = parent / 'published-b9'
        journal_path = parent / 'journal.json'
        receipt_path = parent / 'receipt.json'
        if journal_path.exists() or journal_path.is_symlink():
            read_exact(journal_path, journal_raw, owner)
        else:
            require(not b4.exists() and not b4.is_symlink()
                    and not b9.exists() and not b9.is_symlink()
                    and not receipt_path.exists() and not receipt_path.is_symlink(),
                    'PREEXISTING_DESTINATION_WITHOUT_JOURNAL')
            authorize_phase(authorize, 'before_journal', plan)
            exclusive_file(journal_path, journal_raw)
            sync_folder(parent)
        if receipt_path.exists() or receipt_path.is_symlink():
            require(b4.is_dir() and not b4.is_symlink()
                    and b9.is_dir() and not b9.is_symlink(),
                    'RECEIPT_WITH_MISSING_PAIR')
            verify_published(b4, b4_data, owner)
            verify_published(b9, b9_data, owner)
            read_exact(receipt_path, receipt_raw, owner)
            return {'status': 'ALREADY_PUBLISHED_VERIFIED', 'receipt_sha256': digest(receipt_raw),
                    'root_install_authorized': False, 'traffic_enabled': False, 'p8': 'NO-GO'}
        require(not (b9.exists() or b9.is_symlink())
                or (b4.is_dir() and not b4.is_symlink()), 'B9_WITHOUT_B4')
        if b4.exists() or b4.is_symlink():
            verify_published(b4, b4_data, owner)
        if b9.exists() or b9.is_symlink():
            verify_published(b9, b9_data, owner)
        if not b4.exists() and not b4.is_symlink():
            stage_pending(parent, '.pending-b4', b4_data, owner)
        if not b9.exists() and not b9.is_symlink():
            stage_pending(parent, '.pending-b9', b9_data, owner)
        if fault == 'after_stage':
            raise Refusal('INJECTED_AFTER_STAGE')
        if not b4.exists() and not b4.is_symlink():
            authorize_phase(authorize, 'before_b4', plan)
            if fault == 'before_b4':
                raise Refusal('INJECTED_BEFORE_B4')
            rename_noreplace(parent / '.pending-b4', b4)
            sync_folder(parent)
        verify_published(b4, b4_data, owner)
        if fault == 'after_b4':
            raise Refusal('INJECTED_AFTER_B4')
        if not b9.exists() and not b9.is_symlink():
            authorize_phase(authorize, 'before_b9', plan)
            rename_noreplace(parent / '.pending-b9', b9)
            sync_folder(parent)
        verify_published(b9, b9_data, owner)
        if fault == 'after_b9':
            raise Refusal('INJECTED_AFTER_B9')
        authorize_phase(authorize, 'before_receipt', plan)
        if fault == 'before_receipt':
            raise Refusal('INJECTED_BEFORE_RECEIPT')
        if not receipt_path.exists() and not receipt_path.is_symlink():
            exclusive_file(receipt_path, receipt_raw)
            sync_folder(parent)
        read_exact(receipt_path, receipt_raw, owner)
        return {'status': 'PRIVATE_PAIR_PUBLISHED', 'receipt_sha256': digest(receipt_raw),
                'root_install_authorized': False, 'traffic_enabled': False, 'p8': 'NO-GO'}
    finally:
        os.close(fd)


def capabilities() -> dict:
    return {'schema': SCHEMA + '-capabilities', 'durable_journal': True,
            'crash_recovery': True, 'two_nonatomic_renames': True,
            'fresh_authorizer_callback_required': True,
            'root_trust_anchored': False, 'autonomous_root_agent': False,
            'root_install_executed': False, 'physical_execution': False,
            'network_traffic': False, 'p8': 'NO-GO'}
