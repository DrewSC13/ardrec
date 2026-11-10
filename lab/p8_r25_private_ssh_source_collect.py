#!/usr/bin/env python3
"""Operator-only R25 collection of exact SSH config source bytes from pinned QCOW2.

No guest executable is invoked. No shell, network, VM-domain connection, sudo,
credentials, service probe, profile approval or dispatch. Never prints raw bytes.
Uses libguestfs --ro on the *filename*, not the active libvirt domain.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import p8_r25_ssh_source_provenance as p25

PATCHES = Path('/home/cicada/Development/GitHub/ardrec-patches')
IMAGE = Path('/var/lib/libvirt/images/ardrec-dev-point4-v4/runner-base.qcow2')
OLD = PATCHES/'ARDREC_PRIVATE_R24/PROOF_SUFFICIENCY_R24_PRIVATE.json'
PRIVATE = PATCHES/'ARDREC_PRIVATE_R25'
RECEIPT = PRIVATE/'SSH_CONFIG_SOURCE_R25_PRIVATE.json'
EXPECTED_FILE_BYTES = 1_345_847_296
EXPECTED_VIRTUAL_BYTES = 25_769_803_776
GUESTFISH = '/usr/bin/guestfish'
QEMU_IMG = '/usr/bin/qemu-img'


def is_exact_0600(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and \
        stat.S_IMODE(path.stat().st_mode) == 0o600


def is_exact_0700(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink() and \
        stat.S_IMODE(path.stat().st_mode) == 0o700


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run(*argv: str, timeout: int = 180) -> bytes:
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                          check=False, timeout=timeout, env={
        'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
        'LIBGUESTFS_BACKEND': 'direct',
    })
    p25.require(proc.returncode == 0,
                'read_only_tool_failure:' + Path(argv[0]).name + ':' + str(proc.returncode))
    p25.require(len(proc.stdout) <= p25.MAX_TOTAL_BYTES,
                'guest_stdout_size_limit')
    return proc.stdout


def gf(op: str, *args: str) -> bytes:
    """Fixed operations and fixed image: no guest shell or domain lookup."""
    p25.require(op in {'is-symlink', 'is-file', 'is-dir', 'readlink', 'ls', 'download'},
                'guestfish_operation_not_allowed')
    p25.require(all(type(a) is str and a.startswith('/') for a in args if a != '-'),
                'guestfish_path_absolute')
    p25.require(not any(x in ('--rw', 'command', 'sh', 'bash', '-d') for x in args),
                'guestfish_unsafe_arg')
    return run(GUESTFISH, '--ro', '--format=qcow2', '-a', str(IMAGE), '-i', op, *args)


def guest_bool(op: str, path: str) -> bool:
    raw = gf(op, path)
    p25.require(raw in (b'true\n', b'false\n', b'true', b'false'),
                'unknown_guest_boolean:' + op + ':' + path)
    return raw.rstrip(b'\n') == b'true'


def check_path_not_symlink(path: str) -> None:
    p25.require(not guest_bool('is-symlink', path), 'symlink_or_unknown:' + path)


def check_plain_directory(path: str) -> None:
    """Reject symlinks in every guest path component; never follow a chain."""
    p25.require(path.startswith('/') and path != '/' and not path.endswith('/'),
                'directory_not_absolute')
    components = path[1:].split('/')
    p25.require(all(c and c not in ('.', '..') for c in components),
                'unsafe_directory_component')
    current = ''
    for component in components:
        current += '/' + component
        check_path_not_symlink(current)
        p25.require(guest_bool('is-dir', current), 'not_plain_directory:' + current)


def check_regular_file(path: str) -> None:
    check_plain_directory(path.rsplit('/', 1)[0])
    check_path_not_symlink(path)
    p25.require(guest_bool('is-file', path), 'not_plain_regular_file:' + path)


def fragment_source(name: str) -> tuple[bytes, str | None]:
    """An exact symlink is measured via its pinned regular target, never by following."""
    path = p25.FRAGMENT_DIR + '/' + name
    if not guest_bool('is-symlink', path):
        p25.require(guest_bool('is-file', path), 'not_plain_fragment:' + path)
        return gf('download', path, '-'), None
    p25.require(name == p25.ALIAS_NAME and path == p25.ALIAS_PATH,
                'unapproved_guest_symlink:' + path)
    declared = gf('readlink', path)
    target = p25.ALIAS_TARGET.encode('utf-8')
    p25.require(declared in (target, target + b'\n'),
                'unexpected_guest_symlink_target:' + path)
    # The absolute target and its parents must be regular/directories, not links.
    check_regular_file(p25.ALIAS_TARGET)
    raw = gf('download', p25.ALIAS_TARGET, '-')
    # Recheck the literal link after reading; a changed pinned image will block
    # separately at collect() before any receipt is written.
    p25.require(gf('readlink', path) == declared, 'guest_symlink_changed:' + path)
    return raw, p25.ALIAS_TARGET


def image_preflight() -> None:
    p25.require(os.geteuid() != 0, 'root_execution_forbidden')
    p25.require(IMAGE.is_file() and not IMAGE.is_symlink(), 'image_type')
    mode = IMAGE.stat()
    p25.require(stat.S_IMODE(mode.st_mode) == 0o444 and mode.st_nlink == 1
                and mode.st_size == EXPECTED_FILE_BYTES, 'pinned_image_stat')
    p25.require(Path(QEMU_IMG).is_file() and Path(GUESTFISH).is_file(),
                'libguestfs_or_qemu_img_missing')
    info = json.loads(run(QEMU_IMG, 'info', '--output=json', str(IMAGE)))
    p25.require(info.get('format') == 'qcow2'
                and info.get('virtual-size') == EXPECTED_VIRTUAL_BYTES
                and not info.get('backing-filename')
                and not info.get('full-backing-filename'), 'image_format_backing_virtual_size')
    p25.require(sha256_file(IMAGE) == p25.IMAGE_SHA, 'pinned_image_sha')


def read_only_material() -> dict:
    """Returns a *private* source-level receipt without raw config content."""
    check_regular_file(p25.ROOT_PATH)
    check_plain_directory(p25.FRAGMENT_DIR)
    root = gf('download', p25.ROOT_PATH, '-')
    entries_bytes = gf('ls', p25.FRAGMENT_DIR)
    try:
        entries = entries_bytes.decode('utf-8').splitlines()
    except UnicodeDecodeError as e:
        raise p25.SourceError('P8_R25_FAIL_CLOSED:directory_listing_not_utf8') from e
    names = p25.normalize_directory_entries(entries)
    contents = {}
    aliases = {}
    for name in names:
        raw, target = fragment_source(name)
        contents[name] = raw
        if target is not None:
            aliases[p25.FRAGMENT_DIR + '/' + name] = target
    doc = p25.analyze(root, contents, entries, p25.IMAGE_SHA, aliases=aliases)
    p25.validate(doc)
    return doc


def verify_r24_receipt() -> None:
    p25.require(is_exact_0700(OLD.parent) and is_exact_0600(OLD),
                'r24_private_permissions')
    p25.require(OLD.stat().st_size <= 1_048_576, 'r24_receipt_size')
    raw = OLD.read_bytes()
    p25.require(hashlib.sha256(raw).hexdigest() == p25.R24_RECEIPT_SHA,
                'r24_private_receipt_sha')
    obj = json.loads(raw)
    summ = obj.get('summary', {})
    p25.require(obj.get('scope') ==
                'P8_R24_PRIVATE_STATIC_PROOF_REQUIREMENTS_NOT_OPERATIONAL_PROOF'
                and summ.get('matrix_sha256') == p25.R24_MATRIX_SHA
                and summ.get('profiles') == 29
                and summ.get('unverified_gate_instances') == 261
                and summ.get('pending_binding_fields') == 348
                and obj.get('authorized_profiles') == 0
                and obj.get('authorized_cases') == 0
                and obj.get('dispatch_allowed') is False,
                'r24_receipt_promoted_or_changed')


def save_receipt(doc: dict) -> dict:
    p25.validate(doc)
    p25.require(PATCHES.is_dir() and not PATCHES.is_symlink(), 'patches_directory')
    p25.require(not RECEIPT.exists() and not RECEIPT.is_symlink(), 'receipt_already_exists')
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    p25.require(is_exact_0700(PRIVATE), 'private_directory_mode')
    wrapped = {'schema_version': '1.0',
               'scope': 'P8_R25_PRIVATE_PINNED_IMAGE_SSH_CONFIG_BYTES_NOT_EFFECTIVE',
               'r24_receipt_sha256': p25.R24_RECEIPT_SHA,
               'r24_matrix_sha256': p25.R24_MATRIX_SHA,
               'capture': doc,
               'no_approval': True,
               'dispatch_allowed': False,
               'no_guest_binary_execution': True}
    b = (json.dumps(wrapped, indent=2, ensure_ascii=False, sort_keys=True) + '\n').encode()
    p25.require(len(b) <= 65_536, 'receipt_size')
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(b)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            RECEIPT.unlink()
        except OSError:
            pass
        raise
    d = os.open(PRIVATE, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(d)
    finally:
        os.close(d)
    return {
        'status': 'PASS_R25_OFFLINE_SSH_SOURCE_BYTES_MEASURED_NOT_EFFECTIVE',
        'receipt_sha256': hashlib.sha256(b).hexdigest(),
        'image_sha256_verified': True,
        'r24_receipt_authenticated': True,
        'source_file_count': doc['source_file_count'],
        'source_bytes_total': doc['source_bytes_total'],
        'fragment_file_count': doc['fragment_file_count'],
        'resolved_literal_symlink_count': doc['source_alias_count'],
        'unresolved_include_directives': doc['unresolved_include_directive_count'],
        'candidate_ssh_profiles': 8,
        'effective_configuration_verified': False,
        'authorized_profiles': 0,
        'authorized_cases': 0,
        'dispatch_allowed': False,
        'no_guest_execution': True,
    }


def collect(path: Path) -> dict:
    p25.require(path == RECEIPT and path.is_absolute(), 'exact_receipt_path')
    p25.require(not RECEIPT.exists(), 'receipt_already_exists')
    print('R25_PHASE=VERIFY_R24_PROVENANCE', file=sys.stderr, flush=True)
    verify_r24_receipt()
    print('R25_PHASE=VERIFY_IMAGE_PIN', file=sys.stderr, flush=True)
    image_preflight()
    print('R25_PHASE=READ_SSH_CONFIG_SOURCES_ONLY', file=sys.stderr, flush=True)
    doc = read_only_material()
    p25.require(sha256_file(IMAGE) == p25.IMAGE_SHA, 'image_changed_during_read')
    print('R25_PHASE=WRITE_PRIVATE_DIGEST_ONLY', file=sys.stderr, flush=True)
    return save_receipt(doc)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-receipt', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(collect(args.private_receipt), sort_keys=True))
    except (p25.SourceError, ValueError, KeyError, TypeError, OSError,
            subprocess.TimeoutExpired) as e:
        print('R25_COLLECT=BLOCKED:' + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
