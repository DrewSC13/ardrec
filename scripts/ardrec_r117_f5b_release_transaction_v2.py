"""ARDREC R117 F5B: verified source-only release transaction.

The production root entrypoint is NOT enabled in this module.
Public APIs support offline integration and crash injection.

A future trusted root executor must authenticate and pin this source,
the dual-authority verifier, the candidate and both public keys
before invoking installation. No VM or network operation exists here.
"""
from __future__ import annotations

import ctypes
from datetime import datetime
import fcntl
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import secrets
import stat
import zipfile

import ardrec_r117_f5b_dual_authority_v1 as gate
import ardrec_r117_release_core_v1 as core

PILOT_NAME = "r117-f4-ftp-pilot-root-v1"
RELEASE_NAME = "r117-f4-boot-release-v1"
ACTIVATION_NAME = "r117-f5b-activation-v1.json"
ACTIVATION_SCHEMA = "ARDREC-R117-F5B-ACTIVATION-v1"

MARKERS = {
    "prepared.once": b"PREPARED_NOT_PUBLISHED\n",
    "pilot-visible.once":
        b"PILOT_VISIBLE_RELEASE_PENDING\n",
    "release-visible.once":
        b"RELEASE_VISIBLE_INSPECTION_REQUIRED\n",
}

CHECKPOINTS = (
    "PREPARED",
    "PILOT_PUBLISHED",
    "RELEASE_PUBLISHED",
    "COMPLETION_DURABLE",
    "ACTIVATION_PUBLISHED",
)


class Stop(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return (
        json.dumps(
            obj, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False
        ) + "\n"
    ).encode("ascii")


def check_directory(path):
    info = path.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "UNTRUSTED_TRANSACTION_DIRECTORY"
    )


def check_root(root):
    need(
        isinstance(root, Path)
        and root.is_absolute()
        and root.resolve() == root,
        "TRANSACTION_ROOT_INVALID"
    )
    check_directory(root)


def sync_dir(folder):
    fd = os.open(
        folder,
        os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_once(path, raw):
    need(
        type(raw) is bytes
        and 0 < len(raw) <= 200000,
        "TRANSACTION_WRITE_INVALID"
    )
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def rename_noreplace(src, dst):
    """Linux renameat2: atomically reject existing destinations."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    need(function is not None, "RENAMEAT2_UNAVAILABLE")

    function.argtypes = (
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int

    oldfd = os.open(
        src.parent,
        os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    newfd = os.open(
        dst.parent,
        os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )

    try:
        result = function(
            oldfd, os.fsencode(src.name),
            newfd, os.fsencode(dst.name), 1
        )
        need(
            result == 0,
            "RELEASE_ATOMIC_PUBLISH_REJECTED_" +
            str(ctypes.get_errno())
        )
        os.fsync(newfd)
    finally:
        os.close(oldfd)
        os.close(newfd)


def directory_payload(folder, files):
    need(
        type(files) is dict
        and 0 < len(files) <= 64,
        "TRANSACTION_PAYLOAD_SCOPE"
    )

    folder.mkdir(mode=0o700)

    for name, raw in sorted(files.items()):
        need(
            type(name) is str
            and re.fullmatch(r"[a-zA-Z0-9_./-]+", name)
            and not name.startswith("/")
            and all(
                part not in ("", ".", "..")
                for part in name.split("/")
            ),
            "PAYLOAD_PATH_REJECTED"
        )

        relative = Path(name)
        destination = folder / relative

        for parent in reversed(
            destination.parent.parents
        ):
            if parent == folder:
                break

        destination.parent.mkdir(
            mode=0o700, parents=True, exist_ok=True
        )

        write_once(destination, raw)

    nested = sorted(
        (
            entry for entry in folder.rglob("*")
            if entry.is_dir()
        ),
        key=lambda entry: len(entry.parts),
        reverse=True,
    )

    for path in nested:
        check_directory(path)
        sync_dir(path)

    sync_dir(folder)


def read_exact(path, expected):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600,
            "RELEASE_FILE_METADATA_CHANGED"
        )

        actual = os.read(fd, len(expected) + 1)
        need(
            actual == expected,
            "RELEASE_FILE_BYTES_CHANGED_" + path.name
        )
        return actual
    finally:
        os.close(fd)


def audit_tree(folder, files, empty_dirs=()):
    check_directory(folder)

    expected_dirs = set(empty_dirs)

    for name in files:
        parts = name.split("/")
        expected_dirs.update(
            "/".join(parts[:index])
            for index in range(1, len(parts))
        )

    present_files = set()
    present_dirs = set()

    for item in folder.rglob("*"):
        relative = item.relative_to(folder).as_posix()

        if item.is_symlink():
            raise Stop("RELEASE_SYMLINK_DETECTED")

        if item.is_dir():
            present_dirs.add(relative)
            check_directory(item)
        else:
            present_files.add(relative)

    need(
        present_files == set(files)
        and present_dirs == expected_dirs,
        "RELEASE_TREE_INVENTORY_CHANGED"
    )

    for name, data in files.items():
        read_exact(folder / name, data)


def ensure_new_state(root):
    """Reject completed and interrupted releases without auto-recovery.

    A visible activation denotes a previously published release.
    Without activation, a previous transaction takes precedence
    over partially visible pilot/release directories.
    """
    activation = root / ACTIVATION_NAME

    need(
        not activation.exists() and not activation.is_symlink(),
        "RELEASE_ALREADY_PUBLISHED_" + ACTIVATION_NAME
    )

    need(
        not list(root.glob(".r117-f5b-transaction-*")),
        "PREVIOUS_RELEASE_TRANSACTION_PRESENT"
    )

    need(
        not list(root.glob(".r117-f5b-activation-pending-*")),
        "PENDING_ACTIVATION_REQUIRES_REVIEW"
    )

    for name in (PILOT_NAME, RELEASE_NAME):
        item = root / name

        need(
            not item.exists() and not item.is_symlink(),
            "RELEASE_ALREADY_PUBLISHED_" + name
        )


def install(
    root,
    candidate_raw,
    approval_raw,
    approval_signature,
    approval_public,
    revocation_raw,
    revocation_signature,
    revocation_public,
    *,
    head,
    candidate_sha,
    approval_pin,
    revocation_pin,
    now,
    checkpoint=None,
):
    """Verify two signatures, then publish a durable source-only release.

    Pins are injectable here for offline tests. A production root
    executor must use only hardcoded or independently pinned keys.
    Crash recovery is deliberately manual and fail closed.
    """
    need(
        isinstance(now, datetime)
        and now.tzinfo is not None,
        "INSTALL_TIME_INVALID"
    )

    # No filesystem write occurs before this verification.
    verified = gate.verify_release(
        candidate_raw,
        approval_raw,
        approval_signature,
        approval_public,
        revocation_raw,
        revocation_signature,
        revocation_public,
        now=now,
        head=head,
        candidate_sha=candidate_sha,
        approval_pin=approval_pin,
        revocation_pin=revocation_pin,
        historical=False,
    )

    need(
        verified["file_count_verified"] == 39
        and verified["source_count_verified"] == 36
        and verified["separate_authorities"] is True
        and verified["revoked"] is False
        and verified["p8"] == "NO-GO"
        and verified["boot_authorized"] is False,
        "VERIFIED_RELEASE_SCOPE_CHANGED"
    )

    check_root(root)

    with zipfile.ZipFile(BytesIO(candidate_raw)) as archive:
        members = {
            name: archive.read(name)
            for name in archive.namelist()
        }

    receipt_raw = gate.release_receipt(
        members, head=head
    )

    receipt = core.document(receipt_raw)
    need(
        receipt["pilot_manifest_sha256"] ==
            sha(members["manifest.json"])
        and receipt["authorized_to_boot"] is False,
        "RELEASE_RECEIPT_INCONSISTENT"
    )

    release_files = {
        "receipt.json": receipt_raw,
        "approval.json": approval_raw,
        "approval.sig": approval_signature,
    }

    lock_path = root / ".r117-f5b-install.lock"
    fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT |
        os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )

    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            "RELEASE_LOCK_METADATA_INVALID"
        )

        fcntl.flock(
            fd, fcntl.LOCK_EX | fcntl.LOCK_NB
        )

        ensure_new_state(root)

        token = secrets.token_hex(12)
        transaction = root / (
            ".r117-f5b-transaction-" + token
        )
        transaction.mkdir(mode=0o700)
        sync_dir(root)

        intent_raw = canonical({
            "schema": "ARDREC-R117-F5B-TRANSACTION-v1",
            "head": head,
            "candidate_sha256": candidate_sha,
            "approval_sha256": sha(approval_raw),
            "status": "SOURCE_INSTALL_ATTEMPT",
            "p8": "NO-GO",
        })

        write_once(
            transaction / "intent.json", intent_raw
        )

        directory_payload(
            transaction / "pilot", members
        )

        (transaction / "pilot" / "authority").mkdir(
            mode=0o700
        )
        sync_dir(transaction / "pilot" / "authority")
        sync_dir(transaction / "pilot")

        directory_payload(
            transaction / "release", release_files
        )

        sync_dir(transaction)
        write_once(
            transaction / "prepared.once",
            MARKERS["prepared.once"],
        )
        sync_dir(transaction)

        if checkpoint is not None:
            checkpoint("PREPARED")

        ensure_targets = (
            not (root / PILOT_NAME).exists()
            and not (root / RELEASE_NAME).exists()
        )
        need(
            ensure_targets,
            "RELEASE_TARGET_CHANGED"
        )

        rename_noreplace(
            transaction / "pilot",
            root / PILOT_NAME,
        )

        write_once(
            transaction / "pilot-visible.once",
            MARKERS["pilot-visible.once"],
        )
        sync_dir(transaction)

        if checkpoint is not None:
            checkpoint("PILOT_PUBLISHED")

        rename_noreplace(
            transaction / "release",
            root / RELEASE_NAME,
        )

        write_once(
            transaction / "release-visible.once",
            MARKERS["release-visible.once"],
        )
        sync_dir(transaction)

        if checkpoint is not None:
            checkpoint("RELEASE_PUBLISHED")

        audit_tree(
            root / PILOT_NAME,
            members,
            empty_dirs=("authority",),
        )
        audit_tree(
            root / RELEASE_NAME,
            release_files,
        )

        complete_raw = canonical({
            "schema": "ARDREC-R117-F5B-COMPLETE-v1",
            "head": head,
            "pilot_manifest_sha256":
                sha(members["manifest.json"]),
            "receipt_sha256": sha(receipt_raw),
            "approved_install": True,
            "boot_permit_issued": False,
            "network_connections": 0,
            "vm_starts": 0,
            "p8": "NO-GO",
        })

        write_once(
            transaction / "complete.json",
            complete_raw,
        )
        sync_dir(transaction)
        sync_dir(root)

        if checkpoint is not None:
            checkpoint("COMPLETION_DURABLE")

        activation_raw = canonical({
            "schema": ACTIVATION_SCHEMA,
            "head": head,
            "transaction": transaction.name,
            "candidate_sha256": candidate_sha,
            "approval_sha256": sha(approval_raw),
            "pilot_manifest_sha256":
                sha(members["manifest.json"]),
            "receipt_sha256": sha(receipt_raw),
            "complete_sha256": sha(complete_raw),
            "boot_authorized": False,
            "network_authorized": False,
            "p8": "NO-GO",
        })

        pending = root / (
            ".r117-f5b-activation-pending-" + token
        )
        write_once(pending, activation_raw)
        sync_dir(root)

        rename_noreplace(
            pending, root / ACTIVATION_NAME
        )

        read_exact(
            root / ACTIVATION_NAME,
            activation_raw,
        )

        if checkpoint is not None:
            checkpoint("ACTIVATION_PUBLISHED")

        return {
            "schema": "ARDREC-R117-F5B-INSTALL-v2",
            "head": head,
            "candidate_sha256": candidate_sha,
            "transaction": transaction.name,
            "activation_sha256": sha(activation_raw),
            "files_verified": len(members),
            "approved_install": True,
            "boot_authorized": False,
            "network_authorized": False,
            "p8": "NO-GO",
        }

    finally:
        os.close(fd)
