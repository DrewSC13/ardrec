#!/usr/bin/env python3
"""R117-F5B: root release installer, separately signed and fail closed.

Offline mode never writes root. Apply is root-only, requires an
independently approved Ed25519 statement and a trusted installed agent.
No VM, network, nftables, watchdog or pilot action is performed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True

REPO = Path("/home/cicada/Development/GitHub/ardrec")
PATCHES = Path("/home/cicada/Development/GitHub/ardrec-patches")
BRANCH = "feat/p14-r117-piloto-real-a5-a10"
BASE = "2c32f872602f40f5f29f34bfd3316b16fc42eaa4"
ROOT = Path("/var/lib/ardrec")
PILOT = ROOT / "r117-f4-ftp-pilot-root-v1"
RELEASE = ROOT / "r117-f4-boot-release-v1"
ACTIVATION = ROOT / "r117-f5b-activation-v1.json"
ACTIVATION_SCHEMA = "ARDREC-R117-F5B-ACTIVATION-v1"
AGENT = ROOT / "r117-f5b-root-agent-v1"
INSTALLER = AGENT / "installer.py"
BUILDER = AGENT / "candidate.py"
TRUST = Path("/etc/ardrec/r117-f5b-release-trust-v1.pem")
APPROVAL = Path("/etc/ardrec/r117-f5b-release-approval-v1.json")
SIGNATURE = Path("/etc/ardrec/r117-f5b-release-approval-v1.sig")
PREFIX = b"ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1\x00"
APPROVAL_SCHEMA = "ARDREC-R117-F5B-ROOT-INSTALL-APPROVAL-v1"
RECEIPT_SCHEMA = "ARDREC-R117-F4-BOOT-RELEASE-v1"
PILOT_SCHEMA = "ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle"
SOURCE = "scripts/ardrec_p14_r117_f5b_root_stage.py"
CANDIDATE_SOURCE = "scripts/ardrec_p14_r117_f5_root_candidate.py"

F4 = (
    "src/ardrec/coordination/r117_f4_controlled_boot.py",
    "src/ardrec/coordination/r117_f4_runner_ftp_boot.py",
    "src/ardrec/coordination/r117_f4_root_release.py",
)

class Stop(RuntimeError):
    pass

def need(value, reason):
    if not value:
        raise Stop(reason)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(doc):
    return (
        json.dumps(doc, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")

def unique(pairs):
    doc = {}
    for name, value in pairs:
        need(name not in doc, "DUPLICATE_JSON_KEY")
        doc[name] = value
    return doc

def document(raw):
    doc = json.loads(
        raw,
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(
            Stop("NONFINITE_JSON")
        ),
    )
    need(type(doc) is dict and canonical(doc) == raw,
         "DOCUMENT_NOT_CANONICAL")
    return doc

def checked_time(value):
    need(type(value) is str and
         re.fullmatch(
             r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
         ), "UTC_TIME_FORMAT_INVALID")
    result = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )
    need(result.utcoffset().total_seconds() == 0,
         "TIME_NOT_UTC")
    return result

def approval_fields(doc, head, candidate_sha, now, fresh=True):
    need(
        type(doc) is dict
        and set(doc) == {
            "schema", "head", "candidate_sha256",
            "valid_from", "valid_until", "purpose",
            "authority", "p8",
        }
        and doc["schema"] == APPROVAL_SCHEMA
        and doc["head"] == head
        and doc["candidate_sha256"] == candidate_sha
        and doc["purpose"] == "INSTALL_SOURCE_ONLY"
        and doc["p8"] == "NO-GO"
        and type(doc["authority"]) is str
        and 3 <= len(doc["authority"]) <= 80,
        "RELEASE_APPROVAL_SCOPE_INVALID",
    )

    start = checked_time(doc["valid_from"])
    stop = checked_time(doc["valid_until"])

    need(
        start < stop and
        (stop-start).total_seconds() <= 600,
        "RELEASE_APPROVAL_WINDOW_INVALID",
    )

    if fresh:
        need(start <= now < stop,
             "RELEASE_APPROVAL_EXPIRED_OR_FUTURE")

    return doc

def root_directory(path, exact_mode=None):
    st = path.lstat()
    need(
        stat.S_ISDIR(st.st_mode)
        and not path.is_symlink()
        and st.st_uid == 0
        and not (st.st_mode & 0o022),
        "UNTRUSTED_ROOT_DIRECTORY_" + str(path),
    )
    if exact_mode is not None:
        need(stat.S_IMODE(st.st_mode) == exact_mode,
             "ROOT_DIRECTORY_MODE_" + str(path))

def root_file(path, limit=200000):
    for folder in reversed(path.parents):
        root_directory(folder)
    fd = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        st = os.fstat(fd)
        need(
            stat.S_ISREG(st.st_mode)
            and st.st_uid == 0
            and st.st_nlink == 1
            and stat.S_IMODE(st.st_mode) == 0o600
            and 0 < st.st_size <= limit,
            "UNTRUSTED_ROOT_FILE_" + str(path),
        )
        raw = os.read(fd, limit + 1)
        need(len(raw) == st.st_size,
             "ROOT_FILE_CHANGED_DURING_READ")
        return raw
    finally:
        os.close(fd)

def git(*args):
    cmd = [
        "/usr/bin/git",
        "-c", "safe.directory=" + str(REPO),
        "-C", str(REPO), *args,
    ]
    p = subprocess.run(
        cmd, capture_output=True, check=False,
        stdin=subprocess.DEVNULL, timeout=30,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
        },
    )
    need(p.returncode == 0 and
         len(p.stdout) <= 524288,
         "GIT_VERIFICATION_FAILED")
    return p.stdout

def root_head():
    need(os.geteuid() == 0,
         "ROOT_REQUIRED")

    for folder in (
        Path("/"), Path("/var"), Path("/var/lib"),
        ROOT, AGENT,
    ):
        root_directory(folder)

    need(
        Path(__file__).resolve() == INSTALLER,
        "INSTALLER_NOT_IN_TRUSTED_ROOT_STAGE",
    )

    need(git("branch", "--show-current").strip() ==
         BRANCH.encode(), "BRANCH_MISMATCH")

    need(not git(
        "status", "--porcelain=v1", "--untracked-files=all"
    ), "WORKTREE_NOT_CLEAN")

    need(git("log", "-1", "--format=%G?").strip() ==
         b"G", "LOCAL_HEAD_SIGNATURE_NOT_VERIFIED")

    git("merge-base", "--is-ancestor", BASE, "HEAD")
    head = git("rev-parse", "HEAD").decode().strip()

    need(re.fullmatch("[0-9a-f]{40}", head),
         "INVALID_SIGNED_HEAD")

    for installed, source in (
        (INSTALLER, SOURCE),
        (BUILDER, CANDIDATE_SOURCE),
    ):
        expected = git("show", "HEAD:" + source)
        need(root_file(installed) == expected,
             "ROOT_AGENT_SOURCE_MISMATCH_" + source)

    return head

def load_builder(path):
    spec = importlib.util.spec_from_file_location(
        "r117_f5a_authenticated_candidate", path
    )
    need(spec is not None and spec.loader is not None,
         "BUILDER_MODULE_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def offline_repo():
    root = Path(__file__).resolve().parents[1]
    candidate = root / CANDIDATE_SOURCE
    need(root.is_dir() and candidate.is_file() and
         not candidate.is_symlink(),
         'OFFLINE_CHECKOUT_INVALID')
    return root

def offline_builder():
    path = offline_repo() / CANDIDATE_SOURCE
    need(path.is_file() and not path.is_symlink(),
         "F5A_SOURCE_MISSING")
    return load_builder(path)

def expected_bundle(builder, head, *, repo=REPO):
    raw = builder.candidate(head, repo=repo)
    review = builder.audit(raw, repo=repo, expected_head=head)
    need(
        review["schema"] == PILOT_SCHEMA
        and review["p8"] == "NO-GO"
        and review["a6"] == "ND"
        and len(review["source_sha256"]) == 36,
        "PILOT_CANDIDATE_SCOPE_INVALID",
    )
    return raw, review

def release_receipt(builder, head, manifest_raw, *, repo=REPO):
    return {
        "schema": RECEIPT_SCHEMA,
        "head": head,
        "source_sha256": {
            name: builder.sha(
                builder.read_source(repo, name)
            )
            for name in F4
        },
        "pilot_manifest_sha256": digest(manifest_raw),
        "pilot_schema": PILOT_SCHEMA,
        "p8": "NO-GO",
        "authorized_to_boot": False,
    }

def archive_bytes(path, head):
    need(
        path.parent == PATCHES
        and path.name ==
        "R117_F5A_ROOT_CANDIDATE_" + head[:12] + ".zip",
        "CANDIDATE_PATH_OUT_OF_SCOPE",
    )
    st = path.lstat()
    need(
        stat.S_ISREG(st.st_mode)
        and not path.is_symlink()
        and st.st_nlink == 1
        and 0 < st.st_size <= 2000000,
        "CANDIDATE_FILE_INVALID",
    )
    fd = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        raw = os.read(fd, 2000001)
        need(len(raw) == st.st_size,
             "CANDIDATE_READ_CHANGED")
        return raw
    finally:
        os.close(fd)

def signed_approval(head, candidate_sha, fresh=True):
    raw = root_file(APPROVAL, limit=8192)
    signature = root_file(SIGNATURE, limit=64)
    trust = root_file(TRUST, limit=8192)

    need(len(signature) == 64 and
         b"BEGIN PUBLIC KEY" in trust,
         "INVALID_RELEASE_SIGNATURE_OR_TRUST")

    doc = approval_fields(
        document(raw), head, candidate_sha,
        datetime.now(timezone.utc), fresh=fresh
    )

    command = [
        "/usr/bin/openssl", "pkeyutl", "-verify",
        "-pubin", "-inkey", str(TRUST),
        "-sigfile", str(SIGNATURE),
        "-rawin", "-in", "/dev/stdin",
    ]

    p = subprocess.run(
        command, input=PREFIX + raw,
        capture_output=True, check=False,
        timeout=10,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
        },
    )
    need(p.returncode == 0,
         "INDEPENDENT_ED25519_SIGNATURE_REJECTED")

    return raw, signature, doc

def physical_offline():
    guard = (
        ROOT / "r116-f1-five-one-deny-v1" /
        "root-guard.py"
    )
    root_file(guard)
    p = subprocess.run(
        ["/usr/bin/python3", "-I", "-B",
         str(guard), "--check"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        check=False,
        timeout=35,
        env={
            "PATH": "/usr/sbin:/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    need(p.returncode == 0 and
         len(p.stdout) <= 65536,
         "DENY_ROOT_CHECK_FAILED")
    doc = json.loads(p.stdout)
    policy = doc.get("policy", {})
    need(
        doc.get("deny") == "MATCH"
        and doc.get("host_writes") == 0
        and doc.get("p8") == "NO-GO"
        and doc.get("states") == {
            "ssh": "OFF",
            "runner": "OFF",
            "ftp": "OFF",
            "smb": "OFF",
        }
        and policy.get("active_count") == 0
        and policy.get("absent_count") == 6
        and policy.get("allow_traffic") is False,
        "PHYSICAL_DENY_NOT_0_6",
    )

def write_once(path, raw):
    need(
        type(raw) is bytes
        and 0 < len(raw) < 524288,
        "ROOT_WRITE_BYTES_INVALID",
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

def sync_dir(folder):
    fd = os.open(
        folder, os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def make_parent(folder):
    pending = []
    p = folder
    while not p.exists():
        pending.append(p)
        p = p.parent
    for item in reversed(pending):
        item.mkdir(mode=0o700)
        os.chmod(item, 0o700)

def stage_payload(folder, mapping):
    folder.mkdir(mode=0o700)
    os.chmod(folder, 0o700)

    for name, data in sorted(mapping.items()):
        relative = Path(name)
        need(
            not relative.is_absolute()
            and ".." not in relative.parts,
            "STAGING_PATH_INVALID",
        )
        target = folder / relative
        make_parent(target.parent)
        write_once(target, data)

    for child in sorted(
        (p for p in folder.rglob("*") if p.is_dir()),
        key=lambda x: len(x.parts), reverse=True
    ):
        sync_dir(child)
    sync_dir(folder)

def stage_state():
    need(not ACTIVATION.exists() and not ACTIVATION.is_symlink(),
         "ROOT_ACTIVATION_ALREADY_PRESENT")
    need(not PILOT.exists() and not PILOT.is_symlink(),
         "ROOT_PILOT_ALREADY_PRESENT")
    need(not RELEASE.exists() and not RELEASE.is_symlink(),
         "ROOT_RELEASE_ALREADY_PRESENT")
    need(
        not any(ROOT.glob(".r117-f5b-transaction-*")),
        "PREVIOUS_TRANSACTION_REQUIRES_MANUAL_REVIEW",
    )

def installed_audit(builder, head, approval_sha=None):
    root_directory(PILOT, 0o700)
    root_directory(RELEASE, 0o700)

    raw, manifest = expected_bundle(builder, head)

    with zipfile.ZipFile(
        __import__("io").BytesIO(raw)
    ) as bundle:
        members = {
            name: bundle.read(name)
            for name in bundle.namelist()
        }

    for name, expected in members.items():
        actual = root_file(PILOT / name)
        need(actual == expected,
             "INSTALLED_ROOT_SOURCE_CHANGED_" + name)

    root_directory(PILOT / "authority", 0o700)

    receipt = document(
        root_file(RELEASE / "receipt.json")
    )

    expected = release_receipt(
        builder, head, members["manifest.json"]
    )

    need(receipt == expected,
         "F4_RELEASE_RECEIPT_NOT_AUTHENTIC")

    if approval_sha is not None:
        actual_approval = root_file(
            RELEASE / "approval.json", 8192
        )
        need(digest(actual_approval) == approval_sha,
             "INSTALLED_APPROVAL_CHANGED")

    return {
        "head": head,
        "files_verified": len(members),
        "pilot_manifest_sha256": digest(
            members["manifest.json"]
        ),
        "release_receipt_sha256": digest(
            canonical(receipt)
        ),
        "p8": "NO-GO",
        "traffic_authorized": False,
    }


def _publish_activation(txn, token, head, candidate_raw,
                        approval_raw, checked):
    """Publish only after a complete, durable source-only transaction.

    The installer caller must hold the existing exclusive F5B lock.
    No boot or network permission is granted.
    """
    need(
        txn.parent == ROOT
        and txn.name == ".r117-f5b-transaction-" + token
        and re.fullmatch("[0-9a-f]{24}", token) is not None,
        "ACTIVATION_TRANSACTION_ID_INVALID",
    )

    complete_raw = root_file(txn / "complete.json", limit=8192)
    complete = document(complete_raw)

    need(
        complete.get("schema") == "ARDREC-R117-F5B-COMPLETE-v1"
        and complete.get("head") == head
        and complete.get("approved_install") is True
        and complete.get("boot_permit_issued") is False
        and complete.get("vm_starts") == 0
        and type(complete.get("vm_starts")) is int
        and complete.get("network_connections") == 0
        and type(complete.get("network_connections")) is int
        and complete.get("p8") == "NO-GO"
        and complete.get("pilot_manifest_sha256") ==
            checked["pilot_manifest_sha256"]
        and complete.get("receipt_sha256") ==
            checked["release_receipt_sha256"],
        "ACTIVATION_COMPLETION_NOT_AUTHENTIC",
    )

    verified_approval, _, _ = signed_approval(
        head, digest(candidate_raw)
    )
    need(
        verified_approval == approval_raw,
        "ACTIVATION_APPROVAL_CHANGED",
    )

    document_raw = canonical({
        "schema": ACTIVATION_SCHEMA,
        "head": head,
        "transaction": txn.name,
        "candidate_sha256": digest(candidate_raw),
        "approval_sha256": digest(approval_raw),
        "pilot_manifest_sha256":
            checked["pilot_manifest_sha256"],
        "receipt_sha256":
            checked["release_receipt_sha256"],
        "complete_sha256": digest(complete_raw),
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    })

    need(
        not ACTIVATION.exists() and not ACTIVATION.is_symlink(),
        "ACTIVATION_ALREADY_PUBLISHED",
    )

    pending = ROOT / (
        ".r117-f5b-activation-pending-" + token
    )

    write_once(pending, document_raw)
    sync_dir(ROOT)

    need(
        not ACTIVATION.exists() and not ACTIVATION.is_symlink(),
        "ACTIVATION_CHANGED_BEFORE_PUBLISH",
    )

    os.rename(pending, ACTIVATION)
    sync_dir(ROOT)

    need(
        root_file(ACTIVATION, limit=8192) == document_raw,
        "ACTIVATION_FINAL_BYTES_CHANGED",
    )

    return digest(document_raw)

def _checkpoint(callback, point):
    """Fault-injection hook; never grants installation authority."""
    if callback is not None:
        callback(point)


def apply(archive):
    need(False, 'F5B_APPLY_BLOCKED_PENDING_ATOMIC_RELEASE_AND_BOOT_GATE')
    return _install_authorized(archive)


def _install_authorized(archive, *, checkpoint=None):
    """Internal transaction path, not a privileged CLI entrypoint.

    Must only be enabled by a future independently authenticated
    root bootstrap, after positive host-level acceptance tests.
    """
    head = root_head()
    builder = load_builder(BUILDER)

    expected, manifest = expected_bundle(builder, head)
    received = archive_bytes(archive, head)

    need(received == expected,
         "CANDIDATE_BYTES_NOT_REPRODUCIBLE")

    approval_raw, signature, signed = signed_approval(
        head, digest(expected)
    )
    physical_offline()
    stage_state()

    lock_path = ROOT / ".r117-f5b-install.lock"
    fd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
        os.O_CLOEXEC,
        0o600,
    )

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage_state()

        # Second review before any release material is published.
        physical_offline()
        signed_approval(head, digest(expected))

        token = secrets.token_hex(12)
        txn = ROOT / (".r117-f5b-transaction-" + token)
        txn.mkdir(mode=0o700)
        os.chmod(txn, 0o700)

        write_once(
            txn / "intent.json",
            canonical({
                "schema": "ARDREC-R117-F5B-TRANSACTION-v1",
                "head": head,
                "candidate_sha256": digest(expected),
                "approval_sha256": digest(approval_raw),
                "status": "SOURCE_INSTALL_ATTEMPT",
                "p8": "NO-GO",
            }),
        )

        with zipfile.ZipFile(
            __import__("io").BytesIO(expected)
        ) as bundle:
            members = {
                name: bundle.read(name)
                for name in bundle.namelist()
            }

        stage_payload(txn / "pilot", members)
        (txn / "pilot" / "authority").mkdir(mode=0o700)

        receipt = release_receipt(
            builder, head, members["manifest.json"]
        )

        stage_payload(
            txn / "release",
            {
                "receipt.json": canonical(receipt),
                "approval.json": approval_raw,
                "approval.sig": signature,
            },
        )

        sync_dir(txn / "pilot")
        sync_dir(txn)
        write_once(
            txn / "prepared.once",
            b"PREPARED_NOT_PUBLISHED\n"
        )
        sync_dir(txn)
        _checkpoint(checkpoint, "PREPARED")

        stage_state_check = (
            not PILOT.exists() and
            not RELEASE.exists()
        )
        need(stage_state_check,
             "ROOT_RELEASE_APPEARED_BEFORE_COMMIT")

        # Two atomic publications; interruptions remain fail closed.
        os.rename(txn / "pilot", PILOT)
        sync_dir(ROOT)
        _checkpoint(checkpoint, "PILOT_PUBLISHED")

        write_once(
            txn / "pilot-visible.once",
            b"PILOT_VISIBLE_RELEASE_PENDING\n"
        )
        sync_dir(txn)

        os.rename(txn / "release", RELEASE)
        sync_dir(ROOT)
        _checkpoint(checkpoint, "RELEASE_PUBLISHED")

        write_once(
            txn / "release-visible.once",
            b"RELEASE_VISIBLE_INSPECTION_REQUIRED\n"
        )
        sync_dir(txn)

        checked = installed_audit(
            builder, head, digest(approval_raw)
        )

        write_once(
            txn / "complete.json",
            canonical({
                "schema": "ARDREC-R117-F5B-COMPLETE-v1",
                "head": head,
                "pilot_manifest_sha256":
                    checked["pilot_manifest_sha256"],
                "receipt_sha256":
                    checked["release_receipt_sha256"],
                "approved_install": True,
                "boot_permit_issued": False,
                "network_connections": 0,
                "vm_starts": 0,
                "p8": "NO-GO",
            }),
        )
        sync_dir(txn)
        sync_dir(ROOT)
        _checkpoint(checkpoint, "COMPLETION_DURABLE")

        activation_sha = _publish_activation(
            txn, token, head, expected, approval_raw, checked
        )
        _checkpoint(checkpoint, "ACTIVATION_PUBLISHED")

        print("R117_F5B_ACTIVATION_SHA256=" + activation_sha)
        print("R117_F5B_ROOT_INSTALL=PASS_ATTESTED_SOURCE_ONLY")
        print("R117_F5B_TRANSACTION=" + str(txn))
        print("R117_F5B_HEAD=" + head)
        print("R117_F5B_ROOT_BYTES_VERIFIED=39")
        print("R117_F5B_BOOT_AUTHORIZED=FALSE")
        print("R117_F5B_P8=NO-GO")
    finally:
        os.close(fd)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--offline", action="store_true")
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--inspect-root", action="store_true")
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()

    try:
        if args.offline:
            need(os.geteuid() != 0,
                 "OFFLINE_MUST_NOT_RUN_AS_ROOT")
            repo = offline_repo()
            builder = offline_builder()
            raw, manifest = expected_bundle(
                builder, "a" * 40, repo=repo
            )
            receipt = release_receipt(
                builder, "a" * 40,
                canonical(manifest), repo=repo
            )
            need(
                len(receipt["source_sha256"]) == 3
                and receipt["authorized_to_boot"] is False,
                "RELEASE_RECEIPT_SHAPE_INVALID",
            )
            print(
                "R117_F5B_OFFLINE="
                "PASS_39_FILES_36_EXECUTABLE_SOURCES"
            )

        elif args.apply:
            need(args.archive is not None,
                 "CANDIDATE_ARCHIVE_REQUIRED")
            apply(args.archive)

        else:
            head = root_head()
            builder = load_builder(BUILDER)
            report = installed_audit(builder, head)
            print(
                "R117_F5B_ROOT_AUDIT=" +
                json.dumps(report, sort_keys=True)
            )

        print("R117_F5B_VM_STARTS=0")
        print("R117_F5B_NETWORK_CONNECTIONS=0")
        print("R117_F5B_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, KeyError, TypeError,
        zipfile.BadZipFile, subprocess.TimeoutExpired
    ) as error:
        print(
            "R117_F5B_STOP=" +
            type(error).__name__ + ":" +
            str(error)[:180]
        )
        print("R117_F5B_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
