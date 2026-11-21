#!/usr/bin/env python3
"""ARDREC R117-F5D-A: Ed25519 and descriptor-based root file reader.

Source-only verification primitives. No privileged deployment,
release publication, boot, network access or operational authority.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
OPENSSL = "/usr/bin/openssl"

ROOT = Path("/var/lib/ardrec")
PILOT = ROOT / "r117-f4-ftp-pilot-root-v1"
RELEASE = ROOT / "r117-f4-boot-release-v1"

APPROVAL_PREFIX = (
    b"ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1\x00"
)
REVOCATION_PREFIX = (
    b"ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1\x00"
)
REVOCATION_SCHEMA = (
    "ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1"
)

ED25519_SPKI = bytes.fromhex(
    "302a300506032b6570032100"
)

FLAGS_DIR = (
    os.O_RDONLY | os.O_DIRECTORY |
    os.O_NOFOLLOW | os.O_CLOEXEC
)
FLAGS_FILE = (
    os.O_RDONLY | os.O_NOFOLLOW |
    os.O_CLOEXEC
)

class Stop(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Stop(reason)

def command(args):
    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        },
    )
    need(len(result.stdout) < 8192 and
         len(result.stderr) < 8192,
         "CRYPTO_COMMAND_OUTPUT_EXCESSIVE")
    return result

def exclusive(path, data):
    need(type(data) is bytes and
         0 < len(data) <= 8192,
         "CRYPTO_INPUT_SIZE_INVALID")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT |
        os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

def ed25519_verify(public_pem, message, signature):
    """Verify genuine Ed25519 using known-size private temporary files.

    Returns the raw 32-byte public identity only after verification.
    Never loads a private key or accepts stdin as signed message.
    """
    need(
        type(public_pem) is bytes
        and b"-----BEGIN PUBLIC KEY-----" in public_pem
        and len(public_pem) <= 8192
        and type(message) is bytes
        and 0 < len(message) <= 8192
        and type(signature) is bytes
        and len(signature) == 64,
        "ED25519_INPUT_INVALID",
    )

    with tempfile.TemporaryDirectory(
        prefix="ardrec-f5d-ed25519-"
    ) as temporary:
        folder = Path(temporary)
        key = folder / "public.pem"
        payload = folder / "message.bin"
        sig = folder / "signature.bin"

        exclusive(key, public_pem)
        exclusive(payload, message)
        exclusive(sig, signature)

        converted = command([
            OPENSSL, "pkey",
            "-pubin", "-in", str(key),
            "-outform", "DER",
        ])
        need(converted.returncode == 0,
             "PUBLIC_KEY_PARSE_FAILED")

        der = converted.stdout

        need(
            len(der) == 44
            and der.startswith(ED25519_SPKI),
            "PUBLIC_KEY_NOT_ED25519",
        )

        verified = command([
            OPENSSL, "pkeyutl",
            "-verify", "-rawin",
            "-pubin", "-inkey", str(key),
            "-sigfile", str(sig),
            "-in", str(payload),
        ])

        need(verified.returncode == 0,
             "ED25519_SIGNATURE_REJECTED")

        return der[-32:]

def utc(value):
    need(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
            value,
        ),
        "UTC_FORMAT_INVALID",
    )
    result = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )
    need(
        result.utcoffset().total_seconds() == 0,
        "NON_UTC_TIMESTAMP",
    )
    return result

def verify_statements(
    head, candidate_sha,
    approval_raw, approval_signature, approval_key,
    revocation_raw, revocation_signature, revocation_key,
    *, now, repo=REPO,
):
    """Verify two independently signed and narrowly scoped assertions.

    A successful result is cryptographic verification only, not
    installed-root attestation or permission to boot.
    """
    need(
        type(head) is str
        and re.fullmatch("[0-9a-f]{40}", head)
        and type(candidate_sha) is str
        and re.fullmatch("[0-9a-f]{64}", candidate_sha),
        "INVALID_RELEASE_IDENTITY",
    )

    need(
        isinstance(now, datetime)
        and now.tzinfo is not None
        and now.utcoffset().total_seconds() == 0,
        "VERIFY_TIME_NOT_UTC",
    )

    from importlib.util import (
        spec_from_file_location,
        module_from_spec,
    )

    path = repo / (
        "scripts/ardrec_p14_r117_f5b_root_stage.py"
    )

    need(path.is_file() and not path.is_symlink(),
         "F5B_SOURCE_NOT_AVAILABLE")

    spec = spec_from_file_location("ardrec_f5d_f5b", path)
    need(spec is not None and spec.loader is not None,
         "F5B_IMPORT_UNAVAILABLE")

    b = module_from_spec(spec)
    spec.loader.exec_module(b)

    try:
        approval = b.document(approval_raw)
        b.approval_fields(
            approval, head, candidate_sha, now,
            fresh=True,
        )
        revocation = b.document(revocation_raw)
    except (
        b.Stop, ValueError, TypeError, KeyError
    ) as error:
        raise Stop("SIGNED_DOCUMENT_INVALID") from error

    need(
        set(revocation) == {
            "schema", "head", "candidate_sha256",
            "issued_at", "valid_until", "revoked",
            "authority", "p8",
        }
        and revocation["schema"] == REVOCATION_SCHEMA
        and revocation["head"] == head
        and revocation["candidate_sha256"] ==
            candidate_sha
        and revocation["p8"] == "NO-GO"
        and revocation["revoked"] is False
        and type(revocation["authority"]) is str
        and len(revocation["authority"]) >= 3,
        "REVOCATION_STATEMENT_INVALID",
    )

    start = utc(revocation["issued_at"])
    finish = utc(revocation["valid_until"])

    need(
        start <= now < finish
        and start < finish
        and (finish - start).total_seconds() <= 90,
        "REVOCATION_ASSERTION_NOT_FRESH",
    )

    approval_identity = ed25519_verify(
        approval_key,
        APPROVAL_PREFIX + approval_raw,
        approval_signature,
    )

    revocation_identity = ed25519_verify(
        revocation_key,
        REVOCATION_PREFIX + revocation_raw,
        revocation_signature,
    )

    need(
        approval_identity != revocation_identity,
        "RELEASE_AND_REVOCATION_SAME_KEY",
    )

    return {
        "schema":
            "ARDREC-R117-F5D-A-CRYPTO-REVIEW-v1",
        "head": head,
        "candidate_sha256": candidate_sha,
        "approval_ed25519": "VERIFIED",
        "revocation_ed25519": "VERIFIED",
        "revoked": False,
        "separate_keys": True,
        "root_ownership_attested": False,
        "durability_attested": False,
        "boot_authorized": False,
        "network_authorized": False,
        "a6": "ND",
        "p8": "NO-GO",
    }

def check_dir(fd, uid):
    st = os.fstat(fd)
    need(
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == uid
        and stat.S_IMODE(st.st_mode) == 0o700,
        "DIRECTORY_OWNERSHIP_OR_MODE",
    )

def check_name(name):
    need(
        type(name) is str
        and name not in (".", "..")
        and re.fullmatch("[A-Za-z0-9_.-]+", name),
        "INVALID_TREE_COMPONENT",
    )

def read_tree_fd(
    root_fd, expected_files, *,
    uid=0, empty_dirs=(),
):
    """Read a sealed directory tree through openat-style operations.

    The caller must provide an already trusted directory descriptor.
    Operational root attestation must separately authenticate this
    descriptor and its ancestor chain.
    """
    need(
        type(expected_files) in (set, frozenset)
        and 0 < len(expected_files) <= 64,
        "EXPECTED_FILE_SET_INVALID",
    )

    files = set(expected_files)
    dirs = set(empty_dirs)

    for name in files | dirs:
        need(
            type(name) is str
            and not name.startswith("/")
            and len(name) <= 160,
            "TREE_PATH_OUT_OF_SCOPE",
        )
        parts = name.split("/")
        for component in parts:
            check_name(component)
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))

    need(not files.intersection(dirs),
         "TREE_FILE_DIRECTORY_COLLISION")

    check_dir(root_fd, uid)
    results = {}
    visited_dirs = set()

    def visit(fd, prefix):
        for item in sorted(os.listdir(fd)):
            check_name(item)
            rel = prefix + "/" + item if prefix else item

            if rel in dirs:
                child = os.open(
                    item, FLAGS_DIR, dir_fd=fd
                )
                try:
                    check_dir(child, uid)
                    visited_dirs.add(rel)
                    visit(child, rel)
                finally:
                    os.close(child)

            elif rel in files:
                child = os.open(
                    item, FLAGS_FILE, dir_fd=fd
                )
                try:
                    st = os.fstat(child)
                    need(
                        stat.S_ISREG(st.st_mode)
                        and st.st_uid == uid
                        and st.st_nlink == 1
                        and stat.S_IMODE(st.st_mode) == 0o600
                        and 0 < st.st_size <= 200000,
                        "FILE_OWNERSHIP_MODE_OR_LINK",
                    )

                    chunks = []
                    remaining = st.st_size

                    while remaining:
                        part = os.read(
                            child, min(remaining, 65536)
                        )
                        need(part, "SHORT_FILE_READ")
                        chunks.append(part)
                        remaining -= len(part)

                    end = os.fstat(child)

                    need(
                        (end.st_ino, end.st_dev,
                         end.st_size, end.st_mtime_ns,
                         end.st_ctime_ns) ==
                        (st.st_ino, st.st_dev,
                         st.st_size, st.st_mtime_ns,
                         st.st_ctime_ns),
                        "FILE_CHANGED_DURING_READ",
                    )

                    results[rel] = b"".join(chunks)
                finally:
                    os.close(child)
            else:
                raise Stop(
                    "UNEXPECTED_TREE_ENTRY_" + rel
                )

    visit(root_fd, "")

    need(
        set(results) == files
        and visited_dirs == dirs,
        "TREE_INCOMPLETE",
    )
    return results

def open_trusted_root(path):
    """Open a fixed root-owned F4 location without following symlinks.

    Not called by the offline CLI. Intended for integration in a
    separately authenticated root agent.
    """
    need(
        os.geteuid() == 0
        and path in (PILOT, RELEASE),
        "TRUSTED_ROOT_SCOPE_INVALID",
    )

    fd = os.open("/", FLAGS_DIR)

    try:
        for component in path.parts[1:]:
            check_name(component)
            child = os.open(
                component, FLAGS_DIR, dir_fd=fd
            )
            os.close(fd)
            fd = child

            st = os.fstat(fd)
            need(
                stat.S_ISDIR(st.st_mode)
                and st.st_uid == 0
                and not (st.st_mode & 0o022),
                "ROOT_ANCESTOR_UNTRUSTED",
            )

        check_dir(fd, 0)
        return fd

    except BaseException:
        os.close(fd)
        raise

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline", action="store_true",
        required=True,
    )
    parser.parse_args()

    try:
        need(
            os.geteuid() != 0,
            "OFFLINE_MUST_RUN_UNPRIVILEGED",
        )

        need(
            (REPO / "scripts/ardrec_p14_r117_f5c_transaction_closure.py").is_file(),
            "F5C_SOURCE_MISSING",
        )

        result = command([OPENSSL, "version"])
        need(
            result.returncode == 0,
            "OPENSSL_NOT_AVAILABLE",
        )

        print("R117_F5D_A_OFFLINE=PASS_SOURCE_ONLY")
        print("R117_F5D_A_CRYPTO=READY_FOR_TESTS")
        print("R117_F5D_A_ROOT_READER=READY_FOR_TESTS")
        print("R117_F5D_A_ROOT_INSTALLED=FALSE")
        print("R117_F5D_A_APPLY=BLOCKED_IN_F5B")
        print("R117_F5D_A_VM_STARTS=0")
        print("R117_F5D_A_NETWORK_CONNECTIONS=0")
        print("R117_F5D_A_A6=ND")
        print("R117_F5D_A_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, TypeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(
            "R117_F5D_A_STOP=" +
            type(error).__name__ + ":" +
            str(error)[:160]
        )
        print("R117_F5D_A_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
