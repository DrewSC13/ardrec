"""ARDREC R117 F5B V2: privileged, independently pinned source installer.

Requires a root-owned module package, authenticated candidate, separate
Ed25519 approval and nonrevocation, physical R116 deny and explicit consent.

Only SOURCE_ONLY publication. No boot/network/VM operations.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path("/var/lib/ardrec")
ENGINE = ROOT / "r117-f5b-release-executor-v3"
SELF = ENGINE / "executor.py"

PREFLIGHT = ROOT / "r117-f5b-root-preflight-v2.py"

HEAD = "197785a38bf166ec0b4c8d3ae17346d1fa217265"
CANDIDATE_SHA = (
    "5ef729690589497c787f34e99dba8fefea798459fc6c10a2d144a64a71cb2bf7"
)

CANDIDATE = Path(
    "/home/cicada/Development/GitHub/ardrec-patches/"
    "R117_F5A_ROOT_CANDIDATE_197785a38bf1_V3.zip"
)

TRUST_APPROVAL = Path(
    "/etc/ardrec/r117-authorities-v3/approval-public.pem"
)
TRUST_REVOCATION = Path(
    "/etc/ardrec/r117-authorities-v3/revocation-public.pem"
)

APPROVAL_PIN = (
    "304c3409f9d074f2ab68881622de9129ab41ee1e1652e8a0ee102211637159d8"
)
REVOCATION_PIN = (
    "4c32a558cf5b4c6032234ee91a457f203a8dd3472141a29906d6fb0b775a3509"
)

APPROVAL_LEDGER = (
    ROOT / ".r117-f5b-release-authorization-ledger-v3.json"
)
EVENT_LOG = ROOT / ".r117-f5b-release-publication-events-v3.jsonl"

REVOCATION = Path(
    "/etc/ardrec/r117-f5b-release-revocation-v1.json"
)
REVOCATION_SIG = Path(
    "/etc/ardrec/r117-f5b-release-revocation-v1.sig"
)

MODULES = {
    "executor.py",
    "ardrec_r117_release_core_v1.py",
    "ardrec_r117_f5b_dual_authority_v1.py",
    "ardrec_r117_f5b_release_transaction_v2.py",
}


class Stop(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(doc):
    return (
        json.dumps(
            doc, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ) + "\n"
    ).encode("ascii")


def root_dir(path, exact=None):
    info = path.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and not (info.st_mode & 0o022),
        "UNTRUSTED_ROOT_DIRECTORY",
    )
    if exact is not None:
        need(
            stat.S_IMODE(info.st_mode) == exact,
            "ROOT_DIRECTORY_MODE_INVALID",
        )


def secure_root_file(path, limit=200000):
    for parent in reversed(path.parents):
        root_dir(parent)

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= limit,
            "ROOT_FILE_INVALID_" + path.name,
        )

        raw = os.read(fd, limit + 1)
        need(len(raw) == info.st_size, "ROOT_FILE_READ_CHANGED")
        return raw
    finally:
        os.close(fd)


def input_file(path, maximum):
    need(
        path.is_absolute(),
        "SIGNED_INPUT_MUST_BE_ABSOLUTE",
    )

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not info.st_mode & 0o022
            and 0 < info.st_size <= maximum,
            "SIGNED_INPUT_METADATA_INVALID",
        )
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size, "SIGNED_INPUT_CHANGED")
        return raw
    finally:
        os.close(fd)


def check_package():
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    need(
        Path(__file__).absolute() == SELF,
        "UNTRUSTED_EXECUTOR_LOCATION",
    )

    root_dir(ROOT, 0o700)
    root_dir(ENGINE, 0o700)

    manifest = json.loads(
        secure_root_file(ENGINE / "manifest.json", 8192)
    )

    need(
        manifest.get("schema") ==
            "ARDREC-R117-F5B-ROOT-EXECUTOR-v3"
        and manifest.get("candidate_head") == HEAD
        and manifest.get("candidate_sha256") == CANDIDATE_SHA
        and manifest.get("p8") == "NO-GO"
        and type(manifest.get("files")) is dict
        and set(manifest["files"]) == MODULES,
        "ROOT_EXECUTOR_MANIFEST_INVALID",
    )

    need(
        set(path.name for path in ENGINE.iterdir()) ==
        MODULES | {"manifest.json"},
        "ROOT_EXECUTOR_INVENTORY_CHANGED",
    )

    for name, expected in manifest["files"].items():
        need(
            re.fullmatch("[0-9a-f]{64}", expected) is not None,
            "ROOT_EXECUTOR_PIN_INVALID",
        )
        need(
            sha(secure_root_file(ENGINE / name)) == expected,
            "ROOT_EXECUTOR_MODULE_CHANGED_" + name,
        )

    need(
        sha(secure_root_file(
            ROOT / "r117-f5b-root-agent-v1" /
            "ardrec_r117_release_core_v1.py"
        )) ==
        manifest["files"]["ardrec_r117_release_core_v1.py"],
        "INSTALLED_CORE_NOT_IDENTICAL",
    )

    for location, expected in (
        (TRUST_APPROVAL, APPROVAL_PIN),
        (TRUST_REVOCATION, REVOCATION_PIN),
    ):
        need(
            sha(secure_root_file(location, 4096)) == expected,
            "ROOT_RELEASE_AUTHORITY_CHANGED",
        )

    return manifest


def check_physical_deny():
    result = subprocess.run(
        [
            "/usr/bin/python3", "-I", "-B",
            str(PREFLIGHT), "--root",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=45,
        env={"PATH": "/usr/sbin:/usr/bin:/bin",
             "LC_ALL": "C"},
    )

    need(
        result.returncode == 0
        and b"R117_F5B_ROOT_PREFLIGHT=PASS_READ_ONLY"
            in result.stdout
        and b"R117_P8=NO-GO" in result.stdout,
        "ROOT_PHYSICAL_PREFLIGHT_REJECTED",
    )


def load_verified_modules():
    # Python -I excludes user PYTHONPATH; all local modules are
    # first verified and then loaded from root-owned directory.
    sys.path.insert(0, str(ENGINE))

    import ardrec_r117_release_core_v1 as core
    import ardrec_r117_f5b_dual_authority_v1 as gate
    import ardrec_r117_f5b_release_transaction_v2 as txn

    return core, gate, txn


def write_once(path, raw):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )

    with os.fdopen(fd, "wb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())

    fd = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY |
        os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(args):
    check_package()
    check_physical_deny()

    need(
        args.i_authorize_source_only_release is True,
        "EXPLICIT_SOURCE_ONLY_CONSENT_REQUIRED",
    )

    need(
        not APPROVAL_LEDGER.exists()
        and not APPROVAL_LEDGER.is_symlink(),
        "PREVIOUS_AUTHORIZATION_LEDGER_REQUIRES_REVIEW",
    )
    need(
        not EVENT_LOG.exists()
        and not EVENT_LOG.is_symlink(),
        "PREVIOUS_EVENT_LOG_REQUIRES_REVIEW",
    )

    for location in (REVOCATION, REVOCATION_SIG):
        need(
            not location.exists() and not location.is_symlink(),
            "ROOT_REVOCATION_STATUS_ALREADY_PRESENT",
        )

    core, gate, txn = load_verified_modules()

    candidate = input_file(CANDIDATE, 2_000_000)
    need(
        sha(candidate) == CANDIDATE_SHA,
        "SIGNED_CANDIDATE_BYTES_CHANGED",
    )

    approval = input_file(args.approval, 8192)
    approval_sig = input_file(args.approval_signature, 64)
    revocation = input_file(args.revocation, 8192)
    revocation_sig = input_file(args.revocation_signature, 64)

    approval_public = secure_root_file(TRUST_APPROVAL, 4096)
    revocation_public = secure_root_file(TRUST_REVOCATION, 4096)

    now = datetime.now(timezone.utc)

    # No write above this line.
    result = gate.verify_release(
        candidate,
        approval,
        approval_sig,
        approval_public,
        revocation,
        revocation_sig,
        revocation_public,
        head=HEAD,
        candidate_sha=CANDIDATE_SHA,
        approval_pin=APPROVAL_PIN,
        revocation_pin=REVOCATION_PIN,
        now=now,
        historical=False,
    )

    need(
        result["file_count_verified"] == 39
        and result["source_count_verified"] == 36
        and result["separate_authorities"] is True
        and result["revoked"] is False
        and result["boot_authorized"] is False
        and result["network_authorized"] is False,
        "RELEASE_SIGNATURE_SCOPE_CHANGED",
    )

    # Durable, exclusive, nonreusable local authorization.
    # Crash after this point requires manual reconciliation.
    record = canonical({
        "schema": "ARDREC-R117-F5B-AUTHORIZATION-LEDGER-v3",
        "head": HEAD,
        "candidate_sha256": CANDIDATE_SHA,
        "approval_sha256": sha(approval),
        "approval_signature_sha256": sha(approval_sig),
        "revocation_sha256": sha(revocation),
        "revocation_signature_sha256": sha(revocation_sig),
        "admitted_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    })

    write_once(APPROVAL_LEDGER, record)

    # F4 reads this separately signed, short-lived status.
    # Any partial publication remains fail-closed.
    write_once(REVOCATION, revocation)
    write_once(REVOCATION_SIG, revocation_sig)

    def checkpoint(phase):
        current = datetime.now(timezone.utc)

        gate.verify_release(
            candidate, approval, approval_sig,
            approval_public, revocation, revocation_sig,
            revocation_public,
            head=HEAD,
            candidate_sha=CANDIDATE_SHA,
            approval_pin=APPROVAL_PIN,
            revocation_pin=REVOCATION_PIN,
            now=current,
            historical=False,
        )

        entry = canonical({
            "phase": phase,
            "at": current.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "head": HEAD,
            "candidate_sha256": CANDIDATE_SHA,
            "approval_sha256": sha(approval),
            "revocation_sha256": sha(revocation),
            "p8": "NO-GO",
        })

        fd = os.open(
            EVENT_LOG,
            os.O_WRONLY | os.O_APPEND |
            os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(fd, entry)
            os.fsync(fd)
        finally:
            os.close(fd)

    installed = txn.install(
        ROOT,
        candidate,
        approval,
        approval_sig,
        approval_public,
        revocation,
        revocation_sig,
        revocation_public,
        head=HEAD,
        candidate_sha=CANDIDATE_SHA,
        approval_pin=APPROVAL_PIN,
        revocation_pin=REVOCATION_PIN,
        now=datetime.now(timezone.utc),
        checkpoint=checkpoint,
    )

    print(
        "R117_F5B_ROOT_INSTALL_REPORT=" +
        json.dumps(installed, sort_keys=True)
    )
    print("R117_F5B_ROOT_RELEASE=INSTALLED_SOURCE_ONLY")
    print("R117_F5B_BOOT_AUTHORIZED=FALSE")
    print("R117_F5B_NETWORK_AUTHORIZED=FALSE")
    print("R117_P8=NO-GO")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--root-inspect", action="store_true")
    modes.add_argument("--root-apply-source-only", action="store_true")

    for name in (
        "approval", "approval_signature",
        "revocation", "revocation_signature",
    ):
        parser.add_argument(
            "--" + name.replace("_", "-"),
            type=Path,
        )

    parser.add_argument(
        "--i-authorize-source-only-release",
        action="store_true",
    )

    args = parser.parse_args()

    try:
        check_package()

        if args.root_inspect:
            check_physical_deny()

            # V2 physical preflight checks the R116 deny.
            # V3 additionally authenticates its OWN candidate.
            core, gate, txn = load_verified_modules()
            raw = input_file(CANDIDATE, 2_000_000)

            need(
                sha(raw) == CANDIDATE_SHA,
                "V3_CANDIDATE_BYTES_CHANGED",
            )

            inspected = core.verify_candidate(
                raw,
                head=HEAD,
                expected_sha=CANDIDATE_SHA,
            )

            need(
                inspected["file_count"] == 39
                and inspected["source_count"] == 36,
                "V3_CANDIDATE_SCOPE_CHANGED",
            )

            print("R117_V3_CANDIDATE=PASS_EXACT_39")
            print("R117_V3_AUTHORITIES=PASS_ROOT_PINS")
            print("R117_ROOT_RELEASE_EXECUTOR=PASS_READ_ONLY")
            print("R117_ROOT_RELEASE=NOT_INSTALLED")
        else:
            need(
                all(
                    getattr(args, name) is not None
                    for name in (
                        "approval", "approval_signature",
                        "revocation", "revocation_signature",
                    )
                ),
                "FOUR_SIGNED_INPUTS_REQUIRED",
            )
            install(args)

        print("R117_VM_STARTS=0")
        print("R117_NETWORK_ACTIONS=0")
        print("R117_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, KeyError, TypeError,
        RuntimeError, subprocess.TimeoutExpired,
    ) as error:
        print(
            "R117_ROOT_RELEASE_STOP=" +
            type(error).__name__ + ":" + str(error)[:180]
        )
        print("R117_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
