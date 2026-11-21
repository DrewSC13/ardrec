"""R117-F5B: independent dual-authority release admission.

Offline validation only. No root installation, filesystem publication,
VM, network, Git dependency or boot authorization.

Privileged installation must separately pin this module, validate host
provenance, enforce revocation anti-replay and acquire the root lock.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import hashlib
import json
import os
import re
import subprocess
import zipfile

import ardrec_r117_release_core_v1 as core

HEAD = "ba7a184406a08cd545d1d795b0d97101a8c112a1"
CANDIDATE_SHA = (
    "574eca7c66da8b6067adfc08bf89b7bbfa7ad238eb1b805004b9016705310f9d"
)

APPROVAL_PIN = (
    "9c6753b9a439de6eb4a17ae87fe5a09b95816461f93a76a100b4e7b2c4843389"
)
REVOCATION_PIN = (
    "db3ac74dc6121d894b63cac0c55fec8405f281147df03c34d148d71c030dc828"
)

REVOCATION_SCHEMA = (
    "ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1"
)
REVOCATION_PREFIX = (
    b"ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1\x00"
)

REVOCATION_FIELDS = {
    "schema", "head", "candidate_sha256",
    "issued_at", "valid_until", "revoked",
    "authority", "p8",
}

F4 = (
    "src/ardrec/coordination/r117_f4_controlled_boot.py",
    "src/ardrec/coordination/r117_f4_runner_ftp_boot.py",
    "src/ardrec/coordination/r117_f4_root_release.py",
)

SPKI = bytes.fromhex("302a300506032b6570032100")


class Stop(RuntimeError):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def key_identity(public_pem):
    """Return canonical Ed25519 identity, not PEM-text identity."""
    need(
        isinstance(public_pem, bytes)
        and 0 < len(public_pem) <= 4096,
        "PUBLIC_KEY_INPUT_INVALID",
    )

    fd = os.memfd_create(
        "ardrec-r117-key-identity",
        os.MFD_CLOEXEC,
    )

    try:
        need(
            os.write(fd, public_pem) == len(public_pem),
            "IDENTITY_MEMFD_WRITE_FAILED",
        )
        os.lseek(fd, 0, os.SEEK_SET)

        result = subprocess.run(
            [
                "/usr/bin/openssl", "pkey",
                "-pubin", "-in",
                "/proc/self/fd/" + str(fd),
                "-outform", "DER",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
            pass_fds=(fd,),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )

        need(
            result.returncode == 0
            and len(result.stdout) == 44
            and result.stdout.startswith(SPKI),
            "PUBLIC_IDENTITY_NOT_ED25519",
        )

        return result.stdout[-32:]
    finally:
        os.close(fd)


def verify_approval(
    raw, signature, public, public_pin, *,
    now, historical, head=HEAD, candidate_sha=CANDIDATE_SHA
):
    approval = core.document(raw)

    if historical:
        need(
            set(approval) == core.APPROVAL_FIELDS
            and approval["schema"] == core.APPROVAL_SCHEMA
            and approval["head"] == head
            and approval["candidate_sha256"] ==
                candidate_sha
            and approval["purpose"] == "INSTALL_SOURCE_ONLY"
            and approval["p8"] == "NO-GO"
            and type(approval["authority"]) is str
            and 3 <= len(approval["authority"]) <= 80,
            "HISTORICAL_APPROVAL_SCOPE_INVALID",
        )

        start = core.utc(approval["valid_from"])
        end = core.utc(approval["valid_until"])

        need(
            0 < (end - start).total_seconds() <= 600,
            "HISTORICAL_APPROVAL_WINDOW_INVALID",
        )

    else:
        core.approval_fields(
            raw,
            head=head,
            candidate_sha=candidate_sha,
            now=now,
        )

    core.verify_signature(
        public,
        signature,
        core.PREFIX + raw,
        expected_public_sha=public_pin,
    )

    return approval


def verify_revocation(
    raw, signature, public, public_pin, *, now,
    head=HEAD, candidate_sha=CANDIDATE_SHA
):
    statement = core.document(raw)

    need(
        set(statement) == REVOCATION_FIELDS
        and statement["schema"] == REVOCATION_SCHEMA
        and statement["head"] == head
        and statement["candidate_sha256"] ==
            candidate_sha
        and statement["revoked"] is False
        and statement["p8"] == "NO-GO"
        and type(statement["authority"]) is str
        and 3 <= len(statement["authority"]) <= 80,
        "REVOCATION_SCOPE_INVALID",
    )

    issued = core.utc(statement["issued_at"])
    until = core.utc(statement["valid_until"])

    need(
        issued <= now < until
        and 0 < (until - issued).total_seconds() <= 90,
        "REVOCATION_ASSERTION_EXPIRED_OR_FUTURE",
    )

    core.verify_signature(
        public,
        signature,
        REVOCATION_PREFIX + raw,
        expected_public_sha=public_pin,
    )

    return statement


def release_receipt(members, *, head=HEAD):
    need(
        "manifest.json" in members,
        "MANIFEST_MISSING",
    )

    source_hashes = {}

    for name in F4:
        runtime_name = (
            "runtime/ardrec/coordination/" +
            name.rsplit("/", 1)[-1]
        )

        need(runtime_name in members,
             "F4_RUNTIME_SOURCE_MISSING")

        source_hashes[name] = core.sha(
            members[runtime_name]
        )

    return core.canonical({
        "schema": "ARDREC-R117-F4-BOOT-RELEASE-v1",
        "head": head,
        "source_sha256": source_hashes,
        "pilot_manifest_sha256":
            core.sha(members["manifest.json"]),
        "pilot_schema": core.SCHEMA,
        "p8": "NO-GO",
        "authorized_to_boot": False,
    })


def verify_release(
    candidate_raw,
    approval_raw,
    approval_signature,
    approval_public,
    revocation_raw,
    revocation_signature,
    revocation_public,
    *,
    now,
    approval_pin=APPROVAL_PIN,
    revocation_pin=REVOCATION_PIN,
    historical=False,
    head=HEAD, candidate_sha=CANDIDATE_SHA,
):
    """Verify all source bytes and independent signed statements.

    Injected pins support offline unit tests. A privileged entrypoint
    MUST use the hardcoded production pins, never caller-selected pins.
    """
    need(
        isinstance(now, datetime)
        and now.tzinfo is not None
        and now.utcoffset().total_seconds() == 0,
        "VERIFICATION_TIME_NOT_UTC",
    )
    need(type(historical) is bool,
         "HISTORICAL_MODE_INVALID")

    need(
        type(head) is str
        and re.fullmatch(r"[0-9a-f]{40}", head)
        and type(candidate_sha) is str
        and re.fullmatch(r"[0-9a-f]{64}", candidate_sha),
        "SIGNED_CANDIDATE_IDENTITY_INVALID",
    )

    report = core.verify_candidate(
        candidate_raw,
        head=head,
        expected_sha=candidate_sha,
    )

    approval = verify_approval(
        approval_raw,
        approval_signature,
        approval_public,
        approval_pin,
        now=now,
        historical=historical,
        head=head,
        candidate_sha=candidate_sha,
    )

    revocation = verify_revocation(
        revocation_raw,
        revocation_signature,
        revocation_public,
        revocation_pin,
        now=now,
        head=head,
        candidate_sha=candidate_sha,
    )

    need(
        key_identity(approval_public) !=
            key_identity(revocation_public),
        "APPROVAL_REVOCATION_KEYS_NOT_INDEPENDENT",
    )

    with zipfile.ZipFile(BytesIO(candidate_raw)) as bundle:
        members = {
            name: bundle.read(name)
            for name in bundle.namelist()
        }

    receipt = release_receipt(members, head=head)

    return {
        "schema": "ARDREC-R117-F5B-DUAL-AUTHORITY-v1",
        "head": head,
        "candidate_sha256": candidate_sha,
        "file_count_verified": report["file_count"],
        "source_count_verified": report["source_count"],
        "pilot_manifest_sha256": report["manifest_sha256"],
        "release_receipt_sha256": core.sha(receipt),
        "approval_signature": "VERIFIED_ED25519",
        "revocation_signature": "VERIFIED_ED25519",
        "revoked": False,
        "separate_authorities": True,
        "approval_mode": (
            "HISTORICAL_SIGNATURE"
            if historical else "FRESH_INSTALL_APPROVAL"
        ),
        "new_installation_allowed_by_this_module": False,
        "root_provenance_attested": False,
        "physical_installation_executed": False,
        "anti_replay_root_attested": False,
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    }
