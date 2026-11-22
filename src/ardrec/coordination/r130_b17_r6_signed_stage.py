"""R130/B17-R6B1: verificación Ed25519 y staging privado.

La validez criptográfica no equivale a confianza root instalada.

No instala software root, no configura autoridades, no inicia VM,
no abre conexiones y no concede autorización operacional.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from ardrec.coordination import (
    r130_b17_r6_install_contract as intake,
)
from ardrec.evidence import r58f_signed_witness as crypto

SCHEMA = "ARDREC-R130-B17-R6-SIGNED-INSTALL-v1"

APPROVAL_SCHEMA = SCHEMA + "-approval"
REV_SCHEMA = SCHEMA + "-revocation"
TRUST_SCHEMA = SCHEMA + "-trust"

APPROVAL_PREFIX = (
    APPROVAL_SCHEMA + "\0"
).encode("ascii")

REV_PREFIX = (
    REV_SCHEMA + "\0"
).encode("ascii")

IDENT = re.compile(r"[A-Za-z0-9_.:-]{3,80}\Z")

BOOT = re.compile(
    r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z"
)

TARGETS = [
    "/var/lib/ardrec/r126-ftp-session-guard-v1",
    "/var/lib/ardrec/r128-one-session-v2",
]


class Stop(ValueError):
    """Rechazo explícito y conservador."""


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def canon(value):
    return intake.canon(value)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def exact(value, fields, reason):
    need(
        type(value) is dict and set(value) == set(fields),
        reason,
    )
    return value


def instant(value):
    need(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
            value,
        ),
        "TIME_FORMAT",
    )

    try:
        dt = datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%SZ",
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Stop("TIME_VALUE") from exc

    return dt


def signer(value):
    exact(
        value,
        {"key_id", "public_key_pem"},
        "SIGNER_FIELDS",
    )

    need(
        type(value["key_id"]) is str
        and IDENT.fullmatch(value["key_id"]) is not None,
        "SIGNER_ID",
    )

    need(
        type(value["public_key_pem"]) is str,
        "SIGNER_PEM_TYPE",
    )

    try:
        key = value["public_key_pem"].encode("ascii")
    except UnicodeError as exc:
        raise Stop("SIGNER_PEM_ENCODING") from exc

    need(
        80 <= len(key) <= 1024
        and key.startswith(
            b"-----BEGIN PUBLIC KEY-----\n"
        )
        and key.endswith(
            b"-----END PUBLIC KEY-----\n"
        ),
        "SIGNER_PEM",
    )

    return key


def verify(envelope, signer_entry, prefix):
    exact(
        envelope,
        {
            "statement",
            "signer_key_id",
            "signature_b64",
        },
        "SIGNED_WRAPPER",
    )

    need(
        envelope["signer_key_id"] == signer_entry["key_id"]
        and type(envelope["statement"]) is dict,
        "SIGNER_NOT_TRUSTED",
    )

    encoded = envelope["signature_b64"]

    need(
        type(encoded) is str
        and 0 < len(encoded) <= 128,
        "SIGNATURE_ENCODING",
    )

    try:
        signature = base64.b64decode(
            encoded,
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise Stop("SIGNATURE_ENCODING") from exc

    need(
        len(signature) == 64
        and base64.b64encode(
            signature
        ).decode("ascii") == encoded,
        "SIGNATURE_NOT_CANONICAL",
    )

    try:
        crypto._verify_signature(
            signer(signer_entry),
            prefix + canon(envelope["statement"]),
            signature,
        )
    except crypto.WitnessError as exc:
        raise Stop("SIGNATURE_NOT_VERIFIED") from exc

    return envelope["statement"]


def review(entries, approval, revocation, trust, *, now):
    """Revisión criptográfica sin autoridad root operacional."""

    source = intake.review_entries(entries)

    need(
        type(now) is datetime
        and now.tzinfo is not None
        and now.utcoffset() is not None,
        "UTC_CLOCK_REQUIRED",
    )

    now = now.astimezone(timezone.utc)

    exact(
        trust,
        {
            "schema",
            "installation_signer",
            "revocation_signer",
        },
        "TRUST_FIELDS",
    )

    need(
        trust["schema"] == TRUST_SCHEMA,
        "TRUST_SCHEMA",
    )

    installation = trust["installation_signer"]
    revoke_signer = trust["revocation_signer"]

    installation_key = signer(installation)
    revocation_key = signer(revoke_signer)

    need(
        installation["key_id"] != revoke_signer["key_id"]
        and digest(installation_key) != digest(revocation_key),
        "SIGNERS_NOT_DISTINCT",
    )

    statement = verify(
        approval,
        installation,
        APPROVAL_PREFIX,
    )

    exact(
        statement,
        {
            "schema",
            "install_id",
            "source_head",
            "source_tree",
            "archive_sha256",
            "b4_sha256",
            "b9_sha256",
            "targets",
            "boot_id",
            "valid_from",
            "valid_until",
            "purpose",
            "one_time",
            "automatic_network",
            "p8",
        },
        "APPROVAL_FIELDS",
    )

    need(
        statement["schema"] == APPROVAL_SCHEMA
        and type(statement["install_id"]) is str
        and IDENT.fullmatch(
            statement["install_id"]
        ) is not None
        and statement["source_head"] == intake.HEAD
        and statement["source_tree"] == intake.TREE
        and statement["archive_sha256"] == intake.ARCHIVE_SHA
        and statement["b4_sha256"] == intake.B4_SHA
        and statement["b9_sha256"] == intake.B9_SHA
        and statement["targets"] == TARGETS
        and type(statement["boot_id"]) is str
        and BOOT.fullmatch(
            statement["boot_id"]
        ) is not None
        and statement["purpose"]
        == "INSTALL_SOURCE_ONLY_WITHOUT_ACTIVATION"
        and statement["one_time"] is True
        and statement["automatic_network"] is False
        and statement["p8"] == "NO-GO",
        "INSTALL_SCOPE_MISMATCH",
    )

    begin = instant(statement["valid_from"])
    end = instant(statement["valid_until"])

    need(
        begin <= now < end
        and 0 < (end - begin).total_seconds() <= 600,
        "INSTALL_APPROVAL_NOT_CURRENT",
    )

    rev = verify(
        revocation,
        revoke_signer,
        REV_PREFIX,
    )

    exact(
        rev,
        {
            "schema",
            "install_id",
            "approval_sha256",
            "issued_at",
            "valid_until",
            "revoked",
            "reason_code",
        },
        "REVOCATION_FIELDS",
    )

    need(
        rev["schema"] == REV_SCHEMA
        and rev["install_id"] == statement["install_id"]
        and rev["approval_sha256"]
        == digest(canon(approval))
        and rev["revoked"] is False
        and rev["reason_code"] == "CURRENT_CLEAR",
        "REVOCATION_NOT_BOUND_OR_REVOKED",
    )

    issued = instant(rev["issued_at"])
    rev_end = instant(rev["valid_until"])

    need(
        issued <= now < rev_end
        and 0 <= (now - issued).total_seconds() <= 30
        and rev_end <= end,
        "REVOCATION_NOT_FRESH",
    )

    result = {
        "schema": SCHEMA + "-offline-review",
        "source_review_sha256": source["sha256"],
        "source_head": intake.HEAD,
        "install_id": statement["install_id"],
        "approval_sha256": digest(canon(approval)),
        "revocation_sha256": digest(canon(revocation)),
        "signature_verification": "PASS",
        "two_documentary_signers_distinct": True,
        "independent_root_trust_anchored": False,
        "upstream_operational_signers_excluded": False,
        "root_install_authorized": False,
        "root_install_executed": False,
        "physical_pilot_executed": False,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }

    result["sha256"] = digest(canon(result))
    return result


def fsync_folder(folder):
    fd = os.open(
        folder,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )

    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def user_stage(
    entries,
    approval,
    revocation,
    trust,
    *,
    now,
    parent,
    fail_after_first=False,
):
    """Publicación privada de revisión; nunca instalación root."""

    report = review(
        entries,
        approval,
        revocation,
        trust,
        now=now,
    )

    need(
        isinstance(parent, Path)
        and parent.is_absolute()
        and not parent.is_symlink(),
        "PRIVATE_PARENT_PATH",
    )

    metadata = parent.lstat()

    need(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700,
        "PRIVATE_PARENT_REQUIRED",
    )

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    final = parent / (
        "review-" + report["sha256"][:16]
    )

    need(
        not final.exists()
        and not final.is_symlink(),
        "REVIEW_ALREADY_EXISTS",
    )

    pending = Path(
        tempfile.mkdtemp(
            prefix=".r130-incomplete-",
            dir=parent,
        )
    )

    need(
        stat.S_IMODE(
            pending.stat().st_mode
        ) == 0o700,
        "PENDING_DIRECTORY_MODE",
    )

    data = {
        "root-controller.py.source-only":
            entries["root-controller.py.source-only"],
        "root-executor.py.source-only":
            entries["root-executor.py.source-only"],
        "offline-review.json":
            canon(report),
    }

    for index, (name, raw) in enumerate(
        sorted(data.items())
    ):
        fd = os.open(
            pending / name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
        )

        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

        if fail_after_first and index == 0:
            fsync_folder(pending)
            fsync_folder(parent)
            raise Stop(
                "INJECTED_STOP_PENDING_PRESERVED"
            )

    fsync_folder(pending)

    os.rename(pending, final)

    fsync_folder(parent)

    return {
        "path": str(final),
        "review_sha256": report["sha256"],
        "root_install": False,
        "operational_activation": False,
        "p8": "NO-GO",
    }


def capabilities():
    return {
        "schema": SCHEMA + "-capabilities",
        "verifies_real_ed25519": True,
        "verifies_signed_revocation": True,
        "can_stage_unprivileged_review": True,
        "can_install_root": False,
        "can_enable_network": False,
        "can_boot_vm": False,
        "can_create_authority": False,
        "root_trust_anchored": False,
        "p8": "NO-GO",
    }
