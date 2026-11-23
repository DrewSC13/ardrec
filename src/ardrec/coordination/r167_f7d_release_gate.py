"""R167-F7D: independently signed, root-revocable DENY release."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6

REPO = Path("/home/cicada/Development/GitHub/ardrec")
MANIFEST = REPO / "lab/operational-controller/r167-f7d-source-v1.json"
APPROVAL = Path(
    "/home/cicada/ardrec-lab/r167-f7d-release-v1/release.json"
)
REVOCATION = Path(
    "/etc/ardrec/r167-f7d-release-revocation-v1.json"
)

RELEASE_TRUST = Path(
    "/etc/ardrec/r167-f7d-release-trust-v1.json"
)

PREFIX = b"ARDREC-R167-F7D-INDEPENDENT-RELEASE-v1\x00"
REVOKE_PREFIX = b"ARDREC-R167-F7D-RELEASE-REVOCATION-v1\x00"

FILES = (
    "src/ardrec/coordination/r167_f7d_controlled_boot.py",
    "src/ardrec/coordination/r167_f7d_release_gate.py",
    "scripts/ardrec_p14_r167_f7d_controlled_boot.py",
    "lab/tests/test_p14_r167_f7d_release.py",
)

class Stop(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Stop(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def source_admission():
    need(
        MANIFEST.is_file() and not MANIFEST.is_symlink(),
        "RELEASE_MANIFEST_NOT_TRUSTED",
    )
    doc = f1.load(MANIFEST.read_bytes())
    need(
        set(doc) == {
            "schema", "historical_sha256", "files_sha256",
            "release_state", "root_release_installed",
            "network_traffic", "vm_starts_during_build", "p8",
        },
        "RELEASE_MANIFEST_FIELDS",
    )
    need(
        doc["schema"] == "ARDREC-R167-F7D-SOURCE-v1"
        and doc["historical_sha256"] ==
        "361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af"
        and doc["release_state"] == "EXTERNAL_SIGNATURE_REQUIRED"
        and doc["root_release_installed"] is False
        and doc["network_traffic"] is False
        and type(doc["vm_starts_during_build"]) is int
        and doc["vm_starts_during_build"] == 0
        and doc["p8"] == "NO-GO",
        "RELEASE_SOURCE_ONLY_INVARIANT",
    )
    pinned = doc["files_sha256"]
    need(
        type(pinned) is dict and set(pinned) == set(FILES),
        "RELEASE_PIN_SET",
    )
    for name in FILES:
        path = REPO / name
        need(
            path.is_file()
            and not path.is_symlink()
            and path.resolve().is_relative_to(REPO.resolve())
            and type(pinned[name]) is str
            and f1.SHA.fullmatch(pinned[name])
            and sha(path.read_bytes()) == pinned[name],
            "RELEASE_SOURCE_DRIFT:" + name,
        )
    return pinned

def root_policy(path):
    need(
        isinstance(path, Path)
        and path in (RELEASE_TRUST, REVOCATION),
        "ROOT_POLICY_NOT_ALLOWLISTED",
    )
    for item in (Path("/"), Path("/etc"), Path("/etc/ardrec")):
        s = item.lstat()
        need(
            stat.S_ISDIR(s.st_mode)
            and s.st_uid == 0
            and not (s.st_mode & 0o022),
            "RELEASE_ROOT_PARENT_UNSAFE",
        )

    try:
        s = path.lstat()
    except OSError as exc:
        raise Stop("RELEASE_ROOT_REVOCATION_UNAVAILABLE") from exc

    need(
        stat.S_ISREG(s.st_mode)
        and s.st_uid == 0
        and s.st_nlink == 1
        and not (s.st_mode & 0o022)
        and 0 < s.st_size <= 8192,
        "RELEASE_ROOT_REVOCATION_UNTRUSTED",
    )

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        current = os.fstat(fd)
        need(
            current.st_dev == s.st_dev
            and current.st_ino == s.st_ino
            and current.st_uid == 0
            and current.st_nlink == 1
            and current.st_size == s.st_size,
            "RELEASE_ROOT_POLICY_RACE",
        )
        raw = os.read(fd, 8193)
        need(
            len(raw) == s.st_size,
            "RELEASE_ROOT_READBACK_FAILED",
        )
        return f1.load(raw)
    finally:
        os.close(fd)

def root_revocation():
    return root_policy(REVOCATION)

def require(plan, *, now):
    pins = source_admission()

    need(
        type(now) is datetime
        and now.tzinfo is not None
        and now.utcoffset() is not None,
        "RELEASE_CLOCK_REQUIRED",
    )
    moment = now.astimezone(timezone.utc)

    try:
        approval = f1.load(f2.private_read(APPROVAL))
    except (OSError, f2.Stop, f1.Rejected) as exc:
        raise Stop("RELEASE_APPROVAL_UNAVAILABLE") from exc

    need(
        type(plan) is dict
        and plan.get("role") == "ssh"
        and plan.get("traffic_authorized") is False
        and plan.get("p8") == "NO-GO",
        "RELEASE_PLAN_NOT_DENY",
    )

    trust = f1.load(root_policy(RELEASE_TRUST))
    f3.trust_check(trust)

    scope_trust = f1.load(f6.secure_root_file(f6.TRUST))
    f3.trust_check(scope_trust)

    release_keys = {
        trust["scope_signer"]["public_key_pem"],
        trust["revocation_signer"]["public_key_pem"],
    }
    scope_keys = {
        scope_trust["scope_signer"]["public_key_pem"],
        scope_trust["revocation_signer"]["public_key_pem"],
    }

    need(
        release_keys.isdisjoint(scope_keys),
        "RELEASE_TRUST_REUSES_SCOPE_AUTHORITY",
    )

    f3.exact(
        approval,
        {"statement", "signer_key_id", "signature_b64"},
        "RELEASE_WRAPPER",
    )

    statement = approval["statement"]
    f3.exact(
        statement,
        {
            "schema", "release_id", "head", "role",
            "plan_sha256", "contract_sha256",
            "authorization_sha256", "files_sha256",
            "valid_from", "valid_until",
            "action", "network_traffic_authorized", "p8",
        },
        "RELEASE_FIELDS",
    )

    need(
        statement["schema"] ==
        "ARDREC-R167-F7D-RELEASE-APPROVAL-v1"
        and type(statement["release_id"]) is str
        and f1.ID.fullmatch(statement["release_id"])
        and statement["head"] == plan["head"]
        and statement["role"] == "ssh"
        and statement["plan_sha256"] ==
        f1.digest(f1.canonical(plan))
        and statement["contract_sha256"] ==
        plan["contract_sha256"]
        and statement["authorization_sha256"] ==
        plan["authorization_sha256"]
        and statement["files_sha256"] == pins
        and statement["action"] == "ONE_DENY_BOOT_ONLY"
        and statement["network_traffic_authorized"] is False
        and statement["p8"] == "NO-GO",
        "RELEASE_BINDING_MISMATCH",
    )

    start = f1._instant(statement["valid_from"], "RELEASE_FROM")
    until = f1._instant(statement["valid_until"], "RELEASE_UNTIL")

    need(
        start <= moment < until
        and 0 < (until - start).total_seconds() <= 900,
        "RELEASE_WINDOW_EXPIRED",
    )

    f3.verified_signature(
        approval, statement, trust["scope_signer"], PREFIX
    )

    revocation = root_revocation()

    f3.exact(
        revocation,
        {"statement", "signer_key_id", "signature_b64"},
        "RELEASE_REVOCATION_WRAPPER",
    )

    rev = revocation["statement"]

    f3.exact(
        rev,
        {
            "schema", "release_sha256", "release_id",
            "issued_at", "valid_until", "revoked", "reason_code",
        },
        "RELEASE_REVOCATION_FIELDS",
    )

    need(
        rev["schema"] ==
        "ARDREC-R167-F7D-RELEASE-REVOCATION-v1"
        and rev["release_sha256"] ==
        f1.digest(f1.canonical(approval))
        and rev["release_id"] == statement["release_id"]
        and type(rev["revoked"]) is bool
        and rev["revoked"] is False
        and type(rev["reason_code"]) is str
        and f1.ID.fullmatch(rev["reason_code"]),
        "RELEASE_REVOCATION_NOT_CLEAR",
    )

    f3.verified_signature(
        revocation, rev, trust["revocation_signer"],
        REVOKE_PREFIX,
    )

    issued = f1._instant(rev["issued_at"], "RELEASE_REVOKED_AT")
    expiration = f1._instant(
        rev["valid_until"], "RELEASE_REVOCATION_UNTIL"
    )

    need(
        issued <= moment < expiration
        and 0 <= (moment - issued).total_seconds() <= 90
        and issued < expiration,
        "RELEASE_REVOCATION_STALE",
    )
    return {
        "release_sha256": f1.digest(f1.canonical(approval)),
        "release_id": statement["release_id"],
        "head": plan["head"],
        "p8": "NO-GO",
    }
