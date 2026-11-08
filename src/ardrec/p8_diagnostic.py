"""P8-R7: strict deny-only diagnostic interoperability (untrusted synthetic JSON).

This parser does not authenticate R5/R6, resolve a material, or authorize any action.
It is deliberately independent of the operational messages and the executor.
"""
from __future__ import annotations

import json
import re
from typing import Any

MAX_DIAGNOSTIC_BYTES = 4096
SCHEMA = "1.0"
IN_KIND = "P8_R7_DIAGNOSTIC_PROPOSAL"
OUT_KIND = "P8_R7_DENIAL_RESULT"
DENIAL = "BLOCKED_UNBOUND_NO_EXECUTION"
FIELDS = frozenset({
    "schema_version", "message_type", "stage", "case_id", "profile_id",
    "snapshot_sha256", "r6_snapshot_sha256", "material_epoch", "r6_material_epoch",
    "authorization_revision", "r6_authorization_revision", "r5_status",
    "r6_status", "r5_dispatch_allowed", "r5_case_authorized",
    "r6_dispatch_allowed", "r6_operational_authorization", "private_issuer_verified",
    "revocation_verified", "dispatch_requested",
})
KNOWN_PROFILES = frozenset(
    [f"SSH-T{i:02d}-BASE" for i in range(1, 9)]
    + [f"FTP-T{i:02d}-BASE" for i in (1, 3, 4, 5, 6, 7)]
    + ["FTP-T02-CONTROL", "FTP-T02-DATA", "FTP-T08-READ", "FTP-T08-WRITE"]
    + [f"SMB-T{i:02d}-BASE" for i in (1, 2, 4, 5, 6, 7, 8)]
    + ["SMB-T03-SIGNING", "SMB-T03-ENCRYPTION", "SMB-T09-READ", "SMB-T09-WRITE"]
)
CASE_RE = re.compile(r"^(SSH|FTP|SMB)-T[0-9]{2}-S[0-9]{2,4}-[0-9]{2}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ACTIVE = "SYNTHETIC_PRECONDITIONS_CONSISTENT_DENY_ALL"
INVALIDATED = "SYNTHETIC_EXPIRED_OR_INVALIDATED_DENY_ALL"
MATERIAL = "SYNTHETIC_MATERIAL_OBSERVATIONS_ONLY_DENY_ALL"


def _deny(code: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "message_type": OUT_KIND,
        "decision": DENIAL,
        "reason_code": code,
        "authorized": False,
        "dispatch_allowed": False,
    }


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-JSON constant")


def evaluate_bytes(raw: bytes) -> dict[str, Any]:
    """Classify one bounded synthetic JSON document; ALWAYS return DENY."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DIAGNOSTIC_BYTES:
        return _deny("P8_R7_INVALID_SCHEMA")
    try:
        item = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=_invalid_constant)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return _deny("P8_R7_INVALID_SCHEMA")
    if type(item) is not dict or set(item) != FIELDS:
        return _deny("P8_R7_INVALID_SCHEMA")
    if (item["schema_version"] != SCHEMA or type(item["schema_version"]) is not str
            or type(item["message_type"]) is not str or item["message_type"] != IN_KIND
            or type(item["stage"]) is not str or item["stage"] not in {"dev", "pilot", "exp"}
            or any(type(item[k]) is not str for k in (
                "case_id", "profile_id", "snapshot_sha256", "r6_snapshot_sha256",
                "r5_status", "r6_status"))
            or any(type(item[k]) is not bool for k in (
                "r5_dispatch_allowed", "r5_case_authorized", "r6_dispatch_allowed",
                "r6_operational_authorization", "private_issuer_verified",
                "revocation_verified", "dispatch_requested"))
            or any(type(item[k]) is not int or item[k] < 0 for k in (
                "material_epoch", "r6_material_epoch", "authorization_revision",
                "r6_authorization_revision"))):
        return _deny("P8_R7_INVALID_SCHEMA")
    if item["profile_id"] not in KNOWN_PROFILES:
        return _deny("P8_R7_UNKNOWN_PROFILE")
    if (CASE_RE.fullmatch(item["case_id"]) is None
            or item["case_id"].split("-S", 1)[0] != item["profile_id"][:7]):
        return _deny("P8_R7_IDENTITY_MISMATCH")
    if (DIGEST_RE.fullmatch(item["snapshot_sha256"]) is None
            or DIGEST_RE.fullmatch(item["r6_snapshot_sha256"]) is None):
        return _deny("P8_R7_DIGEST_INVALID")
    if item["snapshot_sha256"] != item["r6_snapshot_sha256"]:
        return _deny("P8_R7_IDENTITY_MISMATCH")
    if (not 1 <= item["material_epoch"] <= 2**31 - 1
            or not 1 <= item["authorization_revision"] <= 2**31 - 1
            or item["r6_material_epoch"] != item["material_epoch"]
            or item["r6_authorization_revision"] != item["authorization_revision"]):
        return _deny("P8_R7_REVISION_MISMATCH")
    if item["r5_status"] != MATERIAL or item["r6_status"] not in {ACTIVE, INVALIDATED}:
        return _deny("P8_R7_INVALID_CLAIM")
    if any(item[k] for k in (
        "r5_dispatch_allowed", "r5_case_authorized", "r6_dispatch_allowed",
        "r6_operational_authorization", "private_issuer_verified", "revocation_verified",
    )):
        return _deny("P8_R7_AUTHORITY_CLAIM")
    if item["dispatch_requested"]:
        return _deny("P8_R7_DISPATCH_REQUESTED")
    if item["r6_status"] == INVALIDATED:
        return _deny("P8_R7_INVALIDATED")
    return _deny("P8_R7_UNVERIFIED_AUTHORITY")


def evaluate_text(text: str) -> dict[str, Any]:
    if type(text) is not str:
        return _deny("P8_R7_INVALID_SCHEMA")
    try:
        return evaluate_bytes(text.encode("utf-8"))
    except UnicodeError:
        return _deny("P8_R7_INVALID_SCHEMA")
