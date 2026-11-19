"""R101: case-bound, expiring SSH authority proposal.

This module has no positive authorization or dispatch path.
A well-formed proposal is not permission to start a VM or contact SSH.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any

from ardrec.coordination import r100_ssh_a5_bridge as r100
from ardrec.coordination import r59d_a5_result_intake as a5

SCHEMA = "ardrec-r101-ssh-authority-proposal-v1"
REVIEW = "ardrec-r101-ssh-authority-review-v1"
GUEST = "ardrec-r33-dev-ssh"
METHOD = "SSH_EFFECTIVE_CONFIG_READONLY"

PROPOSAL_FIELDS = frozenset({
    "schema", "request_id", "r100_manifest_sha256",
    "session_id", "service_id", "family_id",
    "derived_case_id", "attempt_id", "guest",
    "method_id", "port", "not_before_utc",
    "expires_utc", "ttl_seconds",
    "external_authority_receipt_sha256",
    "approved", "operational_dispatch",
    "p8_operational", "sha256",
})

BLOCKERS = (
    "F11_QEMU_HOOK_DENY_ONLY",
    "P8_OPERATIONAL_NO_GO",
    "INDEPENDENT_CASE_AUTHORIZATION_ABSENT",
    "PHYSICAL_RUNTIME_ADMISSION_NOT_ATTESTED",
    "SSH_EFFECTIVE_CONFIGURATION_NOT_EXECUTED",
)


class AuthorityError(ValueError):
    """An R101 request or receipt violates a mandatory condition."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise AuthorityError(reason)


def timestamp(value: str) -> datetime:
    need(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
        ) is not None,
        "TIME_FORMAT",
    )
    try:
        parsed = datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise AuthorityError("TIME_INVALID") from exc
    need(
        parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value,
        "TIME_NOT_CANONICAL",
    )
    return parsed


def iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_proposal(
    case_root: Path, *, request_id: str,
    not_before_utc: str, ttl_seconds: int = 120,
) -> dict[str, Any]:
    case = r100.verify(case_root)
    need(
        type(request_id) is str
        and re.fullmatch(r"REQ_[A-F0-9]{24}", request_id)
        is not None,
        "REQUEST_ID_INVALID",
    )
    need(
        type(ttl_seconds) is int
        and 1 <= ttl_seconds <= 300,
        "TTL_OUT_OF_BOUNDS",
    )
    start = timestamp(not_before_utc)
    end = start + timedelta(seconds=ttl_seconds)

    doc = {
        "schema": SCHEMA,
        "request_id": request_id,
        "r100_manifest_sha256": case["sha256"],
        "session_id": case["session_id"],
        "service_id": case["service_id"],
        "family_id": case["family_id"],
        "derived_case_id": case["derived_case_id"],
        "attempt_id": case["attempt_id"],
        "guest": GUEST,
        "method_id": METHOD,
        "port": 22,
        "not_before_utc": not_before_utc,
        "expires_utc": iso(end),
        "ttl_seconds": ttl_seconds,
        "external_authority_receipt_sha256": None,
        "approved": False,
        "operational_dispatch": False,
        "p8_operational": "NO-GO",
    }
    doc["sha256"] = a5.digest(doc)
    return doc


def verify_proposal(
    case_root: Path, doc: dict[str, Any]
) -> bool:
    need(
        type(doc) is dict and set(doc) == PROPOSAL_FIELDS,
        "PROPOSAL_SCHEMA",
    )
    expected = make_proposal(
        case_root,
        request_id=doc["request_id"],
        not_before_utc=doc["not_before_utc"],
        ttl_seconds=doc["ttl_seconds"],
    )
    need(
        doc == expected
        and doc["expires_utc"] == expected["expires_utc"],
        "PROPOSAL_BINDING_OR_AUTHORITY_DRIFT",
    )
    return True


def review(
    case_root: Path, proposal: dict[str, Any]
) -> dict[str, Any]:
    verify_proposal(case_root, proposal)
    case = r100.verify(case_root)

    result = {
        "schema": REVIEW,
        "request_id": proposal["request_id"],
        "proposal_sha256": proposal["sha256"],
        "r100_manifest_sha256": case["sha256"],
        "session_id": case["session_id"],
        "derived_case_id": case["derived_case_id"],
        "guest": GUEST,
        "ttl_seconds": proposal["ttl_seconds"],
        "blockers": list(BLOCKERS),
        "authority_independently_attested": False,
        "authorized": False,
        "dispatch_allowed": False,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "vm_start_attempts": 0,
        "host_security_mutations": 0,
        "p8_operational": "NO-GO",
    }
    result["sha256"] = a5.digest(result)
    return result


def parse_private(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    try:
        doc = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise AuthorityError("INVALID_JSON") from exc

    need(
        type(doc) is dict
        and raw == a5.canonical(doc) + b"\n",
        "NONCANONICAL_JSON",
    )
    return doc


def file_names(proposal: dict) -> tuple[str, str]:
    h = proposal["sha256"]
    return (
        "r101-proposal-" + h + ".json",
        "r101-review-" + h + ".json",
    )


def verify_stored(case_root: Path, root: Path) -> dict:
    a5._private_root(root)
    entries = list(root.iterdir())
    need(
        len(entries) == 2 and all(
            p.is_file() and not p.is_symlink()
            for p in entries
        ),
        "REVIEW_INVENTORY_INVALID",
    )

    proposals = [
        p for p in entries
        if p.name.startswith("r101-proposal-")
    ]
    need(len(proposals) == 1, "PROPOSAL_FILE_MISSING")

    raw_proposal = a5._read_private(
        proposals[0], a5.MAX_REPORT
    )
    proposal = parse_private(raw_proposal)
    verify_proposal(case_root, proposal)

    proposal_name, review_name = file_names(proposal)
    need(
        proposals[0].name == proposal_name,
        "PROPOSAL_FILENAME_DRIFT",
    )
    raw_review = a5._read_private(
        root / review_name, a5.MAX_REPORT
    )
    stored_review = parse_private(raw_review)
    expected_review = review(case_root, proposal)

    need(
        stored_review == expected_review,
        "REVIEW_CONTENT_OR_DIGEST_DRIFT",
    )
    return stored_review


def persist(
    case_root: Path, root: Path, proposal: dict
) -> dict:
    a5._private_root(root)
    result = review(case_root, proposal)
    need(not list(root.iterdir()), "NONEMPTY_REVIEW_ROOT")

    proposal_name, review_name = file_names(proposal)
    a5._store_once(
        root / proposal_name,
        a5.canonical(proposal) + b"\n",
        a5.MAX_REPORT,
    )
    a5._store_once(
        root / review_name,
        a5.canonical(result) + b"\n",
        a5.MAX_REPORT,
    )
    need(
        verify_stored(case_root, root) == result,
        "PERSISTENCE_REOPEN_FAILED",
    )
    return result
