#!/usr/bin/env python3
"""ARDREC R117-F5C: structural transaction closure, SOURCE_ONLY.

No root writes, authorizations, guest starts, networking or release
publication. Structural consistency is not cryptographic authorization.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from io import BytesIO
import importlib.util
import os
from pathlib import Path
import re
import zipfile

REPO = Path(__file__).resolve().parents[1]

F5A = "scripts/ardrec_p14_r117_f5_root_candidate.py"
F5B = "scripts/ardrec_p14_r117_f5b_root_stage.py"

INTENT_SCHEMA = "ARDREC-R117-F5B-TRANSACTION-v1"
COMPLETE_SCHEMA = "ARDREC-R117-F5B-COMPLETE-v1"

JOURNAL_MARKERS = {
    "prepared.once": b"PREPARED_NOT_PUBLISHED\n",
    "pilot-visible.once":
        b"PILOT_VISIBLE_RELEASE_PENDING\n",
    "release-visible.once":
        b"RELEASE_VISIBLE_INSPECTION_REQUIRED\n",
}

JOURNAL_FILES = set(JOURNAL_MARKERS) | {
    "intent.json", "complete.json"
}

RELEASE_FILES = {
    "receipt.json", "approval.json", "approval.sig"
}

class Stop(ValueError):
    pass

def need(value, code):
    if not value:
        raise Stop(code)

def module(path, name):
    need(path.is_file() and not path.is_symlink(),
         "SOURCE_MODULE_NOT_REGULAR")
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None,
         "MODULE_SPEC_INVALID")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

def modules(repo):
    return (
        module(repo / F5A, "ardrec_f5c_f5a_source"),
        module(repo / F5B, "ardrec_f5c_f5b_source"),
    )

def exact_document(raw, builder, label):
    need(type(raw) is bytes, label + "_NOT_BYTES")
    try:
        obj = builder.strict_json(raw)
        need(builder.canonical(obj) == raw,
             label + "_NOT_CANONICAL")
    except (ValueError, KeyError, TypeError) as exc:
        raise Stop(label + "_INVALID") from exc
    return obj

def exact_fields(doc, keys, code):
    need(type(doc) is dict and set(doc) == set(keys),
         code)
    return doc

def validate(head, candidate, pilot, release, journal, *,
             repo=REPO):
    """Check byte-equivalence and durable structural closure.

    All supplied byte mappings are untrusted until a separate root
    reader attests ownership, permissions and directory scope.
    Ed25519 signature verification is intentionally not performed.
    Returns NO authorization, even when structural checks succeed.
    """
    need(type(head) is str and
         re.fullmatch("[0-9a-f]{40}", head),
         "HEAD_INVALID")

    need(type(pilot) is dict and
         type(release) is dict and
         type(journal) is dict,
         "SNAPSHOT_TYPE_INVALID")

    a, b = modules(repo)

    try:
        a.audit(candidate, repo=repo, expected_head=head)
        need(candidate == a.candidate(head, repo=repo),
             "CANDIDATE_NOT_REPRODUCIBLE")
    except (
        ValueError, KeyError, TypeError,
        zipfile.BadZipFile,
    ) as exc:
        raise Stop("CANDIDATE_NOT_AUTHENTIC") from exc

    with zipfile.ZipFile(BytesIO(candidate)) as archive:
        expected = {
            name: archive.read(name)
            for name in archive.namelist()
        }

    need(len(expected) == 39 and
         set(pilot) == set(expected),
         "PILOT_FILE_SET_INVALID")

    for name, raw in expected.items():
        need(type(pilot[name]) is bytes and
             pilot[name] == raw,
             "PILOT_BYTES_CHANGED_" + name)

    need(set(release) == RELEASE_FILES,
         "RELEASE_FILE_SET_INVALID")

    receipt_raw = release["receipt.json"]
    approval_raw = release["approval.json"]
    signature_raw = release["approval.sig"]

    need(type(signature_raw) is bytes and
         len(signature_raw) == 64,
         "APPROVAL_SIGNATURE_SHAPE_INVALID")

    receipt = exact_document(
        receipt_raw, a, "RELEASE_RECEIPT"
    )

    expected_receipt = b.release_receipt(
        a, head, expected["manifest.json"], repo=repo
    )

    need(receipt == expected_receipt,
         "RELEASE_RECEIPT_NOT_BOUND_TO_SOURCES")

    approval = exact_document(
        approval_raw, a, "RELEASE_APPROVAL"
    )

    try:
        b.approval_fields(
            approval, head, a.sha(candidate),
            datetime.now(timezone.utc), fresh=False
        )
    except (
        b.Stop, ValueError, KeyError, TypeError
    ) as exc:
        raise Stop("APPROVAL_FIELDS_INVALID") from exc

    need(set(journal) == JOURNAL_FILES,
         "JOURNAL_FILES_INCOMPLETE_OR_EXTRA")

    for name, raw in JOURNAL_MARKERS.items():
        need(journal[name] == raw,
             "JOURNAL_MARKER_INVALID_" + name)

    intent = exact_document(
        journal["intent.json"], a, "TRANSACTION_INTENT"
    )

    complete = exact_document(
        journal["complete.json"], a,
        "TRANSACTION_COMPLETE"
    )

    exact_fields(intent, {
        "schema", "head", "candidate_sha256",
        "approval_sha256", "status", "p8"
    }, "INTENT_FIELDS_INVALID")

    need(
        intent["schema"] == INTENT_SCHEMA
        and intent["head"] == head
        and intent["candidate_sha256"] == a.sha(candidate)
        and intent["approval_sha256"] == a.sha(approval_raw)
        and intent["status"] == "SOURCE_INSTALL_ATTEMPT"
        and intent["p8"] == "NO-GO",
        "INTENT_NOT_BOUND_TO_CANDIDATE",
    )

    exact_fields(complete, {
        "schema", "head", "pilot_manifest_sha256",
        "receipt_sha256", "approved_install",
        "boot_permit_issued", "network_connections",
        "vm_starts", "p8"
    }, "COMPLETION_FIELDS_INVALID")

    need(
        complete["schema"] == COMPLETE_SCHEMA
        and complete["head"] == head
        and complete["pilot_manifest_sha256"] ==
            a.sha(expected["manifest.json"])
        and complete["receipt_sha256"] ==
            a.sha(receipt_raw)
        and complete["approved_install"] is True
        and complete["boot_permit_issued"] is False
        and type(complete["network_connections"]) is int
        and complete["network_connections"] == 0
        and type(complete["vm_starts"]) is int
        and complete["vm_starts"] == 0
        and complete["p8"] == "NO-GO",
        "TRANSACTION_NOT_DURABLY_CLOSED",
    )

    return {
        "schema": "ARDREC-R117-F5C-CLOSURE-STRUCTURAL-v1",
        "head": head,
        "source_count": 36,
        "file_count": 39,
        "candidate_sha256": a.sha(candidate),
        "structural_closure": "CONSISTENT",
        "root_ownership_attested": False,
        "ed25519_verified": False,
        "boot_authorized": False,
        "network_authorized": False,
        "a6": "ND",
        "p8": "NO-GO",
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true",
                        required=True)
    args = parser.parse_args(argv)

    try:
        need(os.geteuid() != 0,
             "OFFLINE_NON_ROOT_REQUIRED")
        a, _ = modules(REPO)
        head = "a" * 40
        candidate = a.candidate(head, repo=REPO)
        a.audit(candidate, repo=REPO, expected_head=head)

        need(len(candidate) > 0,
             "EMPTY_CANDIDATE")

        print(
            "R117_F5C_OFFLINE="
            "PASS_REPRODUCIBLE_SOURCE_CANDIDATE"
        )
        print("R117_F5C_APPLY=NOT_AVAILABLE")
        print("R117_F5C_ED25519=NOT_ATTESTED")
        print("R117_F5C_ROOT=NOT_ATTESTED")
        print("R117_F5C_BOOT=NOT_AUTHORIZED")
        print("R117_F5C_VM_STARTS=0")
        print("R117_F5C_NETWORK_CONNECTIONS=0")
        print("R117_F5C_A6=ND")
        print("R117_F5C_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, KeyError,
        TypeError, zipfile.BadZipFile,
    ) as exc:
        print(
            "R117_F5C_STOP=" +
            type(exc).__name__ + ":" + str(exc)[:160]
        )
        print("R117_F5C_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
