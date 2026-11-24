"""R197: prospective, bounded local FTP software rehearsal.

Real local transport, illustrative mathematical inputs.
Never grants historical operational or experimental authority.
"""
from __future__ import annotations

import json
import os
import re
import uuid

from datetime import datetime
from pathlib import Path

from . import local_ssh_pilot as ssh
from . import local_protocol_pilot as transport
from . import local_evidence_bridge as evidence

from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge,
    verify_unit_bridge,
)
from ardrec.stopping.development_stop import (
    preview_stop,
    verify_stop,
)


SCHEMA = "ARDREC-R197-PROSPECTIVE-PILOT-v1"

CONFIRM = "AUTORIZO_R197_FTP_LOCAL"

WEIGHTS = ("1/3", "1/3", "1/3")


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def seal(document):

    need(
        "sha256" not in document,
        "DOUBLE_SEAL",
    )

    result = dict(document)
    result["sha256"] = evidence.digest(result)

    return result


def make_plan(case_id, code_head, created, uid):

    need(
        type(case_id) is str
        and re.fullmatch(
            r"PILOT_FTP_[A-F0-9]{32}",
            case_id,
        ) is not None,
        "PILOT_ID_INVALID",
    )

    need(
        type(code_head) is str
        and re.fullmatch(
            r"[a-f0-9]{40}",
            code_head,
        ) is not None,
        "CODE_HEAD_INVALID",
    )

    need(
        type(uid) is int and uid > 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    need(
        type(created) is str
        and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T"
            r"\d{2}:\d{2}:\d{2}Z",
            created,
        ) is not None,
        "CREATED_TIME_INVALID",
    )

    datetime.strptime(
        created,
        "%Y-%m-%dT%H:%M:%SZ",
    )

    return seal({
        "schema": SCHEMA + "-plan",
        "case_id": case_id,
        "code_head": code_head,
        "created_at_utc": created,
        "operator_uid": uid,
        "protocol": "FTP",
        "candidate_family": "FTP-T01",
        "scope": "LOCAL_EPHEMERAL_TRANSPORT",
        "destination": "127.0.0.1",
        "maximum_attempts": 1,
        "input_kind":
            "ILLUSTRATIVE_SOFTWARE_REHEARSAL",
        "initial_risk": "1/2",
        "normalized_criticality": "1/3",
        "replacement_risk": "1/2",
        "weights": list(WEIGHTS),
        "ftp_source_sha256":
            transport.FTP_SOURCE_SHA256,
        "ftp_compatibility_sha256": [
            item[1]
            for item in transport.FTP_COMPAT_WHEELS
        ],
        "human_operators": 1,
        "historical_authority_granted": False,
        "experimental_unit": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify_plan(plan):

    evidence.verify_digest(plan)

    expected = make_plan(
        plan["case_id"],
        plan["code_head"],
        plan["created_at_utc"],
        plan["operator_uid"],
    )

    need(
        plan == expected,
        "PLAN_CHANGED",
    )

    return True


def make_intent(plan, reserved):

    verify_plan(plan)

    need(
        type(reserved) is str
        and reserved >= plan["created_at_utc"],
        "INTENT_TIME_INVALID",
    )

    datetime.strptime(
        reserved,
        "%Y-%m-%dT%H:%M:%SZ",
    )

    return seal({
        "schema": SCHEMA + "-intent",
        "case_id": plan["case_id"],
        "plan_sha256": plan["sha256"],
        "attempt": 1,
        "reserved_at_utc": reserved,
        "consent": CONFIRM,
        "scope": plan["scope"],
        "historical_authority_granted": False,
    })


def verify_intent(plan, intent):

    evidence.verify_digest(intent)

    need(
        intent == make_intent(
            plan,
            intent["reserved_at_utc"],
        ),
        "INTENT_CHANGED",
    )

    return True


def calculate(plan, intent, receipt):

    verify_plan(plan)
    verify_intent(plan, intent)

    response = evidence.verify_transport(
        "FTP",
        receipt,
    )

    need(
        receipt["started_at_utc"]
            >= intent["reserved_at_utc"]
        and receipt["completed_at_utc"]
            >= receipt["started_at_utc"],
        "TEMPORAL_ORDER_INVALID",
    )

    units = [{
        "service_id": "FTP_DEV",
        "case_id": plan["case_id"],
        "assessment_index": 0,
        "initial_risk": plan["initial_risk"],
        "normalized_criticality":
            plan["normalized_criticality"],
        "replacement_risk":
            plan["replacement_risk"],
        "evidence": [],
    }]

    # No unaccredited evidence is inserted into A7.
    analytical = build_unit_bridge(
        units,
        [],
        weights=tuple(plan["weights"]),
    )

    verify_unit_bridge(analytical)

    interval = analytical["a7"]["results"][0]

    need(
        interval["evidence_lower"] == "0"
        and interval["evidence_upper"] == "1"
        and interval["confirmed_rf"] is None,
        "A7_BOUNDARY_INVALID",
    )

    stop = preview_stop(
        a6_classification="ND",
        accredited=False,
        vm_checked=False,
        operational_dispatch=False,
        source_sha256=receipt["sha256"],
    )

    verify_stop(stop)

    reference = evidence.reference_preview(
        "FTP",
        receipt["sha256"],
    )

    return seal({
        "schema": SCHEMA + "-result",
        "case_id": plan["case_id"],
        "plan_sha256": plan["sha256"],
        "intent_sha256": intent["sha256"],
        "receipt_sha256": receipt["sha256"],
        "observed_response": response,
        "input_kind": plan["input_kind"],
        "a6": "ND",
        "a7_analytical_bridge": analytical,
        "candidate_interval": {
            "lower": interval["rf_lower"],
            "upper": interval["rf_upper"],
        },
        "confirmed_rf": None,
        "a8": stop,
        "reference_i4": reference,
        "operational_a5_admitted": False,
        "operational_a9_published": False,
        "experimental_admission": False,
        "historical_contracts_changed": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def write_once(path, value):

    raw = ssh.canonical(value) + b"\n"

    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
    )

    fd = os.open(
        path,
        flags,
        0o600,
    )

    with os.fdopen(fd, "wb") as handle:

        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())

    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY,
    )

    try:
        os.fsync(directory)

    finally:
        os.close(directory)


def load(path):

    with path.open("rb") as handle:
        raw = handle.read(262145)

    need(
        0 < len(raw) <= 262144,
        "DOCUMENT_SIZE_INVALID",
    )

    value = json.loads(raw)

    need(
        raw == ssh.canonical(value) + b"\n",
        "NONCANONICAL_DOCUMENT",
    )

    return value


def run_local(folder, archive, code_head, confirmation):

    need(
        confirmation == CONFIRM,
        "EXPLICIT_CONSENT_REQUIRED",
    )

    need(
        os.geteuid() != 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    folder = Path(folder)

    # A pre-existing session is never reused for dispatch.
    folder.mkdir(mode=0o700, exist_ok=False)

    plan = make_plan(
        "PILOT_FTP_" + uuid.uuid4().hex.upper(),
        code_head,
        ssh.utc(),
        os.geteuid(),
    )

    write_once(folder / "plan.json", plan)

    intent = make_intent(
        plan,
        ssh.utc(),
    )

    # Intent is written before any FTP execution.
    write_once(folder / "intent.json", intent)

    receipt = transport.evaluate(
        "FTP",
        ftp_source=archive,
    )

    write_once(folder / "receipt.json", receipt)

    need(
        receipt["status"] == "FTP_GREETING_OBSERVED",
        "LOCAL_EXECUTION_INCOMPLETE",
    )

    result = calculate(
        plan,
        intent,
        receipt,
    )

    write_once(folder / "result.json", result)

    return result


def replay(folder):

    folder = Path(folder)

    expected = calculate(
        load(folder / "plan.json"),
        load(folder / "intent.json"),
        load(folder / "receipt.json"),
    )

    recorded = load(
        folder / "result.json"
    )

    need(
        ssh.canonical(recorded)
        == ssh.canonical(expected),
        "PILOT_REPLAY_MISMATCH",
    )

    return expected
