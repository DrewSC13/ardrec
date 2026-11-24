"""R262: missing-data-aware A4 prospective selection.

Reuse the exact native greedy selector. Never substitute zero
for an unknown value or authorize operational dispatch.
"""

import json
import os
import re

from pathlib import Path

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
)

from ardrec.experiments import reference_supports

from ardrec.selection import greedy_development as native


INPUT_SCHEMA = "ARDREC-R262-PRIORITY-INPUT-v1"
SCHEMA = "ARDREC-R262-ADAPTIVE-PRIORITY-v1"

WEIGHTS = ("1/3", "1/3", "1/3")

PHASES = {
    "PREPARADO", "PENDIENTE", "ACTIVO",
    "VALIDACION", "ACTUALIZADO", "PAUSADO",
    "CERRADO", "DETENIDO",
}

FAMILIES = {
    "SSH": "SSH-T06",
    "FTP": "FTP-T08",
    "SMB": "SMB-T09",
}

FIELDS = {
    "service_id", "case_id",
    "protocol", "family_id", "instance_id",
    "phase", "guard", "applicable",
    "baseline_closed", "precedence",
    "initial_risk", "evidence", "criticality",
    "source_preparation_sha256",
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def valid_sha(value):
    return (
        type(value) is str
        and re.fullmatch(
            r"[0-9a-f]{64}", value
        ) is not None
    )


def validate_candidate(row):

    need(
        type(row) is dict
        and set(row) == FIELDS,
        "CANDIDATE_SCHEMA_INVALID",
    )

    protocol = row["protocol"]

    need(
        protocol in FAMILIES
        and row["family_id"] == FAMILIES[protocol]
        and row["service_id"] == protocol + "_PILOT"
        and type(row["case_id"]) is str
        and native.IDENT.fullmatch(row["case_id"])
        and type(row["instance_id"]) is str
        and 0 < len(row["instance_id"]) <= 128
        and valid_sha(row["source_preparation_sha256"]),
        "CANDIDATE_IDENTITY_INVALID",
    )

    need(
        type(row["phase"]) is str
        and row["phase"] in PHASES
        and row["guard"] in ("VERDADERO", "FALSO", "ND")
        and (
            row["applicable"] is None
            or type(row["applicable"]) is bool
        )
        and type(row["baseline_closed"]) is bool,
        "CANDIDATE_STATE_INVALID",
    )

    precedence = row["precedence"]

    need(
        precedence is None
        or (
            type(precedence) is int
            and 0 <= precedence <= 1023
        ),
        "PRECEDENCE_INVALID",
    )

    for name in (
        "initial_risk",
        "evidence",
        "criticality",
    ):
        if row[name] is not None:
            native.rational(row[name])

    return True


def eligibility(row):

    if row["phase"] != "PENDIENTE":
        return "STATE_NOT_PENDING"

    if row["baseline_closed"] is not True:
        return "BASELINE_NOT_CLOSED"

    if row["guard"] != "VERDADERO":
        return "GUARD_NOT_TRUE"

    if row["applicable"] is not True:
        return "APPLICABILITY_NOT_CONFIRMED"

    return None


def build(source, expected_sha256):

    evidence.verify_digest(source)

    need(
        valid_sha(expected_sha256)
        and source["sha256"] == expected_sha256,
        "SOURCE_PIN_MISMATCH",
    )

    need(
        source["schema"] == INPUT_SCHEMA
        and source["scope"] == "PROSPECTIVE_REVIEW_ONLY"
        and source["operational_authority"] is False
        and source["formal_pilot_admitted"] == 0
        and source["experimental_admitted"] == 0
        and source["p7"] == "DRAFT_NOT_FROZEN"
        and source["p8"] == "NO-GO",
        "SOURCE_SCOPE_INVALID",
    )

    candidates = source["candidates"]

    need(
        type(candidates) is list
        and 0 < len(candidates) <= 64,
        "CANDIDATE_COUNT_INVALID",
    )

    for row in candidates:
        validate_candidate(row)

    need(
        len({
            (row["service_id"], row["case_id"])
            for row in candidates
        }) == len(candidates)
        and len({
            row["instance_id"]
            for row in candidates
        }) == len(candidates),
        "DUPLICATE_CANDIDATE",
    )

    rows = []
    complete = []
    unresolved = []

    for row in sorted(
        candidates,
        key=lambda r: (
            r["service_id"], r["case_id"]
        ),
    ):

        blocker = eligibility(row)

        missing = [
            field
            for field in (
                "initial_risk",
                "evidence",
                "criticality",
                "precedence",
            )
            if row[field] is None
        ]

        review = {
            "service_id": row["service_id"],
            "case_id": row["case_id"],
            "instance_id": row["instance_id"],
            "family_id": row["family_id"],
            "eligible": blocker is None,
            "blocker": blocker,
            "missing_priority_inputs": missing,
            "priority": None,
        }

        rows.append(review)

        if blocker is not None:
            continue

        if missing:
            unresolved.append(row["case_id"])
            continue

        complete.append({
            "service_id": row["service_id"],
            "case_id": row["case_id"],
            "phase": row["phase"],
            "guard": row["guard"],
            "applicable": row["applicable"],
            "precedence": row["precedence"],
            "initial_risk": row["initial_risk"],
            "evidence": row["evidence"],
            "criticality": row["criticality"],
        })

    result = None
    selected = None

    if unresolved:

        # Never rank only a known subset while another
        # eligible case has an unresolved priority.
        status = "ELIGIBLE_PRIORITY_UNRESOLVED"

    else:

        result = native.select_development(
            complete,
            source["sha256"],
            weights=WEIGHTS,
        )

        need(
            native.verify_selection(
                result, complete
            ),
            "NATIVE_SELECTION_REPLAY_INVALID",
        )

        priorities = {
            (
                item["service_id"],
                item["case_id"],
            ): item["priority"]
            for item in result["candidates"]
        }

        for row in rows:

            row["priority"] = priorities.get((
                row["service_id"],
                row["case_id"],
            ))

        selected = result["selected"]

        status = (
            "ANALYTICAL_SELECTION_AVAILABLE"
            if selected is not None
            else "NO_ELIGIBLE_CANDIDATES"
        )

    return durable.seal({
        "schema": SCHEMA,
        "source_sha256": source["sha256"],
        "scope": "PROSPECTIVE_REVIEW_ONLY",
        "status": status,
        "weights": list(WEIGHTS),
        "weights_frozen": False,
        "candidate_count": len(rows),
        "eligible_count": sum(
            row["eligible"] for row in rows
        ),
        "unresolved_eligible_count": len(unresolved),
        "unresolved_eligible_cases": unresolved,
        "known_priority_count": len(complete),
        "candidates": rows,
        "native_selection": result,
        "selected_preview": selected,
        "confirmed_operational_selection": None,
        "operational_dispatch": False,
        "a5_attempts_started": 0,
        "a6_classification": "ND",
        "confirmed_rf": None,
        "published_generation": None,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify(report, source, expected_sha256):

    evidence.verify_digest(report)

    need(
        report == build(source, expected_sha256),
        "REPORT_NOT_REPRODUCIBLE",
    )

    return True


def evaluate(path, expected_sha256):

    need(
        os.geteuid() != 0,
        "ROOT_FORBIDDEN",
    )

    source = json.loads(
        reference_supports.read_file(
            Path(path), 262144
        )
    )

    report = build(source, expected_sha256)

    verify(report, source, expected_sha256)

    return report


def render_text(report):

    lines = [
        "ARDREC / SELECCION PROSPECTIVA A4",
        "STATUS=" + report["status"],
        "CANDIDATES=" + str(report["candidate_count"]),
        "ELIGIBLE=" + str(report["eligible_count"]),
        "UNRESOLVED_ELIGIBLE=" + str(
            report["unresolved_eligible_count"]
        ),
    ]

    for row in report["candidates"]:

        lines.append(
            row["case_id"]
            + "|PRIORITY="
            + (row["priority"] or "ND")
            + "|BLOCKER="
            + (row["blocker"] or "NONE")
        )

    lines += [
        "ANALYTICAL_SELECTION="
            + str(report["selected_preview"]),
        "OPERATIONAL_SELECTION=ND",
        "A5_STARTS=0",
        "A6=ND",
        "CONFIRMED_RF=ND",
        "A9=NOT_PUBLISHED",
        "EXPERIMENTAL_ADMITTED=0",
        "P7=" + report["p7"],
        "P8=" + report["p8"],
        "REPORT_SHA256=" + report["sha256"],
    ]

    return "\n".join(lines) + "\n"
