"""Consulta integrada de evidencia funcional local.

Read-only review of previously consolidated local observations.
No dispatch, accreditation or experimental admission.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from pathlib import Path

from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable
from ardrec.stopping.development_stop import verify_stop


SCHEMA = "ARDREC-R223-LOCAL-EVIDENCE-REVIEW-v1"

SOURCE_SCHEMA = (
    "ARDREC-R222-MULTIPROTOCOL-CONSOLIDATION-v1"
)

FAMILIES = {
    "SSH": "SSH-T06",
    "FTP": "FTP-T08",
    "SMB": "SMB-T09",
}

EXPECTED_CASES = {
    (
        f"PILOT-{protocol}-{index:02}",
        protocol,
        profile,
    )
    for protocol in FAMILIES
    for index, profile in (
        (1, "CONTROL"),
        (2, "CONTRAST"),
    )
}


def need(value, reason):

    if not value:
        raise ValueError(reason)


def valid_digest(value):

    return (
        type(value) is str
        and re.fullmatch(
            r"[0-9a-f]{64}", value
        ) is not None
    )


def load_families(path):

    path = Path(path)

    need(
        path.is_file() and not path.is_symlink(),
        "CATALOG_INVALID",
    )

    raw = path.read_bytes()

    need(
        hashlib.sha256(raw).hexdigest()
        == evidence.CATALOG_SHA256,
        "CATALOG_PIN_INVALID",
    )

    document = json.loads(raw)

    need(
        document["execution_enabled"] is False,
        "CATALOG_AUTHORITY_INVALID",
    )

    families = {
        row["id"]: row
        for row in document["families"]
    }

    need(
        len(families) == 25
        and len(document["families"]) == 25,
        "CATALOG_COUNT_INVALID",
    )

    return families


def support_review(unit, family):

    required = family["required_supports"]

    need(
        unit["required_supports"] == required,
        "FAMILY_SUPPORT_REQUIREMENTS_CHANGED",
    )

    protocol = unit["protocol"]

    result = []

    for name in required:

        status = "PENDING_INDIVIDUAL_VALIDATION"
        fields = []

        if unit["origin"] == "R219":

            status = "HISTORICAL_SOURCE_RETAINED"

        elif name == "RESOURCE_READ":

            status = "LOCAL_OBSERVATION_DOCUMENTED"

            fields = [
                "allowed_status",
                "allowed_bytes",
            ]

        elif name == "KNOWN_CONTENT_DIGEST":

            need(
                valid_digest(unit["allowed_sha256"]),
                "RESOURCE_DIGEST_INVALID",
            )

            status = "LOCAL_DIGEST_DOCUMENTED"

            fields = [
                "allowed_sha256",
                "restricted_sha256",
            ]

        elif name in (
            "ACCESS_COMPARISON",
            "OPERATION_RESPONSE",
        ) and protocol == "SMB":

            status = "LOCAL_OBSERVATION_DOCUMENTED"

            fields = [
                "allowed_status",
                "restricted_status",
                "restricted_bytes",
            ]

        elif name in (
            "TARGET_ATTESTATION",
            "INTEGRITY_PROVENANCE",
        ):

            status = "LOCAL_REFERENCES_DOCUMENTED"

            fields = [
                "plan_sha256",
                "context_sha256",
                "binding_sha256",
            ]

        result.append({
            "support": name,
            "status": status,
            "source_fields": fields,
            "operationally_accredited": False,
        })

    return result


def review_unit(wrapper, families):

    evidence.verify_digest(wrapper)

    unit = wrapper["unit"]

    evidence.verify_digest(unit)
    verify_stop(wrapper["a8"])

    need(
        wrapper["a8"]["source_sha256"]
        == unit["sha256"],
        "STOP_SOURCE_MISMATCH",
    )

    protocol = unit["protocol"]
    profile = unit["profile"]
    case_id = unit["case_id"]

    need(
        (case_id, protocol, profile) in EXPECTED_CASES,
        "CASE_IDENTITY_INVALID",
    )

    family_id = FAMILIES[protocol]

    need(
        unit["family"] == family_id
        and unit["variant"]
            == (None if protocol == "SSH" else "READ"),
        "FAMILY_IDENTITY_INVALID",
    )

    need(
        unit["a2_baseline_closed"] is False
        and unit["a4_adaptive_selection_verified"] is False
        and unit["a5_operational_admitted"] is False
        and unit["a6"] == "ND"
        and unit["initial_risk"] is None
        and unit["confirmed_rf"] is None
        and unit["a9_operational_published"] is False
        and unit["i4"] == "ND"
        and unit["formal_pilot_admission"] is False
        and unit["experimental_admission"] is False,
        "FALSE_OPERATIONAL_PROMOTION",
    )

    need(
        unit["allowed_status"] == "READ_OK"
        and type(unit["restricted_bytes"]) is int
        and (
            (
                profile == "CONTROL"
                and unit["restricted_status"]
                    == "ACCESS_DENIED"
                and unit["restricted_bytes"] == 0
            )
            or (
                profile == "CONTRAST"
                and unit["restricted_status"] == "READ_OK"
                and unit["restricted_bytes"] > 0
            )
        ),
        "LOCAL_OBSERVATION_INVALID",
    )

    normalized = protocol != "FTP"

    if normalized:

        need(
            unit["origin"] == "R221"
            and unit["source_kind"]
                == "REAL_LOCAL_FUNCTIONAL_RECEIPT"
            and unit["attempts"] == 1
            and unit["a3_local_consent_recorded"] is True
            and unit["a5_local_attempt_recorded"] is True
            and all(
                valid_digest(unit[name])
                for name in (
                    "source_receipt_sha256",
                    "plan_sha256",
                    "context_sha256",
                    "binding_sha256",
                    "snapshot_sha256",
                )
            ),
            "LOCAL_RECEIPT_BINDING_INVALID",
        )

    else:

        need(
            unit["origin"] == "R219"
            and unit["source_kind"]
                == "PRIOR_APPROVED_LOCAL_REHEARSAL_REPORT"
            and unit["individual_receipt_normalized"]
                is False
            and valid_digest(unit["source_summary_pin"])
            and valid_digest(unit["comparison_summary_pin"]),
            "HISTORICAL_SOURCE_INVALID",
        )

    blockers = [
        "BASELINE_NOT_CLOSED",
        "ADAPTIVE_SELECTION_NOT_VERIFIED",
        "OPERATIONAL_A6_NOT_ACCREDITED",
        "CONFIRMED_RISK_UNAVAILABLE",
        "OPERATIONAL_A9_NOT_PUBLISHED",
        "INDEPENDENT_REFERENCE_UNAVAILABLE",
        "FORMAL_PILOT_NOT_ADMITTED",
    ]

    if not normalized:

        blockers.insert(
            0,
            "FTP_INDIVIDUAL_NORMALIZATION_PENDING",
        )

    return {
        "case_id": case_id,
        "protocol": protocol,
        "family": family_id,
        "profile": profile,
        "origin": unit["origin"],
        "source_unit_sha256": unit["sha256"],
        "source_kind": unit["source_kind"],
        "individual_receipt_normalized": normalized,
        "allowed_status": unit["allowed_status"],
        "restricted_status": unit["restricted_status"],
        "restricted_bytes": unit["restricted_bytes"],
        "supports": support_review(
            unit,
            families[family_id],
        ),
        "stages": {
            "A1": "CATALOG_FAMILY_IDENTIFIED",
            "A2": "BASELINE_NOT_CLOSED",
            "A3": (
                "LOCAL_CONSENT_DOCUMENTED"
                if normalized else "PRIOR_SOURCE_RETAINED"
            ),
            "A4": "ADAPTIVE_SELECTION_NOT_VERIFIED",
            "A5": (
                "LOCAL_ATTEMPT_DOCUMENTED"
                if normalized else "PRIOR_SOURCE_RETAINED"
            ),
            "A6": "ND",
            "A7": "CONFIRMED_RF_UNAVAILABLE",
            "A8": wrapper["a8"]["recommendation"],
            "A9": "NOT_PUBLISHED",
            "A10": "READ_ONLY_REPORT_AVAILABLE",
        },
        "a6": "ND",
        "confirmed_rf": None,
        "reference_i4": "ND",
        "formal_pilot_admission": False,
        "experimental_admission": False,
        "blockers": blockers,
    }


def review_report(source, expected_sha256, families):

    need(
        valid_digest(expected_sha256),
        "EXPECTED_DIGEST_INVALID",
    )

    evidence.verify_digest(source)

    need(
        source["sha256"] == expected_sha256,
        "SOURCE_PIN_MISMATCH",
    )

    need(
        source["schema"] == SOURCE_SCHEMA
        and source["scope"]
            == "PRELIMINARY_LOCAL_FUNCTIONAL_EVIDENCE"
        and source["catalog_sha256"]
            == evidence.CATALOG_SHA256
        and source["preliminary_units"] == 6
        and source["individual_r221_receipts_linked"] == 4
        and source["r219_units_retained"] == 2
        and source["r219_individual_receipts_normalized"] == 0
        and source["network_operations"] == 0
        and source["physical_reexecutions"] == 0
        and source["operational_a6_admitted"] == 0
        and source["confirmed_rf_count"] == 0
        and source["a8_operational_transitions"] == 0
        and source["a9_operational_publications"] == 0
        and source["formal_pilot_admitted"] == 0
        and source["experimental_admitted"] == 0
        and source["experimental_pairs_available"] == 0
        and source["p7"] == "DRAFT_NOT_FROZEN"
        and source["p8"] == "NO-GO",
        "SOURCE_AUTHORITY_BOUNDARY_INVALID",
    )

    rows = [
        review_unit(wrapper, families)
        for wrapper in source["units"]
    ]

    need(
        len(rows) == 6
        and {
            (
                row["case_id"],
                row["protocol"],
                row["profile"],
            )
            for row in rows
        } == EXPECTED_CASES,
        "CASE_SET_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA,
        "scope": "READ_ONLY_LOCAL_EVIDENCE_REVIEW",
        "source_sha256": source["sha256"],
        "source_head": source["candidate_head"],
        "cases": rows,
        "preliminary_units": len(rows),
        "protocols": len({
            row["protocol"]
            for row in rows
        }),
        "families_exercised": len({
            row["family"]
            for row in rows
        }),
        "normalized_receipts": sum(
            row["individual_receipt_normalized"]
            for row in rows
        ),
        "historical_units_retained": sum(
            not row["individual_receipt_normalized"]
            for row in rows
        ),
        "required_support_entries": sum(
            len(row["supports"])
            for row in rows
        ),
        "operational_supports_accredited": 0,
        "operational_a6_admitted": 0,
        "confirmed_rf_count": 0,
        "a8_operational_transitions": 0,
        "a9_operational_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "experimental_pairs_available": 0,
        "network_operations": 0,
        "physical_reexecutions": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def evaluate(path, expected_sha256, catalog):

    need(
        os.geteuid() > 0,
        "ROOT_FORBIDDEN",
    )

    path = Path(path)

    need(
        path.is_file() and not path.is_symlink(),
        "SOURCE_FILE_INVALID",
    )

    return review_report(
        durable.load(path),
        expected_sha256,
        load_families(catalog),
    )


def render_text(report):

    lines = [
        "ARDREC / CONSULTA INTEGRADA DE EVIDENCIA LOCAL",
        "ALCANCE=" + report["scope"],
        "ORIGEN_SHA256=" + report["source_sha256"],
    ]

    for row in report["cases"]:

        lines.extend([
            "",
            (
                row["case_id"] + " "
                + row["family"] + " "
                + row["profile"]
            ),
            "ORIGEN=" + row["origin"],
            "LECTURA_AUTORIZADA=" + row["allowed_status"],
            "LECTURA_RESTRINGIDA=" + row["restricted_status"],
            "BYTES_RESTRINGIDOS=" + str(row["restricted_bytes"]),
        ])

        for stage, status in row["stages"].items():

            lines.append(stage + "=" + status)

        for support in row["supports"]:

            lines.append(
                "SOPORTE="
                + support["support"]
                + ":"
                + support["status"]
            )

        lines.append(
            "BLOQUEOS=" + ",".join(row["blockers"])
        )

    for key in (
        "preliminary_units",
        "protocols",
        "families_exercised",
        "normalized_receipts",
        "historical_units_retained",
        "required_support_entries",
        "operational_supports_accredited",
        "operational_a6_admitted",
        "confirmed_rf_count",
        "a8_operational_transitions",
        "a9_operational_publications",
        "formal_pilot_admitted",
        "experimental_admitted",
        "experimental_pairs_available",
        "network_operations",
        "physical_reexecutions",
        "p7",
        "p8",
    ):

        lines.append(
            key.upper() + "=" + str(report[key])
        )

    lines.append(
        "REPORT_SHA256=" + report["sha256"]
    )

    return "\n".join(lines) + "\n"
