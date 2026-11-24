"""I4: motor candidato de referencia metodologicamente independiente.

No acredita hechos tecnicos ni importa motores de riesgo ARDREC.
Los resultados son candidatos de valoracion, no observaciones admitidas.
"""
from __future__ import annotations

import hashlib
import json


SCHEMA = "ARDREC-I4-REFERENCE-CANDIDATE-v3"

COMMON_CHECKS = (
    "CE01_SERVICE_IDENTITY",
    "CE02_INITIAL_CONFIGURATION",
    "CE03_EXPOSURE",
    "CE04_ACCESS_CONTROLS",
    "CE05_CAPABILITIES_PERMISSIONS",
    "CE06_CONTROL_EFFECTIVENESS",
    "CE07_TECHNICAL_CONSEQUENCES",
    "CE08_FINAL_STATE_RESTORATION",
    "CE09_SUPPORT_PROVENANCE",
)

FACTS = {
    "exposure": (
        "NONE", "LIMITED", "PRESENT", "ND",
    ),
    "access_controls": (
        "EFFECTIVE", "WEAK", "FAILED", "ND",
    ),
    "capability": (
        "NONE",
        "VERIFIED_WEAKNESS",
        "VERIFIED_UNAUTHORIZED_CAPABILITY",
        "ND",
    ),
    "confidentiality": (
        "NONE", "LIMITED", "RELEVANT", "GRAVE", "NA", "ND",
    ),
    "integrity": (
        "NONE", "LIMITED", "RELEVANT", "GRAVE", "NA", "ND",
    ),
    "availability": (
        "NONE", "LIMITED", "RELEVANT", "GRAVE", "NA", "ND",
    ),
    "context": (
        "NONE", "LIMITED", "RELEVANT", "GRAVE", "NA", "ND",
    ),
}

IMPACTS = (
    "confidentiality",
    "integrity",
    "availability",
    "context",
)

SEVERITY = {
    "NONE": 0,
    "LIMITED": 1,
    "RELEVANT": 2,
    "GRAVE": 3,
}

LEVELS = {
    0: ("RESIDUAL_DESPRECIABLE", "0.00"),
    1: ("LIMITADO", "0.25"),
    2: ("MODERADO", "0.50"),
    3: ("ALTO", "0.75"),
    4: ("CRITICO", "1.00"),
}

ADDITIONAL_REASONS = (
    "MISSING_REQUIRED_SUPPORT",
    "CONTRADICTORY_SUPPORT",
    "AMBIGUOUS_APPLICABILITY",
    "UNRESOLVED_TECHNICAL_CONDITION",
)


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def canonical(value):

    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def digest(value):

    return hashlib.sha256(canonical(value)).hexdigest()


def validate_supports(value, required):

    need(
        type(value) is list and len(value) <= 32,
        "SUPPORT_LIST_INVALID",
    )

    need(
        all(
            type(item) is str
            and 0 < len(item) <= 128
            and item == item.strip()
            and all(
                c.isascii() and (
                    c.isalnum() or c in "_-.:"
                )
                for c in item
            )
            for item in value
        ),
        "SUPPORT_ID_INVALID",
    )

    need(
        len(value) == len(set(value)),
        "DUPLICATE_SUPPORT",
    )

    need(
        not required or bool(value),
        "SUPPORT_REQUIRED",
    )

    return sorted(value)


def normalize_record(record, allowed):

    need(
        type(record) is dict
        and set(record) == {"value", "supports", "reason"},
        "RECORD_SCHEMA_INVALID",
    )

    value = record["value"]
    reason = record["reason"]

    need(
        type(value) is str and value in allowed,
        "RECORD_VALUE_INVALID",
    )

    need(
        type(reason) is str
        and 0 < len(reason.strip()) <= 1000,
        "JUSTIFICATION_REQUIRED",
    )

    supports = validate_supports(
        record["supports"],
        required=value != "ND",
    )

    return {
        "value": value,
        "supports": supports,
        "reason": reason.strip(),
    }


def normalize(document):

    need(
        type(document) is dict
        and set(document) == {
            "unit_id",
            "protocol",
            "common_checks",
            "facts",
        },
        "INPUT_SCHEMA_INVALID",
    )

    unit = document["unit_id"]

    need(
        type(unit) is str
        and 0 < len(unit) <= 96
        and all(
            c.isascii() and (
                c.isalnum() or c in "_-."
            )
            for c in unit
        ),
        "UNIT_ID_INVALID",
    )

    need(
        document["protocol"] in ("SSH", "FTP", "SMB"),
        "PROTOCOL_INVALID",
    )

    checks = document["common_checks"]
    facts = document["facts"]

    need(
        type(checks) is dict
        and set(checks) == set(COMMON_CHECKS),
        "COMMON_CHECK_SET_INVALID",
    )

    need(
        type(facts) is dict
        and set(facts) == set(FACTS),
        "FACT_SET_INVALID",
    )

    return {
        "unit_id": unit,
        "protocol": document["protocol"],
        "common_checks": {
            key: normalize_record(
                checks[key],
                ("COMPLETE", "ND"),
            )
            for key in COMMON_CHECKS
        },
        "facts": {
            key: normalize_record(
                facts[key],
                allowed,
            )
            for key, allowed in FACTS.items()
        },
    }


def decide(values):

    if "ND" in values.values():
        return None, "UNRESOLVED_FACTS"

    exposure = values["exposure"]
    controls = values["access_controls"]
    capability = values["capability"]

    applicable = [
        values[key]
        for key in IMPACTS
        if values[key] != "NA"
    ]

    if not applicable:
        return None, "NO_APPLICABLE_IMPACT"

    severity = max(
        SEVERITY[value]
        for value in applicable
    )

    if (
        exposure == "NONE"
        and (
            capability != "NONE"
            or severity > 0
        )
    ):
        return None, "EXPOSURE_CONTRADICTION"

    if (
        controls == "EFFECTIVE"
        and capability ==
        "VERIFIED_UNAUTHORIZED_CAPABILITY"
    ):
        return None, "ACCESS_CONTROL_CONTRADICTION"

    if capability == "NONE":

        if (
            controls != "EFFECTIVE"
            or severity != 0
        ):
            return None, "UNRESOLVED_CONTROL_OR_IMPACT"

        if exposure == "NONE":
            return 0, "RESIDUAL_CONDITIONS_VERIFIED"

        return 1, "EXPOSURE_WITH_EFFECTIVE_CONTROLS"

    if severity == 3:
        return 4, "SUPPORTED_GRAVE_CONSEQUENCE"

    if severity == 2:

        if capability == "VERIFIED_UNAUTHORIZED_CAPABILITY":
            return 3, "SUPPORTED_RELEVANT_CONSEQUENCE"

        return None, "RELEVANT_CONSEQUENCE_UNRESOLVED"

    return 2, "BOUNDED_VERIFIED_WEAKNESS_OR_CAPABILITY"


def evaluate(document):

    normalized = normalize(document)

    complete = all(
        value["value"] == "COMPLETE"
        for value in normalized["common_checks"].values()
    )

    if not complete:

        level = None
        reason = "COMMON_EVIDENCE_INCOMPLETE"

    else:

        values = {
            key: value["value"]
            for key, value in normalized["facts"].items()
        }

        level, reason = decide(values)

    label, score = (
        ("ND", None)
        if level is None
        else LEVELS[level]
    )

    report = {
        "schema": SCHEMA,
        "unit_id": normalized["unit_id"],
        "protocol": normalized["protocol"],
        "input_sha256": digest(normalized),
        "level": level,
        "classification": label,
        "candidate_reference_score": score,
        "decision_reason": reason,
        "source_kind": "DECLARED_FACTS_CANDIDATE_ONLY",
        "input_facts_independently_authenticated": False,
        "method_outputs_used": False,
        "external_validation_claimed": False,
        "rubric_frozen": False,
        "confirmed_reference_score": None,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    report["sha256"] = digest(report)

    return report


def verify(document, report):

    need(
        canonical(evaluate(document)) == canonical(report),
        "REFERENCE_REPLAY_MISMATCH",
    )

    return True
