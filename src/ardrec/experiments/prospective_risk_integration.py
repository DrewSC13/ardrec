"""R232: prospective I2 to native A7/A8 integration.

Documentary baseline candidates are not frozen baselines.
Unaccredited evidence stays ND and retains full uncertainty.
No operational A6, A9 publication, dispatch or experimental admission.
"""

from __future__ import annotations

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
)

from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge,
    verify_unit_bridge,
)

from ardrec.experiments import (
    baseline_preparation as baseline,
    initial_assessment as initial,
)


SCHEMA = "ARDREC-R232-PROSPECTIVE-RISK-v1"

WEIGHTS = ("1/3", "1/3", "1/3")


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def validate_baseline(report):

    evidence.verify_digest(report)

    need(
        report["schema"] == baseline.SCHEMA
        and report["planned_slots"] == 54
        and report["baselines_closed"] == 0
        and report["experimental_observations"] == 0
        and report["network_operations"] == 0,
        "SOURCE_BASELINE_INVALID",
    )

    for key, value in baseline.boundaries().items():

        need(
            report[key] == value,
            "BASELINE_AUTHORITY_MISMATCH:" + key,
        )

    slots = report["slots"]

    need(
        type(slots) is list
        and len(slots) == 54
        and len({row["slot_id"] for row in slots}) == 54,
        "BASELINE_SLOT_SET_INVALID",
    )

    expected_slots = {
        f"{protocol}-{index:02}"
        for protocol in ("SSH", "FTP", "SMB")
        for index in range(1, 19)
    }

    need(
        {row["slot_id"] for row in slots} == expected_slots
        and all(
            row["baseline_closed"] is False
            and row["initial_risk"] is None
            and row["normalized_criticality"] is None
            for row in slots
        ),
        "BASELINE_SLOT_PROMOTION_FORBIDDEN",
    )

    candidate = report["candidate"]

    if candidate is None:

        need(
            report["documentary_candidates_calculated"] == 0,
            "BASELINE_CANDIDATE_COUNT_INVALID",
        )

        return None

    evidence.verify_digest(candidate)

    need(
        candidate["schema"] == baseline.SCHEMA + "-candidate"
        and candidate["scope"] == "DOCUMENTARY_BASELINE_CANDIDATE"
        and candidate["selection_sha256"] == report["selection_sha256"]
        and candidate["support_integrity_verified"] is True
        and candidate["scope_authority_authenticated"] is False
        and candidate["static_freeze_authenticated"] is False
        and report["documentary_candidates_calculated"] == 1,
        "BASELINE_CANDIDATE_INVALID",
    )

    for key, value in baseline.boundaries().items():

        need(
            candidate[key] == value,
            "CANDIDATE_AUTHORITY_MISMATCH:" + key,
        )

    matches = [
        row for row in slots
        if row["slot_id"] == candidate["slot_id"]
    ]

    need(
        len(matches) == 1
        and matches[0]["protocol"] == candidate["protocol"]
        and matches[0]["chosen_family"] == candidate["family_id"]
        and matches[0]["selection_status"] == "COMPLETE_UNVERIFIED",
        "CANDIDATE_SLOT_BINDING_INVALID",
    )

    ratings = candidate["ratings"]

    need(
        set(ratings) == set(initial.DIMENSIONS),
        "CANDIDATE_DIMENSIONS_INVALID",
    )

    values = {
        name: initial.ordinal(ratings[name]["ordinal"])
        for name in initial.DIMENSIONS
    }

    calculated = initial.compute(
        values["exposure"],
        values["probability"],
        values["impact"],
        [
            values["operational_importance"],
            values["data_sensitivity"],
            values["dependencies"],
        ],
    )

    need(
        calculated == candidate["calculated"],
        "BASELINE_ARITHMETIC_MISMATCH",
    )

    return candidate


def build(baseline_report):

    candidate = validate_baseline(baseline_report)

    bridge = None
    decision = None
    initial_risk = None
    criticality = None

    status = "BLOCKED_BASELINE_UNAVAILABLE"

    if candidate is not None:

        calculated = candidate["calculated"]

        initial_risk = calculated["initial_risk"]
        criticality = calculated["normalized_criticality"]

        # R58-D/R58-E support the native DEV identity domain.
        # The canonical slot is a mathematical surrogate,
        # not an actual service identity or physical attestation.

        native_identity = {
            "service_id": candidate["protocol"] + "_DEV",
            "case_id": candidate["slot_id"],
            "assessment_index": 0,
        }

        native_input = {
            **native_identity,
            "initial_risk": initial_risk,
            "normalized_criticality": criticality,

            # No validated replacement condition exists.
            # Preserve R0 as the replacement candidate.
            "replacement_risk": initial_risk,

            # No simulated contribution can be injected.
            "evidence": [],
        }

        bridge = build_unit_bridge(
            [native_input],
            [],
            weights=WEIGHTS,
        )

        need(
            verify_unit_bridge(bridge)
            and bridge["unit_count"] == 1
            and bridge["all_a6_nd"] is True
            and bridge["operational_dispatch"] is False
            and bridge["published_generation"] is None,
            "NATIVE_BRIDGE_BOUNDARY_INVALID",
        )

        native = bridge["decisions"][0]

        interval = bridge["a7"]["results"][0]

        need(
            interval["evidence_lower"] == "0"
            and interval["evidence_upper"] == "1"
            and native["a6_classification"] == "ND"
            and native["confirmed_rf"] is None
            and native["a8_applied_transition"] is None,
            "UNKNOWN_EVIDENCE_COLLAPSED",
        )

        decision = {
            "slot_id": candidate["slot_id"],
            "case_id": candidate["case_id"],
            "scenario_id": candidate["scenario_id"],
            "service_instance_id": candidate["service_instance_id"],
            "family_id": candidate["family_id"],
            "native_dev_identity": native_identity,
            "identity_mapping": "MATHEMATICAL_SURROGATE_ONLY",
            "candidate_initial_risk": initial_risk,
            "candidate_normalized_criticality": criticality,
            "candidate_replacement_risk": initial_risk,
            "evidence_lower": "0",
            "evidence_upper": "1",
            "hypothetical_rf_lower": native["a7_rf_lower"],
            "hypothetical_rf_upper": native["a7_rf_upper"],
            "a6_classification": "ND",
            "a8_recommendation": native["a8_recommendation"],
            "confirmed_rf": None,
            "applied_transition": None,
            "published_generation": None,
            "technical_truth_accredited": False,
            "experimental_admission": False,
        }

        status = "MATHEMATICAL_CANDIDATE_REPRODUCED"

    return durable.seal({
        "schema": SCHEMA,
        "baseline_report_sha256": baseline_report["sha256"],
        "selection_sha256": baseline_report["selection_sha256"],
        "planned_slots": 54,
        "documentary_candidate_count": int(candidate is not None),
        "candidate_sha256": (
            candidate["sha256"]
            if candidate is not None else None
        ),
        "candidate_decision": decision,
        "native_bridge": bridge,
        "status": status,
        "weights": list(WEIGHTS),
        "weights_frozen": False,
        "baseline_closed": False,
        "a4_operational_selection": None,
        "a5_attempts_started": 0,
        "a6_classification": "ND",
        "confirmed_rf": None,
        "applied_transition": None,
        "published_generation": None,
        "operational_dispatch": False,
        "technical_truth_accredited": False,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "network_operations": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify(report, baseline_report):

    evidence.verify_digest(report)

    need(
        build(baseline_report) == report,
        "RISK_REPORT_NOT_REPRODUCIBLE",
    )

    return True


def evaluate(*args, **kwargs):

    source = baseline.evaluate(*args, **kwargs)

    report = build(source)

    verify(report, source)

    return report


def render_text(report):

    lines = [
        "ARDREC / INTEGRACION PROSPECTIVA I2-A7-A8",
        "STATUS=" + report["status"],
        "PLANNED_SLOTS=54",
        "DOCUMENTARY_CANDIDATES="
            + str(report["documentary_candidate_count"]),
    ]

    candidate = report["candidate_decision"]

    if candidate is not None:

        lines.extend([
            "SLOT=" + candidate["slot_id"],
            "R0_CANDIDATE="
                + candidate["candidate_initial_risk"],
            "CN_CANDIDATE="
                + candidate["candidate_normalized_criticality"],
            "EVIDENCE_INTERVAL=[0,1]",
            "HYPOTHETICAL_RF_LOWER="
                + candidate["hypothetical_rf_lower"],
            "HYPOTHETICAL_RF_UPPER="
                + candidate["hypothetical_rf_upper"],
            "A8=" + candidate["a8_recommendation"],
        ])

    lines.extend([
        "A6=ND",
        "CONFIRMED_RF=ND",
        "A9=NOT_PUBLISHED",
        "EXPERIMENTAL_ADMITTED=0",
        "P7=DRAFT_NOT_FROZEN",
        "P8=NO-GO",
        "REPORT_SHA256=" + report["sha256"],
    ])

    return "\n".join(lines) + "\n"
