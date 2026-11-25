"""A10 source-bound analytical review.

Reconstructs the expected native snapshots and ordinary closure
reports before exposing their contents.

No state mutation, physical dispatch or operational publication.
"""

import os
from pathlib import Path

from ardrec.analytical import check_frozen_compatibility

from ardrec.analytical_references import (
    ROLES,
    canonical,
    decode,
)

from ardrec.contracts import ND

from ardrec.coordination import (
    pilot_controller,
    pilot_observation,
    pilot_analytical_archive as native,
    prospective_local_pilot as durable,
)

from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
)

from ardrec.stopping import ordinary_closure as a8


SCHEMA = "ARDREC-R278-SOURCE-BOUND-READBACK-v1"


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def source_document(root, name, pin):

    root = Path(root)

    need(
        root.is_absolute()
        and root.resolve(strict=True) == root
        and root.is_dir(),
        "PRIVATE_SOURCE_DIRECTORY_INVALID",
    )

    doc = pilot_controller.read(root, name)

    return pilot_controller.verify_seal(doc, pin)


def index_payloads(snapshot):

    result = {}

    for raw in snapshot.references.object_bytes:

        obj = decode(raw)

        key = (
            obj["service_scenario_id"],
            obj["role"],
        )

        need(
            key not in result,
            "DUPLICATE_ANALYTICAL_REFERENCE",
        )

        result[key] = obj["payload"]

    expected = {
        (uid, role)
        for uid in pilot_controller.UNITS
        for role in ROLES
    }

    need(
        set(result) == expected,
        "ANALYTICAL_REFERENCE_SCOPE_INVALID",
    )

    return result


def evaluate_archived_unit(projection, payloads):

    uid = projection.service_scenario_id

    character = payloads[(uid, "characterization")]
    history = payloads[(uid, "history")]
    counters = payloads[(uid, "execution_counters")]
    repository = payloads[(uid, "evidence_repository")]
    controls = payloads[(uid, "pending_controls")]
    window = payloads[(uid, "convergence_window")]
    objective = payloads[(uid, "objective_status")]

    need(
        projection.operational_state.value == "PREPARADO"
        and isinstance(projection.frozen.initial_risk, ND)
        and isinstance(
            projection.frozen.normalized_criticality, ND
        )
        and isinstance(
            projection.analysis.accumulated_evidence, ND
        )
        and isinstance(
            projection.analysis.recalibrated_risk, ND
        )
        and projection.analysis.priority is None
        and character["operational_baseline_closed"] is False
        and history["operational_publications"] == 0
        and history["confirmed_rf"] is None
        and repository["a6"] == "ND"
        and repository["confirmed_evidence_count"] == 0
        and type(counters["operational_attempts"]) is int
        and counters["operational_attempts"] == 0
        and window["confirmed_samples"] == []
        and window["convergence_accredited"] is False
        and objective["technical_objective_accredited"] is False
        and controls["dispatch_allowed"] is False
        and type(controls["blockers"]) is list
        and len(controls["blockers"]) > 0,
        "ARCHIVED_UNIT_SCOPE_INVALID",
    )

    facts = {
        name: "ND"
        for name in a8.FACTS
    }

    # Known pending controls prevent a claim that
    # every outstanding action has been exhausted.

    facts["no_pending_work"] = "FALSO"

    result = a8.evaluate(
        facts=facts,
        history=[],
        executions=counters["operational_attempts"],
        budget=None,
        phase=projection.operational_state.value,
    )

    need(
        a8.verify(result)
        and result["criteria"] == {
            "ES": "ND",
            "SA": "FALSO",
            "CV": "FALSO",
            "LE": "ND",
        }
        and result["candidate_transition"] is None
        and result["applied_transition"] is None,
        "A8_RECONSTRUCTION_INVALID",
    )

    return result


def reconstruct_closure_report(snapshot, archive_report):

    payloads = index_payloads(snapshot)

    records = []

    for projection in snapshot.projections:

        uid = projection.service_scenario_id

        result = evaluate_archived_unit(
            projection,
            payloads,
        )

        records.append({
            "unit_id": uid,
            "source_snapshot_sha256":
                snapshot.snapshot_sha256,
            "previous_recommendation":
                payloads[(uid, "pending_controls")][
                    "a8_recommendation"
                ],
            "a8": result,
        })

    need(
        len(records) == 6
        and {
            row["unit_id"] for row in records
        } == pilot_controller.UNITS,
        "A8_UNIT_COVERAGE_INVALID",
    )

    return durable.seal({
        "schema": "ARDREC-R277-ARCHIVED-A8-REVIEW-v1",
        "source_r276_sha256": archive_report["sha256"],
        "source_snapshot_sha256":
            snapshot.snapshot_sha256,
        "records": records,
        "units_evaluated": 6,
        "ordinary_criteria_evaluated": 24,
        "confirmed_convergence_samples": 0,
        "candidate_closures": 0,
        "applied_transitions": 0,
        "operational_a9_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify_closure_report(snapshot, archive_report, supplied):

    expected = reconstruct_closure_report(
        snapshot, archive_report
    )

    need(
        canonical(supplied) == canonical(expected),
        "A8_SOURCE_REPLAY_MISMATCH",
    )

    return expected


def evaluate(
    archive_folder,
    closure_folder,
    preregistration_folder,
    execution_folder,
    recovery_folder,
    *,
    archive_pin,
    closure_pin,
    preregistration_pin,
    recovery_pin,
):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    archive_folder = Path(archive_folder)

    archive_report = source_document(
        archive_folder,
        "06-archive-report.json",
        archive_pin,
    )

    closure_report = source_document(
        closure_folder,
        "06-native-a8-report.json",
        closure_pin,
    )

    review = pilot_controller.evaluate(
        preregistration_folder,
        preregistration_pin,
    )

    observation = pilot_observation.evaluate(
        recovery_folder,
        execution_folder,
        preregistration_folder,
        recovery_pin,
    )

    need(
        archive_report["schema"] == native.SCHEMA
        and archive_report["scope"] ==
            "NON_OPERATIONAL_ANALYTICAL_REVIEW"
        and archive_report["source_controller_sha256"] ==
            review["sha256"]
        and archive_report["source_observation_sha256"] ==
            observation["sha256"]
        and archive_report["review_snapshots"] == 2
        and archive_report["native_projections_verified"] == 12
        and archive_report["native_reference_bindings_verified"] == 84
        and archive_report["frozen_characterizations_preserved"] == 6
        and archive_report["development_observations_archived"] == 3
        and archive_report["archive_reopen_verified"] is True
        and archive_report["archive_idempotence_verified"] is True
        and archive_report["confirmed_rf_count"] == 0
        and archive_report["operational_a9_publications"] == 0
        and archive_report["operational_dispatch"] is False
        and archive_report["formal_pilot_admitted"] == 0
        and archive_report["experimental_admitted"] == 0
        and archive_report["p7"] == "DRAFT_NOT_FROZEN"
        and archive_report["p8"] == "NO-GO",
        "ARCHIVE_REPORT_SCOPE_INVALID",
    )

    pins = archive_report["snapshot_sha256"]

    need(
        type(pins) is list
        and len(pins) == 2
        and len(set(pins)) == 2,
        "SNAPSHOT_IDENTITIES_INVALID",
    )

    expected_first = native.build_snapshot(
        review, None, 0
    )

    expected_second = native.build_snapshot(
        review, observation, 1
    )

    with AnalyticalArchive(
        archive_folder / "analytical-archive"
    ) as archive:

        first = native.verify_readback(
            archive, pins[0], expected_first
        )

        second = native.verify_readback(
            archive, pins[1], expected_second
        )

        for previous, current in zip(
            first.projections,
            second.projections,
            strict=True,
        ):

            check_frozen_compatibility(
                previous, current
            )

        closure = verify_closure_report(
            second,
            archive_report,
            closure_report,
        )

        payloads = index_payloads(second)

    decisions = {
        row["unit_id"]: row["a8"]
        for row in closure["records"]
    }

    rows = []

    for projection in second.projections:

        uid = projection.service_scenario_id

        character = payloads[(uid, "characterization")]
        repository = payloads[(uid, "evidence_repository")]
        counters = payloads[(uid, "execution_counters")]
        controls = payloads[(uid, "pending_controls")]
        window = payloads[(uid, "convergence_window")]

        result = decisions[uid]

        rows.append({
            "unit_id": uid,
            "protocol": character["protocol"],
            "family_id": character["family_id"],
            "profile": character["profile"],
            "phase": projection.operational_state.value,
            "initial_risk_candidate":
                character["initial_risk_candidate"],
            "criticality_candidate":
                character["criticality_candidate"],
            "hypothetical_rf_interval": [
                window["hypothetical_rf_lower"],
                window["hypothetical_rf_upper"],
            ],
            "confirmed_r0": None,
            "confirmed_rf": None,
            "development_observations":
                counters["development_observations"],
            "operational_attempts":
                counters["operational_attempts"],
            "support_entries": len(repository["i7"]),
            "supports_accredited": 0,
            "a6": repository["a6"],
            "a8_criteria": result["criteria"],
            "a8_stop": result["ordinary_stop"],
            "a8_decision": result["decision"],
            "previous_a8_recommendation":
                controls["a8_recommendation"],
            "blockers": list(controls["blockers"]),
            "candidate_transition": None,
            "applied_transition": None,
            "operational_generation": None,
        })

    need(
        len(rows) == 6
        and sum(
            row["development_observations"]
            for row in rows
        ) == 3
        and sum(
            row["support_entries"]
            for row in rows
        ) == 24
        and all(
            row["confirmed_rf"] is None
            and row["operational_attempts"] == 0
            and row["applied_transition"] is None
            for row in rows
        ),
        "READBACK_COVERAGE_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA,
        "scope": "SOURCE_BOUND_DEVELOPMENT_READBACK",
        "source_archive_sha256": archive_report["sha256"],
        "source_closure_sha256": closure["sha256"],
        "source_controller_sha256": review["sha256"],
        "source_observation_sha256": observation["sha256"],
        "snapshot_sha256": pins,
        "units": rows,
        "snapshots_reconstructed": 2,
        "projections_verified": 12,
        "references_verified": 84,
        "characterizations_preserved": 6,
        "a8_reports_reconstructed": 6,
        "a8_criteria_reconstructed": 24,
        "development_observations": 3,
        "operational_supports_accredited": 0,
        "operational_a9_publications": 0,
        "confirmed_rf_count": 0,
        "applied_transitions": 0,
        "new_protocol_attempts": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def render_text(report):

    lines = [
        "ARDREC / CONSULTA ANALITICA INTEGRADA",
        "SCOPE=" + report["scope"],
    ]

    for row in report["units"]:

        lines.extend([
            "",
            "UNIT=" + row["unit_id"],
            "PHASE=" + row["phase"],
            "R0_CANDIDATE=" + row["initial_risk_candidate"],
            "CN_CANDIDATE=" + row["criticality_candidate"],
            "RF_HYPOTHETICAL_INTERVAL=" + ",".join(
                row["hypothetical_rf_interval"]
            ),
            "RF_CONFIRMED=ND",
            "DEVELOPMENT_OBSERVATIONS=" + str(
                row["development_observations"]
            ),
            "A6=" + row["a6"],
            "A8=" + ",".join(
                name + ":" + row["a8_criteria"][name]
                for name in a8.ORDER
            ),
            "A8_STOP=" + row["a8_stop"],
            "A9=NOT_PUBLISHED",
        ])

        lines.extend(
            "BLOCKER=" + item
            for item in row["blockers"]
        )

    for key in (
        "snapshots_reconstructed",
        "projections_verified",
        "references_verified",
        "characterizations_preserved",
        "a8_reports_reconstructed",
        "a8_criteria_reconstructed",
        "development_observations",
        "operational_supports_accredited",
        "operational_a9_publications",
        "confirmed_rf_count",
        "applied_transitions",
        "new_protocol_attempts",
        "formal_pilot_admitted",
        "experimental_admitted",
        "p7",
        "p8",
    ):

        lines.append(
            key.upper() + "=" + str(report[key])
        )

    lines.append("REPORT_SHA256=" + report["sha256"])

    return "\n".join(lines) + "\n"
