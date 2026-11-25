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

    # R286: validate the entire historical scope before evaluating A8.
    # These are the R276 review semantics, not an operational gate.
    baseline_nd = ND("BASELINE_NOT_CLOSED")
    evidence_nd = ND("EVIDENCE_NOT_ACCREDITED")
    generation = projection.generation_index
    observed = generation == 1 and uid in native.CONTROLS
    supports = repository["i7"]

    need(
        uid in pilot_controller.UNITS
        and generation in (0, 1)
        and projection.operational_state.value == "PREPARADO"
        and projection.frozen.initial_risk == baseline_nd
        and projection.frozen.normalized_criticality == baseline_nd
        and projection.analysis.accumulated_evidence == evidence_nd
        and projection.analysis.substituted_baseline == baseline_nd
        and projection.analysis.upper_bound == evidence_nd
        and projection.analysis.lower_adjustment_bound == baseline_nd
        and projection.analysis.recalibrated_risk == evidence_nd
        and projection.analysis.priority is None
        and character["operational_baseline_closed"] is False
        and character["protocol"] == uid.split("-")[1]
        and character["family_id"] == pilot_controller.FAMILIES[character["protocol"]]
        and character["profile"] == ("CONTROL" if uid in native.CONTROLS else "CONTRAST")
        and type(history["review_generation"]) is int
        and history["review_generation"] == generation
        and history["native_phase"] == "PREPARADO"
        and type(history["operational_publications"]) is int
        and history["operational_publications"] == 0
        and history["confirmed_rf"] is None
        and repository["a6"] == "ND"
        and type(repository["confirmed_evidence_count"]) is int
        and repository["confirmed_evidence_count"] == 0
        and type(supports) is list and len(supports) == 4
        and all(type(item) is dict and type(item.get("support")) is str
                and item.get("operationally_accredited") is False for item in supports)
        and len({item["support"] for item in supports}) == 4
        and type(counters["development_observations"]) is int
        and counters["development_observations"] == int(observed)
        and type(counters["operational_attempts"]) is int
        and counters["operational_attempts"] == 0
        and counters["automatic_retry"] is False
        and (repository["i3"] is not None) == observed
        and (counters["i6"] is not None) == observed
        and window["confirmed_samples"] == []
        and window["convergence_accredited"] is False
        and objective["technical_objective_accredited"] is False
        and objective["selected_for_dispatch"] is False
        and objective["status"] == "ND"
        and controls["a3_authority"] == "ND"
        and controls["a4_operational_selection"] is None
        and controls["dispatch_allowed"] is False
        and controls["blockers"] == list(pilot_controller.BLOCKERS),
        "ARCHIVED_UNIT_SCOPE_INVALID",
    )

    if observed:
        i3, i6 = repository["i3"], counters["i6"]
        need(
            type(i3) is dict and type(i6) is dict
            and i3["unit_id"] == uid
            and i3["instance_id"] == character["instance_id"]
            and i3["plan_sha256"] == character["plan_sha256"]
            and i3["experimental_admission"] is False
            and i6["operational_attempt_admitted"] is False
            and i6["automatic_retry"] is False,
            "ARCHIVED_DEVELOPMENT_OBSERVATION_INVALID",
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
    unit_id=None,
):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    need(unit_id is None or unit_id == "todas" or unit_id in pilot_controller.UNITS,
         "PILOT_UNIT_UNKNOWN")

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

    report = durable.seal({
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


    if unit_id is None:
        return report

    prereg = source_document(
        preregistration_folder, "05-pilot-preregistration.json",
        preregistration_pin,
    )
    if unit_id == "todas":
        return explain_batch(report, second, prereg, review,
            lambda relative: pilot_controller.read(Path(preregistration_folder), relative))
    record = next(row for row in prereg["records"]
                  if row["unit_id"] == unit_id)
    controller_unit = next(row for row in review["units"]
                           if row["unit_id"] == unit_id)
    return explain_unit(report, second, record, controller_unit, preregistration_pin)


def explain_unit(report, snapshot, record, controller_unit, preregistration_pin):
    """Project a previously verified replay; never grant current authority."""
    uid = record["unit_id"]
    rows = [row for row in report["units"] if row["unit_id"] == uid]
    need(len(rows) == 1 and uid == controller_unit["unit_id"],
         "REPLAY_UNIT_BINDING_INVALID")
    row = rows[0]
    payloads = index_payloads(snapshot)
    character = payloads[(uid, "characterization")]
    controls = payloads[(uid, "pending_controls")]
    bindings = {(item["service_scenario_id"], item["role"]): item
                for item in decode(snapshot.references.manifest_bytes)["bindings"]}
    need(snapshot.snapshot_sha256 == report["snapshot_sha256"][-1]
         and character["operational_baseline_closed"] is False
         and controller_unit["baseline_closed"] is False
         and controls["dispatch_allowed"] is False
         and controls["blockers"] == row["blockers"]
         and tuple(row["blockers"]) == pilot_controller.BLOCKERS
         and character["plan_sha256"] == record["plan_sha256"]
         == controller_unit["plan_sha256"]
         and character["source_preregistration_sha256"]
         == preregistration_pin
         and controller_unit["native_t1_rejection"] == "authority_unverified",
         "REPLAY_GUARD_BINDING_INVALID")
    return durable.seal({
        "schema": "ARDREC-R281-UNIT-REPLAY-v1",
        "scope": "HISTORICAL_DEVELOPMENT_READBACK_ONLY",
        "readback_sha256": report["sha256"],
        "snapshot_sha256": snapshot.snapshot_sha256,
        "unit": row,
        "first_pending_guard": {
            "code": row["blockers"][0],
            "ordering": "ARCHIVED_CONTROLLER_BLOCKER_ORDER",
            "status": "NOT_CLOSED_IN_ARCHIVED_SOURCE",
            "current_operational_status": "ND",
            "support": [
                {"file": f"method/{uid}/I1.json", "field": "baseline_closed",
                 "value": False, "document_sha256": record["i1_sha256"]},
                {"file": f"method/{uid}/I2.json", "field": "operational_baseline_closed",
                 "value": False, "document_sha256": record["i2_sha256"]},
            ],
            "characterization": bindings[(uid, "characterization")],
            "pending_controls": bindings[(uid, "pending_controls")],
            "preregistration_sha256": preregistration_pin,
        },
        "native_t1_rejection": controller_unit["native_t1_rejection"],
        "plan_sha256": record["plan_sha256"],
        "new_protocol_attempts": 0,
        "operational_a9_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": report["p7"], "p8": report["p8"],
    })


def explain_batch(report, snapshot, prereg, review, read_document):
    """One verified reconstruction, all historical guards, no current authority."""
    pin = prereg["sha256"]
    records = pilot_controller.validate_source(prereg, pin)
    pilot_controller.verify_seal(report)
    pilot_controller.recover_state(review)
    need(report["source_controller_sha256"] == review["sha256"]
         and review["source_sha256"] == pin
         and report["p7"] == "DRAFT_NOT_FROZEN" and report["p8"] == "NO-GO"
         and report["scope"] == "SOURCE_BOUND_DEVELOPMENT_READBACK",
         "BATCH_SOURCE_BINDING_INVALID")
    controllers = {row["unit_id"]: row for row in review["units"]}
    need(len(review["units"]) == len(controllers) == 6
         and set(controllers) == pilot_controller.UNITS,
         "BATCH_UNIT_SET_INVALID")
    payloads = index_payloads(snapshot)
    units = []
    for rec in sorted(records, key=lambda row: row["unit_id"]):
        uid = rec["unit_id"]
        item = explain_unit(report, snapshot, rec, controllers[uid], pin)
        def document(name, expected):
            relative = f"method/{uid}/{name}.json"
            doc = pilot_controller.verify_seal(read_document(relative), expected)
            need(doc["unit_id"] == uid
                 and doc["schema"] == pilot_controller.SOURCE_SCHEMA + "-" + name,
                 "BATCH_DOCUMENT_CONTEXT_INVALID")
            return doc
        i1 = document("I1", rec["i1_sha256"])
        i2 = document("I2", rec["i2_sha256"])
        plan = document("plan", rec["plan_sha256"])
        need(plan["i1_sha256"] == i1["sha256"] == i2["i1_sha256"]
             and plan["i2_sha256"] == i2["sha256"], "BATCH_DAG_INVALID")
        controls = payloads[(uid, "pending_controls")]
        def fact(name, doc, field, value):
            need(type(doc[field]) is type(value) and doc[field] == value,
                 "BATCH_HISTORICAL_FACT_MISMATCH:" + name + ":" + field)
            return {"file": f"method/{uid}/{name}.json", "field": field,
                    "value": value, "document_sha256": doc["sha256"]}
        first = item["first_pending_guard"]
        native = first["pending_controls"]
        def guard(code, status, supports):
            need(code in pilot_controller.BLOCKERS, "BATCH_GUARD_UNKNOWN")
            return {"code": code, "historical_status": status,
                    "current_operational_status": "ND", "supports": supports}
        guards = [
            guard(pilot_controller.BLOCKERS[0], "NOT_CLOSED_IN_ARCHIVED_SOURCE", [
                fact("I1", i1, "baseline_closed", False),
                fact("I2", i2, "operational_baseline_closed", False)]),
            guard(pilot_controller.BLOCKERS[1], "PENDING_IN_ARCHIVED_I1", [
                fact("I1", i1, "service_specific_identity_pending", True)]),
            guard(pilot_controller.BLOCKERS[2], "PENDING_IN_ARCHIVED_I1", [
                fact("I1", i1, "fresh_service_credentials_pending", True)]),
            guard(pilot_controller.BLOCKERS[3], "AUTHORITY_ND_IN_ARCHIVED_REVIEW", [
                fact("plan", plan, "guard", "ND"),
                fact("plan", plan, "execution_authorized", False),
                {"reference": native, "field": "a3_authority", "value": "ND"}]),
            guard(pilot_controller.BLOCKERS[4], "ARCHIVED_BLOCKER_ONLY_CURRENT_CONTRACT_ND", [
                {"reference": native, "field": "blockers", "value": pilot_controller.BLOCKERS[4]},
                {"reference": native, "field": "dispatch_allowed", "value": False}]),
        ]
        need(controls["a3_authority"] == "ND" and controls["dispatch_allowed"] is False
             and tuple(g["code"] for g in guards) == tuple(controls["blockers"]),
             "BATCH_GUARD_SOURCE_INVALID")
        units.append({"unit_id": uid, "replay": item, "guards": guards,
                      "static_method": fact("I2", i2, "static_method_definitively_frozen", False)})
    return durable.seal({"schema": "ARDREC-R284-GUARD-BATCH-v1",
        "scope": "HISTORICAL_DEVELOPMENT_READBACK_ONLY",
        "readback_sha256": report["sha256"], "snapshot_sha256": snapshot.snapshot_sha256,
        "preregistration_sha256": pin, "units": units, "units_replayed": len(units),
        "historical_guards_explained": sum(len(u["guards"]) for u in units),
        "current_guards_accredited": 0, "new_protocol_attempts": 0,
        "operational_a9_publications": 0, "formal_pilot_admitted": 0,
        "experimental_admitted": 0, "p7": report["p7"], "p8": report["p8"]})


def render_batch_text(report):
    lines = ["ARDREC / REAPERTURA HISTORICA INTEGRADA", "SCOPE=" + report["scope"]]
    for unit in report["units"]:
        row = unit["replay"]["unit"]
        lines.append(f'UNIT={unit["unit_id"]} PHASE={row["phase"]} DECISION={row["a8_decision"]}')
        for guard in unit["guards"]:
            lines.append(f'  GUARD={guard["code"]} HISTORICAL={guard["historical_status"]} CURRENT=ND')
            for support in guard["supports"]:
                if "file" in support:
                    source = support["file"] + " SHA256=" + support["document_sha256"]
                else:
                    source = support["reference"]["reference"] + " SHA256=" + support["reference"]["sha256"]
                lines.append(f'    {source} FIELD={support["field"]} VALUE={json_value_text(support["value"])}')
    lines += ["UNITS_REPLAYED=" + str(report["units_replayed"]),
              "HISTORICAL_GUARDS_EXPLAINED=" + str(report["historical_guards_explained"]),
              "CURRENT_GUARDS_ACCREDITED=0", "NEW_PROTOCOL_ATTEMPTS=0", "A9=NOT_PUBLISHED",
              "P7=" + report["p7"], "P8=" + report["p8"], "REPORT_SHA256=" + report["sha256"]]
    return "\n".join(lines) + "\n"


def json_value_text(value):
    return {True: "true", False: "false"}[value] if type(value) is bool else str(value)


def render_unit_text(report):
    unit, guard = report["unit"], report["first_pending_guard"]
    lines = ["ARDREC / REAPERTURA HISTORICA POR UNIDAD",
             "SCOPE=" + report["scope"], "UNIT=" + unit["unit_id"],
             "PHASE=" + unit["phase"], "DECISION=" + unit["a8_decision"],
             "FIRST_PENDING_GUARD=" + guard["code"],
             "GUARD_ORDER=" + guard["ordering"],
             "GUARD_STATUS=" + guard["status"],
             "CURRENT_OPERATIONAL_STATUS=" + guard["current_operational_status"],
             "NATIVE_T1_REJECTION=" + report["native_t1_rejection"],
             "READBACK_SHA256=" + report["readback_sha256"],
             "SNAPSHOT_SHA256=" + report["snapshot_sha256"],
             "PREREGISTRATION_SHA256=" + guard["preregistration_sha256"],
             "PLAN_SHA256=" + report["plan_sha256"]]
    for item in guard["support"]:
        lines.append(f'SUPPORT={item["file"]}:{item["field"]}=false '
                     f'DOCUMENT_SHA256={item["document_sha256"]}')
    for role in ("characterization", "pending_controls"):
        lines.append(role.upper() + "_SHA256=" + guard[role]["sha256"])
    lines.extend(["RF_CONFIRMED=ND", "A9=NOT_PUBLISHED",
                  "NEW_PROTOCOL_ATTEMPTS=0", "P7=" + report["p7"],
                  "P8=" + report["p8"], "REPORT_SHA256=" + report["sha256"]])
    return "\n".join(lines) + "\n"


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
