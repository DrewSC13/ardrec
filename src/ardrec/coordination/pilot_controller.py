"""Prospective pilot controller with native state and exact kernels.

Consumes immutable preregistration packets. This controller
does not grant A3 authority or dispatch physical operations.
"""

from pathlib import Path
import json
import os

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
)

from ardrec.coordination.r58e_evidence_risk_bridge import (
    verify_unit_bridge,
)

from ardrec.experiments import (
    initial_assessment as initial,
    reference_supports,
)

from ardrec.selection import prospective_priority as priority

from ardrec.persistence.codec import pack, unpack

from ardrec.state import (
    ConfirmedState,
    GlobalState,
    GuardFact,
    ServicePhase,
    ServiceState,
    StateError,
    Transition,
    TransitionContext,
    Truth,
    transition_service,
)


SCHEMA = "ARDREC-R267-PILOT-CONTROLLER-v1"
SOURCE_SCHEMA = "ARDREC-R266-PILOT-PREREGISTRATION-v1"

UNITS = {
    f"PILOT-{protocol}-{index:02}"
    for protocol in ("SSH", "FTP", "SMB")
    for index in (1, 2)
}

FAMILIES = {
    "SSH": "SSH-T06",
    "FTP": "FTP-T08",
    "SMB": "SMB-T09",
}

BLOCKERS = (
    "OPERATIONAL_BASELINE_NOT_CLOSED",
    "SERVICE_IDENTITY_NOT_AUTHENTICATED",
    "FRESH_SERVICE_CREDENTIALS_NOT_ATTESTED",
    "A3_SCOPE_AUTHORITY_NOT_ESTABLISHED",
    "PHYSICAL_DISPATCH_CONTRACT_NOT_INTEGRATED",
)


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def read(root, relative):

    path = root / relative

    need(
        path.resolve(strict=True) == path
        and path.is_relative_to(root),
        "PRIVATE_PATH_INVALID",
    )

    return json.loads(
        reference_supports.read_file(
            path, 262144
        )
    )


def verify_seal(document, expected=None):

    need(
        evidence.verify_digest(document),
        "DOCUMENT_DIGEST_INVALID",
    )

    if expected is not None:

        need(
            document["sha256"] == expected,
            "DOCUMENT_PIN_MISMATCH",
        )

    return document


def validate_source(source, expected):

    verify_seal(source, expected)

    need(
        source["schema"] == SOURCE_SCHEMA
        and source["pilot_units_preregistered"] == 6
        and source["researcher_ratings_preserved"] == 36
        and source["static_candidates_registered"] == 6
        and source["native_uncertainty_intervals"] == 6
        and source["required_support_entries"] == 24
        and source["operational_supports_accredited"] == 0
        and source["physical_baselines_closed"] == 0
        and source["operational_a5_attempts"] == 0
        and source["formal_pilot_admitted"] == 0
        and source["experimental_admitted"] == 0
        and source["p7"] == "DRAFT_NOT_FROZEN"
        and source["p8"] == "NO-GO",
        "PREREGISTRATION_SCOPE_INVALID",
    )

    rows = source["records"]

    need(
        type(rows) is list
        and len(rows) == 6
        and {row["unit_id"] for row in rows} == UNITS
        and len({
            row["instance_id"] for row in rows
        }) == 6,
        "PILOT_IDENTITY_SET_INVALID",
    )

    return rows


def native_state(source_sha, unit_ids):

    need(
        type(source_sha) is str
        and len(source_sha) == 64
        and all(c in "0123456789abcdef" for c in source_sha),
        "SOURCE_IDENTITY_INVALID",
    )

    need(
        len(unit_ids) == 6
        and set(unit_ids) == UNITS,
        "NATIVE_STATE_UNIT_SET_INVALID",
    )

    services = tuple(
        ServiceState(
            unit, ServicePhase.PREPARADO
        )
        for unit in sorted(unit_ids)
    )

    confirmed = ConfirmedState(
        record_id="PILOT-REVIEW-" + source_sha[:24],
        generation=0,
        generation_reference="REVIEW-GEN-0",
        configuration_sha256=source_sha,
        versions_reference="R266-PREREGISTRATION",
        services=services,
    )

    return GlobalState(
        confirmed=confirmed,
        execution_id="REVIEW-" + source_sha[:24],
        services=services,
        authority=Truth.ND,
        simulation=True,
    )


def verify_state(state):

    need(
        type(state) is GlobalState
        and state.simulation is True
        and state.authority is Truth.ND
        and state.confirmed.generation == 0
        and not state.attempts
        and not state.confirmed.incorporated_events
        and state.services == state.confirmed.services
        and len(state.services) == 6
        and {
            service.service_scenario_id
            for service in state.services
        } == UNITS
        and all(
            service.phase is ServicePhase.PREPARADO
            and not service.local_trace
            for service in state.services
        ),
        "REVIEW_STATE_AUTHORITY_DRIFT",
    )

    return True


def native_t1_rejection(state, unit, plan_sha):

    verify_state(state)

    context = TransitionContext(
        record_id=state.confirmed.record_id,
        execution_id=state.execution_id,
        generation=state.confirmed.generation,
        configuration_sha256=(
            state.confirmed.configuration_sha256
        ),
        event_reference="REVIEW-T1-" + unit,
        facts=(
            GuardFact(
                "preparation_authorized",
                Truth.ND,
                plan_sha,
            ),
            GuardFact(
                "preconditions_valid",
                Truth.ND,
                plan_sha,
            ),
        ),
    )

    try:

        transition_service(
            state,
            unit,
            Transition.PREPARAR,
            context,
        )

    except StateError as error:

        need(
            error.code == "authority_unverified",
            "UNEXPECTED_NATIVE_REJECTION",
        )

        return error.code

    raise ValueError("UNAUTHORIZED_T1_ACCEPTED")


def validate_unit(row, i1, i2, i3, i6, i7, plan):

    unit = row["unit_id"]
    protocol = row["protocol"]

    need(
        unit in UNITS
        and protocol in FAMILIES
        and unit.startswith("PILOT-" + protocol + "-")
        and row["family_id"] == FAMILIES[protocol]
        and row["profile"] == (
            "CONTROL"
            if unit.endswith("-01")
            else "CONTRAST"
        ),
        "UNIT_FAMILY_PROFILE_INVALID",
    )

    documents = {
        "I1": i1,
        "I2": i2,
        "I3": i3,
        "I6": i6,
        "I7": i7,
        "plan": plan,
    }

    for name, document in documents.items():

        verify_seal(document)

        need(
            document["schema"] ==
                SOURCE_SCHEMA + "-" + name
            and document["unit_id"] == unit,
            "UNIT_DOCUMENT_BINDING_INVALID",
        )

    need(
        plan["sha256"] == row["plan_sha256"]
        and i1["sha256"] == row["i1_sha256"]
        and i2["sha256"] == row["i2_sha256"]
        and plan["i1_sha256"] == i1["sha256"]
        and plan["i2_sha256"] == i2["sha256"]
        and plan["i3_sha256"] == i3["sha256"]
        and plan["i6_sha256"] == i6["sha256"]
        and plan["i7_sha256"] == i7["sha256"]
        and i2["i1_sha256"] == i1["sha256"]
        and i3["i1_sha256"] == i1["sha256"],
        "PREREGISTRATION_DAG_INVALID",
    )

    need(
        i1["instance_id"] == row["instance_id"]
        and plan["instance_id"] == row["instance_id"]
        and plan["image_sha256"] == i1["image_sha256"]
        and i1["family_id"] == row["family_id"]
        and i1["protocol"] == protocol
        and i1["profile"] == row["profile"]
        and plan["protocol"] == protocol
        and plan["family_id"] == row["family_id"]
        and plan["profile"] == row["profile"]
        and i7["family_id"] == row["family_id"],
        "SCENARIO_IDENTITY_DRIFT",
    )

    need(
        i1["baseline_closed"] is False
        and i1["initial_configuration_characterized"] is True
        and i1["runtime_local_permissions_characterized"] is True
        and i1["service_specific_identity_pending"] is True
        and i1["fresh_service_credentials_pending"] is True
        and i2["operational_baseline_closed"] is False
        and i2["static_method_definitively_frozen"] is False
        and plan["phase"] == "PREPARADO"
        and plan["guard"] == "ND"
        and plan["execution_authorized"] is False
        and plan["formal_pilot_admitted"] is False
        and plan["experimental_admitted"] is False
        and plan["p8"] == "NO-GO"
        and plan["catalog_sha256"] ==
            evidence.CATALOG_SHA256,
        "UNIT_AUTHORITY_PROMOTION",
    )

    need(
        i3["observations"] == []
        and i3["attempt_count"] == 0
        and i6["events"] == []
        and i6["reserved_attempts"] == 0
        and i6["completed_attempts"] == 0
        and i6["uncertain_attempts"] == 0
        and i6["automatic_retry_allowed"] is False
        and i7["a6_classification"] == "ND"
        and i7["operational_supports_accredited"] == 0,
        "PREMATURE_OBSERVATION",
    )

    supports = i7["required_supports"]

    need(
        len(supports) == 4
        and set(supports) ==
            set(plan["required_supports"])
        and all(
            item == {
                "status": "ND",
                "original_sha256": None,
                "derived_sha256": None,
                "accredited": False,
            }
            for item in supports.values()
        ),
        "PREMATURE_SUPPORT_ADMISSION",
    )

    ratings = i2["ratings"]

    need(
        set(ratings) == set(initial.DIMENSIONS),
        "INITIAL_DIMENSION_SET_INVALID",
    )

    values = [
        initial.ordinal(ratings[name]["ordinal"])
        for name in initial.DIMENSIONS
    ]

    calculated = initial.compute(
        values[0],
        values[1],
        values[2],
        values[3:],
    )

    need(
        calculated == i2["native_calculation"]
        and calculated["initial_risk"] ==
            row["static_candidate"]
        and calculated["initial_risk"] ==
            i2["static_method_candidate"]
        and calculated["normalized_criticality"] ==
            row["normalized_criticality"],
        "INITIAL_ARITHMETIC_DRIFT",
    )

    return {
        "unit_id": unit,
        "protocol": protocol,
        "family_id": row["family_id"],
        "instance_id": row["instance_id"],
        "profile": row["profile"],
        "plan_sha256": plan["sha256"],
        "initial_risk_candidate":
            calculated["initial_risk"],
        "normalized_criticality":
            calculated["normalized_criticality"],
        "required_supports": sorted(supports),
        "baseline_closed": False,
        "physical_dispatch_allowed": False,
    }


def recover_state(report):

    verify_seal(report)

    need(
        report["schema"] == SCHEMA
        and report["operational_dispatch"] is False
        and report["operational_a9_publications"] == 0
        and report["p8"] == "NO-GO",
        "CONTROLLER_SCOPE_INVALID",
    )

    state = unpack(report["native_review_state"])

    verify_state(state)

    expected = native_state(
        report["source_sha256"],
        [row["unit_id"] for row in report["units"]],
    )

    need(
        state == expected,
        "NATIVE_STATE_REPLAY_MISMATCH",
    )

    return state


def evaluate(folder, expected_sha256):

    need(
        os.geteuid() != 0,
        "ROOT_FORBIDDEN",
    )

    root = Path(folder)

    need(
        root.is_absolute()
        and root.resolve(strict=True) == root
        and root.is_dir(),
        "PRIVATE_SOURCE_DIRECTORY_INVALID",
    )

    source = read(
        root, "05-pilot-preregistration.json"
    )

    rows = validate_source(
        source, expected_sha256
    )

    state = native_state(
        source["sha256"],
        [row["unit_id"] for row in rows],
    )

    verify_state(state)

    a4_input = read(
        root, "method/A4-input.json"
    )

    a4_report = read(
        root, "method/A4-report.json"
    )

    verify_seal(
        a4_report,
        source["native_a4_sha256"],
    )

    need(
        priority.verify(
            a4_report,
            a4_input,
            a4_input["sha256"],
        )
        and a4_report["candidate_count"] == 6
        and a4_report["eligible_count"] == 0
        and a4_report["selected_preview"] is None,
        "NATIVE_A4_BOUNDARY_INVALID",
    )

    bridge = read(
        root, "method/native-A6-A7-A8.json"
    )

    need(
        bridge["sha256"] ==
            source["native_bridge_sha256"]
        and verify_unit_bridge(bridge)
        and bridge["unit_count"] == 6
        and bridge["all_a6_nd"] is True
        and bridge["published_generation"] is None,
        "NATIVE_RISK_BRIDGE_INVALID",
    )

    risk_inputs = {
        item["case_id"]: item
        for item in bridge["inputs"]
    }

    intervals = {
        item["case_id"]: item
        for item in bridge["a7"]["results"]
    }

    decisions = {
        item["case_id"]: item
        for item in bridge["decisions"]
    }

    priorities = {
        item["case_id"]: item
        for item in a4_input["candidates"]
    }

    result_rows = []

    for row in sorted(
        rows, key=lambda item: item["unit_id"]
    ):

        unit = row["unit_id"]
        cid = unit.replace("-", "_")

        documents = [
            read(root, f"method/{unit}/I1.json"),
            read(root, f"method/{unit}/I2.json"),
            read(root, f"observations/{unit}/I3.json"),
            read(root, f"observations/{unit}/I6.json"),
            read(root, f"observations/{unit}/I7.json"),
            read(root, f"method/{unit}/plan.json"),
        ]

        current = validate_unit(
            row, *documents
        )

        candidate = priorities[cid]
        risk = risk_inputs[cid]
        interval = intervals[cid]
        decision = decisions[cid]

        need(
            candidate["instance_id"] ==
                current["instance_id"]
            and candidate["source_preparation_sha256"] ==
                current["plan_sha256"]
            and candidate["initial_risk"] ==
                current["initial_risk_candidate"]
            and candidate["criticality"] ==
                current["normalized_criticality"]
            and risk["initial_risk"] ==
                current["initial_risk_candidate"]
            and risk["normalized_criticality"] ==
                current["normalized_criticality"]
            and interval["evidence_lower"] == "0"
            and interval["evidence_upper"] == "1"
            and interval["confirmed_rf"] is None
            and decision["a6_classification"] == "ND"
            and decision["confirmed_rf"] is None
            and decision["a8_applied_transition"] is None,
            "CROSS_KERNEL_UNIT_BINDING_INVALID",
        )

        rejection = native_t1_rejection(
            state,
            unit,
            current["plan_sha256"],
        )

        current.update({
            "native_state": "PREPARADO",
            "native_t1_rejection": rejection,
            "blockers": list(BLOCKERS),
            "hypothetical_rf_interval": [
                interval["rf_lower"],
                interval["rf_upper"],
            ],
            "a6": "ND",
            "confirmed_rf": None,
            "a8": decision["a8_recommendation"],
            "a9": "NOT_PUBLISHED",
        })

        result_rows.append(current)

    report = durable.seal({
        "schema": SCHEMA,
        "source_sha256": source["sha256"],
        "scope": "NON_DISPATCHABLE_NATIVE_REVIEW",
        "native_review_state": pack(state),
        "units": result_rows,
        "unit_contracts_verified": 6,
        "native_t1_rejections": 6,
        "native_a4_replayed": True,
        "native_a6_a7_a8_replayed": True,
        "required_support_entries": 24,
        "operational_supports_accredited": 0,
        "operational_dispatch": False,
        "operational_transitions": 0,
        "operational_a9_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "new_network_operations": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })

    need(
        recover_state(report) == state,
        "NATIVE_STATE_ROUNDTRIP_FAILED",
    )

    return report


def render_text(report):

    lines = [
        "ARDREC / CONTROLADOR NATIVO DEL PILOTO",
        "SCOPE=" + report["scope"],
    ]

    for row in report["units"]:

        lines.extend([
            "",
            "UNIT=" + row["unit_id"],
            "STATE=" + row["native_state"],
            "R0=" + row["initial_risk_candidate"],
            "T1=" + row["native_t1_rejection"],
            "RF_CONFIRMED=ND",
        ])

        lines.extend(
            "BLOCKER=" + blocker
            for blocker in row["blockers"]
        )

    lines.extend([
        "",
        "UNIT_CONTRACTS_VERIFIED=6/6",
        "NATIVE_T1_REJECTIONS=6/6",
        "NATIVE_STATE_RECOVERY=PASS",
        "OPERATIONAL_TRANSITIONS=0",
        "OPERATIONAL_DISPATCH=NO",
        "EXPERIMENTAL_ADMITTED=0",
        "P7=" + report["p7"],
        "P8=" + report["p8"],
        "REPORT_SHA256=" + report["sha256"],
    ])

    return "\n".join(lines) + "\n"
