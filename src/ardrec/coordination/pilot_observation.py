"""R270: ingest recovered pilot development observations.

Preserves original receipts and historical acceptance failures.
No dispatch, operational evidence admission or A9 publication.
"""

import hashlib
import json
import os

from pathlib import Path

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
    pilot_controller,
)

from ardrec.experiments import reference_supports

from ardrec.stopping.development_stop import (
    preview_stop,
    verify_stop,
)


SCHEMA = "ARDREC-R270-PILOT-OBSERVATION-v1"

PROTOCOLS = {"ssh", "ftp", "smb"}

CONTROL_UNITS = {
    "PILOT-SSH-01",
    "PILOT-FTP-01",
    "PILOT-SMB-01",
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(root, relative, limit=262144):

    path = root / relative

    need(
        path.resolve(strict=True) == path
        and path.is_relative_to(root),
        "PRIVATE_PATH_INVALID",
    )

    return reference_supports.read_file(
        path, limit
    )


def document(root, relative, expected=None):

    value = json.loads(
        read(root, relative)
    )

    evidence.verify_digest(value)

    if expected is not None:

        need(
            value["sha256"] == expected,
            "SOURCE_PIN_MISMATCH",
        )

    return value


def validate_attempts(attempts):

    need(
        type(attempts) is list
        and len(attempts) == 3
        and all(type(item) is str for item in attempts)
        and set(attempts) == PROTOCOLS,
        "ATTEMPT_SET_INVALID",
    )

    return len(attempts)


def validate_smoke(smoke, individual, raw, protocol):

    evidence.verify_digest(smoke)
    evidence.verify_digest(individual)

    need(
        smoke == individual,
        "INDIVIDUAL_RECEIPT_MISMATCH",
    )

    need(
        protocol in PROTOCOLS
        and smoke["protocol"] == protocol
        and smoke["schema"] ==
            "ARDREC-R260-SERVICE-SMOKE-v1"
        and smoke["scope"] ==
            "PRIVATE_SYNTHETIC_CONTROL_READ"
        and type(smoke["client_invocations"]) is int
        and smoke["client_invocations"] == 1
        and smoke["functional_read_verified"] is True
        and smoke["runner_deny_restored"] is True
        and smoke["target_deny_restored"] is True
        and smoke["target_account_locked"] is True
        and smoke["target_service_masked"] is True
        and smoke["client_credential_removed"] is True
        and smoke["formal_pilot_admitted"] is False
        and smoke["experimental_admitted"] is False
        and smoke["a6"] == "ND"
        and smoke["confirmed_rf"] is None
        and smoke["p8"] == "NO-GO",
        "FUNCTIONAL_RECEIPT_SCOPE_INVALID",
    )

    expected = (
        "ARDREC:PILOT:" + protocol
        + ":CONTROL:REFERENCE\n"
    ).encode()

    observation = smoke["observation"]

    need(
        type(raw) is bytes
        and raw == expected
        and type(observation["bytes_read"]) is int
        and observation["bytes_read"] == len(raw)
        and type(observation["client_returncode"]) is int
        and observation["client_returncode"] == 0
        and observation["read_sha256"] == sha(raw)
        and smoke["fixture_sha256"] == sha(raw),
        "CONTROL_CONTENT_INVALID",
    )

    return {
        "read_bytes": len(raw),
        "raw_artifact_sha256": sha(raw),
        "source_receipt_sha256": smoke["sha256"],
    }


def support_status(name, observed):

    if not observed:
        return "ND_NOT_OBSERVED"

    if name in {
        "RESOURCE_READ",
        "KNOWN_CONTENT_DIGEST",
    }:
        return "CONTROL_BYTES_VERIFIED"

    if name == "ACCESS_COMPARISON":
        return "MISSING_RESTRICTED_COMPARISON"

    if name == "OPERATION_RESPONSE":
        return "CONTROL_RESPONSE_ONLY"

    return "DOCUMENTARY_PARTIAL"


def evaluate(recovery_folder, runtime_folder,
             preregistration_folder, expected_sha256):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    recovery, execution, preregistration = map(
        Path,
        (
            recovery_folder,
            runtime_folder,
            preregistration_folder,
        ),
    )

    for root in (recovery, execution, preregistration):

        need(
            root.is_absolute()
            and root.resolve(strict=True) == root
            and root.is_dir(),
            "SOURCE_DIRECTORY_INVALID",
        )

    recovered = document(
        recovery,
        "06-integrated-handoff.json",
        expected_sha256,
    )

    need(
        recovered["schema"] ==
            "ARDREC-R269D-RECOVERED-HANDOFF-v1-summary"
        and recovered["recovery_status"] ==
            "READONLY_EVIDENCE_RECOVERED"
        and recovered["source_runtime_status"] ==
            "PARTIAL_REVIEW_REQUIRED"
        and recovered["original_runtime_report_modified"]
            is False
        and recovered["physical_reexecution_performed"]
            is False
        and recovered["source_attempt_counter_type"] ==
            "list"
        and recovered["source_attempt_count_normalized"] == 3
        and recovered["control_units_bound"] == 3
        and recovered["functional_observations_verified"] == 3
        and recovered["raw_artifacts_verified"] == 3
        and recovered["raw_bytes_verified"] == 105
        and recovered["restricted_attempts"] == 0
        and recovered["contrast_attempts"] == 0
        and recovered["new_vm_starts"] == 0
        and recovered["new_protocol_attempts"] == 0
        and recovered["operational_a5_admitted"] == 0
        and recovered["operational_supports_accredited"] == 0
        and recovered["confirmed_rf_count"] == 0
        and recovered["operational_a9_publications"] == 0
        and recovered["formal_pilot_admitted"] == 0
        and recovered["experimental_admitted"] == 0
        and recovered["p8"] == "NO-GO",
        "RECOVERY_SCOPE_INVALID",
    )

    runtime = document(
        execution,
        "CONTROL/05-control-handoff.json",
        recovered["source_runtime_sha256"],
    )

    intent = document(
        execution,
        "02-control-intent.json",
        recovered["source_intent_sha256"],
    )

    need(
        document(
            recovery,
            "02-control-intent.json",
            intent["sha256"],
        ) == intent,
        "RECOVERY_INTENT_MISMATCH",
    )

    need(
        sha(read(
            execution,
            "control_handoff.py",
            1048576,
        )) == intent["composed_controller_sha256"],
        "EXECUTOR_SOURCE_PIN_INVALID",
    )

    need(
        runtime["status"] == "PARTIAL_REVIEW_REQUIRED"
        and runtime["failure"] ==
            recovered["source_runtime_failure"]
        and "CONTROL_FUNCTIONAL_ACCEPTANCE_FAILED"
            in json.dumps(runtime["failure"])
        and runtime["profile"] == "CONTROL"
        and runtime["initial_target_states_verified"] == 3
        and runtime["functional_services_verified"] == 3
        and runtime["private_vms_started"] == 4
        and runtime["graceful_shutdowns_verified"] == 4
        and runtime["connected_interfaces_verified"] == 6
        and runtime["connected_firewalls_verified"] == 4
        and runtime["original_baselines_preserved"] == 4
        and runtime["restricted_resource_attempts"] == 0
        and runtime["host_firewall_writes"] == 0
        and runtime["operational_a5_admitted"] is False
        and runtime["formal_pilot_admitted"] == 0
        and runtime["experimental_admitted"] == 0
        and runtime["p8"] == "NO-GO"
        and runtime["code_head"] == intent["code_head"],
        "ORIGINAL_RUNTIME_SCOPE_INVALID",
    )

    count = validate_attempts(
        runtime["protocol_service_attempts"]
    )

    for revision in ("r266", "r267", "r268"):

        key = "source_" + revision + "_sha256"

        need(
            runtime[key] == intent[key],
            "SOURCE_CHAIN_INVALID:" + revision,
        )

    review = pilot_controller.evaluate(
        preregistration,
        intent["source_r266_sha256"],
    )

    need(
        review["sha256"] ==
            intent["source_r267_sha256"],
        "NATIVE_CONTROLLER_BINDING_INVALID",
    )

    state = pilot_controller.recover_state(review)

    need(
        state.simulation
        and state.authority.value == "ND"
        and not state.attempts,
        "PREMATURE_OPERATIONAL_STATE",
    )

    records = recovered["records"]

    need(
        len(records) == 3
        and {row["unit_id"] for row in records}
            == CONTROL_UNITS,
        "RECOVERED_UNIT_SET_INVALID",
    )

    plans = {
        row["unit_id"]: row
        for row in intent["units"]
    }

    need(
        len(intent["units"]) == 3
        and set(plans) == CONTROL_UNITS,
        "INTENT_UNIT_SET_INVALID",
    )

    smokes = {
        row["protocol"]: row
        for row in runtime["functional_smokes"]
    }

    need(
        len(runtime["functional_smokes"]) == count
        and set(smokes) == PROTOCOLS,
        "SMOKE_PROTOCOL_SET_INVALID",
    )

    originals = {
        row["unit_id"]: row
        for row in records
    }

    rows = []

    for unit in review["units"]:

        uid = unit["unit_id"]
        protocol = unit["protocol"].lower()

        observed = uid in CONTROL_UNITS

        i3 = None
        i6 = None

        source_sha = unit["plan_sha256"]

        if observed:

            plan = plans[uid]
            record = originals[uid]

            evidence.verify_digest(record)

            need(
                document(
                    recovery,
                    uid + "-handoff.json",
                    record["sha256"],
                ) == record,
                "RECOVERED_RECEIPT_MISMATCH",
            )

            instance = runtime[
                "instance_receipts"
            ][protocol]

            evidence.verify_digest(instance)

            need(
                instance["sha256"] ==
                    plan["instance_receipt_sha256"]
                and instance["unit_id"] == uid
                and instance["instance_id"] ==
                    unit["instance_id"]
                and instance["image_sha256"] ==
                    plan["image_sha256"]
                and instance["profile"] == "CONTROL"
                and plan["plan_sha256"] ==
                    unit["plan_sha256"]
                and plan["maximum_client_invocations"] == 1
                and record["instance_id"] ==
                    unit["instance_id"]
                and record["family_id"] ==
                    unit["family_id"]
                and record["protocol"] ==
                    unit["protocol"]
                and record["plan_sha256"] ==
                    unit["plan_sha256"]
                and record["intent_sha256"] ==
                    intent["sha256"]
                and record["runtime_report_sha256"] ==
                    runtime["sha256"]
                and record["development_observation"] is True
                and record["operational_a5_admitted"] is False
                and record["a6"] == "ND"
                and record["confirmed_rf"] is None
                and record["formal_pilot_admitted"] is False
                and record["experimental_admitted"] is False,
                "UNIT_OBSERVATION_BINDING_INVALID",
            )

            smoke = smokes[protocol]

            individual = document(
                execution,
                "CONTROL/" + protocol
                + "-functional-smoke.json",
                record["functional_receipt_sha256"],
            )

            raw = read(
                recovery,
                "raw-evidence/" + protocol + ".bin",
                4096,
            )

            verified = validate_smoke(
                smoke,
                individual,
                raw,
                protocol,
            )

            need(
                record["raw_artifact_sha256"] ==
                    verified["raw_artifact_sha256"]
                and record["read_bytes"] ==
                    verified["read_bytes"]
                and record["client_invocations"] == 1
                and record["control_read_verified"] is True
                and record["deny_restored"] is True,
                "RECOVERED_CONTENT_BINDING_INVALID",
            )

            source_sha = smoke["sha256"]

            i3 = {
                "status": "DEVELOPMENT_OBSERVATION",
                **verified,
                "unit_id": uid,
                "instance_id": unit["instance_id"],
                "plan_sha256": unit["plan_sha256"],
                "control_read_verified": True,
                "restricted_comparison_verified": False,
                "experimental_admission": False,
            }

            i6 = {
                "status": "FUNCTIONAL_RECEIPT_LINKED",
                "client_invocations": 1,
                "source_receipt_sha256": source_sha,
                "source_runtime_sha256": runtime["sha256"],
                "runner_deny_restored":
                    smoke["runner_deny_restored"],
                "target_deny_restored":
                    smoke["target_deny_restored"],
                "target_account_locked":
                    smoke["target_account_locked"],
                "target_service_masked":
                    smoke["target_service_masked"],
                "client_credential_removed":
                    smoke["client_credential_removed"],
                "autonomous_closure_accredited": False,
                "full_restoration_accredited": False,
                "operational_attempt_admitted": False,
                "automatic_retry": False,
            }

        i7 = [
            {
                "support": name,
                "status": support_status(
                    name, observed
                ),
                "operationally_accredited": False,
            }
            for name in unit["required_supports"]
        ]

        stop = preview_stop(
            a6_classification="ND",
            accredited=False,
            vm_checked=False,
            operational_dispatch=False,
            source_sha256=source_sha,
        )

        need(
            verify_stop(stop)
            and stop["recommendation"] == unit["a8"]
            and stop["applied_transition"] is None,
            "NATIVE_STOP_REPLAY_INVALID",
        )

        rows.append({
            "unit_id": uid,
            "protocol": unit["protocol"],
            "family_id": unit["family_id"],
            "profile": unit["profile"],
            "native_phase": unit["native_state"],
            "initial_risk":
                unit["initial_risk_candidate"],
            "hypothetical_rf_interval":
                unit["hypothetical_rf_interval"],
            "i3": i3,
            "i6": i6,
            "i7": i7,
            "a6": "ND",
            "confirmed_rf": None,
            "a8": stop,
            "a9": "NOT_PUBLISHED",
            "formal_pilot_admitted": False,
            "experimental_admitted": False,
        })

    observations = [
        row["i3"] for row in rows
        if row["i3"] is not None
    ]

    need(
        len(rows) == 6
        and len(observations) == 3
        and sum(
            item["read_bytes"] for item in observations
        ) == 105
        and sum(
            len(row["i7"]) for row in rows
        ) == 24,
        "FINAL_COVERAGE_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA,
        "scope": "PILOT_DEVELOPMENT_OBSERVATION_REPLAY",
        "recovery_sha256": recovered["sha256"],
        "original_runtime_sha256": runtime["sha256"],
        "original_runtime_status": runtime["status"],
        "controller_sha256": review["sha256"],
        "source_intent_sha256": intent["sha256"],
        "units": rows,
        "unit_count": 6,
        "observations_verified": 3,
        "original_artifacts_verified": 3,
        "raw_bytes_verified": 105,
        "native_a8_replays": 6,
        "required_support_entries": 24,
        "operational_supports_accredited": 0,
        "operational_a5_admitted": 0,
        "confirmed_rf_count": 0,
        "operational_a9_publications": 0,
        "new_vm_starts": 0,
        "new_protocol_attempts": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def render_text(report):

    lines = [
        "ARDREC / OBSERVACIONES FUNCIONALES DEL PILOTO",
        "SCOPE=" + report["scope"],
    ]

    for row in report["units"]:

        lines.extend([
            "",
            "UNIT=" + row["unit_id"],
            "PHASE=" + row["native_phase"],
            "R0=" + row["initial_risk"],
            "I3=" + (
                row["i3"]["status"]
                if row["i3"] else "NOT_RUN"
            ),
            "I6=" + (
                row["i6"]["status"]
                if row["i6"] else "NOT_RUN"
            ),
            "A6=ND",
            "RF_CONFIRMED=ND",
            "A8=" + row["a8"]["recommendation"],
            "A9=NOT_PUBLISHED",
        ])

        lines.extend(
            item["support"] + "=" + item["status"]
            for item in row["i7"]
        )

    for key in (
        "unit_count",
        "observations_verified",
        "original_artifacts_verified",
        "raw_bytes_verified",
        "native_a8_replays",
        "required_support_entries",
        "operational_supports_accredited",
        "confirmed_rf_count",
        "new_vm_starts",
        "new_protocol_attempts",
        "formal_pilot_admitted",
        "experimental_admitted",
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
