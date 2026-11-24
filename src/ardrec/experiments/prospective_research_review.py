"""Prospective research receipt interpretation.

No historical authorization, operational A6 accreditation,
network dispatch or authoritative A9 publication.
"""
from pathlib import Path

from ardrec.coordination import prospective_local_pilot as durable
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import local_ssh_pilot as ssh

from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge,
    verify_unit_bridge,
)

from ardrec.experiments import initial_assessment as initial
from ardrec.experiments import functional_ftp_fixture as ftp
from ardrec.experiments import functional_local_fixtures as local
from ardrec.experiments import prospective_attempt_journal as journal


SCHEMA = "ARDREC-R215-PROSPECTIVE-REVIEW-v1"
PROTOCOLS = ("SSH", "FTP", "SMB")

CLAIMS = {
    "SSH": "LOCAL_TRANSPORT_AND_HOST_KEY_MATCH",
    "FTP": "LOCAL_CONTROL_CHANNEL_RESPONSE",
    "SMB": "LOCAL_SMB2_NEGOTIATION",
}


def need(value, reason):

    if not value:
        raise ValueError(reason)


def load(path, sealed=True):

    value = durable.load(path)

    if sealed:
        evidence.verify_digest(value)

    return value


def file_sha(path):

    return ssh.digest(path.read_bytes())


def calculate(protocol, ratings):

    need(protocol in PROTOCOLS, "PROTOCOL_INVALID")

    need(
        type(ratings) is dict
        and set(ratings) == set(initial.DIMENSIONS),
        "RATINGS_INVALID",
    )

    values = initial.compute(
        ratings["exposure"],
        ratings["probability"],
        ratings["impact"],
        (
            ratings["operational_importance"],
            ratings["data_sensitivity"],
            ratings["dependencies"],
        ),
    )

    bridge = build_unit_bridge(
        [{
            "service_id": protocol + "_DEV",
            "case_id": "REHEARSAL-R213-" + protocol,
            "assessment_index": 0,
            "initial_risk": values["initial_risk"],
            "normalized_criticality":
                values["normalized_criticality"],
            "replacement_risk": values["initial_risk"],
            "evidence": [],
        }],
        [],
        weights=("1/3", "1/3", "1/3"),
    )

    verify_unit_bridge(bridge)

    need(
        bridge["all_a6_nd"] is True
        and bridge["confirmed_final_risk"] is None
        and bridge["published_generation"] is None,
        "AUTHORITY_PROMOTION_INVALID",
    )

    return values, bridge


def review(protocol, folder, initial_folder):

    need(protocol in PROTOCOLS, "PROTOCOL_INVALID")

    folder = Path(folder)
    initial_folder = Path(initial_folder)

    plan = load(folder / "plan.json")
    baseline = load(folder / "baseline-candidate.json")
    intent = load(folder / "dispatch-intent.json")
    receipt = load(folder / "receipt.json")
    snapshot = load(folder / "journal-snapshot.json")

    before = load(
        folder / "preoperation.json", sealed=False
    )

    observed = load(
        folder / "raw-observation.json", sealed=False
    )

    i2 = load(
        initial_folder / "I2-reviewed-candidate.json"
    )

    journal.verify_plan(plan)

    need(
        plan["protocol"] == protocol
        and plan["runner_sha256"] ==
            file_sha(folder / "instrumented.py")
        and baseline["plan_sha256"] == plan["sha256"]
        and baseline["source_i2_sha256"] == i2["sha256"]
        and baseline["ratings"] == i2["ratings"]
        and i2["researcher_rating_review"] is True
        and i2["baseline_closed"] is False
        and intent["plan_sha256"] == plan["sha256"]
        and intent["baseline_sha256"] == baseline["sha256"]
        and receipt["plan_sha256"] == plan["sha256"]
        and receipt["dispatch_intent_sha256"] == intent["sha256"]
        and receipt["preoperation_file_sha256"] ==
            file_sha(folder / "preoperation.json")
        and receipt["observation_file_sha256"] ==
            file_sha(folder / "raw-observation.json")
        and before["baseline_file_sha256"] ==
            file_sha(folder / "baseline-candidate.json")
        and before["plan_sha256"] == plan["sha256"]
        and before["payload_sha256"] == plan["fixture_sha256"],
        "SOURCE_CHAIN_INVALID",
    )

    need(
        snapshot["plan_sha256"] == plan["sha256"]
        and snapshot["receipt_sha256"] == receipt["sha256"]
        and snapshot["state"] ==
            "RECEIPT_RECORDED_UNVERIFIED"
        and snapshot["attempt_count"] == 1
        and [
            row["action"] for row in snapshot["events"]
        ] == [
            "REGISTERED",
            "LOCAL_CONSENT_RECORDED",
            "ATTEMPT_RESERVED",
            "DISPATCH_CLAIMED",
            "RECEIPT_RECORDED_UNVERIFIED",
        ],
        "JOURNAL_CHAIN_INVALID",
    )

    reserved = {
        key: value
        for key, value in snapshot.items()
        if key != "sha256"
    }

    reserved["state"] = "RESERVED"
    reserved["receipt_sha256"] = None
    reserved["events"] = reserved["events"][:-1]

    reserved = durable.seal(reserved)

    need(
        reserved["sha256"] ==
            intent["journal_snapshot_sha256"],
        "DISPATCH_SNAPSHOT_INVALID",
    )

    need(
        before["namespace"] == observed["child_namespace"]
        and before["namespace"] != before["host_namespace"]
        and before["interfaces"] == ["lo"]
        and before["endpoint"] == "127.0.0.1"
        and before["listener_active"] is True
        and before["client_operation_not_started"] is True
        and int(before["effective_capabilities"], 16) == 0
        and receipt["functional_validation_passed"] is True
        and receipt["temporary_workspace_removed"] is True
        and receipt["technical_evidence_accredited"] is False,
        "OBSERVATION_BOUNDARY_INVALID",
    )

    if protocol == "FTP":

        ftp.verify_observation(
            observed, before["host_namespace"]
        )

    else:

        local.verify_observation(
            protocol, observed, before["host_namespace"]
        )

    values, bridge = calculate(
        protocol, baseline["ratings"]
    )

    need(
        values == baseline["calculated"] == i2["calculated"],
        "INITIAL_ASSESSMENT_REPLAY_INVALID",
    )

    result = bridge["a7"]["results"][0]

    return durable.seal({
        "schema": SCHEMA,
        "protocol": protocol,
        "related_family": protocol + "-T01",
        "observed_condition": CLAIMS[protocol],
        "condition_verified_in_fixture": True,
        "source_plan_sha256": plan["sha256"],
        "source_receipt_sha256": receipt["sha256"],
        "source_baseline_sha256": baseline["sha256"],
        "source_observation_sha256":
            receipt["observation_file_sha256"],
        "initial_assessment": values,
        "risk_interval_candidate": {
            "lower": result["rf_lower"],
            "upper": result["rf_upper"],
        },
        "analytical_bridge": bridge,
        "same_operator_provenance": True,
        "independent_attestation": False,
        "baseline_formally_closed": False,
        "operational_a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def verify(report, protocol, folder, initial_folder):

    evidence.verify_digest(report)

    need(
        report == review(protocol, folder, initial_folder),
        "RESEARCH_REPLAY_INVALID",
    )

    return True
