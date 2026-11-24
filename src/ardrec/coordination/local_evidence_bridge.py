"""R195: real local transport receipt replay.

This module does not grant operational authority.
Transport observations are not promoted to A6 truth.
"""
from __future__ import annotations

import json

from . import local_ssh_pilot as ssh
from . import local_protocol_pilot as transport

from ardrec.state import Truth
from ardrec.stopping.development_stop import (
    preview_stop,
    verify_stop,
)
from ardrec.experiments import reference_rubric as rubric


SCHEMA = "ARDREC-R195-LOCAL-EVIDENCE-BRIDGE-v1"

CATALOG_SHA256 = (
    "5161cdfc3c88281adbf21b839b40b12f9"
    "2298d5a58f650ad761c0c6dbe16f88e"
)

SSH_RECEIPT_PIN = (
    "dce1c8bf1a2ec0a08f7b46d8b30784672"
    "c0846dcff80536270f1db9f319c4221"
)

PROTOCOLS = ("SSH", "FTP", "SMB")

STATUSES = {
    "SSH": "LOCAL_SSH_IDENTIFICATION_OBSERVED",
    "FTP": "FTP_GREETING_OBSERVED",
    "SMB": "SMB2_NEGOTIATION_OBSERVED",
}


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def digest(value):

    return ssh.digest(ssh.canonical(value))


def verify_digest(value):

    need(
        type(value) is dict
        and type(value.get("sha256")) is str,
        "RECEIPT_SCHEMA_INVALID",
    )

    expected = digest({
        key: item
        for key, item in value.items()
        if key != "sha256"
    })

    need(
        expected == value["sha256"],
        "RECEIPT_DIGEST_INVALID",
    )

    return True


def load_catalog(raw):

    need(
        type(raw) is bytes
        and 0 < len(raw) <= 131072,
        "CATALOG_SIZE_INVALID",
    )

    need(
        ssh.digest(raw) == CATALOG_SHA256,
        "CATALOG_PIN_INVALID",
    )

    document = json.loads(raw)

    need(
        document["counts"] == {
            "ssh": 8,
            "ftp": 8,
            "smb": 9,
            "total": 25,
        }
        and document["execution_enabled"] is False,
        "CATALOG_AUTHORITY_INVALID",
    )

    selected = {}

    for protocol in PROTOCOLS:

        family_id = protocol + "-T01"

        matches = [
            row for row in document["families"]
            if row["id"] == family_id
        ]

        need(
            len(matches) == 1,
            "CATALOG_FAMILY_ID_INVALID",
        )

        selected[protocol] = matches[0]

    return selected


def verify_transport(protocol, record):

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    verify_digest(record)

    need(
        record["status"] == STATUSES[protocol]
        and record["authentication_attempts"] == 0
        and record["historical_vm_access"] is False
        and record["process_cleanup_verified"] is True
        and record["a6"] == "ND"
        and record["confirmed_rf"] is None,
        "TRANSPORT_AUTHORITY_OR_STATUS_INVALID",
    )

    need(
        record["local_address"] == "127.0.0.1",
        "LOCAL_SCOPE_INVALID",
    )

    raw = bytes.fromhex(record["received_hex"])

    need(
        ssh.digest(raw) == record["received_sha256"],
        "RESPONSE_DIGEST_INVALID",
    )

    if protocol == "SSH":

        need(
            record["schema"] == ssh.SCHEMA
            and record["actual_sshd_started"] is True
            and record["tcp_connections_established"] == 1
            and record["client_application_bytes_sent"] == 0
            and record["remote_commands"] == 0
            and record["temporary_workspace_removed"] is True
            and record["physical_a5_admitted"] is False
            and record["operational_a9_published"] is False
            and record["experimental_observations_admitted"] == 0
            and record["p8"] == "NO-GO",
            "SSH_BOUNDARY_INVALID",
        )

        parsed = ssh.parse_banner(raw)

        need(
            parsed == record["banner"],
            "SSH_REPLAY_INVALID",
        )

        return {
            "identification": parsed,
        }

    need(
        record["protocol"] == protocol
        and record["process_started"] is True
        and record["tcp_connections"] == 1
        and record["file_operations"] == 0
        and record["workspace_removed"] is True
        and record["experimental_admission"] is False,
        "FTP_SMB_BOUNDARY_INVALID",
    )

    if protocol == "FTP":

        need(
            record["client_application_bytes"] == 0
            and record["implementation"] ==
                "PYFTPDLIB_PINNED_SOURCE"
            and record["sandbox_requested"] is True
            and "FTP_COMPAT_IMPORTS=PASS"
                in record.get("diagnostics", ""),
            "FTP_SCOPE_INVALID",
        )

        dependencies = record[
            "ftp_dependency"
        ]["compatibility_dependencies"]

        need(
            record["ftp_dependency"]["archive_sha256"]
                == transport.FTP_SOURCE_SHA256
            and len(dependencies) == 2
            and {
                (
                    item["filename"],
                    item["sha256"],
                    item["module"],
                )
                for item in dependencies
            } == set(transport.FTP_COMPAT_WHEELS),
            "FTP_DEPENDENCY_PROVENANCE_INVALID",
        )

        parsed = transport.parse_ftp(raw)

    else:

        need(
            record["implementation"] == "SAMBA_SMBD"
            and record["sandbox_requested"] is True
            and record["client_application_bytes"] ==
                len(transport.smb_request())
            and record["request_sha256"] ==
                ssh.digest(transport.smb_request()),
            "SMB_SCOPE_INVALID",
        )

        parsed = transport.parse_smb(raw)

    need(
        parsed == record["parsed_response"],
        "PROTOCOL_REPLAY_INVALID",
    )

    return parsed


def reference_preview(protocol, receipt_sha256):

    # Local transport does not establish the full I4 scenario.
    # Even partially observed CE groups remain ND.
    common = {}

    for key in rubric.COMMON_CHECKS:

        related = key in {
            "CE01_SERVICE_IDENTITY",
            "CE03_EXPOSURE",
            "CE08_FINAL_STATE_RESTORATION",
            "CE09_SUPPORT_PROVENANCE",
        }

        common[key] = {
            "value": "ND",
            "supports": (
                [receipt_sha256] if related else []
            ),
            "reason":
                "Local transport is insufficient for a complete "
                "experimental service-scenario assessment.",
        }

    facts = {
        key: {
            "value": "ND",
            "supports": [],
            "reason":
                "No complete reference assessment available.",
        }
        for key in rubric.FACTS
    }

    document = {
        "unit_id": "PILOT_LOCAL_" + protocol,
        "protocol": protocol,
        "common_checks": common,
        "facts": facts,
    }

    result = rubric.evaluate(document)

    rubric.verify(document, result)

    need(
        result["classification"] == "ND"
        and result["candidate_reference_score"] is None
        and result["confirmed_reference_score"] is None
        and result["experimental_admission"] is False,
        "REFERENCE_PROMOTION_INVALID",
    )

    return {
        "input": document,
        "result": result,
    }


def build(
    ssh_record,
    smb_document,
    ftp_record,
    coverage,
    catalog_raw,
):

    catalog = load_catalog(catalog_raw)

    for item in (
        ssh_record,
        smb_document,
        ftp_record,
        coverage,
    ):

        verify_digest(item)

    need(
        ssh_record["sha256"] == SSH_RECEIPT_PIN,
        "SSH_RECEIPT_PIN_INVALID",
    )

    need(
        smb_document["schema"] == transport.SCHEMA
        and smb_document["physical_a5_admitted"] is False
        and smb_document["confirmed_rf"] is None
        and smb_document["operational_a9_published"] is False
        and smb_document["experimental_observations_admitted"] == 0
        and smb_document["p8"] == "NO-GO",
        "SMB_PARENT_AUTHORITY_INVALID",
    )

    matches = [
        item
        for item in smb_document["results"]
        if item["protocol"] == "SMB"
    ]

    need(
        len(matches) == 1,
        "SMB_RECEIPT_IDENTITY_INVALID",
    )

    records = {
        "SSH": ssh_record,
        "FTP": ftp_record,
        "SMB": matches[0],
    }

    need(
        coverage["schema"] ==
            "ARDREC-R194D-TRANSPORT-COVERAGE-v1"
        and coverage["protocols_observed"] ==
            ["FTP", "SMB", "SSH"]
        and coverage["transport_coverage_count"] == 3
        and coverage["protocol_count"] == 3
        and coverage["experimental_observations_admitted"] == 0
        and coverage["physical_a5_admitted"] is False
        and coverage["confirmed_rf"] is None
        and coverage["operational_a9_published"] is False
        and coverage["p8"] == "NO-GO",
        "COVERAGE_AUTHORITY_INVALID",
    )

    rows = []

    for protocol in PROTOCOLS:

        record = records[protocol]

        need(
            coverage[
                protocol.lower() + "_receipt_sha256"
            ] == record["sha256"],
            "COVERAGE_RECEIPT_BINDING_INVALID",
        )

        parsed = verify_transport(
            protocol, record
        )

        family = catalog[protocol]

        # These are observed local equivalents, not A6 admissions.
        candidate_supports = {
            "SSH": [],
            "FTP": ["CONTROL_CHANNEL_RESPONSE"],
            "SMB": [
                "SMB_DIALECT",
                "TRANSPORT_NEGOTIATION",
            ],
        }[protocol]

        required = set(
            family["required_supports"]
        )

        need(
            set(candidate_supports) <= required,
            "CATALOG_SUPPORT_MISMATCH",
        )

        missing_local_equivalents = sorted(
            required - set(candidate_supports)
        )

        truth = Truth.ND.value

        stop = preview_stop(
            a6_classification=truth,
            accredited=False,
            vm_checked=False,
            operational_dispatch=False,
            source_sha256=record["sha256"],
        )

        verify_stop(stop)

        reference = reference_preview(
            protocol,
            record["sha256"],
        )

        row = {
            "protocol": protocol,
            "pilot_id": "PILOT_LOCAL_" + protocol,
            "candidate_family": family["id"],
            "observed_response": parsed,
            "source_receipt_sha256": record["sha256"],
            "local_candidate_supports": candidate_supports,
            "required_supports": sorted(required),
            "missing_local_equivalents":
                missing_local_equivalents,
            "operationally_admitted_supports": [],
            "operationally_missing_supports":
                sorted(required),
            "required_preconditions":
                family["preconditions"],
            "historical_preconditions_verified": False,
            "a1": "NOT_EXECUTED_HISTORICAL_RULE_ENGINE",
            "a2": "LOCAL_RECEIPT_IDENTITY_REPLAYED",
            "a3": "NO_OPERATIONAL_AUTHORIZATION",
            "a4": "CATALOG_FAMILY_ASSOCIATION_ONLY",
            "a5": "LOCAL_TRANSPORT_NOT_OPERATIONAL_A5",
            "a6": truth,
            "a7": "NOT_COMPUTED_NO_FROZEN_BASELINE",
            "confirmed_rf": None,
            "a8": stop,
            "a9": "NOT_PUBLISHED",
            "a10": "REPLAYABLE_STATUS_REPORT",
            "reference_i4": reference,
            "experimental_admission": False,
        }

        row["sha256"] = digest(row)

        rows.append(row)

    report = {
        "schema": SCHEMA,
        "mode": "REAL_LOCAL_RECEIPTS_CONSERVATIVE_REPLAY",
        "catalog_sha256": CATALOG_SHA256,
        "coverage_sha256": coverage["sha256"],
        "protocol_count": len(rows),
        "rows": rows,
        "new_protocol_executions": 0,
        "actual_a8_kernel_evaluations": len(rows),
        "actual_i4_kernel_evaluations": len(rows),
        "a6_operational_admissions": 0,
        "a7_confirmed_values": 0,
        "a8_applied_transitions": 0,
        "a9_operational_publications": 0,
        "experimental_observations_admitted": 0,
        "historical_operational_chain_complete": False,
        "external_validation_claimed": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    report["sha256"] = digest(report)

    return report


def verify(report, *inputs):

    need(
        ssh.canonical(report) ==
            ssh.canonical(build(*inputs)),
        "BRIDGE_REPLAY_INVALID",
    )

    return True
