"""R261: private VM functional evidence ingestion.

Import of previously acquired synthetic control reads.
No dispatch, risk confirmation or experimental admission.
"""

import hashlib
import json
import os

from pathlib import Path

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
)

from ardrec.experiments import (
    local_consolidation,
    reference_supports,
)

from ardrec.stopping.development_stop import (
    preview_stop,
    verify_stop,
)

SCHEMA = "ARDREC-R261-VM-FUNCTIONAL-EVIDENCE-v1"

FAMILIES = {
    "ssh": "SSH-T06",
    "ftp": "FTP-T08",
    "smb": "SMB-T09",
}

SOURCE_SCHEMA = "ARDREC-R260-FUNCTIONAL-SMOKE-v1"

SMOKE_SCHEMA = "ARDREC-R260-SERVICE-SMOKE-v1"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_source(source, expected_sha256):

    evidence.verify_digest(source)

    need(
        source["sha256"] == expected_sha256,
        "SOURCE_PIN_MISMATCH",
    )

    need(
        source["schema"] == SOURCE_SCHEMA
        and source["status"] == "PRIVATE_SERVICE_SMOKE_PASS"
        and source["transport"] == "QEMU_PRIVATE_UNIX_STREAM"
        and source["private_vms_started"] == 4
        and source["connected_roles_verified"] == 4
        and source["connected_interfaces_verified"] == 6
        and source["connected_firewalls_verified"] == 4
        and source["private_links_verified"] == 3
        and source["functional_services_verified"] == 3
        and source["positive_service_connectivity_verified"] is True
        and source["protocol_service_attempts"] == 3
        and source["restricted_resource_attempts"] == 0
        and source["graceful_shutdowns_verified"] == 4
        and source["original_baselines_preserved"] == 4
        and source["host_firewall_writes"] == 0
        and source["formal_pilot_admitted"] == 0
        and source["experimental_admitted"] == 0
        and source["p7"] == "DRAFT_NOT_FROZEN"
        and source["p8"] == "NO-GO",
        "SOURCE_SCOPE_INVALID",
    )

    rows = source["functional_smokes"]

    need(
        type(rows) is list
        and len(rows) == 3
        and {row["protocol"] for row in rows}
            == set(FAMILIES),
        "SMOKE_SET_INVALID",
    )

    return {
        row["protocol"]: row
        for row in rows
    }


def build(source, expected_sha256, originals, artifacts, catalog):

    smokes = validate_source(
        source, expected_sha256
    )

    need(
        set(originals) == set(FAMILIES)
        and set(artifacts) == set(FAMILIES),
        "ARTIFACT_SET_INVALID",
    )

    rows = []

    for protocol, family_id in FAMILIES.items():

        smoke = smokes[protocol]
        original = originals[protocol]
        raw = artifacts[protocol]

        evidence.verify_digest(smoke)
        evidence.verify_digest(original)

        need(
            original == smoke,
            "INDIVIDUAL_RECEIPT_MISMATCH",
        )

        need(
            smoke["schema"] == SMOKE_SCHEMA
            and smoke["scope"] == "PRIVATE_SYNTHETIC_CONTROL_READ"
            and type(smoke["client_invocations"]) is int
            and smoke["client_invocations"] == 1
            and smoke["functional_read_verified"] is True
            and smoke["runner_deny_restored"] is True
            and smoke["target_deny_restored"] is True
            and smoke["target_service_masked"] is True
            and smoke["target_account_locked"] is True
            and smoke["client_credential_removed"] is True
            and smoke["formal_pilot_admitted"] is False
            and smoke["experimental_admitted"] is False
            and smoke["a6"] == "ND"
            and smoke["confirmed_rf"] is None
            and smoke["p8"] == "NO-GO",
            "SMOKE_SCOPE_INVALID",
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
            and observation["client_returncode"] == 0
            and observation["read_sha256"] == digest(raw)
            and smoke["fixture_sha256"] == digest(raw),
            "TRANSFER_CONTENT_INVALID",
        )

        family = catalog[family_id]

        need(
            family["id"] == family_id
            and family["protocol"] == protocol,
            "CATALOG_FAMILY_INVALID",
        )

        supports = []

        for support in family["required_supports"]:

            if support in (
                "RESOURCE_READ",
                "KNOWN_CONTENT_DIGEST",
            ):

                status = "CONTROL_READ_BYTES_VERIFIED"

            elif support == "ACCESS_COMPARISON":

                status = "MISSING_RESTRICTED_COMPARISON"

            elif support == "OPERATION_RESPONSE":

                status = "CONTROL_CLIENT_RESPONSE_ONLY"

            else:

                status = "DOCUMENTARY_SUPPORT_ONLY"

            supports.append({
                "support": support,
                "status": status,
                "operationally_accredited": False,
            })

        # Native A8, without applying a transition.
        stop = preview_stop(
            a6_classification="ND",
            accredited=False,
            vm_checked=False,
            operational_dispatch=False,
            source_sha256=smoke["sha256"],
        )

        need(
            verify_stop(stop),
            "NATIVE_A8_REPLAY_INVALID",
        )

        rows.append({
            "protocol": protocol.upper(),
            "candidate_family": family_id,
            "source_smoke_sha256": smoke["sha256"],
            "source_report_sha256": source["sha256"],
            "read_bytes": len(raw),
            "raw_artifact_sha256": digest(raw),
            "control_read_verified": True,
            "restricted_comparison_verified": False,
            "supports": supports,
            "stages": {
                "A1": "CATALOG_FAMILY_LINKED",
                "A2": "BASELINE_NOT_CLOSED",
                "A3": "DEVELOPMENT_SCOPE_ONLY",
                "A4": "ADAPTIVE_SELECTION_NOT_EXECUTED",
                "A5": "FUNCTIONAL_READ_REPLAY_ONLY",
                "A6": "ND",
                "A7": "CONFIRMED_RF_UNAVAILABLE",
                "A8": stop["recommendation"],
                "A9": "NOT_PUBLISHED",
                "A10": "NATIVE_READONLY_REPORT",
            },
            "native_a8": stop,
            "a6": "ND",
            "confirmed_rf": None,
            "reference_i4": None,
            "formal_pilot_admitted": False,
            "experimental_admitted": False,
        })

    return durable.seal({
        "schema": SCHEMA,
        "scope": "PRIVATE_VM_FUNCTIONAL_REPLAY",
        "source_sha256": source["sha256"],
        "source_head": source["code_head"],
        "catalog_sha256": evidence.CATALOG_SHA256,
        "rows": rows,
        "functional_reads_verified": len(rows),
        "raw_bytes_verified": sum(
            row["read_bytes"] for row in rows
        ),
        "native_a8_replays": len(rows),
        "required_support_entries": sum(
            len(row["supports"]) for row in rows
        ),
        "operational_supports_accredited": 0,
        "confirmed_rf_count": 0,
        "operational_a9_publications": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "new_network_operations": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def read_private_json(path):

    raw = reference_supports.read_file(
        path, 262144
    )

    return json.loads(raw)


def evaluate(folder, expected_sha256, artifacts_folder, catalog_path):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    folder = Path(folder)
    artifacts_folder = Path(artifacts_folder)

    source = read_private_json(
        folder / "05-functional-service-report.json"
    )

    originals = {
        protocol: read_private_json(
            folder / (protocol + "-functional-smoke.json")
        )
        for protocol in FAMILIES
    }

    artifacts = {
        protocol: reference_supports.read_file(
            artifacts_folder / (protocol + ".bin"),
            4096,
        )
        for protocol in FAMILIES
    }

    catalog = local_consolidation.load_families(
        catalog_path
    )

    return build(
        source,
        expected_sha256,
        originals,
        artifacts,
        catalog,
    )


def render_text(report):

    lines = [
        "ARDREC / EVIDENCIA FUNCIONAL DE VM",
        "ALCANCE=" + report["scope"],
        "SOURCE_SHA256=" + report["source_sha256"],
    ]

    for row in report["rows"]:

        lines += [
            "",
            "PROTOCOL=" + row["protocol"],
            "FAMILY_CANDIDATE=" + row["candidate_family"],
            "READ_BYTES=" + str(row["read_bytes"]),
            "ARTIFACT_SHA256=" + row["raw_artifact_sha256"],
        ]

        for stage, status in row["stages"].items():
            lines.append(stage + "=" + status)

        for support in row["supports"]:
            lines.append(
                support["support"]
                + "=" + support["status"]
            )

    for key in (
        "functional_reads_verified",
        "raw_bytes_verified",
        "native_a8_replays",
        "required_support_entries",
        "operational_supports_accredited",
        "confirmed_rf_count",
        "operational_a9_publications",
        "formal_pilot_admitted",
        "experimental_admitted",
        "new_network_operations",
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
