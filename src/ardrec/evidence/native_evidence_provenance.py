"""Native receipt provenance index.

Documentary association only. No technical classification,
physical execution or operational publication.
"""

from contextlib import ExitStack
from copy import deepcopy
import hashlib

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.analytical_references import fingerprint, identifier
from ardrec.coordination.durable_source_guards import path_contract
from ardrec.messages import decode_message
from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.persistence import codec
from ardrec.state import Truth

SCHEMA = "ARDREC-R360-NATIVE-EVIDENCE-PROVENANCE-v1"
CATALOG_SCHEMA = SCHEMA + "-catalog"

MAX_BINDINGS = 1024
MAX_ATTEMPTS = 4096

BINDING_FIELDS = {
    "service_scenario_id",
    "derived_case_id",
    "condition_id",
    "profile_reference",
    "parameters_reference",
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def byte_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_catalog(catalog, expected_catalog_sha256):

    fingerprint(expected_catalog_sha256)

    require(
        type(catalog) is dict
        and set(catalog) == {
            "schema",
            "record_id",
            "execution_id",
            "configuration_sha256",
            "bindings",
        }
        and catalog["schema"] == CATALOG_SCHEMA,
        "CATALOG_SCHEMA_INVALID",
    )

    catalog = deepcopy(catalog)

    require(
        digest(catalog) == expected_catalog_sha256,
        "CATALOG_PIN_MISMATCH",
    )

    identifier(catalog["record_id"])
    identifier(catalog["execution_id"])
    fingerprint(catalog["configuration_sha256"])

    rows = catalog["bindings"]

    require(
        type(rows) is list
        and 1 <= len(rows) <= MAX_BINDINGS,
        "CATALOG_DOMAIN_INVALID",
    )

    index = {}

    for row in rows:

        require(
            type(row) is dict
            and set(row) == BINDING_FIELDS,
            "BINDING_SCHEMA_INVALID",
        )

        for value in row.values():
            identifier(value)

        key = (
            row["service_scenario_id"],
            row["derived_case_id"],
        )

        require(
            key not in index,
            "AMBIGUOUS_CASE_CONDITION_BINDING",
        )

        index[key] = row

    return catalog, index


def attempt_provenance(attempt, bindings):

    request = attempt.identity

    require(
        request["scope"] == "attempt",
        "NON_CASE_REQUEST",
    )

    key = (
        request["service_scenario_id"],
        request["derived_case_id"],
    )

    binding = bindings.get(key)

    receipt = attempt.incorporation

    row = {
        "service_scenario_id": key[0],
        "derived_case_id": key[1],
        "attempt_id": request["attempt_id"],
        "decision_index": request["decision_index"],
        "request_sha256": byte_hash(attempt.request),
        "report_sha256": None,
        "incorporation_event": None,
        "incorporation_generation": None,
        "condition_id": None,
        "declared_support_references": [],
        "effective_parameters_reference": None,
        "documentary_link_verified": False,
        "support_bytes_verified": False,
        "technical_truth_accredited": False,
        "classification": "ND",
        "status": None,
    }

    if attempt.reports:

        row["report_sha256"] = byte_hash(
            attempt.reports[-1].message
        )

    if receipt is None:

        row["status"] = "PENDING_INCORPORATION"
        return row

    row["incorporation_event"] = receipt.event_reference
    row["incorporation_generation"] = receipt.generation

    require(
        attempt.technical_resolved,
        "INCORPORATED_ATTEMPT_UNRESOLVED",
    )

    snapshot = attempt.snapshot

    if snapshot["start"]["status"] == "NO_INICIADO":

        row["status"] = "VERIFIED_NON_START"
        return row

    require(
        snapshot["start"]["status"] == "VERIFICADO",
        "INCORPORATED_START_UNRESOLVED",
    )

    if binding is None:

        row["status"] = "CASE_BINDING_MISSING"
        return row

    payload = request["payload"]

    require(
        payload["profile_reference"]
            == binding["profile_reference"]
        and payload["parameters_reference"]
            == binding["parameters_reference"],
        "FROZEN_CASE_REFERENCE_MISMATCH",
    )

    row["condition_id"] = binding["condition_id"]

    if (
        snapshot["phase"] != "completed"
        or snapshot["termination"]["status"] != "VERIFICADO"
        or snapshot["cleanup"]["status"] != "completed"
        or snapshot["result"]["status"] != "DISPONIBLE"
    ):

        row["status"] = "RESULT_NOT_REVIEWABLE"
        return row

    final_message = decode_message(
        attempt.reports[-1].message
    )

    # A status report cannot substitute for the full
    # result carrying the declared support inventory.
    if final_message["message_type"] != "execution_result":

        row["status"] = "FULL_RESULT_REQUIRED"
        return row

    outcome = final_message["payload"]["outcome"]

    supports = outcome["supports"]

    row["declared_support_references"] = sorted(supports)

    row["effective_parameters_reference"] = (
        outcome["effective_parameters_reference"]
    )

    if not supports:

        row["status"] = "SUPPORTS_MISSING"
        return row

    row["documentary_link_verified"] = True

    row["status"] = "SUPPORT_REVIEW_REQUIRED"

    return row


def build(
    store_path,
    *,
    catalog,
    expected_catalog_sha256,
    expected_head,
    archive_path=None,
    expected_snapshot=None,
):

    catalog, bindings = validate_catalog(
        catalog, expected_catalog_sha256
    )

    fingerprint(expected_head)

    require(
        (archive_path is None) == (expected_snapshot is None),
        "ARCHIVE_PIN_PAIR_REQUIRED",
    )

    if expected_snapshot is not None:
        fingerprint(expected_snapshot)

    with ExitStack() as stack:

        archive = None

        if archive_path is not None:

            archive = stack.enter_context(
                AnalyticalArchive(
                    path_contract(archive_path)
                )
            )

        store = stack.enter_context(
            DurableStore.open(
                path_contract(store_path),
                record_id=catalog["record_id"],
                configuration_sha256=
                    catalog["configuration_sha256"],
                expected_head=expected_head,
                analytical_archive=archive,
            )
        )

        state = store.state

        require(
            state.authority is Truth.VERDADERO
            and not state.simulation
            and state.execution_id == catalog["execution_id"],
            "DURABLE_CONTEXT_MISMATCH",
        )

        require(
            store.head_sha256 == expected_head
            and store.analytical_snapshot_sha256
                == expected_snapshot,
            "DURABLE_ANCHOR_MISMATCH",
        )

        known_services = {
            service.service_scenario_id
            for service in state.confirmed.services
        }

        require(
            all(
                sid in known_services
                for sid, _ in bindings
            ),
            "FOREIGN_CATALOG_SERVICE",
        )

        require(
            len(state.attempts) <= MAX_ATTEMPTS,
            "ATTEMPT_INVENTORY_LIMIT",
        )

        state_pin = codec.digest(
            codec.canonical(codec.pack(state))
        )

        rows = []

        non_case_attempts = 0

        for attempt in state.attempts:

            if attempt.identity["scope"] != "attempt":

                non_case_attempts += 1
                continue

            rows.append(
                attempt_provenance(attempt, bindings)
            )

        rows.sort(
            key=lambda row: (
                row["service_scenario_id"],
                row["derived_case_id"],
                row["attempt_id"],
            )
        )

        conditions = {}

        for row in rows:

            if not row["documentary_link_verified"]:
                continue

            key = (
                row["service_scenario_id"],
                row["condition_id"],
            )

            conditions.setdefault(key, []).append({
                "derived_case_id":
                    row["derived_case_id"],
                "attempt_id": row["attempt_id"],
                "request_sha256": row["request_sha256"],
                "report_sha256": row["report_sha256"],
                "incorporation_event":
                    row["incorporation_event"],
                "incorporation_generation":
                    row["incorporation_generation"],
            })

        condition_rows = [
            {
                "service_scenario_id": sid,
                "condition_id": cid,
                "linked_receipts": entries,
                "classification": "ND",
                "active_evidence_revision": None,
                "confirmed_contribution": None,
            }
            for (sid, cid), entries in sorted(
                conditions.items()
            )
        ]

        counts = {}

        for row in rows:

            status = row["status"]

            counts[status] = counts.get(status, 0) + 1

        report = {
            "schema": SCHEMA,
            "scope": "NATIVE_DOCUMENTARY_PROVENANCE_ONLY",
            "catalog_sha256": expected_catalog_sha256,
            "head_sha256": expected_head,
            "state_sha256": state_pin,
            "record_id": state.confirmed.record_id,
            "execution_id": state.execution_id,
            "configuration_sha256":
                state.confirmed.configuration_sha256,
            "generation": state.confirmed.generation,
            "snapshot_sha256": expected_snapshot,
            "attempts": rows,
            "conditions": condition_rows,
            "status_counts": counts,
            "case_attempt_count": len(rows),
            "non_case_attempt_count": non_case_attempts,
            "documentary_links_verified": sum(
                row["documentary_link_verified"]
                for row in rows
            ),
            "pending_attempt_count": len(
                state.pending_attempts
            ),
            "technical_conditions_accredited": 0,
            "support_bytes_verified": 0,
            "technical_truth_accredited": False,
            "external_catalog_authority_accredited": False,
            "external_freshness_accredited": False,
            "a6": "ND",
            "confirmed_rf": None,
            "operational_dispatch": False,
            "published_generation": None,
            "experimental_admitted": 0,
            "p8": "NO-GO",
        }

        require(
            store.head_sha256 == expected_head
            and codec.digest(
                codec.canonical(codec.pack(store.state))
            ) == state_pin,
            "SOURCE_CHANGED_DURING_REVIEW",
        )

        report["sha256"] = digest(report)

        return report


def verify(
    report,
    expected_report_sha256,
    store_path,
    **kwargs,
):

    fingerprint(expected_report_sha256)

    require(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and digest({
            key: value
            for key, value in report.items()
            if key != "sha256"
        }) == expected_report_sha256,
        "REPORT_PIN_INVALID",
    )

    expected = build(store_path, **kwargs)

    require(
        canonical(report) == canonical(expected),
        "PROVENANCE_REPLAY_MISMATCH",
    )

    return True
