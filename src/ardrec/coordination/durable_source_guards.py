"""Source-bound durable-state diagnostics.

Recover an existing native journal using externally supplied pins.
Never reserve, dispatch, transition, publish or confirm technical risk.
"""

import argparse
from contextlib import ExitStack
from pathlib import Path
import json

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.analytical_counters import counter_payload
from ardrec.analytical_references import fingerprint, identifier
from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.persistence import codec
from ardrec.rules.kernel import evaluate as evaluate_rule
from ardrec.state import GuardFact, Truth, ServicePhase, InvocationPhase
from ardrec.stopping import ordinary_closure

SCHEMA = "ARDREC-R359-DURABLE-SOURCE-GUARDS-v1"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def path_contract(path):
    path = Path(path)

    require(
        path.is_absolute()
        and ".." not in path.parts,
        "ABSOLUTE_PRIVATE_PATH_REQUIRED",
    )

    return path


def fact_record(name, value, head, state_pin, source):
    require(type(value) is Truth, "TRUTH_TYPE_INVALID")

    reference = digest({
        "name": name,
        "value": value.value,
        "head_sha256": head,
        "state_sha256": state_pin,
        "source": source,
    })

    native = GuardFact(name, value, reference)

    return {
        "name": native.name,
        "value": native.value.value,
        "reference": native.reference,
        "source": source,
        "operationally_accredited": False,
    }


def truth(value):
    require(type(value) is bool, "BOOLEAN_REQUIRED")

    return (
        Truth.VERDADERO
        if value
        else Truth.FALSO
    )


def evaluate_quiescence(facts):
    schema = {
        name: "LOGICO"
        for name in facts
    }

    expression = {
        "op": "Y",
        "args": [
            {"op": "CAMPO", "nombre": name}
            for name in facts
        ],
    }

    return evaluate_rule(expression, schema, facts)


def inspect(
    store_path,
    *,
    record_id,
    configuration_sha256,
    expected_head,
    archive_path=None,
    expected_snapshot=None,
):
    """Read/replay a pinned native state under existing storage locks.

    The supplied pin is not itself a proof of custody or freshness.
    The journal's authority is not external operational authorization.
    """
    identifier(record_id)
    fingerprint(configuration_sha256)
    fingerprint(expected_head)

    store_path = path_contract(store_path)

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
                AnalyticalArchive(path_contract(archive_path))
            )

        store = stack.enter_context(
            DurableStore.open(
                store_path,
                record_id=record_id,
                configuration_sha256=configuration_sha256,
                expected_head=expected_head,
                analytical_archive=archive,
            )
        )

        state = store.state

        require(
            not state.simulation
            and state.authority is Truth.VERDADERO,
            "NATIVE_STORAGE_AUTHORITY_REQUIRED",
        )

        require(
            store.head_sha256 == expected_head
            and store.analytical_snapshot_sha256
                == expected_snapshot,
            "DURABLE_ANCHOR_MISMATCH",
        )

        state_pin = codec.digest(
            codec.canonical(codec.pack(state))
        )

        snapshot_mode = "ABSENT"

        if expected_snapshot is not None:
            snapshot = store.analytical_snapshot

            require(
                snapshot is not None
                and snapshot.snapshot_sha256
                    == expected_snapshot,
                "ANALYTICAL_SNAPSHOT_MISMATCH",
            )

            snapshot_mode = store.analytical_validation

        confirmed = {
            item.service_scenario_id: item
            for item in state.confirmed.services
        }

        current = {
            item.service_scenario_id: item
            for item in state.services
        }

        require(
            set(confirmed) == set(current),
            "SERVICE_SCOPE_DRIFT",
        )

        temporal = store.temporal_status
        recovery = store.recovery_action

        pending = list(state.pending_attempts)
        candidate_present = state.services != state.confirmed.services

        facts = {
            "invocation_active": truth(
                state.invocation is InvocationPhase.EN_CURSO
            ),
            "no_pending_attempt": truth(not pending),
            "no_unpublished_candidate": truth(
                not candidate_present
            ),
            "temporal_review_clear": (
                Truth.VERDADERO
                if temporal == "PASS"
                else Truth.ND
            ),
            "recovery_clear": truth(recovery == "NONE"),
        }

        quiescence = evaluate_quiescence(facts)

        global_guards = [
            fact_record(
                name,
                value,
                expected_head,
                state_pin,
                "NATIVE_DURABLE_STATE",
            )
            for name, value in facts.items()
        ]

        global_guards.append(
            fact_record(
                "journal_quiescent",
                quiescence,
                expected_head,
                state_pin,
                "A1_DERIVED_FROM_NATIVE_STATE",
            )
        )

        # External technical identity, evidence admission,
        # safety and physical authority remain undetermined.
        global_guards.append(
            fact_record(
                "external_operational_authority",
                Truth.ND,
                expected_head,
                state_pin,
                "EXTERNAL_ATTESTATION_NOT_PROVIDED",
            )
        )

        global_guards.append(
            fact_record(
                "dispatch_permitted",
                Truth.FALSO,
                expected_head,
                state_pin,
                "R359_DIAGNOSTIC_ONLY",
            )
        )

        services = []

        for sid in sorted(confirmed):
            original = confirmed[sid]
            candidate = current[sid]

            counters = counter_payload(state, sid)

            executions = sum(
                case["confirmed_executions"]
                for case in counters["cases"]
            )

            pending_ids = [
                item.identity["attempt_id"]
                for item in state.attempts
                if item.pending
                and item.identity["service_scenario_id"] == sid
            ]

            terminal = original.phase in {
                ServicePhase.CERRADO,
                ServicePhase.DETENIDO,
            }

            closure_facts = {
                name: Truth.ND.value
                for name in ordinary_closure.FACTS
            }

            # A pending attempt blocks closure. An empty
            # journal cannot prove physical reconciliation.
            if pending or candidate_present:
                closure_facts["attempt_reconciled"] = (
                    Truth.FALSO.value
                )

            closure = ordinary_closure.evaluate(
                facts=closure_facts,
                history=[],
                executions=executions,
                budget=None,
                phase=original.phase.value,
            )

            ordinary_closure.verify(closure)

            require(
                closure["candidate_transition"] is None
                and closure["applied_transition"] is None,
                "OPERATIONAL_CLOSURE_PROMOTED",
            )

            services.append({
                "service_scenario_id": sid,
                "confirmed_phase": original.phase.value,
                "candidate_phase": candidate.phase.value,
                "candidate_differs": candidate != original,
                "terminal": terminal,
                "pending_attempt_ids": pending_ids,
                "execution_counters": counters,
                "incorporated_case_executions": executions,
                "ordinary_criteria": closure["criteria"],
                "ordinary_gate": closure["ordinary_gate"],
                "closure_decision": closure["decision"],
                "closure_sha256": closure["sha256"],
                "closure_candidate": None,
                "a6": "ND",
                "confirmed_rf": None,
                "technical_safety": "ND",
            })

        report = {
            "schema": SCHEMA,
            "scope": "DURABLE_DIAGNOSTIC_ONLY",
            "record_id": record_id,
            "execution_id": state.execution_id,
            "configuration_sha256": configuration_sha256,
            "head_sha256": expected_head,
            "state_sha256": state_pin,
            "generation": state.confirmed.generation,
            "generation_reference":
                state.confirmed.generation_reference,
            "snapshot_sha256": expected_snapshot,
            "snapshot_validation": snapshot_mode,
            "snapshot_full_semantics_accredited": False,
            "invocation": state.invocation.value,
            "pending_attempts": pending,
            "candidate_present": candidate_present,
            "temporal_status": temporal,
            "recovery_action": recovery,
            "dispatch_blockers": list(state.dispatch_blockers),
            "incorporated_execution_count":
                state.incorporated_execution_count,
            "journal_quiescence": quiescence.value,
            "guards": global_guards,
            "services": services,
            "external_freshness_accredited": False,
            "external_operational_authority": "ND",
            "dispatch_allowed": False,
            "published_generation": None,
            "confirmed_rf": None,
            "experimental_admitted": 0,
            "p8": "NO-GO",
        }

        require(
            store.head_sha256 == expected_head
            and codec.digest(
                codec.canonical(codec.pack(store.state))
            ) == state_pin,
            "STATE_CHANGED_DURING_DIAGNOSTIC",
        )

        report["sha256"] = digest(report)

        return report


def verify(report, expected_report_sha256, store_path, **kwargs):
    fingerprint(expected_report_sha256)

    require(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and digest({
            k: v for k, v in report.items()
            if k != "sha256"
        }) == expected_report_sha256,
        "DIAGNOSTIC_PIN_MISMATCH",
    )

    expected = inspect(store_path, **kwargs)

    require(
        canonical(report) == canonical(expected),
        "DURABLE_DIAGNOSTIC_REPLAY_MISMATCH",
    )

    return True


def main():
    parser = argparse.ArgumentParser(
        description="ARDREC native durable-state diagnostic"
    )

    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--record-id", required=True)
    parser.add_argument("--configuration-sha256", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--expected-snapshot")

    args = parser.parse_args()

    report = inspect(
        args.store,
        record_id=args.record_id,
        configuration_sha256=args.configuration_sha256,
        expected_head=args.expected_head,
        archive_path=args.archive,
        expected_snapshot=args.expected_snapshot,
    )

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
