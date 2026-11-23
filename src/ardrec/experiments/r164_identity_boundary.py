"""R164-F5: frontera entre modelo sintético y estudio experimental.

No convierte una coincidencia de nombres o familias en identidad probada.
No admite A6, Rf confirmado, A9, autoridad P8 ni observaciones físicas.
"""
from __future__ import annotations

from collections import Counter

from ardrec.coordination import (
    r109_executable_decision_chain as r109,
)
from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
)

SCHEMA = "ARDREC-R164-F5-CROSS-POPULATION-BOUNDARY-v1"

MODEL = {"SSH_DEV": 16, "FTP_DEV": 20, "SMB_DEV": 18}
EXPERIMENT = {"SSH": 18, "FTP": 18, "SMB": 18}


class Stop(ValueError):
    """Inconsistencia de procedencia o de contrato."""


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def build(
    catalog,
    protocol,
    registry,
    plan,
    checklist,
    working_csv,
    unified,
    trace,
    model,
    decision,
):
    """Reconcilia contratos, no empareja muestras diferentes."""

    audit = r148.validate(
        protocol, registry, catalog
    )

    selection = r149.validate_selection(
        plan, checklist, working_csv,
        catalog, protocol, registry
    )

    need(
        r109.verify(decision, unified, trace, model),
        "R109_REPLAY_FAILED",
    )

    need(
        decision["protocol_counts"] == MODEL
        and audit["by_protocol"] == EXPERIMENT,
        "POPULATION_DISTRIBUTION_CHANGED",
    )

    need(
        decision["case_count"] == 54
        and decision["family_count"] == 25
        and decision["status_stage_count"] == 540
        and decision["offline_case_checks_by_stage"] == {
            "A4": 54,
            "A6": 54,
            "A7": 54,
            "A8": 54,
            "A10": 54,
        }
        and decision["rechecked_r108_model_events"] == 72,
        "OFFLINE_KERNEL_COVERAGE_INVALID",
    )

    need(
        decision["a1_a10_operational_implementation_complete"]
            is False
        and decision["a5_operational_starts"] == 0
        and decision["a6_classification"] == "ND"
        and decision["a7_confirmed_rf"] is None
        and decision["a8_operational_transitions"] == 0
        and decision["a9_published_generations"] == 0
        and decision["operational_dispatch"] is False
        and decision["vm_starts"] == 0
        and decision["host_mutations"] == 0
        and decision["p8_operational"] == "NO-GO",
        "MODEL_AUTHORITY_ESCALATION",
    )

    rows = r149.parse_csv(working_csv)

    need(
        len(rows) == 54
        and len(registry["slots"]) == 54,
        "EXPERIMENT_SLOT_COUNT_INVALID",
    )

    result_rows = []
    counts = Counter()

    for candidate, slot in zip(rows, registry["slots"]):
        need(
            candidate["slot_id"] == slot["slot_id"]
            and candidate["protocol"] == slot["protocol"],
            "EXPERIMENT_IDENTITY_DRIFT",
        )

        values = [
            candidate[key] != ""
            for key in r149.ENTRY_FIELDS
        ]

        if all(values):
            status = "CANDIDATE_ONLY_UNVERIFIED"
        elif any(values):
            status = "PARTIAL_UNVERIFIED"
        else:
            status = "UNASSIGNED"

        counts[status] += 1

        result_rows.append({
            "slot_id": slot["slot_id"],
            "protocol": slot["protocol"],
            "selection_state": status,
            "candidate_case_id":
                candidate["case_id"] or None,
            "candidate_scenario_id":
                candidate["scenario_id"] or None,
            "candidate_family_id":
                candidate["chosen_family"] or None,
            "model_r109_case_id": None,
            "cross_population_identity_attested": False,
            "technical_evidence_admitted": False,
            "experimental_observation_confirmed": False,
            "a6": "ND",
            "rf_confirmed": None,
            "a9": None,
            "p8": "NO-GO",
        })

    need(
        sum(counts.values()) == 54
        and counts["CANDIDATE_ONLY_UNVERIFIED"]
            == selection["statuses"]["COMPLETE"]
        and counts["PARTIAL_UNVERIFIED"]
            == selection["statuses"]["PARTIAL"]
        and counts["UNASSIGNED"]
            == selection["statuses"]["EMPTY"],
        "EXPERIMENT_READINESS_RECONCILIATION_FAILED",
    )

    need(
        audit["confirmed_physical_observations"] == 0
        and selection["physical_observations"] == 0
        and audit["p8"] == selection["p8"] == "NO-GO",
        "EXPERIMENT_AUTHORITY_ESCALATION",
    )

    result = {
        "schema": SCHEMA,
        "source_head": protocol["head"],
        "r148_protocol_sha256": protocol["sha256"],
        "r148_registry_sha256": registry["sha256"],
        "r149_plan_sha256": plan["sha256"],
        "r149_selection_sha256": r149.sha(working_csv),
        "r109_model_sha256": decision["sha256"],
        "model_distribution": MODEL.copy(),
        "experiment_distribution": EXPERIMENT.copy(),
        "model_case_windows": 54,
        "planned_experimental_units": 54,
        "model_offline_kernel_checks": 270,
        "model_case_coverage_family_count": 25,
        "candidate_counts": dict(sorted(counts.items())),
        "cross_population_pair_count": 0,
        "accepted_evidence_count": 0,
        "confirmed_physical_observations": 0,
        "experimental_wilcoxon_admitted": False,
        "model_and_experiment_samples_equal": False,
        "independent_human_authority_verified": False,
        "root_activation_authorized": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
        "a6": "ND",
        "a9": "NOT_PUBLISHED",
        "slots": result_rows,
    }

    result["sha256"] = r148.digest(
        r148.canonical(result)
    )

    return result


def verify(
    document,
    catalog,
    protocol,
    registry,
    plan,
    checklist,
    working_csv,
    unified,
    trace,
    model,
    decision,
):
    expected = build(
        catalog,
        protocol,
        registry,
        plan,
        checklist,
        working_csv,
        unified,
        trace,
        model,
        decision,
    )

    need(
        type(document) is dict
        and document == expected,
        "BOUNDARY_REPLAY_MISMATCH",
    )

    return True
