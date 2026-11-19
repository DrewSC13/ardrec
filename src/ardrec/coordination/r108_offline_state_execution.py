"""R108: executable *counterfactual* T8/T9/T10 for 54 R107 windows.

Evaluates guards and model state changes using the existing R58-U transition
semantics. References are synthetic assumptions, NOT authorizations, actual
machine transitions, physical A5 evidence, technical truth, or A9 publication.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r58u_counterfactual_pause_recovery as model
from ardrec.coordination import r107_offline_a1_a10_orchestrator as r107
from ardrec.state import Transition

SCHEMA = "ardrec-r108-54-window-counterfactual-transition-engine-v1"
MODE = "OFFLINE_EXECUTED_MODEL_TRANSITIONS_NO_AUTHORITY"
MAX_BYTES = 950_000
MAX_EVENTS = 54 * 2
PATTERNS = ("PAUSE_ONLY", "PAUSE_AND_RESUME", "STOP_ONLY")
EXPECTED_PHASES = {"PAUSADO": 18, "PENDIENTE": 18, "DETENIDO": 18}


class StateModelError(ValueError):
    """Model input or replay violates the strict offline execution boundary."""


def need(valid: bool, message: str) -> None:
    if not valid:
        raise StateModelError(message)


def _receipt(value: dict[str, Any]) -> str:
    return a5.digest(value)


def _initial() -> dict[str, Any]:
    return {"phase": "PENDIENTE", "revision": 0,
            "wait_ref": None, "pause_ref": None, "stop_cause": None}


def _transitions(position: int) -> list[tuple[str, dict[str, str], str | None]]:
    """Fixed fixture branches with valid R58-U *model-only* fact references."""
    num = f"{position:03d}"
    pause = (
        Transition.PAUSAR.value,
        {"external_wait_registered": "SIM_WAIT_" + num,
         "pause_authorized": "SIM_PAUSE_" + num,
         "precedence_resolved": "SIM_PRECEDENCE_" + num},
        None,
    )
    resume = (
        Transition.REANUDAR.value,
        {"new_authorization": "SIM_NEW_AUTH_" + num,
         "wait_resolved": "SIM_WAIT_" + num,
         "preconditions_valid": "SIM_VALID_" + num},
        None,
    )
    stop = (
        Transition.DETENER.value,
        {"cause_verified": "SIM_CAUSE_" + num,
         "effect_processable": "SIM_EFFECT_" + num},
        "CONTROL",
    )
    return ([pause] if position % 3 == 0 else
            [pause, resume] if position % 3 == 1 else [stop])


def _source(trace: dict[str, Any]) -> list[dict[str, Any]]:
    """R107's original sources MUST ALSO be independently replayed by caller."""
    need(type(trace) is dict and trace.get("schema") == r107.SCHEMA
         and type(trace.get("sha256")) is str
         and _receipt({k: v for k, v in trace.items() if k != "sha256"}) == trace["sha256"]
         and trace.get("case_window_count") == 54
         and trace.get("stage_status_count") == 540
         and trace.get("family_count") == 25
         and trace.get("count_by_service") == r107.COUNTS
         and trace.get("algorithm_ids") == list(r107.ALGORITHMS)
         and trace.get("a1_a10_operational_implementation_complete") is False
         and trace.get("a3_state_transitions_applied") == 0
         and trace.get("a5_operational_starts") == 0
         and trace.get("a6_classification") == "ND"
         and trace.get("a7_confirmed_rf") is None
         and trace.get("a8_applied_transitions") == 0
         and trace.get("a9_published_generations") == 0
         and trace.get("technical_truth_accredited") is False
         and trace.get("operational_dispatch") is False
         and trace.get("p8_operational") == "NO-GO", "SOURCE_NOT_CONSERVATIVE")
    cases = trace.get("cases")
    need(type(cases) is list and len(cases) == 54, "SOURCE_CASE_COUNT")
    keys = set()
    for case in cases:
        need(type(case) is dict
             and type(case.get("case_id_a7")) is str
             and case.get("case_sha256") == _receipt({
                 k: v for k, v in case.items() if k != "case_sha256"})
             and case.get("phase_assumed_not_applied") == "PENDIENTE"
             and case.get("a5_operational_starts") == 0
             and case.get("a6_classification") == "ND"
             and case.get("a7_confirmed_rf") is None
             and case.get("a8_applied_transition") is None
             and case.get("a9_published_generation") is None
             and type(case.get("stages")) is list
             and len(case["stages"]) == 10,
             "SOURCE_CASE_OR_STAGES_INVALID")
        key = case["case_id_a7"]
        need(key not in keys, "DUPLICATE_CASE_ID")
        keys.add(key)
    need(sum(bool(c.get("r106_provenance_association_only")) for c in cases) == 1,
         "R106_ASSOCIATION_DRIFT")
    return sorted(cases, key=lambda c: c["case_id_a7"])


def build(trace: dict[str, Any]) -> dict[str, Any]:
    """Execute bounded deterministic *model* transitions, never host actions."""
    cases = _source(trace)
    entries: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    phase_counts: Counter[str] = Counter()
    previous = None

    for position, case in enumerate(cases, 1):
        current = _initial()
        case_events = []
        branch = PATTERNS[(position - 1) % 3]
        for action, assumptions, stop_cause in _transitions(position - 1):
            # R58-U is the existing source-pinned T8/T9/T10 state machine.
            # It accepts the names and integrity of declared MODEL assumptions,
            # not the actual external facts they would have to represent.
            try:
                refs = model._validate_refs(action, assumptions, stop_cause)
                after = model._evolve(current, action, refs, stop_cause)
            except (ValueError, KeyError, TypeError) as error:
                raise StateModelError("MODEL_TRANSITION_REJECTED") from error
            need(after["revision"] == current["revision"] + 1
                 and after["phase"] in ("PAUSADO", "PENDIENTE", "DETENIDO"),
                 "MODEL_REVISION_OR_PHASE")
            event = {
                "event_number": len(events) + 1,
                "case_id_a7": case["case_id_a7"],
                "r107_case_sha256": case["case_sha256"],
                "transition_code": action,
                "before_phase": current["phase"],
                "after_phase": after["phase"],
                "revision_before": current["revision"],
                "revision_after": after["revision"],
                "synthetic_model_fact_references": refs,
                "stop_cause": stop_cause,
                "previous_event_sha256": previous,
                "operational_authority_attested": False,
                "operational_transition_applied": False,
            }
            event["sha256"] = _receipt(event)
            previous = event["sha256"]
            events.append(event)
            case_events.append(event["sha256"])
            current = after
        phase_counts[current["phase"]] += 1
        entry = {
            "case_id_a7": case["case_id_a7"],
            "r107_case_sha256": case["case_sha256"],
            "service_id": case["service_id"],
            "family_id": case["family_id"],
            "model_branch": branch,
            "initial_model_phase": "PENDIENTE",
            "final_model_phase": current["phase"],
            "model_revision": current["revision"],
            "model_stop_cause": current["stop_cause"],
            "model_event_sha256": case_events,
            "a6_classification": "ND",
            "a7_confirmed_rf": None,
            "operational_transition_applied": False,
            "a9_published_generation": None,
        }
        entry["sha256"] = _receipt(entry)
        entries.append(entry)

    need(len(events) == 72 and len(entries) == 54
         and dict(phase_counts) == EXPECTED_PHASES
         and len(events) <= MAX_EVENTS,
         "COUNTERFACTUAL_COVERAGE_DRIFT")
    result = {
        "schema": SCHEMA,
        "mode": MODE,
        "r107_trace_sha256": trace["sha256"],
        "r107_case_digest_chain_sha256": trace["case_digest_chain_sha256"],
        "source_state_machine_schema": model.SCHEMA,
        "case_window_count": len(entries),
        "families_covered": 25,
        "model_event_count": len(events),
        "model_event_head_sha256": previous,
        "model_phase_counts": dict(phase_counts),
        "cases": entries,
        "events": events,
        "a1_a10_operational_implementation_complete": False,
        "counterfactual_transitions_executed": len(events),
        "a3_operational_transitions_applied": 0,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "a8_operational_transitions_applied": 0,
        "a9_published_generations": 0,
        "independent_case_authority_attested": False,
        "dispatch_allowed": False,
        "vm_starts": 0,
        "host_mutations": 0,
        "p8_operational": "NO-GO",
    }
    need(len(a5.canonical(result)) <= MAX_BYTES, "REPORT_TOO_LARGE")
    result["sha256"] = _receipt(result)
    return result


def verify(report: dict[str, Any], trace: dict[str, Any]) -> bool:
    """Re-execute every transition and compare exact canonical records."""
    need(type(report) is dict and report == build(trace), "MODEL_REPLAY_MISMATCH")
    return True
