"""A8 ordinary closure and exact convergence.

Computes criteria from explicit inputs, without claiming that
their provenance or operational authorization is established.

No execution, state mutation or A9 publication.
"""

from copy import deepcopy
from fractions import Fraction
import re

from ardrec.analytics.exact_preview import (
    canonical,
    digest,
    rational,
)

from ardrec.state import (
    ClosureCriteria,
    GuardFact,
    ServicePhase,
    Truth,
)

SCHEMA = "ARDREC-R277-ORDINARY-CLOSURE-v1"

EPSILON = Fraction(1, 1000)

WINDOW_SIZE = 3

MAX_EVENTS = 4096

ORDER = ("ES", "SA", "CV", "LE")

FACTS = (
    "evidence_current",
    "contradiction_free",
    "maximum_demonstration",
    "complete_coverage",
    "no_executable_cases",
    "no_potential_cases",
    "no_pending_work",
    "no_larger_case",
    "precedence_resolved",
    "attempt_reconciled",
    "safety_clear",
)

EVENT_FIELDS = {
    "event_id",
    "projection_sha256",
    "risk",
    "reset",
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def conjunction(*values):

    need(
        all(type(value) is Truth for value in values),
        "TRUTH_DOMAIN_INVALID",
    )

    if Truth.FALSO in values:
        return Truth.FALSO

    if Truth.ND in values:
        return Truth.ND

    return Truth.VERDADERO


def disjunction(*values):

    need(
        all(type(value) is Truth for value in values),
        "TRUTH_DOMAIN_INVALID",
    )

    if Truth.VERDADERO in values:
        return Truth.VERDADERO

    if Truth.ND in values:
        return Truth.ND

    return Truth.FALSO


def convergence(events):
    """Rebuild the active window from the ordered history."""

    need(
        type(events) is list
        and len(events) <= MAX_EVENTS,
        "HISTORY_DOMAIN_INVALID",
    )

    seen = {}

    variations = []

    previous_risk = None
    previous_projection = None

    computable_updates = 0
    duplicate_events = 0
    repeated_projections = 0
    resets = 0

    for event in events:

        need(
            type(event) is dict
            and set(event) == EVENT_FIELDS,
            "HISTORY_EVENT_SCHEMA_INVALID",
        )

        event_id = event["event_id"]
        projection = event["projection_sha256"]
        raw_risk = event["risk"]
        reset = event["reset"]

        need(
            type(event_id) is str
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
                event_id,
            ) is not None
            and type(reset) is bool,
            "HISTORY_EVENT_IDENTITY_INVALID",
        )

        need(
            projection is None
            or (
                type(projection) is str
                and re.fullmatch(
                    r"[a-f0-9]{64}",
                    projection,
                ) is not None
            ),
            "EVIDENCE_PROJECTION_IDENTITY_INVALID",
        )

        need(
            raw_risk is None
            or projection is not None,
            "RISK_WITHOUT_EVIDENCE_PROJECTION",
        )

        risk = (
            None if raw_risk is None
            else rational(raw_risk)
        )

        if event_id in seen:

            need(
                seen[event_id] == event,
                "EVENT_IDENTITY_CONFLICT",
            )

            duplicate_events += 1
            continue

        seen[event_id] = dict(event)

        # Reset takes precedence over calculating
        # a new variation on the same event.

        if reset:

            variations.clear()

            previous_risk = risk

            previous_projection = (
                projection
                if risk is not None
                else None
            )

            resets += 1
            continue

        if risk is None:

            # Non-computable transitions remain in
            # history without creating a sample.

            continue

        if projection == previous_projection:

            need(
                risk == previous_risk,
                "RISK_CHANGED_WITHOUT_PROJECTION_CHANGE",
            )

            repeated_projections += 1
            continue

        computable_updates += 1

        if previous_risk is not None:

            variations.append(
                abs(risk - previous_risk)
            )

            variations = variations[-WINDOW_SIZE:]

        previous_risk = risk
        previous_projection = projection

    complete = len(variations) == WINDOW_SIZE

    stable = (
        complete
        and all(value <= EPSILON for value in variations)
    )

    return {
        "history_events": len(seen),
        "computable_updates": computable_updates,
        "duplicate_events": duplicate_events,
        "repeated_projections": repeated_projections,
        "resets": resets,
        "epsilon": str(EPSILON),
        "required_variations": WINDOW_SIZE,
        "variations": [
            str(value) for value in variations
        ],
        "last_computable_risk": (
            None
            if previous_risk is None
            else str(previous_risk)
        ),
        "window_complete": complete,
        "window_stable": stable,
    }


def evaluate(*, facts, history, executions, budget, phase):

    need(
        type(facts) is dict
        and set(facts) == set(FACTS)
        and all(type(value) is str for value in facts.values()),
        "CLOSURE_FACT_SET_INVALID",
    )

    values = {
        name: Truth(facts[name])
        for name in FACTS
    }

    phase_value = ServicePhase(phase)

    for value in (executions, budget):

        need(
            value is None
            or (
                type(value) is int
                and 0 <= value < 2**63
            ),
            "EXECUTION_BUDGET_DOMAIN_INVALID",
        )

    if executions is not None and budget is not None:

        need(
            executions <= budget,
            "EXECUTION_BUDGET_EXCEEDED",
        )

    window = convergence(history)

    es = conjunction(
        values["evidence_current"],
        values["contradiction_free"],
        disjunction(
            values["maximum_demonstration"],
            values["complete_coverage"],
        ),
    )

    sa = conjunction(
        values["no_executable_cases"],
        values["no_potential_cases"],
        values["no_pending_work"],
    )

    cv = conjunction(
        (
            Truth.VERDADERO
            if window["window_stable"]
            else Truth.FALSO
        ),
        values["evidence_current"],
        values["contradiction_free"],
        values["no_larger_case"],
    )

    le = (
        Truth.ND
        if executions is None or budget is None
        else (
            Truth.VERDADERO
            if executions == budget
            else Truth.FALSO
        )
    )

    criteria = {
        "ES": es,
        "SA": sa,
        "CV": cv,
        "LE": le,
    }

    source = {
        "facts": dict(facts),
        "history": deepcopy(history),
        "executions": executions,
        "budget": budget,
        "phase": phase,
    }

    # Native ClosureCriteria establishes the ordinary
    # precedence ES > SA > CV > LE.

    closure = ClosureCriteria(**{
        name: GuardFact(
            name,
            criteria[name],
            digest({
                "source": source,
                "criterion": name,
            }),
        )
        for name in ORDER
    })

    satisfied = [
        name for name in ORDER
        if criteria[name] is Truth.VERDADERO
    ]

    overall = disjunction(*criteria.values())

    gate = conjunction(
        values["safety_clear"],
        values["attempt_reconciled"],
        values["precedence_resolved"],
    )

    phase_eligible = phase_value in {
        ServicePhase.PENDIENTE,
        ServicePhase.ACTUALIZADO,
    }

    candidate = None

    if phase_value in {
        ServicePhase.CERRADO,
        ServicePhase.DETENIDO,
    }:

        decision = "ESTADO_TERMINAL_CONSERVADO"

    elif gate is not Truth.VERDADERO:

        decision = "CIERRE_NO_EVALUABLE_OPERACIONALMENTE"

    elif not phase_eligible:

        decision = "FASE_NO_ADMITE_CIERRE_ORDINARIO"

    elif overall is Truth.VERDADERO:

        decision = "CIERRE_ORDINARIO_CANDIDATO"
        candidate = "T7"

    elif overall is Truth.ND:

        decision = "CRITERIOS_ORDINARIOS_INDETERMINADOS"

    else:

        decision = "SIN_CRITERIO_ORDINARIO_DE_CIERRE"

    report = {
        "schema": SCHEMA,
        "scope": "MATHEMATICAL_LOGICAL_EVALUATION_ONLY",
        "inputs": source,
        "criteria": {
            name: criteria[name].value
            for name in ORDER
        },
        "criteria_satisfied": satisfied,
        "primary_reason": closure.primary_reason,
        "ordinary_stop": overall.value,
        "ordinary_gate": gate.value,
        "window": window,
        "decision": decision,
        "candidate_transition": candidate,
        "applied_transition": None,
        "operational_authority": False,
        "published_generation": None,
    }

    report["sha256"] = digest(report)

    return report


def verify(report):

    expected = evaluate(**report["inputs"])

    need(
        canonical(report) == canonical(expected),
        "ORDINARY_CLOSURE_REPLAY_MISMATCH",
    )

    return True
