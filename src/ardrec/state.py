"""Modelos operacionales puros; no ejecutan acciones ni publican generaciones."""

from dataclasses import dataclass, replace
from enum import Enum
import re

from ardrec.messages import (
    MessageError, correlate, correlate_status, decode_message, encode_message,
)
from ardrec.messages_v2 import timestamp


class StateError(ValueError):
    """Infracción del contrato de estado, independiente del error de transporte."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"Estado rechazado: {code}")


class ServicePhase(Enum):
    PREPARADO = "PREPARADO"
    PENDIENTE = "PENDIENTE"
    ACTIVO = "ACTIVO"
    VALIDACION = "VALIDACION"
    ACTUALIZADO = "ACTUALIZADO"
    PAUSADO = "PAUSADO"
    CERRADO = "CERRADO"
    DETENIDO = "DETENIDO"


class AttemptPhase(Enum):
    RESERVADO = "reserved"
    ACEPTADO = "accepted"
    EN_CURSO = "running"
    COMPLETADO = "completed"
    INTERRUMPIDO = "interrupted"
    NO_INICIADO = "not_started"
    INCIERTO = "uncertain"


class InvocationPhase(Enum):
    EN_CURSO = "EN_CURSO"
    FINALIZADA = "FINALIZADA"
    PAUSADA = "PAUSADA"
    DETENIDA = "DETENIDA"


class Truth(Enum):
    VERDADERO = "VERDADERO"
    FALSO = "FALSO"
    ND = "ND"

    def __bool__(self):
        raise TypeError("Comparar explícitamente la guarda con Truth.VERDADERO")


class Transition(Enum):
    PREPARAR = "T1"
    ACREDITAR_INICIO = "T2"
    VALIDAR_RESULTADO = "T3"
    APLICAR_RESULTADO = "T4"
    APLICAR_CONTROL = "T5_CONTROL"
    APLICAR_NO_INICIO = "T5_NO_INICIO"
    CONTINUAR = "T6"
    CERRAR = "T7"
    PAUSAR = "T8"
    REANUDAR = "T9"
    DETENER = "T10"


TERMINAL = frozenset({ServicePhase.CERRADO, ServicePhase.DETENIDO})
PUBLISHABLE = frozenset({ServicePhase.PREPARADO, ServicePhase.PENDIENTE,
                         ServicePhase.PAUSADO, *TERMINAL})
MAX_INDEX = 2**63 - 1


def _need(condition, code="state_invalid"):
    if not condition:
        raise StateError(code)


def _id(value):
    _need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)


def _hash(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def _index(value):
    _need(type(value) is int and 0 <= value <= MAX_INDEX)


def _items(value, cls):
    _need(type(value) is tuple and all(type(item) is cls for item in value))


def _message(raw):
    _need(type(raw) is bytes)
    try:
        message = decode_message(raw)
        _need(message["schema_version"] == "2.0", "state_version_incompatible")
        _need(encode_message(message) == raw, "noncanonical_record")
        return message
    except MessageError as error:
        raise StateError(error.code) from error


@dataclass(frozen=True, slots=True)
class GuardFact:
    name: str
    value: Truth
    reference: str

    def __post_init__(self):
        _id(self.name)
        _id(self.reference)
        _need(type(self.value) is Truth)


@dataclass(frozen=True, slots=True)
class ClosureCriteria:
    ES: GuardFact
    SA: GuardFact
    CV: GuardFact
    LE: GuardFact

    def __post_init__(self):
        for name in ("ES", "SA", "CV", "LE"):
            fact = getattr(self, name)
            _need(type(fact) is GuardFact and fact.name == name)

    @property
    def primary_reason(self):
        # Registrar el orden declarado sin calcular los criterios de A8.
        return next((name for name in ("ES", "SA", "CV", "LE")
                     if getattr(self, name).value is Truth.VERDADERO), None)


@dataclass(frozen=True, slots=True)
class TransitionContext:
    record_id: str
    execution_id: str
    generation: int
    configuration_sha256: str
    event_reference: str
    facts: tuple[GuardFact, ...]
    reason_reference: str | None = None
    wait_reference: str | None = None
    closure: ClosureCriteria | None = None
    stop_cause: str | None = None

    def __post_init__(self):
        for value in (self.record_id, self.execution_id, self.event_reference):
            _id(value)
        _index(self.generation)
        _hash(self.configuration_sha256)
        _items(self.facts, GuardFact)
        _need(len({fact.name for fact in self.facts}) == len(self.facts))
        for value in (self.reason_reference, self.wait_reference):
            if value is not None:
                _id(value)
        _need(self.closure is None or type(self.closure) is ClosureCriteria)
        _need(self.stop_cause is None or type(self.stop_cause) is str and self.stop_cause in {
            "SEGURIDAD", "INTEGRIDAD", "AUTORIZACION", "LIMPIEZA", "CONTROL",
        })


@dataclass(frozen=True, slots=True)
class TransitionRecord:
    transition: Transition
    before: ServicePhase
    after: ServicePhase
    context: TransitionContext

    def __post_init__(self):
        _need(type(self.transition) is Transition and type(self.before) is ServicePhase
              and type(self.after) is ServicePhase and type(self.context) is TransitionContext)
        origins, target, _ = _RULES[self.transition]
        _need(self.before in origins and self.after is target, "transition_forbidden")
        required = _RULES[self.transition][2]
        _need({f.name for f in self.context.facts} == required, "guard_set_mismatch")
        _need(all(f.value is Truth.VERDADERO for f in self.context.facts), "guard_not_true")


@dataclass(frozen=True, slots=True)
class ServiceState:
    service_scenario_id: str
    phase: ServicePhase
    reason_reference: str | None = None
    wait_reference: str | None = None
    closure: ClosureCriteria | None = None
    stop_cause: str | None = None
    local_trace: tuple[TransitionRecord, ...] = ()
    pause_authorization_reference: str | None = None

    def __post_init__(self):
        _id(self.service_scenario_id)
        _need(type(self.phase) is ServicePhase)
        _items(self.local_trace, TransitionRecord)
        if self.phase in TERMINAL or self.phase is ServicePhase.PAUSADO:
            _id(self.reason_reference)
        else:
            _need(self.reason_reference is None)
        if self.phase is ServicePhase.PAUSADO:
            _id(self.wait_reference)
            _id(self.pause_authorization_reference)
        else:
            _need(self.wait_reference is None and self.pause_authorization_reference is None)
        if self.phase is ServicePhase.CERRADO:
            _need(type(self.closure) is ClosureCriteria and self.closure.primary_reason is not None)
        else:
            _need(self.closure is None)
        if self.phase is ServicePhase.DETENIDO:
            _need(type(self.stop_cause) is str and self.stop_cause in {
                "SEGURIDAD", "INTEGRIDAD", "AUTORIZACION", "LIMPIEZA", "CONTROL",
            })
        else:
            _need(self.stop_cause is None)
        if self.local_trace:
            _need(self.local_trace[-1].after is self.phase)
            for left, right in zip(self.local_trace, self.local_trace[1:]):
                _need(left.after is right.before)


@dataclass(frozen=True, slots=True)
class ConfirmedState:
    record_id: str
    generation: int
    generation_reference: str
    configuration_sha256: str
    versions_reference: str
    services: tuple[ServiceState, ...]
    incorporated_events: tuple[str, ...] = ()

    def __post_init__(self):
        for value in (self.record_id, self.generation_reference, self.versions_reference):
            _id(value)
        _index(self.generation)
        _hash(self.configuration_sha256)
        _items(self.services, ServiceState)
        _need(bool(self.services) and len({s.service_scenario_id for s in self.services}) == len(self.services))
        _need(all(s.phase in PUBLISHABLE and not s.local_trace for s in self.services))
        _need(type(self.incorporated_events) is tuple)
        for event in self.incorporated_events:
            _id(event)
        _need(len(set(self.incorporated_events)) == len(self.incorporated_events))
        if self.generation == 0:
            _need(not self.incorporated_events and all(s.phase is ServicePhase.PREPARADO for s in self.services),
                  "invalid_initial_generation")


@dataclass(frozen=True, slots=True)
class Report:
    message: bytes
    query: bytes | None = None

    def __post_init__(self):
        _message(self.message)
        if self.query is not None:
            _message(self.query)


@dataclass(frozen=True, slots=True)
class Incorporation:
    event_reference: str
    generation: int

    def __post_init__(self):
        _id(self.event_reference)
        _index(self.generation)


def _snapshot(report):
    return _message(report.message)["payload"]["snapshot"]


def _compatible_snapshots(before, after):
    # Una consulta posterior puede resolver incertidumbre, pero no borrar hechos acreditados.
    _need(timestamp(after["observed_at"]) >= timestamp(before["observed_at"]), "stale_report")
    _need(after["journal_reference"] == before["journal_reference"], "journal_mismatch")
    phases = {
        "accepted": {"accepted", "running", "completed", "interrupted", "not_started", "uncertain"},
        "running": {"running", "completed", "interrupted", "uncertain"},
        "uncertain": {"accepted", "running", "completed", "interrupted", "not_started", "uncertain"},
        "completed": {"completed"}, "interrupted": {"interrupted"}, "not_started": {"not_started"},
    }
    _need(after["phase"] in phases[before["phase"]], "attempt_regression")
    for field, fixed in {
        "start": {"VERIFICADO", "NO_INICIADO"}, "termination": {"VERIFICADO"},
        "cleanup": {"completed", "not_required"}, "result": {"DISPONIBLE"},
    }.items():
        if before[field]["status"] in fixed:
            _need(after[field] == before[field], "established_fact_conflict")


@dataclass(frozen=True, slots=True)
class AttemptState:
    request: bytes
    reports: tuple[Report, ...] = ()
    uncertainty_reference: str | None = None
    incorporation: Incorporation | None = None

    def __post_init__(self):
        request = _message(self.request)
        _need(request["message_type"] in {"execution_request", "discovery_request"})
        _items(self.reports, Report)
        if self.uncertainty_reference is not None:
            _id(self.uncertainty_reference)
        ids = {request["message_id"]}
        previous = None
        for report in self.reports:
            message = _message(report.message)
            kind = message["message_type"]
            _need(kind in {"accepted_for_execution", "attempt_status_result", "execution_result", "discovery_result"})
            _need(message["message_id"] not in ids, "duplicate_conflict")
            ids.add(message["message_id"])
            try:
                if kind == "attempt_status_result":
                    _need(report.query is not None, "query_required")
                    query = _message(report.query)
                    correlate_status(request, query, message)
                    _need(timestamp(request["created_at"]) <= timestamp(query["created_at"])
                          <= timestamp(message["created_at"]), "stale_report")
                else:
                    _need(report.query is None)
                    correlate(request, message)
            except MessageError as error:
                raise StateError(error.code) from error
            current = message["payload"]["snapshot"]
            _need(timestamp(current["observed_at"]) >= timestamp(request["created_at"]), "stale_report")
            if previous is not None:
                _compatible_snapshots(previous, current)
            previous = current
        _need(self.incorporation is None or type(self.incorporation) is Incorporation)
        if self.incorporation is not None:
            _need(self.technical_resolved and not request["simulation"], "incorporation_forbidden")
            _need(self.incorporation.generation > request["decision_index"], "generation_mismatch")

    @property
    def identity(self):
        return _message(self.request)

    @property
    def snapshot(self):
        return _snapshot(self.reports[-1]) if self.reports else None

    @property
    def phase(self):
        if self.uncertainty_reference is not None:
            return AttemptPhase.INCIERTO
        return AttemptPhase(self.snapshot["phase"]) if self.reports else AttemptPhase.RESERVADO

    @property
    def technical_resolved(self):
        snapshot = self.snapshot
        return (self.uncertainty_reference is None and snapshot is not None
                and snapshot["phase"] in {"completed", "interrupted", "not_started"}
                and snapshot["reconciliation_required"] is False)

    @property
    def pending(self):
        return self.incorporation is None

@dataclass(frozen=True, slots=True)
class GlobalState:
    confirmed: ConfirmedState
    execution_id: str
    services: tuple[ServiceState, ...]
    attempts: tuple[AttemptState, ...] = ()
    authority: Truth = Truth.ND
    invocation: InvocationPhase = InvocationPhase.EN_CURSO
    invocation_reason_reference: str | None = None
    simulation: bool = False

    def __post_init__(self):
        _need(type(self.confirmed) is ConfirmedState)
        _id(self.execution_id)
        _need(type(self.authority) is Truth and type(self.invocation) is InvocationPhase)
        _need(type(self.simulation) is bool)
        _items(self.services, ServiceState)
        _items(self.attempts, AttemptState)
        before = {s.service_scenario_id: s for s in self.confirmed.services}
        current = {s.service_scenario_id: s for s in self.services}
        _need(len(current) == len(self.services) and current.keys() == before.keys(), "scope_mismatch")
        for name, service in current.items():
            if before[name].phase in TERMINAL:
                _need(service == before[name], "terminal_state")
            elif service != before[name]:
                _need(bool(service.local_trace) and service.local_trace[0].before is before[name].phase)
            for step in service.local_trace:
                context = step.context
                _need(context.record_id == self.confirmed.record_id and context.execution_id == self.execution_id
                      and context.generation == self.confirmed.generation
                      and context.configuration_sha256 == self.confirmed.configuration_sha256, "context_mismatch")
        seen = set()
        consumed = set()
        for attempt in self.attempts:
            request = attempt.identity
            _need(request["simulation"] is self.simulation, "simulation_mismatch")
            _need(request["record_id"] == self.confirmed.record_id
                  and request["service_scenario_id"] in current, "identifier_mismatch")
            _need(request["versions"] == {"reference": self.confirmed.versions_reference,
                                         "sha256": self.confirmed.configuration_sha256}, "configuration_mismatch")
            _need(request["decision_index"] <= self.confirmed.generation, "generation_mismatch")
            _need(request["attempt_id"] not in seen, "attempt_reuse")
            seen.add(request["attempt_id"])
            if attempt.incorporation is not None:
                receipt = attempt.incorporation
                _need(receipt.generation <= self.confirmed.generation
                      and receipt.event_reference in self.confirmed.incorporated_events, "incorporation_unconfirmed")
                _need(receipt.event_reference not in consumed, "duplicate_consumption")
                consumed.add(receipt.event_reference)
        _need(sum(attempt.pending for attempt in self.attempts) <= 1, "multiple_pending_attempts")
        for service in self.services:
            if service.phase in {ServicePhase.ACTIVO, ServicePhase.VALIDACION}:
                matching = [a for a in self.attempts if a.pending
                            and a.identity["scope"] == "attempt"
                            and a.identity["service_scenario_id"] == service.service_scenario_id]
                _need(len(matching) == 1 and matching[0].snapshot is not None
                      and matching[0].snapshot["start"]["status"] == "VERIFICADO", "attempt_required")
                if service.phase is ServicePhase.VALIDACION:
                    _need(matching[0].technical_resolved, "attempt_unresolved")
        if self.invocation is InvocationPhase.EN_CURSO:
            _need(self.invocation_reason_reference is None)
        else:
            _id(self.invocation_reason_reference)
            if self.invocation is not InvocationPhase.DETENIDA:
                _need(self.authority is Truth.VERDADERO and not self.pending_attempts
                      and self.services == self.confirmed.services, "unconfirmed_output")
                if self.invocation is InvocationPhase.FINALIZADA:
                    _need(all(s.phase in TERMINAL for s in self.services), "unfinished_services")
                else:
                    _need(any(s.phase is ServicePhase.PAUSADO for s in self.services)
                          and all(s.phase in TERMINAL or s.phase is ServicePhase.PAUSADO for s in self.services),
                          "pause_unavailable")
        _unique_messages(self.attempts)

    @property
    def pending_attempts(self):
        return tuple(a.identity["attempt_id"] for a in self.attempts if a.pending)

    @property
    def incorporated_execution_count(self):
        # Contar solo los intentos representados cuya incorporación pertenece a la autoridad validada.
        _need(self.authority is Truth.VERDADERO, "authority_unverified")
        return sum(a.incorporation is not None and a.snapshot["start"]["status"] == "VERIFICADO"
                   for a in self.attempts)

    @property
    def dispatch_blockers(self):
        result = []
        if self.invocation is not InvocationPhase.EN_CURSO:
            result.append("invocation_terminal")
        if self.authority is not Truth.VERDADERO:
            result.append("authority_unverified")
        if self.pending_attempts:
            result.append("attempt_pending_incorporation")
        if self.services != self.confirmed.services:
            result.append("candidate_unpublished")
        return tuple(result)


def _unique_messages(attempts):
    known = {}
    for attempt in attempts:
        records = [attempt.request]
        for report in attempt.reports:
            records.append(report.message)
            if report.query is not None:
                records.append(report.query)
        for raw in records:
            key = _message(raw)["message_id"]
            _need(key not in known or known[key] == raw, "duplicate_conflict")
            known[key] = raw


def _active(state):
    _need(type(state) is GlobalState)
    _need(state.invocation is InvocationPhase.EN_CURSO, "invocation_terminal")


def reserve_attempt(state, request):
    """Reservar una intención en memoria; no enviar la solicitud ni escribir un diario."""
    _active(state)
    _need(not state.dispatch_blockers, "dispatch_blocked")
    attempt = AttemptState(encode_message(request))
    identity = attempt.identity
    _need(identity["execution_id"] == state.execution_id
          and identity["decision_index"] == state.confirmed.generation, "context_mismatch")
    service = next((s for s in state.services if s.service_scenario_id == identity["service_scenario_id"]), None)
    _need(service is not None, "out_of_scope")
    required = ServicePhase.PREPARADO if identity["scope"] == "discovery" else ServicePhase.PENDIENTE
    _need(service.phase is required, "dispatch_blocked")
    return replace(state, attempts=(*state.attempts, attempt))


def _find_attempt(state, attempt_id):
    _id(attempt_id)
    found = [a for a in state.attempts if a.identity["attempt_id"] == attempt_id]
    _need(len(found) == 1, "unknown_attempt")
    return found[0]


def _replace_attempt(state, old, new):
    return replace(state, attempts=tuple(new if item is old else item for item in state.attempts))


def record_report(state, attempt_id, message, *, query=None):
    """Registrar hechos declarados y correlacionados, sin admitir evidencia analítica."""
    _active(state)
    old = _find_attempt(state, attempt_id)
    raw = encode_message(message)
    query_raw = None if query is None else encode_message(query)
    for report in old.reports:
        if _message(report.message)["message_id"] == message["message_id"]:
            _need(report.message == raw and report.query == query_raw, "duplicate_conflict")
            return state
    _need(old.pending, "attempt_already_incorporated")
    new = replace(old, reports=(*old.reports, Report(raw, query_raw)), uncertainty_reference=None)
    return _replace_attempt(state, old, new)


def mark_uncertain(state, attempt_id, reason_reference):
    """Conservar identidad y hechos conocidos cuando no puede confirmarse la continuidad."""
    _active(state)
    _id(reason_reference)
    old = _find_attempt(state, attempt_id)
    _need(old.pending, "attempt_already_incorporated")
    return _replace_attempt(state, old, replace(old, uncertainty_reference=reason_reference))


_RULES = {
    Transition.PREPARAR: ({ServicePhase.PREPARADO}, ServicePhase.PENDIENTE,
                         {"preparation_authorized", "preconditions_valid"}),
    Transition.ACREDITAR_INICIO: ({ServicePhase.PENDIENTE}, ServicePhase.ACTIVO, {"start_verified"}),
    Transition.VALIDAR_RESULTADO: ({ServicePhase.ACTIVO}, ServicePhase.VALIDACION,
                                 {"termination_verified", "cleanup_verified", "outcome_structured"}),
    Transition.APLICAR_RESULTADO: ({ServicePhase.VALIDACION}, ServicePhase.ACTUALIZADO,
                                 {"outcome_processable", "effects_calculated"}),
    Transition.APLICAR_CONTROL: ({ServicePhase.PENDIENTE}, ServicePhase.ACTUALIZADO,
                                {"control_authorized", "effects_calculated"}),
    Transition.APLICAR_NO_INICIO: ({ServicePhase.PENDIENTE}, ServicePhase.ACTUALIZADO,
                                  {"absence_verified", "effects_calculated"}),
    Transition.CONTINUAR: ({ServicePhase.ACTUALIZADO}, ServicePhase.PENDIENTE,
                          {"work_available", "precedence_resolved"}),
    Transition.CERRAR: ({ServicePhase.PENDIENTE, ServicePhase.ACTUALIZADO}, ServicePhase.CERRADO,
                       {"precedence_resolved"}),
    Transition.PAUSAR: ({ServicePhase.PENDIENTE, ServicePhase.ACTUALIZADO}, ServicePhase.PAUSADO,
                       {"external_wait_registered", "pause_authorized", "precedence_resolved"}),
    Transition.REANUDAR: ({ServicePhase.PAUSADO}, ServicePhase.PENDIENTE,
                         {"new_authorization", "wait_resolved", "preconditions_valid"}),
    Transition.DETENER: (set(ServicePhase) - TERMINAL, ServicePhase.DETENIDO,
                        {"cause_verified", "effect_processable"}),
}


def transition_service(state, service_id, transition, context):
    """Construir una fase candidata conforme a guardas ya verificadas por el llamador."""
    _active(state)
    _need(state.authority is Truth.VERDADERO, "authority_unverified")
    _id(service_id)
    _need(type(transition) is Transition and type(context) is TransitionContext)
    service = next((s for s in state.services if s.service_scenario_id == service_id), None)
    _need(service is not None, "out_of_scope")
    _need(service.phase not in TERMINAL, "terminal_state")
    origins, target, required = _RULES[transition]
    _need(service.phase in origins, "transition_forbidden")
    _need(context.event_reference not in state.confirmed.incorporated_events, "event_already_incorporated")
    facts = {f.name: f for f in context.facts}
    _need(facts.keys() == required, "guard_set_mismatch")
    _need(all(f.value is Truth.VERDADERO for f in facts.values()), "guard_not_true")
    _need(context.closure is None if transition is not Transition.CERRAR else type(context.closure) is ClosureCriteria)
    _need(context.wait_reference is None if transition is not Transition.PAUSAR else context.wait_reference is not None)
    _need(context.stop_cause is None if transition is not Transition.DETENER else context.stop_cause is not None)
    _need(context.reason_reference is None if target not in TERMINAL | {ServicePhase.PAUSADO}
          else context.reason_reference is not None)
    if transition is Transition.CERRAR:
        _need(context.closure.primary_reason is not None, "closure_not_satisfied")
    if transition is Transition.PAUSAR:
        _need(facts["external_wait_registered"].reference == context.wait_reference, "reference_mismatch")
    if transition is Transition.REANUDAR:
        _need(facts["wait_resolved"].reference == service.wait_reference, "reference_mismatch")
        _need(facts["new_authorization"].reference != service.pause_authorization_reference, "authorization_not_new")
    if transition is Transition.DETENER:
        _need(facts["cause_verified"].reference == context.reason_reference, "reference_mismatch")

    pending = [a for a in state.attempts if a.pending]
    specific = {
        Transition.ACREDITAR_INICIO, Transition.VALIDAR_RESULTADO,
        Transition.APLICAR_RESULTADO, Transition.APLICAR_NO_INICIO,
    }
    if transition in specific:
        _need(len(pending) == 1 and pending[0].identity["service_scenario_id"] == service_id
              and pending[0].identity["scope"] == "attempt", "attempt_required")
        attempt = pending[0]
        snapshot = attempt.snapshot
        _need(snapshot is not None, "attempt_unresolved")
        if transition is Transition.ACREDITAR_INICIO:
            _need(snapshot["start"]["status"] == "VERIFICADO", "start_unverified")
            _need(facts["start_verified"].reference == snapshot["start"]["reference"], "reference_mismatch")
        else:
            _need(attempt.technical_resolved, "attempt_unresolved")
            if transition is Transition.APLICAR_NO_INICIO:
                _need(snapshot["phase"] == "not_started", "absence_unverified")
                _need(facts["absence_verified"].reference == snapshot["start"]["reference"], "reference_mismatch")
            else:
                _need(snapshot["phase"] in {"completed", "interrupted"}, "outcome_unavailable")
                if transition is Transition.VALIDAR_RESULTADO:
                    for name, field in (("termination_verified", "termination"),
                                        ("cleanup_verified", "cleanup"), ("outcome_structured", "result")):
                        _need(facts[name].reference == snapshot[field]["reference"], "reference_mismatch")
    elif transition is not Transition.DETENER:
        _need(all(a.technical_resolved for a in pending), "attempt_unresolved")
        if transition in {Transition.APLICAR_CONTROL, Transition.REANUDAR}:
            _need(not pending, "attempt_pending_incorporation")

    record = TransitionRecord(transition, service.phase, target, context)
    candidate = ServiceState(service_id, target, context.reason_reference, context.wait_reference,
                             context.closure, context.stop_cause, (*service.local_trace, record),
                             facts["pause_authorized"].reference if target is ServicePhase.PAUSADO else None)
    return replace(state, services=tuple(candidate if s is service else s for s in state.services))


def finish_invocation(state, outcome, reason_reference):
    """Terminar la invocación conservando el último estado confirmado y sus reservas."""
    _active(state)
    _need(type(outcome) is InvocationPhase and outcome is not InvocationPhase.EN_CURSO)
    _id(reason_reference)
    return replace(state, invocation=outcome, invocation_reason_reference=reason_reference)
