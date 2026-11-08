"""P8-R8: read-only, synthetic transition/guard diagnostic boundary.

Never passes an untrusted P8 claim to ``transition_service`` or ``reserve_attempt``.
The transition graph is a structural reference; it is *not* an implementation of
A1-A10, trusted evidence, persistent generations, or an execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

from ardrec.p8_diagnostic import (
    FIELDS as P8_FIELDS, MAX_DIAGNOSTIC_BYTES, KNOWN_PROFILES,
    _no_duplicates, evaluate_bytes,
)
from ardrec.state import GlobalState, ServicePhase, Transition, Truth

SCHEMA = "1.0"
DENIAL = "BLOCKED_UNBOUND_NO_EXECUTION"
LABEL = "P8_R8_SYNTHETIC_STATE_BOUNDARY"
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CASE_RE = re.compile(r"(SSH|FTP|SMB)-T[0-9]{2}-S[0-9]{2,4}-[0-9]{2}\Z")

# Direct, separately reviewed transcription of T1-T10 / ADR 0004.
# The graph documents structure; it never establishes facts or permissions.
GRAPH: dict[Transition, tuple[frozenset[ServicePhase], ServicePhase, frozenset[str]]] = {
    Transition.PREPARAR: (
        frozenset({ServicePhase.PREPARADO}), ServicePhase.PENDIENTE,
        frozenset({"preparation_authorized", "preconditions_valid"})),
    Transition.ACREDITAR_INICIO: (
        frozenset({ServicePhase.PENDIENTE}), ServicePhase.ACTIVO,
        frozenset({"start_verified"})),
    Transition.VALIDAR_RESULTADO: (
        frozenset({ServicePhase.ACTIVO}), ServicePhase.VALIDACION,
        frozenset({"termination_verified", "cleanup_verified", "outcome_structured"})),
    Transition.APLICAR_RESULTADO: (
        frozenset({ServicePhase.VALIDACION}), ServicePhase.ACTUALIZADO,
        frozenset({"outcome_processable", "effects_calculated"})),
    Transition.APLICAR_CONTROL: (
        frozenset({ServicePhase.PENDIENTE}), ServicePhase.ACTUALIZADO,
        frozenset({"control_authorized", "effects_calculated"})),
    Transition.APLICAR_NO_INICIO: (
        frozenset({ServicePhase.PENDIENTE}), ServicePhase.ACTUALIZADO,
        frozenset({"absence_verified", "effects_calculated"})),
    Transition.CONTINUAR: (
        frozenset({ServicePhase.ACTUALIZADO}), ServicePhase.PENDIENTE,
        frozenset({"work_available", "precedence_resolved"})),
    Transition.CERRAR: (
        frozenset({ServicePhase.PENDIENTE, ServicePhase.ACTUALIZADO}), ServicePhase.CERRADO,
        frozenset({"precedence_resolved"})),
    Transition.PAUSAR: (
        frozenset({ServicePhase.PENDIENTE, ServicePhase.ACTUALIZADO}), ServicePhase.PAUSADO,
        frozenset({"external_wait_registered", "pause_authorized", "precedence_resolved"})),
    Transition.REANUDAR: (
        frozenset({ServicePhase.PAUSADO}), ServicePhase.PENDIENTE,
        frozenset({"new_authorization", "wait_resolved", "preconditions_valid"})),
    Transition.DETENER: (
        frozenset(set(ServicePhase) - {ServicePhase.CERRADO, ServicePhase.DETENIDO}),
        ServicePhase.DETENIDO, frozenset({"cause_verified", "effect_processable"})),
}


class BridgeError(ValueError):
    """Fail closed at the pure input contract boundary; no state is changed."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise BridgeError(code)


@dataclass(frozen=True, slots=True)
class SyntheticProposal:
    """Untrusted, in-memory proposed binding. Never contains an approval."""

    stage: str
    service_id: str
    case_id: str
    profile_id: str
    transition: Transition
    generation: int
    configuration_sha256: str
    snapshot_sha256: str
    guards: tuple[tuple[str, Truth], ...]

    def __post_init__(self) -> None:
        _need(type(self.stage) is str and self.stage in {"dev", "pilot", "exp"}, "invalid_stage")
        _need(type(self.service_id) is str and ID_RE.fullmatch(self.service_id) is not None,
              "invalid_service")
        _need(type(self.case_id) is str and CASE_RE.fullmatch(self.case_id) is not None,
              "invalid_case")
        _need(type(self.profile_id) is str and self.profile_id in KNOWN_PROFILES,
              "unknown_profile")
        _need(type(self.transition) is Transition, "invalid_transition")
        _need(type(self.generation) is int and 0 <= self.generation < 2**63,
              "invalid_generation")
        _need(type(self.configuration_sha256) is str and
              SHA_RE.fullmatch(self.configuration_sha256) is not None, "invalid_configuration")
        _need(type(self.snapshot_sha256) is str and
              SHA_RE.fullmatch(self.snapshot_sha256) is not None, "invalid_snapshot")
        _need(type(self.guards) is tuple and all(type(x) is tuple and len(x) == 2 and
              type(x[0]) is str and type(x[1]) is Truth for x in self.guards),
              "invalid_guard_types")
        names = [name for name, _ in self.guards]
        _need(len(names) == len(set(names)) and set(names) == GRAPH[self.transition][2],
              "guard_set_mismatch")


@dataclass(frozen=True, slots=True)
class BoundaryReview:
    """Immutable diagnostic record; no TransitionContext or dispatch capability."""

    schema_version: str
    kind: str
    decision: str
    p8_reason: str
    boundary_reason: str
    origin_compatible: bool
    synthetic_guards_all_true: bool
    hypothetical_target: str | None
    guard_observations: tuple[tuple[str, str], ...]
    original_generation: int
    authorized: bool = False
    dispatch_allowed: bool = False
    transition_applied: bool = False
    publication_allowed: bool = False
    real_cases_authorized: int = 0


def _identity_from_p8(raw: bytes) -> dict[str, object] | None:
    """Read identity for *comparison only*, never as authenticated evidence."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DIAGNOSTIC_BYTES:
        return None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None
    if type(value) is not dict or set(value) != P8_FIELDS:
        return None
    return value


def review_boundary(state: GlobalState, proposal: SyntheticProposal, p8_raw: bytes) -> BoundaryReview:
    """Review the graph and diagnostic without creating a candidate or reserve.

    A structurally coherent proposal STILL has an untrusted issuer/clock/revocation
    source; the result is ALWAYS DENY. No callback, file I/O or execution path exists.
    """
    _need(type(state) is GlobalState, "invalid_state")
    _need(type(proposal) is SyntheticProposal, "invalid_proposal")
    _need(type(p8_raw) is bytes, "invalid_diagnostic_type")

    p8_result = evaluate_bytes(p8_raw)
    payload = _identity_from_p8(p8_raw)
    service = next((s for s in state.services if s.service_scenario_id == proposal.service_id), None)
    origins, target, _ = GRAPH[proposal.transition]
    current_phase = service.phase if service is not None else None
    origin_ok = current_phase in origins
    guards_true = all(value is Truth.VERDADERO for _, value in proposal.guards)
    hypothetical = target.value if origin_ok and guards_true else None
    raw_matches = (
        payload is not None
        and payload.get("stage") == proposal.stage
        and payload.get("case_id") == proposal.case_id
        and payload.get("profile_id") == proposal.profile_id
        and payload.get("snapshot_sha256") == proposal.snapshot_sha256
    )
    if p8_result["reason_code"] == "P8_R7_INVALID_SCHEMA":
        reason = "P8_R8_DIAGNOSTIC_INVALID"
    elif not raw_matches:
        reason = "P8_R8_IDENTITY_MISMATCH"
    elif service is None:
        reason = "P8_R8_SERVICE_OUT_OF_SCOPE"
    elif (proposal.generation != state.confirmed.generation or
          proposal.configuration_sha256 != state.confirmed.configuration_sha256):
        reason = "P8_R8_STALE_CONFIGURATION"
    elif not origin_ok:
        reason = "P8_R8_ORIGIN_FORBIDDEN"
    elif not guards_true:
        reason = "P8_R8_GUARDS_NOT_VERIFIED"
    elif state.pending_attempts:
        reason = "P8_R8_ATTEMPT_UNRESOLVED"
    elif state.services != state.confirmed.services:
        reason = "P8_R8_CANDIDATE_UNPUBLISHED"
    elif state.invocation.value != "EN_CURSO":
        reason = "P8_R8_INVOCATION_NOT_ACTIVE"
    else:
        reason = "P8_R8_SYNTHETIC_ONLY_DENY_ALL"

    return BoundaryReview(
        schema_version=SCHEMA, kind=LABEL, decision=DENIAL,
        p8_reason=p8_result["reason_code"], boundary_reason=reason,
        origin_compatible=origin_ok, synthetic_guards_all_true=guards_true,
        hypothetical_target=hypothetical,
        guard_observations=tuple(sorted((name, value.value) for name, value in proposal.guards)),
        original_generation=state.confirmed.generation,
    )
