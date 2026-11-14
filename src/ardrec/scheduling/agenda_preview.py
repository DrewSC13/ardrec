"""P14-R23 / A3: orden de candidatos sintéticos, sin agenda ejecutable.

Las guardas proceden exclusivamente del diagnóstico R22, ligado a R17-R21.
Las precedencias ordenan referencias declaradas, no prueban cumplimiento.
Los presupuestos limitan la propuesta, jamás conceden autoridad ni consumen casos.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.initialization.control_preview import ControlPreview
from ardrec.initialization.integrated_preview import IntegratedPreview
from ardrec.scheduling.guard_preview import GuardDiagnosticPreview
from ardrec.state import Truth

FORMAT = 'ardrec-p14-r23-a3-candidate-order-preview-v1'
MAX_BYTES = 393216
MAX_PER_SERVICE = 32
MAX_TOTAL = 2048


class CandidateAgendaError(ValueError):
    """Entrada, integridad, presupuesto o consistencia de agenda no válida."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(value: bool, code: str) -> None:
    if not value:
        raise CandidateAgendaError(code)


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         allow_nan=False, ensure_ascii=True).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise CandidateAgendaError('serializacion_invalida') from exc
    _need(len(raw) <= MAX_BYTES, 'agenda_excesiva')
    return raw


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _need(key not in result, 'clave_duplicada')
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class CandidateSlot:
    service_id: str
    control_id: str
    target_case_id: str
    guard_rule_id: str
    pending_controls: tuple[str, ...]
    pending_cases: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def executable(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class ExcludedControl:
    control_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class UnitCandidateOrder:
    service_id: str
    protocol: str
    candidates: tuple[CandidateSlot, ...]
    excluded: tuple[ExcludedControl, ...]


@dataclass(frozen=True, slots=True)
class CandidateAgendaPreview:
    """Resultado puramente documental, nunca token de capacidad."""

    source: bytes
    sha256: str
    integrated_sha256: str
    diagnostic_sha256: str
    units: tuple[UnitCandidateOrder, ...]
    max_per_service: int
    max_total: int

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview, controls: ControlPreview,
               integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
               environments: dict[str, dict[str, Any]]) -> bool:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'agenda_alterada')
        _need(self.integrated_sha256 == integrated.sha256
              and self.diagnostic_sha256 == diagnostic.sha256,
              'origen_no_coincide')
        expected, units = _compose(rules, initial, dependencies, controls,
                                    integrated, diagnostic, environments,
                                    self.max_per_service, self.max_total)
        try:
            data = json.loads(self.source, object_pairs_hook=_unique_pairs)
        except CandidateAgendaError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise CandidateAgendaError('agenda_invalida') from exc
        _need(type(data) is dict and data.get('format') == FORMAT,
              'version_incompatible')
        _need(_canonical(data) == self.source, 'agenda_no_canonica')
        _need(self.source == expected and self.units == units,
              'agenda_no_coincide')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def executable_agenda(self) -> None:
        return None

    @property
    def published_generation(self) -> None:
        return None


def _budget(value: Any, ceiling: int) -> bool:
    return type(value) is int and 0 <= value <= ceiling


def _compose(rules: FrozenRulePreview, initial: InitialPreview,
             dependencies: DependencyPreview, controls: ControlPreview,
             integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
             environments: dict[str, dict[str, Any]], max_per_service: int,
             max_total: int) -> tuple[bytes, tuple[UnitCandidateOrder, ...]]:
    _need(_budget(max_per_service, MAX_PER_SERVICE), 'limite_servicio_invalido')
    _need(_budget(max_total, MAX_TOTAL), 'limite_global_invalido')
    _need(type(diagnostic) is GuardDiagnosticPreview, 'diagnostico_requerido')
    # Verifica la cadena íntegra y vuelve a evaluar el ambiente, no solo las huellas.
    diagnostic.verify(rules, initial, dependencies, controls,
                      integrated, environments)
    contract = {u.service_id: u for u in integrated.units}
    diagnoses = {u.service_id: u for u in diagnostic.units}
    _need(len(contract) == len(integrated.units)
          and len(diagnoses) == len(diagnostic.units)
          and set(contract) == set(diagnoses), 'servicios_inconsistentes')
    output: list[UnitCandidateOrder] = []
    all_candidates: list[dict[str, Any]] = []
    for sid in sorted(contract):
        unit = contract[sid]
        state = diagnoses[sid]
        _need(unit.protocol == state.protocol, 'protocolo_inconsistente')
        ctrl = {c[0]: c for c in unit.controls}
        diag = {c.control_id: c for c in state.controls}
        case = {c[0]: c for c in unit.cases}
        _need(len(ctrl) == len(unit.controls) == len(diag) == len(state.controls)
              and set(ctrl) == set(diag) == set(unit.control_order),
              'controles_inconsistentes')
        _need(set(case) == set(unit.case_order)
              and len(case) == len(unit.cases), 'casos_inconsistentes')
        candidates: list[CandidateSlot] = []
        excluded: list[ExcludedControl] = []
        included: set[str] = set()
        for cid in unit.control_order:
            _, rid, target, _precedence, requires = ctrl[cid]
            observation = diag[cid]
            _need(observation.guard_rule_id == rid
                  and observation.target_case_id == target,
                  'control_diagnostico_inconsistente')
            reason = None
            if observation.truth is Truth.ND:
                reason = 'GUARDA_ND'
            elif observation.truth is Truth.FALSO:
                reason = 'GUARDA_FALSA'
            elif (state.table_status is not Truth.VERDADERO
                  or state.table_selected != rid):
                reason = 'TABLA_NO_ACREDITADA'
            elif any(required not in included for required in requires):
                reason = 'CONTROL_REQUERIDO_NO_CANDIDATO'
            elif len(candidates) >= max_per_service:
                reason = 'PRESUPUESTO_SERVICIO_AGOTADO'
            elif len(all_candidates) >= max_total:
                reason = 'PRESUPUESTO_GLOBAL_AGOTADO'
            if reason is not None:
                excluded.append(ExcludedControl(cid, reason))
                continue
            _need(target in case, 'caso_no_declarado')
            pending_cases = case[target][2]
            blockers = []
            if requires:
                blockers.append('CONTROLES_REQUERIDOS_NO_APLICADOS')
            if pending_cases:
                blockers.append('CASOS_REQUERIDOS_NO_CONFIRMADOS')
            blockers.append('AUTORIDAD_OPERACIONAL_NO_ACREDITADA')
            slot = CandidateSlot(sid, cid, target, rid, requires,
                                 pending_cases, tuple(blockers))
            candidates.append(slot)
            included.add(cid)
            all_candidates.append({'service_id': sid, 'control_id': cid})
        output.append(UnitCandidateOrder(sid, unit.protocol,
                                         tuple(candidates), tuple(excluded)))
    record = {
        'format': FORMAT, 'scope': 'SYNTHETIC_NON_EXECUTABLE_CANDIDATE_ORDER',
        'integrated_sha256': integrated.sha256,
        'diagnostic_sha256': diagnostic.sha256,
        'limits': {'per_service': max_per_service, 'total': max_total},
        'services': [
            {'id': u.service_id, 'protocol': u.protocol,
             'candidates': [
                 {'id': c.control_id, 'target_case_id': c.target_case_id,
                  'guard_rule_id': c.guard_rule_id,
                  'pending_controls': list(c.pending_controls),
                  'pending_cases': list(c.pending_cases),
                  'blockers': list(c.blockers), 'executable': False}
                 for c in u.candidates],
             'excluded': [{'id': x.control_id, 'reason': x.reason}
                          for x in u.excluded]}
            for u in output],
        'candidate_order': all_candidates,
        'executable_agenda': None,
        'operational_dispatch': False,
        'generation_published': None,
        'controls_applied': False,
        'p8_operational': 'NO-GO',
    }
    return _canonical(record), tuple(output)


def plan_candidate_order(rules: FrozenRulePreview, initial: InitialPreview,
                         dependencies: DependencyPreview, controls: ControlPreview,
                         integrated: IntegratedPreview,
                         diagnostic: GuardDiagnosticPreview,
                         environments: dict[str, dict[str, Any]], *,
                         max_per_service: int = 32,
                         max_total: int = 2048) -> CandidateAgendaPreview:
    """Orden de candidatos; nunca reserva, envía, aplica ni autoriza controles."""
    source, units = _compose(rules, initial, dependencies, controls,
                              integrated, diagnostic, environments,
                              max_per_service, max_total)
    view = CandidateAgendaPreview(source, hashlib.sha256(source).hexdigest(),
                                  integrated.sha256, diagnostic.sha256, units,
                                  max_per_service, max_total)
    view.verify(rules, initial, dependencies, controls, integrated,
                diagnostic, environments)
    return view
