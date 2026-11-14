"""P14-R24 / A3: resolución hipotética de prerrequisitos, nunca ejecución.

Las marcas VERDADERO/FALSO/ND son suposiciones sintéticas no acreditadas:
no representan resultados de prueba, evidencia, permisos ni controles aplicados.
La fuente R23 limita el universo; ninguna entrada crea candidatos nuevos.
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
from ardrec.scheduling.agenda_preview import CandidateAgendaPreview
from ardrec.state import Truth

FORMAT = 'ardrec-p14-r24-a3-hypothetical-readiness-v1'
MAX_SCENARIO_BYTES = 262144
MAX_REPORT_BYTES = 393216


class ReadinessError(ValueError):
    """Contrato R24 inválido o supuesto hipotético inconsistente."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise ReadinessError(code)


def _keys(obj: Any, expected: set[str], code: str) -> None:
    _need(type(obj) is dict and set(obj) == expected, code)


def _canonical(obj: Any, limit: int) -> bytes:
    try:
        raw = json.dumps(obj, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ReadinessError('documento_no_serializable') from exc
    _need(len(raw) <= limit, 'documento_excesivo')
    return raw


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        _need(k not in out, 'clave_duplicada')
        out[k] = v
    return out


@dataclass(frozen=True, slots=True)
class HypotheticalControl:
    control_id: str
    target_case_id: str
    state: str  # LISTO_CONDICIONAL, BLOQUEADO, OMITIDO_SUPUESTO
    reasons: tuple[str, ...]

    @property
    def executable(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class UnitReadiness:
    service_id: str
    protocol: str
    controls: tuple[HypotheticalControl, ...]
    inherited_exclusions: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class ReadinessPreview:
    source: bytes
    sha256: str
    candidate_sha256: str
    scenario_sha256: str
    scenario_source: bytes
    units: tuple[UnitReadiness, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview, controls: ControlPreview,
               integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
               environments: dict[str, dict[str, Any]],
               candidates: CandidateAgendaPreview,
               scenario: dict[str, Any]) -> bool:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'informe_alterado')
        _need(type(self.scenario_source) is bytes and type(self.scenario_sha256) is str
              and hashlib.sha256(self.scenario_source).hexdigest() == self.scenario_sha256,
              'supuestos_alterados')
        _need(self.candidate_sha256 == candidates.sha256, 'candidatos_no_coinciden')
        expected, marks, units = _compose(rules, initial, dependencies, controls,
                                          integrated, diagnostic, environments,
                                          candidates, scenario)
        for raw, limit, code in ((self.source, MAX_REPORT_BYTES, 'informe_no_canonico'),
                                 (self.scenario_source, MAX_SCENARIO_BYTES,
                                  'supuestos_no_canonicos')):
            try:
                doc = json.loads(raw, object_pairs_hook=_unique_pairs)
            except ReadinessError:
                raise
            except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
                raise ReadinessError(code) from exc
            _need(_canonical(doc, limit) == raw, code)
        _need(self.source == expected and self.scenario_source == marks
              and self.units == units, 'reconciliacion_inconsistente')
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


def _normalize_scenario(candidates: CandidateAgendaPreview,
                        integrated: IntegratedPreview, scenario: Any
                        ) -> tuple[bytes, dict[str, tuple[dict[str, Truth], dict[str, Truth]]]]:
    _keys(scenario, {'format', 'candidate_sha256', 'services'}, 'escenario_invalido')
    _need(scenario['format'] == FORMAT, 'version_incompatible')
    _need(type(scenario['candidate_sha256']) is str
          and scenario['candidate_sha256'] == candidates.sha256,
          'candidatos_no_coinciden')
    services = scenario['services']
    _need(type(services) is list and len(services) == len(integrated.units),
          'cantidad_servicios_invalida')
    contract = {u.service_id: u for u in integrated.units}
    parsed: dict[str, tuple[dict[str, Truth], dict[str, Truth]]] = {}
    for service in services:
        _keys(service, {'id', 'cases', 'controls'}, 'servicio_invalido')
        sid = service['id']
        _need(type(sid) is str and sid in contract and sid not in parsed,
              'servicio_no_declarado_o_duplicado')
        unit = contract[sid]
        assumed: list[dict[str, Truth]] = []
        normalized: list[list[dict[str, str]]] = []
        for key, expected in (('cases', {c[0] for c in unit.cases}),
                              ('controls', {c[0] for c in unit.controls})):
            rows = service[key]
            _need(type(rows) is list and len(rows) == len(expected),
                  'cantidad_marcas_invalida')
            facts: dict[str, Truth] = {}
            for record in rows:
                _keys(record, {'id', 'assumed'}, 'marca_invalida')
                ident, val = record['id'], record['assumed']
                _need(type(ident) is str and ident in expected and ident not in facts,
                      'marca_desconocida_o_duplicada')
                _need(type(val) is str and val in Truth.__members__,
                      'valor_hipotetico_invalido')
                facts[ident] = Truth[val]
            _need(set(facts) == expected, 'marcas_incompletas')
            assumed.append(facts)
            normalized.append([{'id': x, 'assumed': facts[x].name} for x in sorted(facts)])
        case_facts, ctrl_facts = assumed
        case_dep = {cid: requires for cid, _ceiling, requires, _refs in unit.cases}
        ctrl_dep = {cid: requires for cid, _rid, _target, _priority, requires in unit.controls}
        for cid, state in case_facts.items():
            if state is Truth.VERDADERO:
                _need(all(case_facts[d] is Truth.VERDADERO for d in case_dep[cid]),
                      'hipotesis_caso_inconsistente')
        for cid, state in ctrl_facts.items():
            if state is Truth.VERDADERO:
                _need(all(ctrl_facts[d] is Truth.VERDADERO for d in ctrl_dep[cid]),
                      'hipotesis_control_inconsistente')
        parsed[sid] = (case_facts, ctrl_facts)
    _need(set(parsed) == set(contract), 'servicios_incompletos')
    normalized_services = []
    for sid in sorted(parsed):
        c, t = parsed[sid]
        normalized_services.append({
            'id': sid,
            'cases': [{'id': x, 'assumed': c[x].name} for x in sorted(c)],
            'controls': [{'id': x, 'assumed': t[x].name} for x in sorted(t)],
        })
    data = {'format': FORMAT, 'candidate_sha256': candidates.sha256,
            'services': normalized_services}
    return _canonical(data, MAX_SCENARIO_BYTES), parsed


def _compose(rules: FrozenRulePreview, initial: InitialPreview,
             dependencies: DependencyPreview, controls: ControlPreview,
             integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
             environments: dict[str, dict[str, Any]],
             candidates: CandidateAgendaPreview,
             scenario: dict[str, Any]
             ) -> tuple[bytes, bytes, tuple[UnitReadiness, ...]]:
    _need(type(candidates) is CandidateAgendaPreview and
          type(integrated) is IntegratedPreview, 'fuentes_invalidas')
    candidates.verify(rules, initial, dependencies, controls,
                      integrated, diagnostic, environments)
    marks_raw, parsed = _normalize_scenario(candidates, integrated, scenario)
    order = {u.service_id: u for u in candidates.units}
    expected = {u.service_id for u in integrated.units}
    _need(len(order) == len(candidates.units) and set(order) == expected,
          'servicios_inconsistentes')
    results: list[UnitReadiness] = []
    for sid in sorted(order):
        service = order[sid]
        c_facts, t_facts = parsed[sid]
        stage: list[HypotheticalControl] = []
        for slot in service.candidates:
            _need(slot.service_id == sid, 'candidato_no_local')
            reasons = []
            if t_facts[slot.control_id] is Truth.VERDADERO:
                reasons.append('CONTROL_ASUMIDO_SATISFECHO')
            elif c_facts[slot.target_case_id] is Truth.VERDADERO:
                reasons.append('CASO_OBJETIVO_ASUMIDO_SATISFECHO')
            else:
                for dep in slot.pending_controls:
                    status = t_facts[dep]
                    if status is not Truth.VERDADERO:
                        reasons.append('CONTROL_REQUERIDO_'+status.name+':'+dep)
                for dep in slot.pending_cases:
                    status = c_facts[dep]
                    if status is not Truth.VERDADERO:
                        reasons.append('CASO_REQUERIDO_'+status.name+':'+dep)
            if reasons and reasons[0] in ('CONTROL_ASUMIDO_SATISFECHO',
                                          'CASO_OBJETIVO_ASUMIDO_SATISFECHO'):
                state = 'OMITIDO_SUPUESTO'
            elif reasons:
                state = 'BLOQUEADO'
            else:
                state = 'LISTO_CONDICIONAL'
            stage.append(HypotheticalControl(slot.control_id, slot.target_case_id,
                                             state, tuple(reasons + [
                                                 'AUTORIDAD_OPERACIONAL_NO_ACREDITADA'])))
        results.append(UnitReadiness(sid, service.protocol, tuple(stage),
                       tuple((c.control_id, c.reason) for c in service.excluded)))
    document = {
        'format': FORMAT,
        'scope': 'HYPOTHETICAL_READ_ONLY_NO_AUTHORITY',
        'candidate_sha256': candidates.sha256,
        'scenario_sha256': hashlib.sha256(marks_raw).hexdigest(),
        'services': [
            {'id': u.service_id, 'protocol': u.protocol,
             'controls': [{'id': r.control_id, 'target_case_id': r.target_case_id,
                           'state': r.state, 'reasons': list(r.reasons),
                           'executable': False} for r in u.controls],
             'inherited_exclusions': [{'id': cid, 'reason': why}
                                      for cid, why in u.inherited_exclusions]}
            for u in results],
        'conditionally_ready_count': sum(c.state == 'LISTO_CONDICIONAL'
                                         for u in results for c in u.controls),
        'blocked_count': sum(c.state == 'BLOQUEADO' for u in results for c in u.controls),
        'omitted_count': sum(c.state == 'OMITIDO_SUPUESTO' for u in results for c in u.controls),
        'executable_agenda': None, 'operational_dispatch': False,
        'generation_published': None, 'controls_applied': False,
        'p8_operational': 'NO-GO',
    }
    return (_canonical(document, MAX_REPORT_BYTES), marks_raw, tuple(results))


def preview_hypothetical_readiness(rules: FrozenRulePreview,
                                   initial: InitialPreview,
                                   dependencies: DependencyPreview,
                                   controls: ControlPreview,
                                   integrated: IntegratedPreview,
                                   diagnostic: GuardDiagnosticPreview,
                                   environments: dict[str, dict[str, Any]],
                                   candidates: CandidateAgendaPreview,
                                   scenario: dict[str, Any]) -> ReadinessPreview:
    """Recalcula elegibilidad simulada; jamás aprueba P8 ni altera estado."""
    report, marks, units = _compose(rules, initial, dependencies, controls,
                                    integrated, diagnostic, environments,
                                    candidates, scenario)
    view = ReadinessPreview(report, hashlib.sha256(report).hexdigest(),
                            candidates.sha256, hashlib.sha256(marks).hexdigest(),
                            marks, units)
    view.verify(rules, initial, dependencies, controls, integrated,
                diagnostic, environments, candidates, scenario)
    return view
