"""A2-R18: instantánea inicial exacta, sintética y sin autoridad operacional.

No publica una generación confirmada, no consume autorizaciones ni inicia
intentos. Los valores y contadores son el estado de *propuesta* previo a A2.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
import re
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview, PreviewDecision
from ardrec.rules.kernel import ID
from ardrec.state import ServicePhase

FORMAT = "ardrec-p14-r18-a2-initial-preview-v1"
MAX_BYTES = 65536
MAX_CASES = 64
FRACTION = re.compile(r"(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?\Z", re.ASCII)


class InitialPreviewError(ValueError):
    """La propuesta de estado inicial no cumple el contrato declarado."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(value: bool, code: str) -> None:
    if not value:
        raise InitialPreviewError(code)


def _fields(value: Any, expected: set[str], code: str) -> None:
    _need(type(value) is dict and set(value) == expected, code)


def _id(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _bounded_fraction(raw: Any) -> Fraction:
    _need(type(raw) is str and len(raw) <= 80 and FRACTION.fullmatch(raw) is not None,
          'magnitud_no_canonica')
    try:
        result = Fraction(raw)
    except (ValueError, ZeroDivisionError, OverflowError) as exc:
        raise InitialPreviewError('magnitud_invalida') from exc
    _need(Fraction(0) <= result <= Fraction(1), 'magnitud_fuera_de_dominio')
    _need(str(result) == raw, 'magnitud_no_canonica')
    return result


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise InitialPreviewError('serializacion_invalida') from exc
    _need(len(raw) <= MAX_BYTES, 'instantanea_excesiva')
    return raw


@dataclass(frozen=True, slots=True)
class CaseInitial:
    id: str
    permitted_attempts_ceiling: int
    starts_confirmed: int = 0
    execution_results: tuple[()] = ()

    def __post_init__(self):
        _need(_id(self.id), 'identidad_caso_invalida')
        _need(type(self.permitted_attempts_ceiling) is int
              and self.permitted_attempts_ceiling in (1, 2), 'limite_caso_invalido')
        _need(type(self.starts_confirmed) is int and self.starts_confirmed == 0,
              'contador_inicial_invalido')
        _need(type(self.execution_results) is tuple and not self.execution_results,
              'resultados_iniciales_no_vacios')


@dataclass(frozen=True, slots=True)
class UnitInitial:
    id: str
    phase: ServicePhase
    initial_risk: Fraction
    normalized_criticality: Fraction
    accumulated_evidence: Fraction
    recalibrated_risk: Fraction
    priority: None
    cases: tuple[CaseInitial, ...]
    local_history: tuple[()] = ()

    def __post_init__(self):
        _need(_id(self.id), 'identidad_servicio_invalida')
        _need(self.phase is ServicePhase.PREPARADO, 'estado_inicial_invalido')
        _need(type(self.initial_risk) is Fraction and Fraction(0) <= self.initial_risk <= Fraction(1),
              'riesgo_inicial_invalido')
        _need(type(self.normalized_criticality) is Fraction
              and Fraction(0) <= self.normalized_criticality <= Fraction(1),
              'criticidad_inicial_invalida')
        _need(type(self.accumulated_evidence) is Fraction
              and self.accumulated_evidence == 0, 'evidencia_inicial_no_cero')
        _need(type(self.recalibrated_risk) is Fraction
              and self.recalibrated_risk == self.initial_risk, 'riesgo_recalculado_inicial_invalido')
        _need(self.priority is None, 'prioridad_inicial_no_vacia')
        _need(type(self.cases) is tuple and bool(self.cases)
              and all(type(c) is CaseInitial for c in self.cases), 'casos_iniciales_invalidos')
        _need(len({c.id for c in self.cases}) == len(self.cases), 'casos_duplicados')
        _need(type(self.local_history) is tuple and not self.local_history,
              'historia_inicial_no_vacia')


@dataclass(frozen=True, slots=True)
class InitialPreview:
    """Vista inmutable; la huella es integridad local, no autoridad A9."""
    source: bytes
    sha256: str
    rule_source_sha256: str
    units: tuple[UnitInitial, ...]

    def verify(self, rules: FrozenRulePreview) -> bool:
        _need(type(rules) is FrozenRulePreview, 'prevalidacion_requerida')
        rules._validated_source()  # valida el contenido SHA-256, no solo el identificador
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'instantanea_alterada')
        try:
            data = json.loads(self.source, object_pairs_hook=_no_duplicates)
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise InitialPreviewError('instantanea_no_valida') from exc
        _need(type(data) is dict and data.get('format') == FORMAT, 'version_incompatible')
        _need(_canonical(data) == self.source, 'instantanea_no_canonica')
        _need(data.get('rule_source_sha256') == rules.sha256
              and self.rule_source_sha256 == rules.sha256, 'reglas_no_coinciden')
        _need(type(data.get('services')) is list, 'servicios_no_coinciden')
        try:
            source_ids = tuple(s['id'] for s in data['services'])
            reconstructed = tuple(_units_from_record(data['services']))
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise InitialPreviewError('instantanea_no_valida') from exc
        _need(source_ids == rules.service_ids, 'servicios_no_coinciden')
        _need(reconstructed == self.units, 'identidad_inicial_alterada')
        return True

    def evaluate_guard(self, rules: FrozenRulePreview, service_id: str,
                       environment: dict[str, Any]) -> PreviewDecision:
        """Solo evaluación A1 sobre el estado previo, sin ejecución ni mutación."""
        self.verify(rules)
        _need(_id(service_id) and service_id in rules.service_ids,
              'servicio_no_declarado')
        return rules.evaluate_service(service_id, environment)

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _need(key not in result, 'clave_duplicada')
        result[key] = value
    return result


def _units_from_record(services: list[dict[str, Any]]) -> list[UnitInitial]:
    units = []
    for service in services:
        _fields(service, {'id', 'initial_risk', 'normalized_criticality', 'cases'},
                'servicio_inicial_invalido')
        sid = service['id']
        _need(_id(sid), 'identidad_servicio_invalida')
        cases = service['cases']
        _need(type(cases) is list and 1 <= len(cases) <= MAX_CASES,
              'casos_iniciales_invalidos')
        case_values = []
        seen = set()
        for c in cases:
            _fields(c, {'id', 'max_repetitions'}, 'caso_invalido')
            cid = c['id']
            _need(_id(cid) and cid not in seen, 'caso_duplicado_o_invalido')
            seen.add(cid)
            repeat = c['max_repetitions']
            _need(type(repeat) is int and repeat in (0, 1), 'repeticion_no_permitida')
            case_values.append(CaseInitial(cid, 1 + repeat))
        risk = _bounded_fraction(service['initial_risk'])
        critical = _bounded_fraction(service['normalized_criticality'])
        units.append(UnitInitial(sid, ServicePhase.PREPARADO, risk, critical,
                                 Fraction(0), risk, None,
                                 tuple(sorted(case_values, key=lambda c: c.id))))
    return units


def prepare_initial_preview(rules: FrozenRulePreview, candidate: dict[str, Any]) -> InitialPreview:
    """Valida servicios/casos vinculados a R17 y conserva solo estado sintético inicial."""
    _need(type(rules) is FrozenRulePreview, 'prevalidacion_requerida')
    rules._validated_source()
    _fields(candidate, {'format', 'rule_source_sha256', 'services'},
            'configuracion_inicial_invalida')
    _need(candidate['format'] == FORMAT, 'version_incompatible')
    _need(candidate['rule_source_sha256'] == rules.sha256, 'reglas_no_coinciden')
    services = candidate['services']
    _need(type(services) is list and len(services) == len(rules.service_ids),
          'cantidad_servicios_no_coincide')
    ids = []
    normalized = []
    for service in services:
        _fields(service, {'id', 'initial_risk', 'normalized_criticality', 'cases'},
                'servicio_inicial_invalido')
        sid = service['id']
        _need(_id(sid) and sid not in ids, 'servicio_duplicado_o_invalido')
        ids.append(sid)
        cases = service['cases']
        _need(type(cases) is list and 1 <= len(cases) <= MAX_CASES, 'casos_iniciales_invalidos')
        seen = set()
        for case in cases:
            _fields(case, {'id', 'max_repetitions'}, 'caso_invalido')
            _need(_id(case['id']) and case['id'] not in seen, 'caso_duplicado_o_invalido')
            seen.add(case['id'])
            _need(type(case['max_repetitions']) is int and case['max_repetitions'] in (0, 1),
                  'repeticion_no_permitida')
        _bounded_fraction(service['initial_risk'])
        _bounded_fraction(service['normalized_criticality'])
        normalized.append({**service, 'cases': sorted(cases, key=lambda c: c['id'])})
    _need(tuple(sorted(ids)) == rules.service_ids, 'servicios_no_coinciden')
    normalized.sort(key=lambda s: s['id'])
    result = {'format': FORMAT, 'rule_source_sha256': rules.sha256, 'services': normalized}
    source = _canonical(result)
    _need(_canonical(json.loads(source, object_pairs_hook=_no_duplicates)) == source,
          'instantanea_no_canonica')
    data = _units_from_record(normalized)
    result_preview = InitialPreview(source, hashlib.sha256(source).hexdigest(),
                                    rules.sha256, tuple(data))
    result_preview.verify(rules)
    return result_preview
