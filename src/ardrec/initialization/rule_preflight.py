"""R17: prevalidación pura de tablas A1 y enlace preparatorio hacia A2.

El resultado no es una configuración ARDREC inicializada, no publica estados,
no ejecuta perfiles ni establece autorización operacional P8.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.rules.kernel import (
    A1Error, ID, MAX_RULES, TYPES, compile_expression, decide, guard_allows,
)
from ardrec.state import Truth

FORMAT = 'ardrec-a1-a2-r17-rule-preflight-v1'
MAX_SERVICES = 32
MAX_SNAPSHOT_BYTES = 65536


class RulePreflightError(ValueError):
    """La configuración candidata no puede congelarse para pruebas sintéticas."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise RulePreflightError(code)


def _id(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _keys(value: Any, expected: set[str], code: str) -> None:
    _need(type(value) is dict and set(value) == expected, code)


def _canon(value: Any) -> bytes:
    try:
        result = json.dumps(value, ensure_ascii=True, allow_nan=False,
                            sort_keys=True, separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as error:
        raise RulePreflightError('configuracion_no_serializable') from error
    _need(len(result) <= MAX_SNAPSHOT_BYTES, 'configuracion_excesiva')
    return result


@dataclass(frozen=True, slots=True)
class FrozenRulePreview:
    """Instantánea por valor; el material de origen no queda referenciado."""

    source: bytes
    sha256: str
    service_ids: tuple[str, ...]

    def _validated_source(self) -> dict[str, Any]:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'instantanea_alterada')
        try:
            data = json.loads(self.source)
        except (TypeError, ValueError, UnicodeError) as error:
            raise RulePreflightError('instantanea_invalida') from error
        _need(type(data) is dict and data.get('format') == FORMAT,
              'version_incompatible')
        return data

    def evaluate_service(self, service_id: str, environment: dict[str, Any]) -> 'PreviewDecision':
        """Consulta pura A1 sobre una instantánea; no inicializa A2."""
        _need(_id(service_id) and service_id in self.service_ids,
              'servicio_no_declarado')
        data = self._validated_source()
        services = [s for s in data['services'] if s['id'] == service_id]
        _need(len(services) == 1, 'instantanea_invalida')
        table = services[0]['rules']
        decision = decide(table, data['fields'], environment)
        return PreviewDecision(self.sha256, service_id, decision.status,
                               decision.selected, decision.evaluations,
                               guard_allows(decision.status))


@dataclass(frozen=True, slots=True)
class PreviewDecision:
    configuration_sha256: str
    service_id: str
    status: Truth
    selected_rule: str | None
    evaluations: tuple[tuple[str, Truth], ...]
    logical_guard_satisfied: bool

    @property
    def operationally_authorized(self) -> bool:
        return False


def preflight_rule_configuration(candidate: dict[str, Any]) -> FrozenRulePreview:
    """Validación total previa a cualquier consulta o evaluación de ambiente.

    A1 valida cada expresión y todas las filas. Este enlace estructural A2
    no atribuye evidencia, autoridad, riesgo congelado o generación publicada.
    """
    _keys(candidate, {'format', 'fields', 'services'}, 'configuracion_invalida')
    _need(candidate['format'] == FORMAT, 'version_incompatible')
    schema = candidate['fields']
    _need(type(schema) is dict and len(schema) <= 128, 'esquema_invalido')
    for name, domain in schema.items():
        _need(_id(name) and type(domain) is str and domain in TYPES,
              'esquema_invalido')
    services = candidate['services']
    _need(type(services) is list and 1 <= len(services) <= MAX_SERVICES,
          'servicios_invalidos')
    seen_services: set[str] = set()
    frozen_services = []
    for service in services:
        _keys(service, {'id', 'initial_state', 'rules'}, 'servicio_invalido')
        sid = service['id']
        _need(_id(sid) and sid not in seen_services,
              'identidad_servicio_invalida_o_duplicada')
        seen_services.add(sid)
        _need(service['initial_state'] == 'PREPARADO',
              'estado_inicial_no_preparado')
        rules = service['rules']
        _need(type(rules) is list and 1 <= len(rules) <= MAX_RULES,
              'tabla_invalida')
        seen_rules: set[str] = set()
        frozen_rules = []
        for row in rules:
            _keys(row, {'id', 'condicion'}, 'fila_invalida')
            rid = row['id']
            _need(_id(rid) and rid not in seen_rules,
                  'identidad_regla_invalida_o_duplicada')
            seen_rules.add(rid)
            # Toda regla se comprueba antes de ordenar y congelar, sin ejecución.
            node = compile_expression(row['condicion'], schema)
            _need(node.domain == 'LOGICO', 'condicion_no_logica')
            frozen_rules.append(row)
        frozen_services.append({'id': sid, 'initial_state': 'PREPARADO',
                                'rules': sorted(frozen_rules, key=lambda r: r['id'])})
    normalized = {'format': FORMAT, 'fields': schema,
                  'services': sorted(frozen_services, key=lambda s: s['id'])}
    raw = _canon(normalized)
    # Round-trip canónico estricto, sin alias ni referencias a objetos del usuario.
    _need(_canon(json.loads(raw)) == raw, 'instantanea_no_canonica')
    digest = hashlib.sha256(raw).hexdigest()
    return FrozenRulePreview(raw, digest, tuple(sorted(seen_services)))
