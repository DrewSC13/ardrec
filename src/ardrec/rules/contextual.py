"""A1-R64: salida contextual declarativa y verificable de DECIDIR (fig. 3.4).

Es información proporcionada por la configuración y el invocador; una huella
permite reproducirla, pero NO acredita procedencia física ni autoriza P8.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.rules.kernel import A1Error, ID
from ardrec.state import ServicePhase

FORMAT = 'ardrec-a1-r64-contextual-decision-v1'
MAX_BYTES = 16384


def _identity(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _canonical(value: dict[str, Any]) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(raw) > MAX_BYTES:
        raise A1Error('contexto_excesivo')
    return raw


@dataclass(frozen=True, slots=True)
class ContextualDecision:
    """Recibo lógico congelado; NO es una generación confirmada ni una prueba de origen."""

    source: bytes
    sha256: str
    configuration_sha256: str

    def json_bytes(self) -> bytes:
        if type(self.source) is not bytes or type(self.sha256) is not str or (
                hashlib.sha256(self.source).hexdigest() != self.sha256):
            raise A1Error('recibo_contextual_alterado')
        return self.source

    def verify(self, frozen: FrozenRulePreview, service_id: str,
               environment: dict[str, Any], *, current_state: ServicePhase,
               origin: str, case_id: str, condition_id: str,
               context_id: str) -> bool:
        """Verifica recomputando contra la configuración y el contexto entregados.

        El invocador debe acreditar por separado origen, identidad y estado.
        """
        reference = evaluate_contextual(
            frozen, service_id, environment, current_state=current_state,
            origin=origin, case_id=case_id, condition_id=condition_id,
            context_id=context_id)
        if (type(self.source) is not bytes or type(self.sha256) is not str or
                type(self.configuration_sha256) is not str or
                self.source != reference.source or
                self.sha256 != reference.sha256 or
                self.configuration_sha256 != reference.configuration_sha256):
            raise A1Error('recibo_contextual_no_coincide')
        return True

    @property
    def operationally_authorized(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def evaluate_contextual(frozen: FrozenRulePreview, service_id: str,
                        environment: dict[str, Any], *,
                        current_state: ServicePhase, origin: str,
                        case_id: str, condition_id: str,
                        context_id: str) -> ContextualDecision:
    """Vincula el resultado A1 a los siete campos contextuales de la figura 3.4.

    `origen`, `estado_actual`, `caso`, `condicion` y `contexto` son
    declaraciones explícitas del invocador, no hechos acreditados aquí.
    """
    if type(frozen) is not FrozenRulePreview:
        raise A1Error('fuente_contextual_invalida')
    if type(current_state) is not ServicePhase:
        raise A1Error('estado_actual_invalido')
    if not all(_identity(v) for v in
               (origin, service_id, case_id, condition_id, context_id)):
        raise A1Error('identidad_contextual_invalida')

    # R17 comprueba que el servicio existe, que la instantánea no cambió y
    # que DECIDIR satisface la lógica de la figura 3.4.
    result = frozen.evaluate_service(service_id, environment)
    document: dict[str, Any] = {
        'schema': FORMAT,
        'estado': current_state.value,
        'origen': origin,
        'configuracion': frozen.sha256,
        'servicio': service_id,
        'caso': case_id,
        'condicion': condition_id,
        'contexto': context_id,
        'estado_tabla': result.status.value,
        'regla_seleccionada': result.selected_rule,
        'salida_declarativa': result.selected_output,
        'evaluaciones': [
            {'id': name, 'valor': value.value}
            for name, value in result.evaluations
        ],
        'procedencia_externa_acreditada': False,
        'autoridad_operacional': False,
        'generacion_publicada': False,
        'p8': 'NO-GO',
    }
    source = _canonical(document)
    return ContextualDecision(source, hashlib.sha256(source).hexdigest(), frozen.sha256)
