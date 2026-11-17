"""P14-R65: A1 en contexto de ConfirmedState, sin autorización operacional.

No valida procedencia física ni deduce que la huella de reglas R17 equivalga
al SHA de la configuración global almacenada en ConfirmedState.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.rules.contextual import evaluate_contextual
from ardrec.rules.kernel import A1Error, ID
from ardrec.state import ConfirmedState, ServiceState

FORMAT = 'ardrec-a1-r65-confirmed-context-model-v1'
ORIGIN = 'CONFIRMED_STATE_MODEL'
MAX_BYTES = 65536


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _id(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _canonical(value: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         sort_keys=True, separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise A1Error('modelo_contextual_no_serializable') from exc
    if len(raw) > MAX_BYTES:
        raise A1Error('modelo_contextual_excesivo')
    return raw


def _projection(confirmed: ConfirmedState) -> dict[str, Any]:
    """Proyección íntegra de los vínculos inmutables de ConfirmedState relevantes para A1.

    Su SHA permite repetición y comparación, no certifica la fuente del objeto.
    """
    if type(confirmed) is not ConfirmedState:
        raise A1Error('estado_confirmado_modelo_invalido')
    # Una instancia forjada con object.__new__ no debe eludir los invariantes.
    try:
        confirmed.__post_init__()
        if any(type(service) is not ServiceState for service in confirmed.services):
            raise A1Error('estado_confirmado_modelo_invalido')
        for service in confirmed.services:
            service.__post_init__()
    except A1Error:
        raise
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise A1Error('estado_confirmado_modelo_invalido') from exc
    return {
        'record_id': confirmed.record_id,
        'generation': confirmed.generation,
        'generation_reference': confirmed.generation_reference,
        'configuration_sha256': confirmed.configuration_sha256,
        'versions_reference': confirmed.versions_reference,
        'incorporated_events': list(confirmed.incorporated_events),
        'services': [
            {'service_id': service.service_scenario_id, 'phase': service.phase.value,
             'reason_reference': service.reason_reference,
             'wait_reference': service.wait_reference,
             'stop_cause': service.stop_cause,
             'closure': None if service.closure is None else {
                 name: {'name': getattr(service.closure, name).name,
                        'value': getattr(service.closure, name).value.value,
                        'reference': getattr(service.closure, name).reference}
                 for name in ('ES', 'SA', 'CV', 'LE')
             }} for service in sorted(
                 confirmed.services, key=lambda s: s.service_scenario_id)
        ],
    }


@dataclass(frozen=True, slots=True)
class ConfirmedContextDecision:
    """Recibo de modelo; el objeto ConfirmedState sigue necesitando acreditación externa."""
    source: bytes
    sha256: str
    confirmed_model_sha256: str
    rules_source_sha256: str

    def json_bytes(self) -> bytes:
        if (type(self.source) is not bytes or type(self.sha256) is not str or
                _sha(self.source) != self.sha256):
            raise A1Error('recibo_estado_modelo_alterado')
        return self.source

    def verify(self, frozen: FrozenRulePreview, confirmed: ConfirmedState,
               service_id: str, environment: dict[str, Any], *,
               case_id: str, condition_id: str, context_id: str) -> bool:
        expected = evaluate_confirmed_context(
            frozen, confirmed, service_id, environment,
            case_id=case_id, condition_id=condition_id, context_id=context_id)
        if (type(self.source) is not bytes or type(self.sha256) is not str or
                type(self.confirmed_model_sha256) is not str or
                type(self.rules_source_sha256) is not str or
                self != expected):
            raise A1Error('recibo_estado_modelo_no_coincide')
        return True

    @property
    def operationally_authorized(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def evaluate_confirmed_context(frozen: FrozenRulePreview,
                               confirmed: ConfirmedState,
                               service_id: str, environment: dict[str, Any], *,
                               case_id: str, condition_id: str,
                               context_id: str) -> ConfirmedContextDecision:
    """Deriva estado/identidad del modelo en vez de aceptar `estado_actual` arbitrario.

    **No prueba** que confirmed provenga del archivo A9 ni que su SHA global
    vincule por sí solo la configuración de reglas R17. No publica ni despacha.
    """
    if type(frozen) is not FrozenRulePreview:
        raise A1Error('fuente_contextual_invalida')
    if not all(_id(x) for x in (service_id, case_id, condition_id, context_id)):
        raise A1Error('identidad_contextual_invalida')

    projection = _projection(confirmed)
    matching = [service for service in confirmed.services
                if service.service_scenario_id == service_id]
    if len(matching) != 1:
        raise A1Error('servicio_no_confirmado')
    selected = matching[0]

    # Reutiliza la evaluación R64 de la instantánea R17. El origen aquí es la
    # clase del objeto entregado, NO una certificación de procedencia técnica.
    contextual = evaluate_contextual(
        frozen, service_id, environment, current_state=selected.phase,
        origin=ORIGIN, case_id=case_id, condition_id=condition_id,
        context_id=context_id)
    contextual_json = json.loads(contextual.json_bytes())
    projection_raw = _canonical(projection)
    record: dict[str, Any] = {
        'schema': FORMAT,
        'a1_contextual': contextual_json,
        'a1_contextual_sha256': contextual.sha256,
        'confirmed_model_sha256': _sha(projection_raw),
        'confirmed_record_id': confirmed.record_id,
        'confirmed_generation': confirmed.generation,
        'confirmed_generation_reference': confirmed.generation_reference,
        'confirmed_configuration_sha256': confirmed.configuration_sha256,
        'confirmed_versions_reference': confirmed.versions_reference,
        'rule_configuration_sha256': frozen.sha256,
        'confirmed_service_id': service_id,
        'confirmed_service_phase': selected.phase.value,
        'source_kind': ORIGIN,
        'state_phase_derived_from_model': True,
        'model_integrity_replayable': True,
        'model_external_origin_attested': False,
        'full_configuration_to_rule_source_attested': False,
        'operational_dispatch': False,
        'published_generation': None,
        'p8_operational': 'NO-GO',
    }
    source = _canonical(record)
    return ConfirmedContextDecision(
        source, _sha(source), _sha(projection_raw), frozen.sha256)
