"""R68 / A1: punto de entrada algorítmico reproducible sobre fuentes R17 y R67.

El algoritmo decide de modo puro. R68 NO acredita origen físico, firma de A9,
publicación de generación ni habilitación operacional P8.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.rules.global_binding import evaluate_global_a1
from ardrec.rules.kernel import A1Error

SCHEMA = 'ardrec-p14-r68-a1-closure-algorithmic-v1'
MAX_RECEIPT_BYTES = 131072


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(doc: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(doc, sort_keys=True, ensure_ascii=True, allow_nan=False,
                         separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise A1Error('a1_recibo_no_canonico') from exc
    if len(raw) > MAX_RECEIPT_BYTES:
        raise A1Error('a1_recibo_excesivo')
    return raw


@dataclass(frozen=True, slots=True)
class A1ClosureDecision:
    """Recibo lógico sin autoridad A9/P8, reproducible desde fuentes exactas."""
    source: bytes
    sha256: str
    global_sha256: str
    confirmed_sha256: str
    rules_sha256: str

    def json_bytes(self) -> bytes:
        if type(self.source) is not bytes or type(self.sha256) is not str or (
                _sha(self.source) != self.sha256):
            raise A1Error('a1_recibo_integridad_invalida')
        return self.source

    def verify(self, frozen: FrozenRulePreview, global_raw: bytes,
               global_pin: str, confirmed_raw: bytes, confirmed_pin: str,
               service_id: str, environment: dict[str, Any], *,
               case_id: str, condition_id: str, context_id: str) -> bool:
        reference = evaluate_complete_a1(
            frozen, global_raw, global_pin, confirmed_raw, confirmed_pin,
            service_id, environment, case_id=case_id,
            condition_id=condition_id, context_id=context_id)
        if self != reference:
            raise A1Error('a1_recibo_no_reproducible')
        return True

    @property
    def operationally_authorized(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def evaluate_complete_a1(frozen: FrozenRulePreview, global_raw: bytes,
                         global_pin: str, confirmed_raw: bytes,
                         confirmed_pin: str, service_id: str,
                         environment: dict[str, Any], *, case_id: str,
                         condition_id: str, context_id: str) -> A1ClosureDecision:
    """Cruza DECIDIR(R17) con la lectura canónica R67 de una misma generación.

    La igualdad entre configuración global y fuente de reglas R17, así como
    el origen confiable de los pines, requieren acreditación INDEPENDIENTE:
    este contrato no declara que A9 haya publicado la generación.
    """
    if type(frozen) is not FrozenRulePreview:
        raise A1Error('a1_fuente_reglas_invalida')
    bound = evaluate_global_a1(
        frozen, global_raw, global_pin, confirmed_raw, confirmed_pin,
        service_id, environment, case_id=case_id,
        condition_id=condition_id, context_id=context_id)
    nested = json.loads(bound.json_bytes())
    contextual = nested['a1_recovered_receipt']['confirmed_model_receipt']['a1_contextual']
    independent = frozen.evaluate_service(service_id, environment)
    expected_evaluations = [
        {'id': rid, 'valor': value.value} for rid, value in independent.evaluations
    ]
    if (contextual['estado_tabla'] != independent.status.value or
            contextual['regla_seleccionada'] != independent.selected_rule or
            contextual['salida_declarativa'] != independent.selected_output or
            contextual['evaluaciones'] != expected_evaluations or
            contextual['servicio'] != service_id or
            contextual['configuracion'] != frozen.sha256 or
            contextual['caso'] != case_id or
            contextual['condicion'] != condition_id or
            contextual['contexto'] != context_id or
            nested['global_storage_sha256'] != global_pin or
            nested['confirmed_storage_sha256'] != confirmed_pin or
            nested['rules_source_sha256'] != frozen.sha256 or
            nested['p8_operational'] != 'NO-GO' or
            nested['operational_dispatch'] is not False or
            nested['published_generation'] is not None):
        raise A1Error('a1_fuentes_o_decision_inconsistentes')
    result = {
        'schema': SCHEMA,
        'scope': 'A1_ALGORITHMIC_ONLY_REPLAYABLE',
        'service_id': service_id,
        'global_storage_sha256': global_pin,
        'confirmed_storage_sha256': confirmed_pin,
        'rules_source_sha256': frozen.sha256,
        'global_receipt_sha256': bound.sha256,
        'record_id': nested['confirmed_record_id'],
        'generation': nested['confirmed_generation'],
        'generation_reference': nested['confirmed_generation_reference'],
        'versions_reference': nested['confirmed_versions_reference'],
        'confirmed_configuration_sha256': nested['confirmed_configuration_sha256'],
        'state': contextual['estado'],
        'origin': contextual['origen'],
        'case_id': case_id,
        'condition_id': condition_id,
        'context_id': context_id,
        'status': independent.status.value,
        'selected_rule': independent.selected_rule,
        'declared_output': independent.selected_output,
        'evaluations': expected_evaluations,
        'global_confirmed_same_generation': True,
        'rule_choice_matches_frozen_R17': True,
        'global_configuration_r17_membership_attested': False,
        'external_pin_authority_attested': False,
        'a9_publication_attested': False,
        'physical_observation_attested': False,
        'operational_dispatch': False,
        'published_generation': None,
        'p8_operational': 'NO-GO',
    }
    raw = _canonical(result)
    return A1ClosureDecision(raw, _sha(raw), global_pin, confirmed_pin,
                             frozen.sha256)
