"""R67/A1: vínculo read-only entre GlobalState y ConfirmedState recuperados.

No verifica firmas/publicación de A9 ni autoridad de un origen externo. El pin
SHA debe provenir de una fuente de confianza independiente. P8 permanece NO-GO.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.persistence.codec import StorageError, canonical, pack, parse, unpack
from ardrec.rules.kernel import A1Error
from ardrec.rules.persisted_context import (
    evaluate_recovered_a1, read_pinned_state_file, restore_confirmed_state,
)
from ardrec.state import ConfirmedState, GlobalState, ServiceState

FORMAT = 'ardrec-a1-r67-global-confirmed-binding-v1'
MAX_STATE_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise A1Error(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pin(pin: str) -> None:
    _need(type(pin) is str and SHA.fullmatch(pin) is not None,
          'pin_global_invalido')


def restore_global_state(raw: bytes, expected_sha256: str) -> GlobalState:
    """Recupera y revalida todos los objetos de la jerarquía persistida."""
    _pin(expected_sha256)
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES,
          'estado_global_tamano_invalido')
    _need(_sha(raw) == expected_sha256, 'estado_global_hash_invalido')
    try:
        value = unpack(parse(raw))
        _need(type(value) is GlobalState, 'objeto_no_es_estado_global')
        _need(type(value.confirmed) is ConfirmedState,
              'estado_global_confirmado_invalido')
        value.confirmed.__post_init__()
        for service in value.confirmed.services:
            _need(type(service) is ServiceState,
                  'estado_global_confirmado_invalido')
            service.__post_init__()
        for service in value.services:
            _need(type(service) is ServiceState, 'estado_global_servicio_invalido')
            service.__post_init__()
        value.__post_init__()
        _need(canonical(pack(value)) == raw, 'estado_global_no_canonico')
    except A1Error:
        raise
    except (StorageError, ValueError, TypeError, KeyError, AttributeError,
            OverflowError, RecursionError) as exc:
        raise A1Error('estado_global_invalido') from exc
    return value


def _document(record: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(record, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise A1Error('recibo_global_no_serializable') from exc
    _need(len(raw) <= MAX_REPORT_BYTES, 'recibo_global_excesivo')
    return raw


@dataclass(frozen=True, slots=True)
class GlobalA1Decision:
    """Recibo lógico que NO certifica publicación, P8 ni procedencia externa."""
    source: bytes
    sha256: str
    global_sha256: str
    confirmed_sha256: str
    rules_sha256: str
    source_mode: str

    def json_bytes(self) -> bytes:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and _sha(self.source) == self.sha256,
              'recibo_global_alterado')
        return self.source

    def verify(self, frozen: FrozenRulePreview, global_raw: bytes, global_pin: str,
               confirmed_raw: bytes, confirmed_pin: str, service_id: str,
               environment: dict[str, Any], *, case_id: str,
               condition_id: str, context_id: str) -> bool:
        _need(self.source_mode == 'CANONICAL_BYTES', 'modo_global_incorrecto')
        expected = evaluate_global_a1(
            frozen, global_raw, global_pin, confirmed_raw, confirmed_pin,
            service_id, environment, case_id=case_id,
            condition_id=condition_id, context_id=context_id)
        _need(self == expected, 'recibo_global_no_coincide')
        return True

    def verify_files(self, frozen: FrozenRulePreview, global_path: Path,
                     global_pin: str, confirmed_path: Path, confirmed_pin: str,
                     service_id: str, environment: dict[str, Any], *,
                     case_id: str, condition_id: str, context_id: str) -> bool:
        _need(self.source_mode == 'READONLY_FILE', 'modo_global_incorrecto')
        expected = evaluate_global_a1_files(
            frozen, global_path, global_pin, confirmed_path, confirmed_pin,
            service_id, environment, case_id=case_id,
            condition_id=condition_id, context_id=context_id)
        _need(self == expected, 'recibo_global_no_coincide')
        return True

    @property
    def operationally_authorized(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _evaluate(frozen: FrozenRulePreview, global_raw: bytes, global_pin: str,
              confirmed_raw: bytes, confirmed_pin: str, service_id: str,
              environment: dict[str, Any], *, case_id: str,
              condition_id: str, context_id: str,
              mode: str) -> GlobalA1Decision:
    _need(type(frozen) is FrozenRulePreview, 'fuente_reglas_invalida')
    _need(type(mode) is str and mode in ('CANONICAL_BYTES', 'READONLY_FILE'),
          'modo_global_invalido')
    global_state = restore_global_state(global_raw, global_pin)
    confirmed = restore_confirmed_state(confirmed_raw, confirmed_pin)
    # Compara objetos Y representaciones canónicas, no solo SHA declarados.
    _need(global_state.confirmed == confirmed and
          canonical(pack(global_state.confirmed)) == confirmed_raw,
          'global_confirmado_no_coincide')
    _need(global_state.services == confirmed.services,
          'candidato_global_no_confirmado')
    _need(not global_state.pending_attempts,
          'intento_global_pendiente')
    a1 = evaluate_recovered_a1(
        frozen, confirmed_raw, confirmed_pin, service_id, environment,
        case_id=case_id, condition_id=condition_id, context_id=context_id)
    record = {
        'schema': FORMAT,
        'source_mode': mode,
        'global_storage_sha256': global_pin,
        'confirmed_storage_sha256': confirmed_pin,
        'rules_source_sha256': frozen.sha256,
        'global_execution_id': global_state.execution_id,
        'global_simulation_declared': global_state.simulation,
        'global_authority_declared': global_state.authority.value,
        'confirmed_record_id': confirmed.record_id,
        'confirmed_generation': confirmed.generation,
        'confirmed_generation_reference': confirmed.generation_reference,
        'confirmed_configuration_sha256': confirmed.configuration_sha256,
        'confirmed_versions_reference': confirmed.versions_reference,
        'a1_recovered_receipt_sha256': a1.sha256,
        'a1_recovered_receipt': json.loads(a1.json_bytes()),
        'model_codec_and_hash_pins_verified': True,
        'global_confirmed_model_identical': True,
        'no_unconfirmed_candidate_state': True,
        'no_pending_attempt': True,
        'external_pin_authority_attested': False,
        'a9_published_generation_attested': False,
        'global_configuration_rules_binding_attested': False,
        'physical_origin_attested': False,
        'operational_dispatch': False,
        'published_generation': None,
        'p8_operational': 'NO-GO',
    }
    data = _document(record)
    return GlobalA1Decision(data, _sha(data), global_pin, confirmed_pin,
                            frozen.sha256, mode)


def evaluate_global_a1(frozen: FrozenRulePreview, global_raw: bytes,
                       global_pin: str, confirmed_raw: bytes,
                       confirmed_pin: str, service_id: str,
                       environment: dict[str, Any], *, case_id: str,
                       condition_id: str, context_id: str) -> GlobalA1Decision:
    """Solo bytes; los pines son referencias suministradas, no certificados."""
    return _evaluate(frozen, global_raw, global_pin, confirmed_raw,
                     confirmed_pin, service_id, environment,
                     case_id=case_id, condition_id=condition_id,
                     context_id=context_id, mode='CANONICAL_BYTES')


def evaluate_global_a1_files(frozen: FrozenRulePreview, global_path: Path,
                             global_pin: str, confirmed_path: Path,
                             confirmed_pin: str, service_id: str,
                             environment: dict[str, Any], *, case_id: str,
                             condition_id: str, context_id: str) -> GlobalA1Decision:
    """Dos fuentes privadas distintas, abiertas únicamente en modo lectura."""
    _need(isinstance(global_path, Path) and isinstance(confirmed_path, Path)
          and global_path != confirmed_path, 'rutas_globales_no_independientes')
    global_raw = read_pinned_state_file(global_path, global_pin)
    confirmed_raw = read_pinned_state_file(confirmed_path, confirmed_pin)
    return _evaluate(frozen, global_raw, global_pin, confirmed_raw,
                     confirmed_pin, service_id, environment,
                     case_id=case_id, condition_id=condition_id,
                     context_id=context_id, mode='READONLY_FILE')
