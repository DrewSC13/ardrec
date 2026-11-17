"""P14-R66 / A1: recuperación canónica y lectura protegida de ConfirmedState.

El pin SHA-256 debe entregarlo una fuente externa confiable. Verificar este
archivo NO demuestra que exista una generación A9 publicada ni acredita P8.
No ejecuta acciones de red, procesos, huéspedes o escrituras de estado.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.persistence.codec import StorageError, canonical, pack, parse, unpack
from ardrec.rules.confirmed_context import evaluate_confirmed_context
from ardrec.rules.kernel import A1Error
from ardrec.state import ConfirmedState

FORMAT = 'ardrec-a1-r66-canonical-state-source-v1'
MAX_STATE_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024
SHA = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise A1Error(code)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pin(value: str) -> None:
    _need(type(value) is str and SHA.fullmatch(value) is not None,
          'pin_estado_invalido')


def _document(value: dict[str, Any]) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError) as exc:
        raise A1Error('recibo_estado_serializacion_invalida') from exc
    _need(len(raw) <= MAX_REPORT_BYTES, 'recibo_estado_excesivo')
    return raw


def restore_confirmed_state(raw: bytes, expected_sha256: str) -> ConfirmedState:
    """Decodificación canónica EXACTA del mismo modelo de persistencia ARDREC.

    La huella no es una firma ni demuestra el origen del pin suministrado.
    """
    _pin(expected_sha256)
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES,
          'estado_serializado_tamano_invalido')
    _need(_sha(raw) == expected_sha256, 'estado_serializado_hash_invalido')
    try:
        value = unpack(parse(raw))
        _need(type(value) is ConfirmedState, 'objeto_no_es_estado_confirmado')
        value.__post_init__()
        _need(canonical(pack(value)) == raw, 'estado_serializado_no_canonico')
    except A1Error:
        raise
    except (StorageError, ValueError, TypeError, AttributeError, KeyError,
            OverflowError, RecursionError) as exc:
        raise A1Error('estado_serializado_invalido') from exc
    return value


def read_pinned_state_file(path: Path, expected_sha256: str) -> bytes:
    """Lee un fichero regular de propiedad del usuario, con pin independiente.

    Sin symlinks (incluidos padres), hardlinks, permisos compartidos ni escrituras.
    No convierte ese fichero en una fuente de publicación A9 acreditada.
    """
    _pin(expected_sha256)
    _need(isinstance(path, Path) and path.is_absolute() and
          '..' not in path.parts, 'ruta_estado_invalida')
    try:
        _need(path.resolve(strict=True) == path and not path.is_symlink(),
              'ruta_estado_insegura')
    except (OSError, RuntimeError) as exc:
        raise A1Error('ruta_estado_insegura') from exc
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd: int | None = None
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
              and before.st_nlink == 1 and (stat.S_IMODE(before.st_mode) & 0o077) == 0,
              'archivo_estado_permisos_invalidos')
        _need(0 < before.st_size <= MAX_STATE_BYTES, 'estado_serializado_tamano_invalido')
        chunks: list[bytes] = []
        size = 0
        while True:
            part = os.read(fd, min(65536, MAX_STATE_BYTES + 1 - size))
            if not part:
                break
            size += len(part)
            _need(size <= MAX_STATE_BYTES, 'estado_serializado_tamano_invalido')
            chunks.append(part)
        after = os.fstat(fd)
        _need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
               before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
               after.st_ctime_ns) and size == before.st_size,
              'archivo_estado_mutado_durante_lectura')
        raw = b''.join(chunks)
    except A1Error:
        raise
    except OSError as exc:
        raise A1Error('archivo_estado_no_legible') from exc
    finally:
        if fd is not None:
            os.close(fd)
    _need(_sha(raw) == expected_sha256, 'estado_serializado_hash_invalido')
    return raw


@dataclass(frozen=True, slots=True)
class RecoveredA1Decision:
    """Recibo recomputable de fuente canónica, SIN acreditación externa."""
    source: bytes
    sha256: str
    storage_sha256: str
    rules_sha256: str
    source_mode: str

    def json_bytes(self) -> bytes:
        _need(type(self.source) is bytes and type(self.sha256) is str and
              _sha(self.source) == self.sha256,
              'recibo_recuperado_alterado')
        return self.source

    def verify(self, frozen: FrozenRulePreview, raw: bytes, pin: str,
               service_id: str, environment: dict[str, Any], *,
               case_id: str, condition_id: str, context_id: str) -> bool:
        _need(self.source_mode == 'CANONICAL_BYTES',
              'verificacion_archivo_requerida')
        comparison = evaluate_recovered_a1(
            frozen, raw, pin, service_id, environment,
            case_id=case_id, condition_id=condition_id, context_id=context_id)
        _need(self == comparison, 'recibo_recuperado_no_coincide')
        return True

    def verify_file(self, frozen: FrozenRulePreview, path: Path, pin: str,
                    service_id: str, environment: dict[str, Any], *,
                    case_id: str, condition_id: str, context_id: str) -> bool:
        _need(self.source_mode == 'READONLY_FILE',
              'verificacion_bytes_requerida')
        comparison = evaluate_recovered_a1_file(
            frozen, path, pin, service_id, environment,
            case_id=case_id, condition_id=condition_id, context_id=context_id)
        _need(self == comparison, 'recibo_recuperado_no_coincide')
        return True

    @property
    def operationally_authorized(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _recovered(frozen: FrozenRulePreview, raw: bytes, pin: str,
               service_id: str, environment: dict[str, Any], *,
               case_id: str, condition_id: str, context_id: str,
               source_mode: str) -> RecoveredA1Decision:
    """Recalcula A1 desde el modelo real restaurado mediante el códec existente."""
    _need(type(frozen) is FrozenRulePreview, 'fuente_reglas_invalida')
    _need(source_mode in ('CANONICAL_BYTES', 'READONLY_FILE') and
          type(source_mode) is str, 'modo_fuente_invalido')
    recovered = restore_confirmed_state(raw, pin)
    decision = evaluate_confirmed_context(
        frozen, recovered, service_id, environment,
        case_id=case_id, condition_id=condition_id, context_id=context_id)
    record: dict[str, Any] = {
        'schema': FORMAT,
        'source_mode': source_mode,
        'state_storage_sha256': pin,
        'rules_source_sha256': frozen.sha256,
        'confirmed_model_receipt_sha256': decision.sha256,
        'confirmed_model_receipt': json.loads(decision.json_bytes()),
        'canonical_codec_verified': True,
        'serialized_state_pin_verified': True,
        'trusted_pin_origin_attested': False,
        'a9_durable_generation_attested': False,
        'global_configuration_rules_binding_attested': False,
        'physical_origin_attested': False,
        'operational_dispatch': False,
        'published_generation': None,
        'p8_operational': 'NO-GO',
    }
    encoded = _document(record)
    return RecoveredA1Decision(encoded, _sha(encoded), pin,
                               frozen.sha256, source_mode)


def evaluate_recovered_a1(frozen: FrozenRulePreview, raw: bytes, pin: str,
                          service_id: str, environment: dict[str, Any], *,
                          case_id: str, condition_id: str,
                          context_id: str) -> RecoveredA1Decision:
    """Decisión sobre bytes canónicos suministrados, no sobre un archivo."""
    return _recovered(frozen, raw, pin, service_id, environment,
                      case_id=case_id, condition_id=condition_id,
                      context_id=context_id, source_mode='CANONICAL_BYTES')


def evaluate_recovered_a1_file(frozen: FrozenRulePreview, path: Path, pin: str,
                               service_id: str, environment: dict[str, Any], *,
                               case_id: str, condition_id: str,
                               context_id: str) -> RecoveredA1Decision:
    """Lectura local acotada e inmutable; no escribe, autoriza ni publica."""
    raw = read_pinned_state_file(path, pin)
    return _recovered(
        frozen, raw, pin, service_id, environment,
        case_id=case_id, condition_id=condition_id, context_id=context_id,
        source_mode='READONLY_FILE')
