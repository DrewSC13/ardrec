"""P14-R37: admisión DOCUMENTAL y sin ejecución de una observación SSH DEV.

La integridad de bytes NO establece procedencia física ni verdad de la condición.
Una aceptación aquí sólo habilita revisión independiente; A6 conserva ND.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any

SCHEMA = "ardrec-p14-r37-a6-defensive-observation-v1"
SOURCE_TYPES = frozenset(("SYNTHETIC_FIXTURE", "OPERATOR_DEV_RECEIPT"))
METHODS = frozenset(("SSH_EFFECTIVE_CONFIG_READONLY",))
RESULTS = frozenset(("MATCH", "DIFF", "INCONCLUSIVE"))
FIELDS = frozenset(("schema", "record_id", "session_id", "service_id", "case_id",
                    "source_kind", "method_id", "captured_at_utc", "configuration_sha256",
                    "support_sha256", "support_bytes", "observed_claim"))
MAX_RECEIPT_BYTES = 16384
MAX_SUPPORT_BYTES = 1048576
MAX_AGE_SECONDS = 86400
HEX = re.compile(r"[0-9a-f]{64}\Z")
IDENT = re.compile(r"[A-Za-z0-9_.:-]{1,80}\Z")


class DefensiveImportError(ValueError):
    """Códigos estables para fallos controlados de admisión."""


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise DefensiveImportError(code)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for k, value in items:
        _need(k not in result, "duplicate_json_key")
        result[k] = value
    return result


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _utc(value: str) -> datetime:
    _need(type(value) is str and
          re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
          "time_format")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise DefensiveImportError("time_invalid") from exc
    _need(parsed.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "time_not_canonical")
    return parsed


def _read_regular(path: Path, max_bytes: int, *, allow_empty: bool = False) -> bytes:
    _need(isinstance(path, Path) and not path.is_symlink(), "source_path_invalid")
    try:
        info = path.stat()
        _need(stat.S_ISREG(info.st_mode), "source_not_regular")
        _need(0 < info.st_size <= max_bytes if not allow_empty else
              0 <= info.st_size <= max_bytes, "source_size_invalid")
        with path.open("rb") as source:
            content = source.read(max_bytes + 1)
        _need(len(content) == info.st_size, "source_changed_or_oversized")
        return content
    except OSError as exc:
        raise DefensiveImportError("source_read_failed") from exc


def read_observation(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, MAX_RECEIPT_BYTES)
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise DefensiveImportError("receipt_invalid_json") from exc
    _need(type(doc) is dict and set(doc) == FIELDS, "receipt_schema")
    return doc, raw


def admit_defensive_observation(receipt: dict[str, Any], raw_receipt: bytes,
                                support_path: Path, *, as_of_utc: str) -> dict[str, Any]:
    """Sólo procedencia declarada + bytes verificables; sin validar condición SSH."""
    _need(type(receipt) is dict and set(receipt) == FIELDS, "receipt_schema")
    _need(receipt["schema"] == SCHEMA, "receipt_format")
    _need(type(receipt["record_id"]) is str and
          IDENT.fullmatch(receipt["record_id"]) is not None, "record_id_invalid")
    _need(receipt["session_id"] == "DEV_TUTOR_001" and
          receipt["service_id"] == "SSH_DEV" and
          receipt["case_id"] == "CASE_REFERENCE", "observation_binding_mismatch")
    _need(type(receipt["source_kind"]) is str and
          receipt["source_kind"] in SOURCE_TYPES, "source_kind_invalid")
    _need(type(receipt["method_id"]) is str and
          receipt["method_id"] in METHODS, "method_not_allowed")
    _need(type(receipt["observed_claim"]) is str and
          receipt["observed_claim"] in RESULTS, "claim_invalid")
    for name in ("configuration_sha256", "support_sha256"):
        _need(type(receipt[name]) is str and HEX.fullmatch(receipt[name]) is not None,
              "hash_invalid_" + name)
    _need(type(receipt["support_bytes"]) is int and
          0 < receipt["support_bytes"] <= MAX_SUPPORT_BYTES, "support_length_invalid")
    captured = _utc(receipt["captured_at_utc"])
    as_of = _utc(as_of_utc)
    delta = (as_of - captured).total_seconds()
    _need(delta >= 0, "capture_in_future_relative_to_as_of")
    _need(delta <= MAX_AGE_SECONDS, "capture_stale_relative_to_as_of")
    _need(type(raw_receipt) is bytes and len(raw_receipt) <= MAX_RECEIPT_BYTES,
          "receipt_raw_invalid")
    _need(readback_matches(receipt, raw_receipt), "receipt_bytes_differ")
    support = _read_regular(support_path, MAX_SUPPORT_BYTES)
    _need(len(support) == receipt["support_bytes"], "support_size_mismatch")
    _need(digest(support) == receipt["support_sha256"], "support_digest_mismatch")
    result = {
        "schema": SCHEMA,
        "admission": "ACCEPTED_FOR_DOCUMENTARY_REVIEW",
        "record_id": receipt["record_id"],
        "session_id": receipt["session_id"],
        "service_id": receipt["service_id"],
        "case_id": receipt["case_id"],
        "source_kind": receipt["source_kind"],
        "method_id": receipt["method_id"],
        "captured_at_utc": receipt["captured_at_utc"],
        "review_as_of_utc": as_of_utc,
        "observed_claim_unverified": receipt["observed_claim"],
        "configuration_sha256_declared": receipt["configuration_sha256"],
        "support_sha256_verified": receipt["support_sha256"],
        "receipt_sha256": digest(raw_receipt),
        "provenance_independently_attested": False,
        "classification": "ND",
        "technical_truth_accredited": False,
        "confirmed_rf": None,
        "reason": "SUPPORT_INTEGRITY_ONLY_INDEPENDENT_REVIEW_PENDING",
    }
    result["sha256"] = digest(canonical(result))
    return result


def readback_matches(receipt: dict[str, Any], raw: bytes) -> bool:
    try:
        return json.loads(raw, object_pairs_hook=_pairs) == receipt
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False


def validate_admission(admission: dict[str, Any]) -> bool:
    """Defensa para consumidores: no aceptar un informe alterado o sobreacreditado."""
    _need(type(admission) is dict, "admission_not_dict")
    claimed = admission.get("sha256")
    _need(type(claimed) is str and HEX.fullmatch(claimed) is not None,
          "admission_hash_invalid")
    _need(digest(canonical({k: v for k, v in admission.items() if k != "sha256"}))
          == claimed, "admission_digest_mismatch")
    _need(admission.get("schema") == SCHEMA and
          admission.get("admission") == "ACCEPTED_FOR_DOCUMENTARY_REVIEW" and
          admission.get("session_id") == "DEV_TUTOR_001" and
          admission.get("service_id") == "SSH_DEV" and
          admission.get("case_id") == "CASE_REFERENCE" and
          admission.get("classification") == "ND" and
          admission.get("technical_truth_accredited") is False and
          admission.get("provenance_independently_attested") is False and
          admission.get("confirmed_rf") is None,
          "admission_unsupported_authority")
    return True


def validate_unique_observations(receipts: list[dict[str, Any]]) -> bool:
    """Guardia de lote: no confundir duplicado con evidencia nueva ni ignorar conflicto."""
    _need(type(receipts) is list and 0 < len(receipts) <= 16, "batch_size")
    ids: set[str] = set()
    facts: dict[tuple[str, str, str], str] = {}
    for rec in receipts:
        _need(type(rec) is dict and set(rec) == FIELDS, "receipt_schema")
        rid = rec["record_id"]
        _need(type(rid) is str and IDENT.fullmatch(rid) is not None, "record_id_invalid")
        _need(rid not in ids, "duplicate_record_id")
        ids.add(rid)
        key = (rec["service_id"], rec["case_id"], rec["method_id"])
        if key in facts and rec["observed_claim"] != facts[key]:
            raise DefensiveImportError("conflicting_observations_require_review")
        facts[key] = rec["observed_claim"]
    return True
