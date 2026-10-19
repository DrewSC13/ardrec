"""Contratos de magnitudes exactas."""

from dataclasses import dataclass
from fractions import Fraction
from math import gcd
import json
import re

MAX_INTEGER_BITS = 256
MAX_JSON_BYTES = 4096


class ContractError(ValueError):
    """Entrada fuera del contrato."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _keys(value: object, expected: set[str]) -> None:
    _require(type(value) is dict and value.keys() == expected,
             "Campos inválidos / Invalid fields")


def _integer(value: object) -> None:
    # bool hereda de int; por eso se exige el tipo exacto.
    _require(type(value) is int, "Se exige int exacto / Exact int required")
    _require(value.bit_length() <= MAX_INTEGER_BITS,
             "Entero demasiado grande / Integer too large")


@dataclass(frozen=True, slots=True)
class ND:
    """Magnitud no determinada con motivo."""

    reason_code: str

    def __post_init__(self) -> None:
        _require(type(self.reason_code) is str and
                 re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", self.reason_code) is not None,
                 "Motivo inválido / Invalid reason code")


def parse_rational(value: object) -> Fraction:
    """Validar sin corregir la entrada."""
    _keys(value, {"numerator", "denominator"})
    n, d = value["numerator"], value["denominator"]
    _integer(n)
    _integer(d)
    # Rechazar entradas no canónicas antes de que Fraction las normalice.
    _require(d > 0 and gcd(abs(n), d) == 1,
             "Racional no canónico / Noncanonical rational")
    return Fraction(n, d)


def dump_rational(value: Fraction) -> dict:
    """Exportar una fracción exacta."""
    _require(type(value) is Fraction, "Se exige Fraction / Fraction required")
    result = {"numerator": value.numerator, "denominator": value.denominator}
    parse_rational(result)
    return result


def parse_magnitude(value: object) -> Fraction | ND:
    """Validar la variante explícita."""
    _require(type(value) is dict, "Se exige objeto / Object required")
    if value.get("status") == "ND":
        _keys(value, {"status", "reason_code"})
        return ND(value["reason_code"])
    _keys(value, {"status", "value"})
    _require(value["status"] == "DETERMINADO", "Estado inválido / Invalid status")
    return parse_rational(value["value"])


def dump_magnitude(value: Fraction | ND) -> dict:
    """Conservar valor o indeterminación."""
    if type(value) is ND:
        return {"status": "ND", "reason_code": value.reason_code}
    return {"status": "DETERMINADO", "value": dump_rational(value)}


def _pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "Clave duplicada / Duplicate key")
        result[key] = value
    return result


def _reject_number(token: str) -> None:
    raise ContractError("Número JSON no permitido / JSON number not allowed")


def decode_magnitude(payload: bytes) -> Fraction | ND:
    """Leer una magnitud JSON UTF-8."""
    _require(type(payload) is bytes, "Se exigen bytes / Bytes required")
    _require(len(payload) <= MAX_JSON_BYTES,
             "Magnitud demasiado grande / Magnitude too large")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_float=_reject_number, parse_constant=_reject_number)
        return parse_magnitude(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ContractError("JSON de magnitud inválido / Invalid magnitude JSON") from error


def encode_magnitude(value: Fraction | ND) -> bytes:
    """Codificar de forma determinista."""
    return json.dumps(dump_magnitude(value), ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
