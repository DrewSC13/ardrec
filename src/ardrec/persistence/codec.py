"""Codificación cerrada y exacta de los modelos persistidos, sin pickle."""

import base64
from dataclasses import fields
from enum import Enum
import hashlib
import json

from ardrec import state as model

MAX_OBJECT_BYTES = 16 * 1024 * 1024
CLASSES = {cls.__name__: cls for cls in (
    model.GuardFact, model.ClosureCriteria, model.TransitionContext,
    model.TransitionRecord, model.ServiceState, model.ConfirmedState,
    model.Report, model.Incorporation, model.AttemptState, model.GlobalState,
)}
ENUMS = {cls.__name__: cls for cls in (
    model.ServicePhase, model.AttemptPhase, model.InvocationPhase,
    model.Truth, model.Transition,
)}


class StorageError(ValueError):
    """Error cerrado: el llamador debe conservar los archivos y revisar la autoridad."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"Persistencia rechazada: {code}")


def require(condition, code):
    if not condition:
        raise StorageError(code)


def exact_fields(value, names):
    require(type(value) is dict and set(value) == set(names), "fields_invalid")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    try:
        result = json.dumps(value, ensure_ascii=True, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise StorageError("encoding_invalid") from error
    require(len(result) <= MAX_OBJECT_BYTES, "object_too_large")
    return result


def parse(raw):
    require(type(raw) is bytes and len(raw) <= MAX_OBJECT_BYTES, "object_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_key")
            result[key] = value
        return result

    def reject(value):
        raise StorageError("noninteger_number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        require(canonical(value) == raw, "noncanonical_object")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, StorageError):
            raise
        raise StorageError("json_invalid") from error


def pack(value):
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        require(-(2**63) <= value < 2**63, "integer_range")
        return value
    if type(value) is bytes:
        return {"@": "bytes", "value": base64.b64encode(value).decode("ascii")}
    if type(value) is tuple:
        return {"@": "tuple", "value": [pack(item) for item in value]}
    if type(value) in ENUMS.values():
        return {"@": type(value).__name__, "value": value.value}
    if type(value) in CLASSES.values():
        return {"@": type(value).__name__, "fields": {
            field.name: pack(getattr(value, field.name)) for field in fields(value)}}
    if type(value) is dict:
        require(all(type(key) is str and key != "@" for key in value), "map_invalid")
        return {key: pack(item) for key, item in value.items()}
    raise StorageError("type_unsupported")


def unpack(value):
    try:
        return _unpack(value)
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        if isinstance(error, StorageError):
            raise
        raise StorageError("model_invalid") from error


def _unpack(value):
    if value is None or type(value) in (str, bool):
        return value
    if type(value) is int:
        require(-(2**63) <= value < 2**63, "integer_range")
        return value
    require(type(value) is dict, "type_unsupported")
    if "@" not in value:
        return {key: _unpack(item) for key, item in value.items()}
    kind = value["@"]
    require(type(kind) is str, "type_unsupported")
    if kind in CLASSES:
        exact_fields(value, ("@", "fields"))
        cls = CLASSES[kind]
        exact_fields(value["fields"], (field.name for field in fields(cls)))
        return cls(**{key: _unpack(item) for key, item in value["fields"].items()})
    exact_fields(value, ("@", "value"))
    if kind == "tuple":
        require(type(value["value"]) is list, "tuple_invalid")
        return tuple(_unpack(item) for item in value["value"])
    if kind == "bytes":
        require(type(value["value"]) is str, "bytes_invalid")
        raw = base64.b64decode(value["value"], validate=True)
        require(base64.b64encode(raw).decode("ascii") == value["value"], "bytes_invalid")
        return raw
    require(kind in ENUMS and type(value["value"]) is str, "type_unsupported")
    return ENUMS[kind](value["value"])
