"""Entrada pública del protocolo con selección explícita de versión."""

import json

from ardrec import messages_v1, messages_v2
from ardrec.messages_v1 import MessageError
from ardrec.transport import MAX_FRAME_BYTES


def _implementation(message):
    if type(message) is not dict:
        raise MessageError()
    if "schema_version" not in message:
        raise MessageError()
    version = message["schema_version"]
    if type(version) is not str or version not in {"1.0", "2.0"}:
        raise MessageError("version_incompatible")
    return messages_v1 if version == "1.0" else messages_v2


def validate_message(message):
    """Validar sin convertir ni degradar silenciosamente una versión."""
    _implementation(message).validate_message(message)


def encode_message(message):
    """Producir una representación determinista después de validar."""
    validate_message(message)
    return messages_v2.canonical(message)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise MessageError()
        result[key] = value
    return result


def _reject_number(token):
    raise MessageError()


def decode_message(raw):
    """Rechazar tramas grandes, claves repetidas y números aproximados."""
    if type(raw) is not bytes:
        raise MessageError()
    if len(raw) > MAX_FRAME_BYTES:
        raise MessageError("message_too_large")
    try:
        message = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                             parse_float=_reject_number, parse_constant=_reject_number)
        validate_message(message)
        return message
    except MessageError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise MessageError() from error


def correlate(request, related):
    """Rechazar asociaciones entre versiones diferentes."""
    validate_message(request)
    validate_message(related)
    if request["schema_version"] != related["schema_version"]:
        raise MessageError("version_incompatible")
    _implementation(request).correlate(request, related)


def correlate_status(request, query, response):
    """Comprobar la correlación triple del perfil 2.0."""
    messages_v2.correlate_status(request, query, response)


def compare_delivery(previous, incoming):
    """Comparar dos registros 2.0 sin escribir ni reenviar mensajes."""
    return messages_v2.compare_delivery(previous, incoming)
