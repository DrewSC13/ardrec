"""Perfil inicial de mensajes operacionales; validar no autoriza la ejecución."""

from datetime import datetime
import json
import re

from ardrec.transport import MAX_FRAME_BYTES

IDENTITIES = (
    "record_id", "execution_id", "correlation_id", "service_scenario_id",
    "derived_case_id", "attempt_id",
)
FIELDS = set(IDENTITIES) | {
    "schema_version", "message_type", "message_id", "decision_index",
    "created_at", "producer", "versions", "payload",
}
PRODUCERS = {
    "execution_request": "analitico",
    "accepted_for_execution": "tecnico",
    "attempt_status_request": "analitico",
    "execution_result": "tecnico",
}


class MessageError(ValueError):
    """Rechazo con código estable para la capa que gestione el protocolo."""

    def __init__(self, code="schema_invalid"):
        self.code = code
        super().__init__(f"Mensaje rechazado: {code}")


def _check(condition, code="schema_invalid"):
    if not condition:
        raise MessageError(code)


def _fields(value, fields):
    _check(type(value) is dict and value.keys() == set(fields))


def _identifier(value):
    _check(type(value) is str and
           re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)


def _integer(value, minimum=0, maximum=2**63 - 1):
    # Los booleanos no se aceptan como índices, puertos ni duraciones.
    _check(type(value) is int and minimum <= value <= maximum)


def _references(payload, names):
    for name in names:
        _identifier(payload[name])


def validate_message(message):
    """Validar estructura e identidades internas sin consultar soportes externos."""
    _fields(message, FIELDS)
    _check(message["schema_version"] == "1.0", "version_incompatible")
    kind = message["message_type"]
    _check(type(kind) is str and kind in PRODUCERS)
    _check(message["producer"] == PRODUCERS[kind])
    _references(message, (*IDENTITIES, "message_id"))
    _integer(message["decision_index"])
    _fields(message["versions"], {"reference"})
    _identifier(message["versions"]["reference"])

    stamp = message["created_at"]
    _check(type(stamp) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", stamp,
        flags=re.ASCII,
    ) is not None)
    try:
        # Validar la fecha antes de normalizar una medianoche 24:00.
        datetime(int(stamp[:4]), int(stamp[5:7]), int(stamp[8:10]))
        datetime.fromisoformat(stamp)
    except ValueError as error:
        raise MessageError() from error

    p = message["payload"]
    if kind == "execution_request":
        refs = ("host_reference", "credential_reference", "case_reference",
                "authorization_reference", "parameters_reference")
        _fields(p, {*refs, "protocol", "port", "timeout_seconds", "simulation"})
        _references(p, refs)
        _check(type(p["protocol"]) is str and p["protocol"] in {"ssh", "ftp", "smb"})
        _integer(p["port"], 1, 65535)
        _integer(p["timeout_seconds"], 1, 86400)
        _check(type(p["simulation"]) is bool)
        _check(p["case_reference"] == message["derived_case_id"], "identifier_mismatch")

    elif kind == "accepted_for_execution":
        _fields(p, {"request_reference", "attempt_id", "acceptance_status",
                    "start_status", "journal_reference"})
        _references(p, ("request_reference", "attempt_id", "journal_reference"))
        # Aceptar una solicitud no acredita que el proceso haya comenzado.
        _check(p["acceptance_status"] == "ACEPTADA" and p["start_status"] == "NO_ACREDITADO")
        _check(p["attempt_id"] == message["attempt_id"], "identifier_mismatch")

    elif kind == "attempt_status_request":
        _fields(p, {"attempt_id", "decision_reference", "requested_information"})
        _references(p, ("attempt_id", "decision_reference"))
        items = p["requested_information"]
        _check(type(items) is list and 1 <= len(items) <= 4)
        _check(all(type(item) is str for item in items))
        _check(len(set(items)) == len(items) and
               set(items) <= {"INICIO", "TERMINACION", "RESULTADO", "LIMPIEZA"})
        _check(p["attempt_id"] == message["attempt_id"] and
               p["decision_reference"] == message["correlation_id"], "identifier_mismatch")

    else:
        refs = ("request_reference", "start_reference", "termination_reference",
                "stdout_reference", "stderr_reference", "effective_parameters_reference")
        _fields(p, {*refs, "technical_status", "start_status", "exit_code", "timed_out",
                    "duration_ms", "supports", "cleanup", "simulation"})
        _references(p, refs)
        # Este primer perfil cubre únicamente el resultado terminado y limpiado.
        _check(p["technical_status"] == "completed" and p["start_status"] == "VERIFICADO")
        _check(p["timed_out"] is False and type(p["simulation"]) is bool)
        _integer(p["exit_code"], -(2**31), 2**31 - 1)
        _integer(p["duration_ms"])
        _fields(p["cleanup"], {"status", "reference"})
        _check(p["cleanup"]["status"] == "completed")
        _identifier(p["cleanup"]["reference"])
        _check(type(p["supports"]) is list and len(p["supports"]) <= 1024)
        for reference in p["supports"]:
            _identifier(reference)
        _check(len(set(p["supports"])) == len(p["supports"]))


def correlate(request, related):
    """Comprobar asociación; no iniciar, contabilizar ni repetir un intento."""
    # Se vuelve a validar porque los diccionarios recibidos son mutables.
    validate_message(request)
    validate_message(related)
    _check(request["message_type"] == "execution_request")
    kind = related["message_type"]
    _check(kind in {"accepted_for_execution", "attempt_status_request", "execution_result"})
    _check(request["message_id"] != related["message_id"], "identifier_mismatch")
    for key in (*IDENTITIES, "decision_index", "versions"):
        _check(request[key] == related[key], "identifier_mismatch")
    if kind != "attempt_status_request":
        _check(related["payload"]["request_reference"] == request["message_id"],
               "identifier_mismatch")
    if kind == "execution_result":
        _check(request["payload"]["simulation"] == related["payload"]["simulation"],
               "identifier_mismatch")


def _pairs(items):
    result = {}
    for key, value in items:
        _check(key not in result)
        result[key] = value
    return result


def _reject_number(token):
    raise MessageError()


def decode_message(raw):
    """Decodificar un documento UTF-8 completo y rechazar JSON ambiguo."""
    _check(type(raw) is bytes)
    _check(len(raw) <= MAX_FRAME_BYTES, "message_too_large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_float=_reject_number, parse_constant=_reject_number)
        validate_message(data)
        return data
    except MessageError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise MessageError() from error


def encode_message(message):
    """Validar antes de producir los bytes que se enviarán por el transporte."""
    validate_message(message)
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("utf-8")
    _check(len(raw) <= MAX_FRAME_BYTES, "message_too_large")
    return raw
