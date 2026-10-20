"""Contratos operacionales completos; ninguna validación ejecuta acciones."""

from datetime import datetime
import hashlib
import json
import re

from ardrec.messages_v1 import MessageError
from ardrec.transport import MAX_FRAME_BYTES

MAX_SUPPORTS = 1024
MAX_TIMEOUT_SECONDS = 86400
MAX_INTEGER = 2**63 - 1
IDENTITIES = (
    "record_id", "execution_id", "correlation_id", "decision_index", "scope",
    "service_scenario_id", "derived_case_id", "attempt_id", "versions", "simulation",
)
FIELDS = set(IDENTITIES) | {
    "schema_version", "message_type", "message_id", "created_at", "producer", "payload",
}
ERROR_CODES = {
    "schema_invalid", "version_incompatible", "identifier_mismatch", "duplicate_conflict",
    "out_of_scope", "catalog_mismatch", "message_too_large", "integrity_failure",
}
PRODUCERS = {
    "execution_request": {"analitico"}, "discovery_request": {"analitico"},
    "accepted_for_execution": {"tecnico"}, "execution_result": {"tecnico"},
    "discovery_result": {"tecnico"}, "attempt_status_request": {"analitico"},
    "attempt_status_result": {"tecnico"}, "supervision_event": {"supervision"},
    "message_rejection": {"analitico", "tecnico", "persistencia"},
    "closure_record": {"analitico"}, "persisted_state": {"persistencia"},
}


def check(condition, code="schema_invalid"):
    if not condition:
        raise MessageError(code)


def fields(value, names):
    check(type(value) is dict and value.keys() == set(names))


def enum(value, choices):
    check(type(value) is str and value in choices)


def identifier(value):
    check(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None)


def integer(value, low=0, high=MAX_INTEGER):
    check(type(value) is int and low <= value <= high)


def digest(value):
    check(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)


def timestamp(value):
    check(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value,
    ) is not None)
    try:
        # Validar la fecha antes de normalizar una medianoche 24:00.
        datetime(int(value[:4]), int(value[5:7]), int(value[8:10]))
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise MessageError() from error


def references(value, names):
    for name in names:
        identifier(value[name])


def information(items):
    check(type(items) is list and 1 <= len(items) <= 4)
    for item in items:
        enum(item, {"INICIO", "TERMINACION", "RESULTADO", "LIMPIEZA"})
    check(len(items) == len(set(items)))


def fact(value, choices, documented):
    fields(value, {"status", "reference"})
    enum(value["status"], choices)
    if value["status"] in documented:
        identifier(value["reference"])
    else:
        check(value["reference"] is None)


def snapshot(value):
    fields(value, {
        "phase", "start", "termination", "cleanup", "result", "reason_code",
        "observed_at", "journal_reference", "reconciliation_required", "new_execution_authorized",
    })
    enum(value["phase"], {"accepted", "running", "completed", "interrupted", "not_started", "uncertain"})
    timestamp(value["observed_at"])
    identifier(value["journal_reference"])
    fact(value["start"], {"VERIFICADO", "NO_INICIADO", "NO_ACREDITADO", "NO_DETERMINADO"},
         {"VERIFICADO", "NO_INICIADO"})
    fact(value["termination"], {"VERIFICADO", "EN_CURSO", "NO_APLICA", "NO_DETERMINADO"}, {"VERIFICADO"})
    fact(value["cleanup"], {"completed", "not_required", "pending", "failed", "unknown"},
         {"completed", "not_required", "failed"})
    fact(value["result"], {"DISPONIBLE", "PENDIENTE", "NO_DISPONIBLE"}, {"DISPONIBLE"})
    phase = value["phase"]
    start, end, cleanup, result = (value[k]["status"] for k in ("start", "termination", "cleanup", "result"))
    clean = cleanup in {"completed", "not_required"}
    if phase in {"accepted", "running", "completed"}:
        check(value["reason_code"] is None)
    else:
        enum(value["reason_code"], {
            "REQUEST_REJECTED", "SPAWN_FAILED", "TIMEOUT", "INTERRUPTED", "EXECUTOR_FAILURE",
            "CONNECTION_LOST", "STATUS_UNAVAILABLE", "CLEANUP_FAILED", "RESULT_UNAVAILABLE",
        })
    if phase == "accepted":
        check((start, end, cleanup, result) == ("NO_ACREDITADO", "NO_DETERMINADO", "pending", "PENDIENTE"))
    elif phase == "running":
        check((start, end, cleanup, result) == ("VERIFICADO", "EN_CURSO", "pending", "PENDIENTE"))
    elif phase in {"completed", "interrupted"}:
        check(start == end == "VERIFICADO" and result == "DISPONIBLE")
        if phase == "interrupted":
            enum(value["reason_code"], {"TIMEOUT", "INTERRUPTED", "EXECUTOR_FAILURE"})
    elif phase == "not_started":
        check((start, end, cleanup, result) == ("NO_INICIADO", "NO_APLICA", "not_required", "NO_DISPONIBLE"))
        enum(value["reason_code"], {"REQUEST_REJECTED", "SPAWN_FAILED"})
    else:
        enum(value["reason_code"], {
            "TIMEOUT", "EXECUTOR_FAILURE", "CONNECTION_LOST", "STATUS_UNAVAILABLE", "CLEANUP_FAILED", "RESULT_UNAVAILABLE",
        })
        enum(start, {"VERIFICADO", "NO_DETERMINADO"})
        enum(end, {"VERIFICADO", "NO_DETERMINADO"})
        check(result != "DISPONIBLE")
        if start == "NO_DETERMINADO":
            check(end == "NO_DETERMINADO" and cleanup in {"pending", "unknown"})
        if end == "NO_DETERMINADO":
            check(not clean)
        if value["reason_code"] == "TIMEOUT":
            check(start == "VERIFICADO")
        if value["reason_code"] == "CLEANUP_FAILED":
            check(cleanup == "failed")
    reconcile = phase in {"accepted", "running", "uncertain"} or not clean
    check(type(value["reconciliation_required"]) is bool and value["reconciliation_required"] == reconcile)
    # Ni una respuesta resuelta autoriza por sí sola un nuevo despacho.
    check(value["new_execution_authorized"] is False)


def outcome(value, state):
    fields(value, {
        "started_at", "ended_at", "exit_code", "signal", "timed_out", "duration_ms",
        "stdout_reference", "stderr_reference", "stdout_truncated", "stderr_truncated",
        "effective_parameters_reference", "supports",
    })
    for flag in ("timed_out", "stdout_truncated", "stderr_truncated"):
        check(type(value[flag]) is bool)
    for name in ("stdout_reference", "stderr_reference", "effective_parameters_reference"):
        if value[name] is not None:
            identifier(value[name])
    for stream in ("stdout", "stderr"):
        check(not value[stream + "_truncated"] or value[stream + "_reference"] is not None)
    check(type(value["supports"]) is list and len(value["supports"]) <= MAX_SUPPORTS)
    for reference in value["supports"]:
        identifier(reference)
    check(len(value["supports"]) == len(set(value["supports"])))
    if value["duration_ms"] is not None:
        integer(value["duration_ms"])
    if value["exit_code"] is not None:
        integer(value["exit_code"], 0, 2**31 - 1)
    if value["signal"] is not None:
        integer(value["signal"], 1, 64)
    check(value["exit_code"] is None or value["signal"] is None)
    started = state["start"]["status"] == "VERIFICADO"
    ended = state["termination"]["status"] == "VERIFICADO"
    if started:
        timestamp(value["started_at"])
        identifier(value["effective_parameters_reference"])
    else:
        check(all(value[n] is None for n in (
            "started_at", "duration_ms", "stdout_reference", "stderr_reference", "effective_parameters_reference",
        )))
        check(not value["supports"] and not value["timed_out"])
    if ended:
        check(started and timestamp(value["ended_at"]) >= timestamp(value["started_at"]))
    else:
        check(value["ended_at"] is None and value["exit_code"] is None and value["signal"] is None)
    phase = state["phase"]
    if phase in {"completed", "interrupted"}:
        integer(value["duration_ms"])
        check((value["exit_code"] is None) != (value["signal"] is None))
    if phase == "completed":
        check(not value["timed_out"] and value["signal"] is None)
        references(value, ("stdout_reference", "stderr_reference"))
    if value["timed_out"]:
        check(started and state["reason_code"] == "TIMEOUT")
    if state["reason_code"] == "TIMEOUT":
        check(value["timed_out"])
    if phase in {"uncertain", "not_started"}:
        check(not value["supports"])


def validate_message(message):
    fields(message, FIELDS)
    check(message["schema_version"] == "2.0", "version_incompatible")
    enum(message["message_type"], PRODUCERS)
    kind = message["message_type"]
    enum(message["producer"], PRODUCERS[kind])
    references(message, ("message_id", "record_id", "execution_id", "correlation_id"))
    integer(message["decision_index"])
    timestamp(message["created_at"])
    check(type(message["simulation"]) is bool)
    fields(message["versions"], {"reference", "sha256"})
    identifier(message["versions"]["reference"])
    digest(message["versions"]["sha256"])
    scope = message["scope"]
    enum(scope, {"attempt", "discovery", "service", "observation"})
    for key, required in {
        "service_scenario_id": scope != "observation",
        "derived_case_id": scope == "attempt",
        "attempt_id": scope in {"attempt", "discovery"},
    }.items():
        if required:
            identifier(message[key])
        else:
            check(message[key] is None)
    scopes = {
        "execution_request": {"attempt"}, "execution_result": {"attempt"},
        "discovery_request": {"discovery"}, "discovery_result": {"discovery"},
        "accepted_for_execution": {"attempt", "discovery"},
        "attempt_status_request": {"attempt", "discovery"},
        "attempt_status_result": {"attempt", "discovery"},
        "supervision_event": {"service", "observation"},
        "closure_record": {"observation"}, "persisted_state": {"observation"},
        "message_rejection": {"attempt", "discovery", "service", "observation"},
    }
    check(scope in scopes[kind])
    p = message["payload"]
    if kind in {"execution_request", "discovery_request"}:
        refs = ("host_reference", "authorization_reference", "scope_reference", "profile_reference", "parameters_reference")
        fields(p, {*refs, "authentication", "protocol", "port", "limits"})
        references(p, refs)
        enum(p["protocol"], {"ssh", "ftp", "smb"})
        integer(p["port"], 1, 65535)
        auth = p["authentication"]
        check(type(auth) is dict and type(auth.get("mode")) is str)
        enum(auth["mode"], {"none", "referenced"})
        fields(auth, {"mode"} if auth["mode"] == "none" else {"mode", "credential_reference"})
        if auth["mode"] == "referenced":
            identifier(auth["credential_reference"])
        limits = p["limits"]
        fields(limits, {"timeout_seconds", "stdout_max_bytes", "stderr_max_bytes", "artifact_max_bytes", "max_supports"})
        integer(limits["timeout_seconds"], 1, MAX_TIMEOUT_SECONDS)
        for name in ("stdout_max_bytes", "stderr_max_bytes", "artifact_max_bytes"):
            integer(limits[name], 1)
        integer(limits["max_supports"], 0, MAX_SUPPORTS)
    elif kind == "attempt_status_request":
        fields(p, {"request_reference", "requested_information"})
        identifier(p["request_reference"])
        information(p["requested_information"])
    elif kind in {"accepted_for_execution", "attempt_status_result", "execution_result", "discovery_result"}:
        extra = ({"query_reference", "requested_information"} if kind == "attempt_status_result" else
                 {"outcome", "characterization_reference"} if kind == "discovery_result" else
                 {"outcome"} if kind == "execution_result" else set())
        fields(p, {"request_reference", "snapshot"} | extra)
        identifier(p["request_reference"])
        snapshot(p["snapshot"])
        check(timestamp(p["snapshot"]["observed_at"]) <= timestamp(message["created_at"]))
        phase = p["snapshot"]["phase"]
        if kind == "accepted_for_execution":
            check(phase == "accepted")
        elif kind == "attempt_status_result":
            identifier(p["query_reference"])
            information(p["requested_information"])
        else:
            check(phase in {"completed", "interrupted", "uncertain", "not_started"})
            outcome(p["outcome"], p["snapshot"])
            if p["outcome"]["started_at"] is not None:
                check(timestamp(p["outcome"]["started_at"]) <= timestamp(p["snapshot"]["observed_at"]))
            if p["outcome"]["ended_at"] is not None:
                check(timestamp(p["outcome"]["ended_at"]) <= timestamp(p["snapshot"]["observed_at"]))
            if phase in {"completed", "interrupted"}:
                check(p["snapshot"]["result"]["reference"] == message["message_id"], "identifier_mismatch")
            if kind == "discovery_result":
                if phase == "completed":
                    identifier(p["characterization_reference"])
                else:
                    check(p["characterization_reference"] is None)
    elif kind == "message_rejection":
        fields(p, {"rejected_message_id", "rejected_message_type", "rejected_sha256", "error_code", "reason_reference"})
        references(p, ("rejected_message_id", "reason_reference"))
        if p["rejected_message_type"] is not None:
            identifier(p["rejected_message_type"])
            check(p["rejected_message_type"] != "message_rejection")
        digest(p["rejected_sha256"])
        enum(p["error_code"], ERROR_CODES)
    elif kind == "supervision_event":
        fields(p, {"action", "actor_reference", "authorization_reference", "instruction_reference", "reason_reference"})
        enum(p["action"], {"record_control", "request_pause", "request_stop", "request_resume"})
        references(p, ("actor_reference", "authorization_reference", "instruction_reference", "reason_reference"))
    else:
        base = {"generation", "state_reference", "state_sha256"}
        extra = ({"report_reference", "reason_reference"} if kind == "closure_record" else
                 {"request_reference", "pointer_reference", "publication_reference", "status"})
        fields(p, base | extra)
        integer(p["generation"])
        check(p["generation"] == message["decision_index"], "identifier_mismatch")
        identifier(p["state_reference"])
        digest(p["state_sha256"])
        if kind == "closure_record":
            references(p, ("report_reference", "reason_reference"))
        else:
            references(p, ("request_reference", "pointer_reference", "publication_reference"))
            check(p["status"] == "PUBLISHED")


def canonical(message):
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    check(len(raw) <= MAX_FRAME_BYTES, "message_too_large")
    return raw


def correlate(request, related):
    """Asociar mensajes válidos sin acreditar sus referencias externas."""
    validate_message(request)
    validate_message(related)
    check(request["message_id"] != related["message_id"], "identifier_mismatch")
    for key in IDENTITIES:
        check(request[key] == related[key], "identifier_mismatch")
    p = related["payload"]
    if related["message_type"] == "message_rejection":
        recipient = {
            "execution_request": "tecnico", "discovery_request": "tecnico", "attempt_status_request": "tecnico",
            "accepted_for_execution": "analitico", "execution_result": "analitico", "discovery_result": "analitico",
            "attempt_status_result": "analitico", "supervision_event": "analitico", "persisted_state": "analitico",
            "closure_record": "persistencia",
        }
        check(request["message_type"] != "message_rejection")
        check(related["producer"] == recipient[request["message_type"]])
        check(p["rejected_message_id"] == request["message_id"]
              and p["rejected_message_type"] == request["message_type"], "identifier_mismatch")
        check(p["rejected_sha256"] == hashlib.sha256(canonical(request)).hexdigest(), "integrity_failure")
        return
    pairs = {
        "execution_request": {"accepted_for_execution", "attempt_status_request", "attempt_status_result", "execution_result"},
        "discovery_request": {"accepted_for_execution", "attempt_status_request", "attempt_status_result", "discovery_result"},
        "attempt_status_request": {"attempt_status_result"}, "closure_record": {"persisted_state"},
    }
    check(related["message_type"] in pairs.get(request["message_type"], set()))
    if request["message_type"] == "attempt_status_request":
        check(p["query_reference"] == request["message_id"]
              and p["request_reference"] == request["payload"]["request_reference"], "identifier_mismatch")
        check(set(p["requested_information"]) == set(request["payload"]["requested_information"]), "identifier_mismatch")
    else:
        check(p["request_reference"] == request["message_id"], "identifier_mismatch")
    if request["message_type"] == "closure_record":
        for key in ("generation", "state_reference", "state_sha256"):
            check(p[key] == request["payload"][key], "identifier_mismatch")
    if related["message_type"] in {"execution_result", "discovery_result"}:
        check(len(p["outcome"]["supports"]) <= request["payload"]["limits"]["max_supports"])


def correlate_status(request, query, response):
    """Vincular la consulta y su respuesta con la solicitud original."""
    check(query.get("message_type") == "attempt_status_request" if type(query) is dict else False)
    correlate(request, query)
    correlate(request, response)
    correlate(query, response)


def compare_delivery(previous, incoming):
    """Detectar conflictos entre dos registros; no sustituye al diario durable."""
    validate_message(previous)
    validate_message(incoming)
    if previous["message_id"] == incoming["message_id"]:
        check(canonical(previous) == canonical(incoming), "duplicate_conflict")
        return "REPLAY"
    requests = {"execution_request", "discovery_request"}
    if previous["message_type"] in requests and incoming["message_type"] in requests:
        check(previous["attempt_id"] != incoming["attempt_id"], "duplicate_conflict")
    return "NEW"
