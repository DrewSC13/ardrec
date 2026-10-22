"""Consultas durables y conciliación estructural, sin ejecutar herramientas."""

from copy import deepcopy
from dataclasses import dataclass
import hashlib

from ardrec.messages import correlate, correlate_status, decode_message, encode_message
from ardrec.messages_v2 import timestamp
from ardrec.state import InvocationPhase, Truth, mark_uncertain, record_report

QUERY = "reconcile_query_v1"
REPLY = "reconcile_reply_v1"
INFORMATION = ("INICIO", "TERMINACION", "RESULTADO", "LIMPIEZA")
FAILURES = frozenset({"TIMEOUT", "CONNECTION_LOST", "ABANDONED", "INVALID_RESPONSE"})
MAX_QUERIES = 1000


class ReconciliationError(ValueError):
    """Consulta incompatible, agotada o asociada con otro intento."""

    def __init__(self, code):
        self.code = code
        super().__init__(f"Conciliación rechazada: {code}")


def _need(condition, code):
    if not condition:
        raise ReconciliationError(code)


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names), "fields_invalid")


def _raw(value):
    message = decode_message(value)
    _need(message["schema_version"] == "2.0", "version_incompatible")
    _need(encode_message(message) == value, "noncanonical_record")
    return message


def _attempt(state, query):
    _need(state.authority is Truth.VERDADERO, "authority_unverified")
    _need(state.invocation is InvocationPhase.EN_CURSO, "invocation_terminal")
    attempts = [a for a in state.attempts if a.pending]
    _need(len(attempts) == 1, "pending_attempt_required")
    attempt = attempts[0]
    _need(query["message_type"] == "attempt_status_request", "query_required")
    correlate(attempt.identity, query)
    _need(tuple(query["payload"]["requested_information"]) == INFORMATION, "information_incomplete")
    _need(timestamp(query["created_at"]) >= timestamp(attempt.identity["created_at"]), "query_too_old")
    return attempt


def _reason(query, kind):
    # La referencia conserva una longitud acotada aunque el identificador sea largo.
    token = hashlib.sha256(encode_message(query)).hexdigest()
    return f"RECON-{kind}-{token}"


def _messages(state):
    for attempt in state.attempts:
        yield attempt.request
        for report in attempt.reports:
            yield report.message
            if report.query is not None:
                yield report.query


def advance_index(index, state, operation, args):
    """Reconstruir el presupuesto y la consulta abierta desde el diario autorizado."""
    opened = [entry for entry in index.values() if entry["reply"] is None]
    if operation not in {QUERY, REPLY}:
        _need(not opened or operation in {"uncertain", "finish"}, "query_incomplete")
        return index
    if operation == QUERY:
        _fields(args, ("query", "limit"))
        query = _raw(args["query"])
        _attempt(state, query)
        limit = args["limit"]
        _need(type(limit) is int and 1 <= limit <= MAX_QUERIES, "query_limit_invalid")
        _need(not opened, "query_incomplete")
        key = query["message_id"]
        _need(key not in index and all(_raw(raw)["message_id"] != key for raw in _messages(state)),
              "query_identifier_reused")
        for entry in index.values():
            if entry["reply"] is not None:
                for field in ("response", "result"):
                    raw = entry["reply"][field]
                    _need(raw is None or _raw(raw)["message_id"] != key, "query_identifier_reused")
        related = [entry for entry in index.values()
                   if _raw(entry["query"])["attempt_id"] == query["attempt_id"]]
        _need(all(entry["limit"] == limit for entry in related), "query_limit_changed")
        _need(len(related) < limit, "query_budget_exhausted")
        # Todas las consultas conservan su turno, incluso si el proceso muere sin enviarlas.
        return {**index, key: {"query": args["query"], "limit": limit, "reply": None}}
    _fields(args, ("query", "response", "result", "failure"))
    query = _raw(args["query"])
    key = query["message_id"]
    _need(key in index and index[key]["query"] == args["query"], "query_not_recorded")
    previous = index[key]["reply"]
    if previous is not None:
        _need(previous == args, "reply_conflict")
        return index
    _need(len(opened) == 1, "query_incomplete")
    # La identidad de un resultado queda ligada a sus bytes, también fuera del modelo de estados.
    known = {_raw(raw)["message_id"]: raw for raw in _messages(state)}
    for entry in index.values():
        known[_raw(entry["query"])["message_id"]] = entry["query"]
        if entry["reply"] is not None:
            for field in ("response", "result"):
                raw = entry["reply"][field]
                if raw is not None:
                    known[_raw(raw)["message_id"]] = raw
    for field in ("response", "result"):
        raw = args[field]
        if raw is not None:
            key_message = _raw(raw)["message_id"]
            _need(key_message not in known or known[key_message] == raw, "message_identity_conflict")
            known[key_message] = raw
    return {**index, key: {**index[key], "reply": deepcopy(args)}}


def reduce_record(state, operation, args):
    """Revalidar los mensajes antes de escribir y durante cada recuperación."""
    query = _raw(args["query"])
    attempt = _attempt(state, query)
    attempt_id = query["attempt_id"]
    if operation == QUERY:
        return mark_uncertain(state, attempt_id, _reason(query, "OPEN"))
    _need(operation == REPLY, "operation_unknown")
    failure = args["failure"]
    if failure is not None:
        _need(type(failure) is str and failure in FAILURES, "failure_invalid")
        _need(args["response"] is None and args["result"] is None, "failure_with_response")
        return mark_uncertain(state, attempt_id, _reason(query, failure))
    response = _raw(args["response"])
    if response["message_type"] == "message_rejection":
        correlate(query, response)
        _need(args["result"] is None, "unexpected_result")
        _need(timestamp(response["created_at"]) >= timestamp(query["created_at"]), "reply_too_old")
        return mark_uncertain(state, attempt_id, _reason(query, "REJECTED"))
    correlate_status(attempt.identity, query, response)
    snapshot = response["payload"]["snapshot"]
    result = None if args["result"] is None else _raw(args["result"])
    if result is not None:
        correlate(attempt.identity, result)
        expected = "discovery_result" if query["scope"] == "discovery" else "execution_result"
        _need(result["message_type"] == expected, "result_type_invalid")
        original = result["payload"]["snapshot"]
        _need(snapshot["phase"] in {"completed", "interrupted"}
              and original["phase"] == snapshot["phase"], "result_phase_mismatch")
        _need(original["reason_code"] == snapshot["reason_code"], "result_reason_mismatch")
        _need(result["message_id"] == snapshot["result"]["reference"], "result_reference_mismatch")
        _need(original["journal_reference"] == snapshot["journal_reference"], "journal_mismatch")
        for field in ("start", "termination", "result"):
            _need(original[field] == snapshot[field], "result_fact_mismatch")
        if original["cleanup"]["status"] in {"completed", "not_required"}:
            _need(original["cleanup"] == snapshot["cleanup"], "result_fact_mismatch")
        _need(timestamp(attempt.identity["created_at"]) <= timestamp(original["observed_at"])
              <= timestamp(snapshot["observed_at"]), "result_time_mismatch")
        _need(timestamp(result["created_at"]) <= timestamp(response["created_at"]), "result_time_mismatch")
    # El resultado puede ser anterior a la consulta; se conserva íntegro en este mismo registro.
    updated = record_report(state, attempt_id, response, query=query)
    if snapshot["phase"] in {"completed", "interrupted"} and result is None:
        updated = mark_uncertain(updated, attempt_id, _reason(query, "RESULT-MISSING"))
    return updated


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    action: str
    attempt_id: str | None
    queries_used: int
    query_limit: int | None
    open_query: bytes | None
    result: bytes | None
    new_execution_authorized: bool = False


def inspect_recovery(store):
    """Describir el siguiente paso sin modificar el almacén ni autorizar un despacho."""
    state = store.state
    pending = [a for a in state.attempts if a.pending]
    attempt = pending[0] if pending else None
    aid = None if attempt is None else attempt.identity["attempt_id"]
    entries = [e for e in store.reconciliation_history if _raw(e["query"])["attempt_id"] == aid]
    limit = entries[0]["limit"] if entries else None
    opened = next((e["query"] for e in entries if e["reply"] is None), None)
    result = None
    if attempt is not None and attempt.snapshot is not None:
        reference = attempt.snapshot["result"]["reference"]
        for report in attempt.reports:
            message = _raw(report.message)
            if message["message_type"] in {"execution_result", "discovery_result"} and message["message_id"] == reference:
                result = report.message
        for entry in entries:
            reply = entry["reply"]
            if reply is not None and reply["result"] is not None:
                if _raw(reply["result"])["message_id"] == reference:
                    result = reply["result"]
    if state.invocation is not InvocationPhase.EN_CURSO:
        action = "INVOCATION_ENDED"
    elif opened is not None:
        action = "QUERY_INCOMPLETE"
    elif attempt is None:
        action = store.recovery_action
    elif attempt.technical_resolved and (attempt.snapshot["phase"] == "not_started" or result is not None):
        action = "READY_FOR_VALIDATION"
    elif limit is not None and len(entries) >= limit:
        action = "BUDGET_EXHAUSTED"
    elif attempt.snapshot is not None and attempt.snapshot["phase"] in {"completed", "interrupted"} and result is None:
        action = "RESULT_REQUIRED"
    else:
        action = "QUERY_REQUIRED"
    return RecoveryDecision(action, aid, len(entries), limit, opened, result)


def begin_query(store, *, message_id, created_at, limit=3):
    """Consumir un turno durable antes de devolver una consulta lista para transporte."""
    decision = inspect_recovery(store)
    _need(decision.action in {"QUERY_REQUIRED", "RESULT_REQUIRED"}, "query_not_available")
    attempt = next(a for a in store.state.attempts if a.pending)
    query = attempt.identity
    query.update(message_type="attempt_status_request", message_id=message_id,
                 created_at=created_at, producer="analitico", payload={
                     "request_reference": attempt.identity["message_id"],
                     "requested_information": list(INFORMATION),
                 })
    raw = encode_message(query)
    store.record_reconciliation(QUERY, {"query": raw, "limit": limit})
    return raw


def complete_query(store, query, response, *, result=None):
    """Publicar consulta, respuesta y resultado correlacionado como una sola operación."""
    args = {"query": encode_message(decode_message(query)),
            "response": encode_message(decode_message(response)),
            "result": None if result is None else encode_message(decode_message(result)), "failure": None}
    store.record_reconciliation(REPLY, args)
    return inspect_recovery(store)


def fail_query(store, query, *, failure):
    """Cerrar una consulta fallida conservando la reserva y los hechos del intento."""
    args = {"query": encode_message(decode_message(query)), "response": None, "result": None, "failure": failure}
    store.record_reconciliation(REPLY, args)
    return inspect_recovery(store)
