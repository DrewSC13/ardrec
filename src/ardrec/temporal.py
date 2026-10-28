"""Admisión temporal-v1 separada de la lectura histórica de mensajes y diarios."""
import os
import time
from ardrec.messages import MessageError, correlate, decode_message
from ardrec.messages_v2 import timestamp

POLICY = 'temporal-v1'


def correlate_current(request, related):
    """Comprobar límites UTC necesarios; no prueba hechos ni autoriza ejecución."""
    correlate(request, related)
    if request['schema_version'] != '2.0':
        raise MessageError('version_incompatible')
    origin = timestamp(request['created_at'])
    if timestamp(related['created_at']) < origin:
        raise MessageError('temporal_inversion')
    if request['message_type'] in {'execution_request', 'discovery_request'}:
        payload = related['payload']
        if 'snapshot' in payload and timestamp(payload['snapshot']['observed_at']) < origin:
            raise MessageError('temporal_inversion')
        if 'outcome' in payload:
            for name in ('started_at', 'ended_at'):
                value = payload['outcome'][name]
                if value is not None and timestamp(value) < origin:
                    raise MessageError('temporal_inversion')


def audit_current(state, queries):
    """Auditar antes de escribir; la recuperación histórica no usa esta política."""
    requests = {a.identity['attempt_id']: a.identity for a in state.attempts}
    for attempt in state.attempts:
        for report in attempt.reports:
            message = decode_message(report.message)
            correlate_current(attempt.identity, message)
            if report.query is not None:
                query = decode_message(report.query)
                correlate_current(attempt.identity, query)
                correlate_current(query, message)
    for entry in queries.values():
        query = decode_message(entry['query'])
        request = requests[query['attempt_id']]
        correlate_current(request, query)
        reply = entry['reply']
        if reply is not None:
            if reply['response'] is not None:
                response = decode_message(reply['response'])
                correlate_current(query, response)
                if response['message_type'] != 'message_rejection':
                    correlate_current(request, response)
            if reply['result'] is not None:
                correlate_current(request, decode_message(reply['result']))


class MonotonicTimer:
    """Duración de proceso: origen no persistible ni transferible tras fork.

    Su uso en el supervisor real y la exclusión de suspensión del host requieren
    validación del laboratorio. No reconstruye intervalos desde fechas UTC.
    """
    __slots__ = ('_pid', '_start')

    def __init__(self):
        self._pid = os.getpid()
        self._start = time.monotonic_ns()

    def elapsed_ms(self):
        if os.getpid() != self._pid:
            raise ValueError('clock_origin_changed')
        elapsed = time.monotonic_ns() - self._start
        if elapsed < 0:
            raise ValueError('monotonic_regression')
        result = elapsed // 1_000_000
        if result > 2**63 - 1:
            raise ValueError('duration_overflow')
        return result

    def __reduce_ex__(self, protocol):
        raise TypeError('monotonic_timer_not_persistable')
