"""Contadores confirmados desde recibos durables; no habilita ni ejecuta casos."""
import hashlib

from ardrec.analytical_references import canonical, decode, need
from ardrec.state import GlobalState, Truth

FORMAT = 'ardrec-execution-counters-1'


def counter_payload(state, service_scenario_id):
    """Proyectar los intentos incorporados, no las reservas ni los mensajes recibidos.

    Solo casos derivados con algún recibo confirmado están presentes. Un caso ausente
    no tiene ejecuciones incorporadas representadas; esto no acredita disponibilidad,
    autorización, límites ni integridad de un catálogo externo. El llamador no obtiene
    autoridad por construir un GlobalState con authority=VERDADERO.
    """
    need(type(state) is GlobalState and not state.simulation
         and state.authority is Truth.VERDADERO, 'counter_state_unverified')
    need(type(service_scenario_id) is str and service_scenario_id in
         {s.service_scenario_id for s in state.confirmed.services}, 'counter_service_unknown')
    by_case = {}
    for attempt in state.attempts:
        request = attempt.identity
        receipt = attempt.incorporation
        if (receipt is None or request['scope'] != 'attempt'
                or request['service_scenario_id'] != service_scenario_id):
            continue
        status = attempt.snapshot['start']['status']
        need(status in ('VERIFICADO', 'NO_INICIADO'), 'counter_start_unresolved')
        by_case.setdefault(request['derived_case_id'], []).append({
            'attempt_id': request['attempt_id'],
            'event_reference': receipt.event_reference,
            'generation_index': receipt.generation,
            'start_status': status,
            'request_sha256': hashlib.sha256(attempt.request).hexdigest(),
            'report_sha256': hashlib.sha256(attempt.reports[-1].message).hexdigest(),
        })
    cases = []
    for case_id, receipts in sorted(by_case.items()):
        receipts.sort(key=lambda r: (r['generation_index'], r['attempt_id']))
        cases.append({'derived_case_id': case_id,
                      'confirmed_executions': sum(r['start_status'] == 'VERIFICADO' for r in receipts),
                      'receipts': receipts})
    result = {'format': FORMAT, 'cases': cases}
    canonical(result)  # Aplicar los límites de tamaño, profundidad y enteros del archivo.
    return result


def check_execution_counters(snapshot, state):
    """Comparación exacta tras resolver el archivo; no interpreta otras seis cargas.

    La publicación y recuperación llaman esta función sobre bytes resueltos por
    AnalyticalArchive. También se compara el conjunto de servicios para impedir
    omisiones. Ningún campo booleano declarado sustituye al recibo y al inicio.
    """
    wanted = {s.service_scenario_id for s in state.confirmed.services}
    found = set()
    for raw in snapshot.references.object_bytes:
        obj = decode(raw)
        if obj['role'] != 'execution_counters':
            continue
        sid = obj['service_scenario_id']
        need(sid in wanted and sid not in found, 'counter_service_scope_mismatch')
        found.add(sid)
        # Comparar bytes canónicos distingue 1 de True y rechaza campos extra,
        # versiones, orden de listas, casos o recibos duplicados y números falsos.
        expected = counter_payload(state, sid)
        need(canonical(obj['payload']) == canonical(expected), 'counter_payload_mismatch')
        need(all(r['generation_index'] <= obj['context']['generation_index']
                 for case in expected['cases'] for r in case['receipts']),
             'counter_receipt_after_object_origin')
    need(found == wanted, 'counter_service_scope_mismatch')
