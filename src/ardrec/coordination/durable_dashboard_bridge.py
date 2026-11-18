"""R69.1: adaptador de la sesión DEV durable R69 al tablero existente R38.

No construye otra TUI ni transforma la inicialización A9 en una publicación
analítica posterior. El único modelo visible procede del recibo R69 recuperado.
"""
from __future__ import annotations

from typing import Any

from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.durable_dev import SCHEMA as R69_SCHEMA
from ardrec.persistence.codec import canonical, digest

VIEW_SCHEMA = 'ardrec-p14-r691-r69-durable-r38-view-v1'


class DurableViewError(ValueError):
    pass


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise DurableViewError(code)


def build_durable_dashboard(doc: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    """Proyecta datos *ya recuperados* al contrato de visualización R38.

    La fuente confiable es open_or_create_dev() (replay + recálculo A1). Esta
    función comprueba su consistencia interna, no otorga confianza externa.
    """
    fixture = normalize_scenario(scenario)
    _need(type(doc) is dict and doc.get('schema') == R69_SCHEMA,
          'invalid_r69_document')
    _need(type(doc.get('sha256')) is str and
          digest(canonical({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
          'r69_receipt_digest_mismatch')
    _need(doc.get('record_id') == fixture['session_id'] and
          doc.get('scope') == 'DEV_SYNTHETIC_DURABLE_INITIAL_GENERATION' and
          doc.get('source_kind') == 'SYNTHETIC_FIXTURE' and
          type(doc.get('generation')) is int and doc['generation'] == 0 and
          doc.get('a9_initialization_durable') is True and
          doc.get('a9_subsequent_publication_attested') is False and
          doc.get('store_recovery_action') == 'NONE', 'not_confirmed_initial_generation')
    _need(doc.get('p8_operational') == 'NO-GO' and
          doc.get('operational_dispatch') is False and
          doc.get('physical_observation_attested') is False and
          doc.get('a5_dispatch_performed') is False and
          doc.get('external_pin_authority_attested') is False and
          doc.get('a7_confirmed_rf') is None, 'unsupported_operational_claim')
    service_ids = {s['id'] for s in fixture['services']}
    _need(type(doc.get('a1_decisions')) is dict and
          set(doc['a1_decisions']) == service_ids and len(service_ids) == 3,
          'incomplete_a1_decisions')
    verified_decisions = {}
    r26_units = []
    for item in fixture['services']:
        sid = item['id']
        receipt = doc['a1_decisions'][sid]
        _need(type(receipt) is dict and type(receipt.get('r68')) is dict,
              'invalid_a1_receipt')
        r68 = receipt['r68']
        _need(receipt.get('r68_sha256') == digest(canonical(r68)) and
              r68.get('service_id') == sid and
              r68.get('record_id') == fixture['session_id'] and
              r68.get('generation') == 0 and
              r68.get('generation_reference') == doc['generation_reference'] and
              r68.get('confirmed_configuration_sha256') == doc['configuration_sha256'] and
              r68.get('rules_source_sha256') == doc['rules_sha256'] and
              r68.get('p8_operational') == 'NO-GO' and
              r68.get('published_generation') is None and
              r68.get('a9_publication_attested') is False and
              r68.get('operational_dispatch') is False,
              'a1_receipt_binding_invalid')
        _need(r68.get('status') in ('VERDADERO', 'FALSO', 'ND') and
              (r68.get('selected_rule') is None or type(r68['selected_rule']) is str) and
              (r68.get('declared_output') is None or type(r68['declared_output']) is str),
              'a1_decision_invalid')
        ctx = receipt.get('seven_field_context')
        _need(type(ctx) is dict and set(ctx) == {
            'estado', 'configuracion', 'origen', 'servicio', 'caso', 'condicion', 'contexto'
        }, 'a1_context_missing')
        verified_decisions[sid] = {
            'status': r68['status'], 'rule': r68['selected_rule'],
            'output': r68['declared_output'], 'r68_sha256': receipt['r68_sha256'],
            'context': ctx,
        }
        r26_units.append({
            'protocol': item['protocol'], 'service_id': sid,
            'a1': r68['status'], 'a2': 'PREPARADO',
            'a3': 'NO_EJECUTADO_EN_R69', 'initial_risk': item['initial_risk'],
        })

    stages = [
        ('R69_R68_CONFIRMED_GEN0', 'R69_RECOVERED', 'Decisiones A1 reproducidas desde la generación confirmada 0'),
        ('INITIALIZED_GEN0', 'R69_DURABLE', 'Configuración congelada y servicios PREPARADO'),
        ('NOT_EXECUTED_R69', 'NOT_EXECUTED', 'Guardas del ciclo completo pendientes de integración'),
        ('NOT_EXECUTED_R69', 'NOT_EXECUTED', 'No hay selección ni despacho técnico confirmado'),
        ('NOT_EXECUTED_R69', 'NOT_EXECUTED', 'No se ejecutó ninguna prueba física ni intento A5'),
        ('ND_NO_EVIDENCE', 'NOT_EXECUTED', 'No existe evidencia técnica acreditada'),
        ('RF_NOT_ACREDITED', 'NOT_EXECUTED', 'Riesgo final ND: sin actualización A7'),
        ('NOT_EXECUTED_R69', 'NOT_EXECUTED', 'La parada A8 aún no se aplicó en una generación posterior'),
        ('INITIAL_GEN0_ONLY', 'R69_DURABLE', 'Generación inicial 0 durable; no hay publicación analítica posterior'),
        ('R38_READ_ONLY_VIEW', 'R69_RECOVERED', 'Monitor R38 original alimentado por recibo R69 recuperado'),
    ]
    report = {
        'schema': VIEW_SCHEMA,
        'source_kind': 'SYNTHETIC_FIXTURE_R69_DURABLE_ONLY',
        'session_id': doc['record_id'],
        'session_sha256': doc['sha256'],
        'r26_units': r26_units,
        'r27': {'selected_actual': None, 'selected_hypothetical': None,
                'a5_state': None, 'a5_start_count': None, 'a6_classification': 'ND'},
        'a7': {'hypothetical_rf': 'ND', 'confirmed_rf': None},
        'a8': {'recommendation': 'NO_EJECUTADA_EN_R69', 'applied_transition': None},
        'a9': {'receipt_sha256': doc['sha256'], 'durable_local_receipt': True,
                'published_generation': None, 'technical_generation_published': False},
        'a10': {'stages': [dict(algorithm=f'A{i}', status=status, source=source, detail=detail)
                           for i, (status, source, detail) in enumerate(stages, 1)]},
        'r69_durable': {
            'generation': 0, 'generation_reference': doc['generation_reference'],
            'execution_id': doc['execution_id'],
            'configuration_sha256': doc['configuration_sha256'],
            'rules_sha256': doc['rules_sha256'],
            'store_head_sha256': doc['store_head_sha256'],
            'store_recovery_action': doc['store_recovery_action'],
            'receipt_sha256': doc['sha256'],
            'a9_initialization_durable': True,
            'a9_subsequent_publication_attested': False,
            'a1_decisions': verified_decisions,
        },
        'vm_checks_executed': False, 'p8_operational': 'NO-GO',
        'operational_dispatch': False, 'final_risk': None,
    }
    report['sha256'] = digest(canonical(report))
    from ardrec.coordination.dashboard_tui import validate_dashboard_report
    validate_dashboard_report(report)
    return report
