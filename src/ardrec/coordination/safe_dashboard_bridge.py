"""R70: renderizar exclusivamente la generación DEV analítica recuperada en R38."""
from __future__ import annotations
from typing import Any
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.safe_generation import SCHEMA
from ardrec.persistence.codec import canonical, digest

VIEW_SCHEMA = 'ardrec-p14-r70-r38-safe-analytical-view-v1'

class SafeViewError(ValueError):
    pass


def _need(ok: bool, code: str):
    if not ok:
        raise SafeViewError(code)


def build_safe_dashboard(doc: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    fixture = normalize_scenario(scenario)
    _need(type(doc) is dict and doc.get('schema') == SCHEMA and
          doc.get('sha256') == digest(canonical({k:v for k,v in doc.items() if k != 'sha256'})),
          'safe_source_integrity_invalid')
    _need(doc.get('record_id') == fixture['session_id'] and
          doc.get('generation') == 1 and type(doc['generation']) is int and
          doc.get('scope') == 'STRUCTURAL_ANALYTICAL_PUBLICATION_ONLY' and
          doc.get('source_kind') == 'SYNTHETIC_DEV_STOP_WITHOUT_DISPATCH' and
          doc.get('analytical_validation') == 'structural_only' and
          doc.get('a3_guard') == 'NO_DISPATCH_AUTHORITY_IN_DEV' and
          doc.get('a4_selected') is None and doc.get('a5_attempt_count') == 0 and
          doc.get('a5_start_count') == 0 and doc.get('a6_classification') == 'ND' and
          doc.get('a7_confirmed_rf') is None and
          doc.get('a8_transition') == 'DETENER' and doc.get('a8_stop_cause') == 'CONTROL' and
          doc.get('a9_structural_generation_published') is True and
          doc.get('a9_technical_evidence_published') is False and
          doc.get('store_recovery_action') == 'NONE' and
          doc.get('physical_observation_attested') is False and
          doc.get('operational_dispatch') is False and doc.get('p8_operational') == 'NO-GO',
          'safe_source_authority_invalid')
    decisions = {}
    _need(type(doc.get('a1_decisions')) is dict and
          set(doc['a1_decisions']) == {s['id'] for s in fixture['services']},
          'incomplete_a1_sources')
    for item in fixture['services']:
        sid = item['id']; receipt = doc['a1_decisions'][sid]
        _need(type(receipt) is dict and type(receipt.get('r68')) is dict and
              digest(canonical(receipt['r68'])) == receipt.get('r68_sha256') and
              receipt['r68'].get('service_id') == sid and
              receipt['r68'].get('generation') == 0 and
              receipt['r68'].get('status') in ('VERDADERO','FALSO','ND') and
              type(receipt.get('seven_field_context')) is dict and
              set(receipt['seven_field_context']) == {
                  'estado','configuracion','origen','servicio','caso','condicion','contexto'},
              'invalid_original_a1')
        decisions[sid] = {
            'status': receipt['r68']['status'],
            'rule': receipt['r68']['selected_rule'],
            'output': receipt['r68']['declared_output'],
            'r68_sha256': receipt['r68_sha256'],
            'context': receipt['seven_field_context'],
        }
    statuses = [
        ('R68_CONFIRMED_GEN0', 'R69_RECOVERED', 'A1 reproducido con configuración original generación 0'),
        ('INITIALIZED_GEN0', 'R69_DURABLE', 'A2 configuración congelada; contexto no modificado'),
        ('DEV_DISPATCH_BLOCKED', 'R70_GUARD', 'A3 no existe habilitación de despacho físico DEV'),
        ('NO_ELIGIBLE_CANDIDATE', 'R70_SELECTION', 'A4 conjunto elegible vacío; no hay selección'),
        ('NO_ATTEMPT_NO_START', 'R70_NO_DISPATCH', 'A5 cero reservas y cero inicios, sin resultado técnico'),
        ('ND_NO_TECH_EVIDENCE', 'R70_DECLARATIVE', 'A6 evidencia técnica ND; sin soporte operacional'),
        ('RF_ND_NO_EVIDENCE', 'R70_ANALYTICAL', 'A7 riesgo final ND; R0 congelado y no sustituido'),
        ('DEV_STOP_APPLIED', 'R70_TRANSITION_T10', 'A8 DETENER (CONTROL) sobre los 3 servicios DEV'),
        ('STRUCTURAL_GEN1_ONLY', 'R70_DURABLE', 'A9 generación 1 analítica estructural; no técnica'),
        ('R38_READ_ONLY_GEN1', 'R70_RECOVERED', 'A10 tablero R38 leyendo generación 1 recuperada'),
    ]
    report = {
        'schema': VIEW_SCHEMA,
        'source_kind': 'SYNTHETIC_R70_ANALYTICAL_NO_DISPATCH',
        'session_id': doc['record_id'],
        'session_sha256': doc['sha256'],
        'r26_units': [dict(protocol=i['protocol'], service_id=i['id'],
                           a1=decisions[i['id']]['status'], a2='PREPARADO',
                           a3='NO_DISPATCH_AUTHORITY_IN_DEV', initial_risk=i['initial_risk'])
                     for i in fixture['services']],
        'r27': {'selected_actual': None, 'selected_hypothetical': None,
                'a5_state': 'NO_ATTEMPT', 'a5_start_count': 0,
                'a6_classification': 'ND'},
        'a7': {'hypothetical_rf': 'ND', 'confirmed_rf': None},
        'a8': {'recommendation': 'DEV_SAFE_STOP', 'applied_transition': 'DETENER'},
        'a9': {'receipt_sha256': doc['sha256'], 'durable_local_receipt': True,
                'published_generation': None, 'technical_generation_published': False,
                'structural_analytical_generation': 1},
        'a10': {'stages': [dict(algorithm=f'A{i}', status=status, source=source, detail=detail)
                           for i, (status,source,detail) in enumerate(statuses,1)]},
        'r70_safe': {
            'generation': 1, 'generation_reference': doc['generation_reference'],
            'original_generation': 0, 'configuration_sha256': doc['configuration_sha256'],
            'r69_receipt_sha256': doc['r69_receipt_sha256'],
            'original_head_sha256': doc['r69_head_sha256'],
            'store_head_sha256': doc['head_sha256'],
            'analytical_snapshot_sha256': doc['analytical_snapshot_sha256'],
            'analytical_validation': doc['analytical_validation'],
            'a1_decisions': decisions, 'store_recovery_action': doc['store_recovery_action'],
        },
        'vm_checks_executed': False, 'p8_operational': 'NO-GO',
        'operational_dispatch': False, 'final_risk': None,
    }
    report['sha256'] = digest(canonical(report))
    from ardrec.coordination.dashboard_tui import validate_dashboard_report
    validate_dashboard_report(report)
    return report
