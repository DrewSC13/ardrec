"""R71: presentar R27 + A5 benigno + A7 sintético en la TUI R38 original."""
from __future__ import annotations
from typing import Any
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.safe_dashboard_bridge import build_safe_dashboard
from ardrec.coordination.shadow_cycle import SCHEMA
from ardrec.persistence.codec import canonical, digest

VIEW_SCHEMA = 'ardrec-p14-r71-shadow-r38-v1'

class ShadowViewError(ValueError):
    pass


def build_shadow_dashboard(doc: dict[str, Any], scenario: dict[str, Any],
                           r70: dict[str, Any]) -> dict[str, Any]:
    fixture = normalize_scenario(scenario)
    if (type(doc) is not dict or doc.get('schema') != SCHEMA or
        doc.get('sha256') != digest(canonical({k:v for k,v in doc.items() if k != 'sha256'})) or
        doc.get('record_id') != fixture['session_id'] or
        doc.get('r70_receipt_sha256') != r70.get('sha256') or
        doc.get('r70_head_sha256') != r70.get('head_sha256') or
        doc.get('r70_snapshot_sha256') != r70.get('analytical_snapshot_sha256') or
        doc.get('a1_decisions') != r70.get('a1_decisions') or
        doc.get('a4_shadow_selection') != {'service_id':'SSH_DEV',
            'case_id':'CASE_REFERENCE','priority':'1/4','precedence':10} or
        doc.get('a3_operational_guard') != 'NO_GO' or
        doc.get('a5_local_benign_outcome') != 'BENIGN_EXIT_ZERO' or
        doc.get('a5_local_benign_starts') != 1 or
        doc.get('a7_hypothetical_rf') != '5/12' or
        doc.get('a7_confirmed_rf') is not None or
        doc.get('physical_observation_attested') is not False or
        doc.get('operational_dispatch') is not False or
        doc.get('p8_operational') != 'NO-GO' or
        doc.get('a9_new_generation_published') is not False):
        raise ShadowViewError('shadow_source_or_authority_invalid')
    base = build_safe_dashboard(r70, fixture)
    preserved = base.pop('r70_safe')
    base['schema'] = VIEW_SCHEMA
    base['source_kind'] = 'R71_LOCAL_BENIGN_WITH_SHADOW_SELECTION'
    base['session_sha256'] = doc['sha256']
    base['a9']['receipt_sha256'] = doc['sha256']
    base['r27'].update({
        'selected_actual': None,
        'selected_hypothetical': doc['a4_shadow_selection'],
        'a5_state': 'RECORDED_LIMITED_LOCAL_BENIGN',
        'a5_start_count': 1,
        'a6_classification': 'ND',
    })
    base['a7']['hypothetical_rf'] = '5/12'
    base['a8'] = {'recommendation': 'DEV_STOP_PRESERVED',
                  'applied_transition': 'DETENER_R70_UNCHANGED'}
    statuses = [
        ('R68_GEN0_REPLAY', 'R69_R70_RECOVERED', 'A1: decisiones originales y configuración inmutable'),
        ('R70_GEN1_FROZEN', 'R70_ARCHIVE', 'A2: GEN1 estructural recuperada sin mutaciones'),
        ('SHADOW_TRUE_NO_GO', 'R27_SHADOW', 'A3: guarda verdadera solo en proyección; P8 NO-GO'),
        ('SHADOW_SSH_SELECTED', 'R27_SELECTION', 'A4: SSH/CASE_REFERENCE elegido hipotéticamente; no despacho'),
        ('LOCAL_BENIGN_ONE_START', 'BENIGN_PIPELINE', 'A5: un proceso local ok, no prueba de SSH'),
        ('ND_NOT_VM_EVIDENCE', 'R27_A6_BOUNDARY', 'A6: integridad local demostrada; verdad técnica ND'),
        ('HYPOTHETICAL_5_12', 'R58D_INTERVAL', 'A7: RF hipotético 5/12; Rf confirmado ND'),
        ('R70_STOP_UNCHANGED', 'R70_REPLAY', 'A8: DETENER original, no se reabre la generación'),
        ('GEN1_NO_NEW_PUBLICATION', 'R70_ARCHIVE', 'A9: GEN1 estructural intacta; GEN2 NO'),
        ('R38_READ_ONLY_SHADOW', 'R38_ORIGINAL', 'A10: monitor de tres paneles y fuente R71 verificable'),
    ]
    base['a10'] = {'stages': [dict(algorithm=f'A{i}', status=status, source=source,
                                   detail=detail) for i,(status,source,detail) in enumerate(statuses,1)]}
    base['r71_shadow'] = {
        'r70_generation': 1,
        'r70_receipt_sha256': doc['r70_receipt_sha256'],
        'r70_head_sha256': doc['r70_head_sha256'],
        'r70_snapshot_sha256': doc['r70_snapshot_sha256'],
        'a1_decisions': preserved['a1_decisions'],
        'a4_selected': doc['a4_shadow_selection'],
        'a4_sha256': doc['a4_shadow_sha256'],
        'a5_request': doc['a5_local_benign_request'],
        'a5_event_head_sha256': doc['a5_event_head_sha256'],
        'a5_review_sha256': doc['a5_review_sha256'],
        'a7_oracle_sha256': doc['a7_synthetic_oracle_sha256'],
        'a7_hypothetical_rf': doc['a7_hypothetical_rf'],
    }
    base['sha256'] = digest(canonical({k:v for k,v in base.items() if k != 'sha256'}))
    from ardrec.coordination.dashboard_tui import validate_dashboard_report
    validate_dashboard_report(base)
    return base
