"""R27: puente limitado A4 -> A5 local benigno -> A6 documental ND.

El resultado A4 es una proyeccion SIN autoridad: el operador autoriza
EXCLUSIVAMENTE ejecutar el fixture benigno local `ok`. Nunca actua en VMs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ardrec.benign_pipeline import BenignPipeline
from ardrec.coordination.demo_session import (
    build_development_session, normalize_scenario,
)
from ardrec.selection.greedy_development import (
    canon, select_development, sha, verify_selection,
)

FORMAT = 'ardrec-p14-r27-a4-a6-benign-review-v1'
RID = 'r27.dev_tutor_001.ssh_case_reference'


class ReviewError(ValueError):
    pass


def source_candidates(session: dict[str, Any], *, hypothetical: bool) -> list[dict[str, Any]]:
    """Estado hipotetico separado, nunca muta el PREPARADO de R26."""
    rows = []
    for unit in session['units']:
        for case_id in unit['a2']['cases']:
            ctl = 'CTRL_REFERENCE' if case_id == 'CASE_REFERENCE' else 'CTRL_POLICY'
            control = next(c for c in unit['a3']['controls'] if c['id'] == ctl)
            rows.append({
                'service_id':unit['service_id'], 'case_id':case_id,
                'phase':('PENDIENTE' if hypothetical and unit['service_id']=='SSH_DEV'
                         else unit['a2']['initial_phase']),
                'guard':control['truth'],
                'applicable':bool(hypothetical and unit['service_id']=='SSH_DEV'),
                'precedence':(10 if case_id == 'CASE_REFERENCE' else 20),
                'initial_risk':unit['a2']['initial_risk'],
                'evidence':unit['a2']['accumulated_evidence'],
                'criticality':unit['a2']['normalized_criticality'],
            })
    return rows


def analyze_selection(scenario: dict[str, Any]) -> dict[str, Any]:
    session = build_development_session(normalize_scenario(scenario))
    session.verify()
    confirmed = source_candidates(session.document, hypothetical=False)
    shadow = source_candidates(session.document, hypothetical=True)
    a4_confirmed = select_development(confirmed, session.sha256)
    a4_projection = select_development(shadow, session.sha256)
    if not verify_selection(a4_confirmed, confirmed) or not verify_selection(a4_projection, shadow):
        raise ReviewError('selection_report_invalid')
    if a4_confirmed['selected'] is not None:
        raise ReviewError('prepared_session_cannot_select')
    if a4_projection['selected'] != {
            'service_id':'SSH_DEV','case_id':'CASE_REFERENCE',
            'priority':'1/4','precedence':10}:
        raise ReviewError('shadow_oracle_mismatch')
    return {'session_sha256':session.sha256,
            'a4_confirmed':a4_confirmed,
            'a4_hypothetical':a4_projection}


def classify_local_attempt(*, rid: str, record: dict[str, Any],
                           verification: dict[str, Any], service_id: str,
                           case_id: str) -> dict[str, Any]:
    """A6 parcial: valida el enlace y mantiene ND para soporte local benigno."""
    if rid != RID or service_id!='SSH_DEV' or case_id!='CASE_REFERENCE':
        raise ReviewError('support_binding_mismatch')
    if (record.get('id') != rid or verification.get('request_id') != rid or
            record.get('p8_operational')!='NO-GO' or
            verification.get('p8_operational')!='NO-GO'):
        raise ReviewError('attempt_identity_mismatch')
    state=record.get('state')
    if state == 'RECORDED_LIMITED':
        if verification.get('artifacts_verified') is not True:
            raise ReviewError('support_integrity_not_verified')
        result=record.get('result',{})
        if (result.get('schema') != 'ardrec-p9-p12-benign-pipeline-v1' or
                result.get('outcome') != 'BENIGN_EXIT_ZERO'):
            raise ReviewError('benign_fixture_outcome_unexpected')
        reason='LOCAL_BENIGN_RECEIPT_NOT_VM_OBSERVATION'
    elif state in ('RECOVERY_UNCERTAIN','START_INTENT','ACCEPTED','RESERVED'):
        reason='ATTEMPT_UNRESOLVED_NO_RETRY'
    else:
        raise ReviewError('attempt_state_unknown')
    return {
        'service_id':service_id,'case_id':case_id,
        'attempt_id':rid,'attempt_state':state,
        'event_head_sha256':verification['event_head_sha256'],
        'support_integrity_verified':verification['artifacts_verified'] is True,
        'classification':'ND', 'reason':reason,
        'technical_truth_accredited':False,
        'technical_evidence':None,'final_risk':None,
        'source_kind':'LOCAL_BENIGN_FIXTURE',
    }


def execute_local_review(scenario: dict[str, Any], root: Path) -> dict[str, Any]:
    """Invoca el ejecutor benigno existente, con ID fijo e idempotencia durable."""
    a4 = analyze_selection(scenario)
    # El A4 proyectado NO habilita ejecucion tecnica: esta ejecucion local
    # solo puede producirla una invocacion CLI explicita --run-local-benign.
    pipeline = BenignPipeline(root)
    pipeline.submit(RID, 'ok', deadline_ms=1000, output_cap=4096)
    pipeline.accept(RID)
    pipeline.execute(RID)  # Idempotente; no inicia dos veces el mismo request.
    record=pipeline.read(RID)
    verification=pipeline.verify(RID)
    a6=classify_local_attempt(rid=RID,record=record,verification=verification,
                               service_id='SSH_DEV',case_id='CASE_REFERENCE')
    report: dict[str, Any] = {
        'schema':FORMAT,'source_kind':'SYNTHETIC_AND_LOCAL_BENIGN_ONLY',
        'session_sha256':a4['session_sha256'],
        'a4_confirmed':a4['a4_confirmed'],
        'a4_hypothetical':a4['a4_hypothetical'],
        'a5':{'request_id':RID,'state':record['state'],
              'start_count_reserved':record['start_count'],
              'event_count':verification['event_count'],
              'event_head_sha256':verification['event_head_sha256'],
              'artifacts_verified':verification['artifacts_verified'],
              'outcome':record.get('result',{}).get('outcome')},
        'a6':a6,'p8_operational':'NO-GO',
        'vm_checks_executed':False,'a4_a6_full':False,
        'final_risk':None,'published_generation':None,
    }
    report['sha256']=sha(canon(report))
    return report
