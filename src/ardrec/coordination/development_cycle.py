"""P14-R28: un ciclo de desarrollo A1-A10 visible, SIN promesa operacional.

A1-A6 invocan rutas existentes. A7 genera sólo un oráculo matemático;
A8 recomienda pausa; A9 conserva recibo de desarrollo local; A10
expone un reporte unificado. Ninguna etapa publica generación técnica.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ardrec.analytics.exact_preview import canonical,digest,preview_bounds,verify_bounds
from ardrec.coordination.demo_session import build_development_session,normalize_scenario
from ardrec.coordination.benign_review import analyze_selection,execute_local_review
from ardrec.persistence.development_receipt import build_receipt,persist_receipt,verify_receipt
from ardrec.stopping.development_stop import preview_stop,verify_stop
from ardrec.evidence.defensive_import import validate_admission

FORMAT='ardrec-p14-r28-a1-a10-tutor-development-cycle-v1'


class CycleError(ValueError):
    pass


def build_development_cycle(scenario: dict[str,Any], *, journal_root: Path | None = None,
                            run_local_benign: bool = False,
                            defensive_observation: dict[str, Any] | None = None) -> dict[str,Any]:
    normalized=normalize_scenario(scenario)
    session=build_development_session(normalized)
    session.verify()
    if defensive_observation is not None:
        validate_admission(defensive_observation)
        if defensive_observation["session_id"] != normalized["session_id"]:
            raise CycleError("defensive_observation_session_mismatch")
    if run_local_benign:
        if not isinstance(journal_root,Path):
            raise CycleError('local_run_requires_journal_root')
        review=execute_local_review(normalized,journal_root)
        if (review['a5']['state']!='RECORDED_LIMITED' or
            review['a5']['start_count_reserved']!=1 or
            review['a5']['artifacts_verified'] is not True):
            raise CycleError('benign_attempt_not_confirmed')
        if (review['a6']['classification']!='ND' or
            review['a6']['technical_truth_accredited'] is not False):
            raise CycleError('invalid_evidence_boundary')
        source_kind='SYNTHETIC_AND_LOCAL_BENIGN_ONLY'
    else:
        if journal_root is not None:
            raise CycleError('preview_must_not_write')
        review=analyze_selection(normalized)
        source_kind='SYNTHETIC_FIXTURE_ONLY'
    if review['session_sha256']!=session.sha256 or review['a4_confirmed']['selected'] is not None:
        raise CycleError('r26_r27_binding_mismatch')
    ssh=next(u for u in session.document['units'] if u['service_id']=='SSH_DEV')
    # Este ejemplo de cálculo no procede de las VM ni se usa como Rf operativo.
    a7=preview_bounds(ssh['a2']['initial_risk'],ssh['a2']['normalized_criticality'],
                      ['1/2'],ssh['a2']['initial_risk'])
    verify_bounds(a7)
    a8=preview_stop(a6_classification='ND',accredited=False,vm_checked=False,
                    operational_dispatch=False,source_sha256=review.get('sha256',digest(review)))
    verify_stop(a8)
    r27_digest=review.get('sha256',digest(review))
    receipt=build_receipt(session_sha=session.sha256,r27_sha=r27_digest,
                          a7_sha=a7['sha256'],a8_sha=a8['sha256'])
    verify_receipt(receipt)
    if run_local_benign:
        persist_receipt(journal_root,receipt)
    stages=[
      {'algorithm':'A1','source':'SYNTHETIC_FIXTURE','status':'EXECUTED_IN_R26',
       'detail':'Reglas tipadas y decisiones trivalentes por servicio'},
      {'algorithm':'A2','source':'SYNTHETIC_FIXTURE','status':'EXECUTED_IN_R26',
       'detail':'PREPARADO, R0 fijo, casos y referencias validadas'},
      {'algorithm':'A3','source':'SYNTHETIC_FIXTURE','status':'DIAGNOSED_NO_AUTHORITY',
       'detail':'Guardas con bloqueo de autorización operacional'},
      {'algorithm':'A4','source':'SYNTHETIC_PROJECTION','status':'SELECTION_WITHOUT_DISPATCH',
       'detail':'Estado PREPARADO: sin candidato; proyección separada'},
      {'algorithm':'A5','source':'LOCAL_BENIGN_FIXTURE' if run_local_benign else 'NOT_RUN',
       'status':'RECORDED_LIMITED' if run_local_benign else 'NOT_EXECUTED',
       'detail':'Intento benigno local; nunca prueba SSH/FTP/SMB'},
      {'algorithm':'A6','source':'LOCAL_BENIGN_FIXTURE' if run_local_benign else 'NOT_RUN',
       'status':'ND', 'detail':'Integridad local no acredita condición técnica'},
      {'algorithm':'A7','source':'MATHEMATICAL_ORACLE_ONLY','status':'RF_NOT_ACREDITED',
       'detail':'Cotas exactas probadas aparte; Rf operativo ND'},
      {'algorithm':'A8','source':'CONSERVATIVE_STOP_PREVIEW','status':'PAUSE_RECOMMENDED_NOT_APPLIED',
       'detail':'Sin evidencia acreditada no autoriza cierre'},
      {'algorithm':'A9','source':'DEVELOPMENT_LOCAL_RECEIPT_ONLY' if run_local_benign else 'NOT_SAVED',
       'status':'RECEIPT_VERIFIED_NO_GENERATION',
       'detail':'Recibo local inmutable, NO generación ARDREC'},
      {'algorithm':'A10','source':'DEVELOPMENT_REPORT','status':'READ_ONLY_REPORT',
       'detail':'Vista de terminal sobre la misma sesión y sus huellas'},
    ]
    if defensive_observation is not None:
        stages[5] = {'algorithm':'A6','source':defensive_observation['source_kind'],
                     'status':'ND_DOCUMENTARY_ACCEPTED',
                     'detail':'Observacion importada para revision; soporte íntegro, procedencia física NO acreditada'}
    doc={
       'schema':FORMAT,'source_kind':source_kind,
       'session_id':session.document['session_id'],
       'session_sha256':session.sha256,
       'r26_units':[{'service_id':u['service_id'],'protocol':u['protocol'],
                     'a1':u['a1']['status'],'a2':u['a2']['initial_phase'],
                     'a3':u['a3']['table_status'],
                     'initial_risk':u['a2']['initial_risk']}
                    for u in session.document['units']],
       'r26_event_count':len(session.document['events']),
       'r27':{'source_sha256':r27_digest,
              'selected_actual':review['a4_confirmed']['selected'],
              'selected_hypothetical':review['a4_hypothetical']['selected'],
              'a5_state':review['a5']['state'] if run_local_benign else None,
              'a5_start_count':review['a5']['start_count_reserved'] if run_local_benign else None,
              'a6_classification':'ND',
              'artifact_sha256':review['a5']['event_head_sha256'] if run_local_benign else None},
       'a7':{'oracle_sha256':a7['sha256'],'hypothetical_rf':a7['hypothetical_rf'],
             'confirmed_rf':None,'technical_evidence':None},
       'a8':a8,
       'a9':{'receipt_sha256':receipt['sha256'],
             'durable_local_receipt':run_local_benign,
             'published_generation':None,'technical_generation_published':False},
       'a10':{'view':'TERMINAL_TUI_OR_TEXT','stages':stages},
       'vm_checks_executed':False,'p8_operational':'NO-GO',
       'operational_dispatch':False,'final_risk':None,
       'a7_a10_full':False,
    }
    if defensive_observation is not None:
        doc['a6_import']=defensive_observation
    doc['sha256']=digest(doc)
    return doc


def verify_development_cycle(doc: dict[str, Any]) -> bool:
    if type(doc) is not dict or type(doc.get('sha256')) is not str:
        raise CycleError('report_invalid')
    if digest({k:v for k,v in doc.items() if k!='sha256'})!=doc['sha256']:
        raise CycleError('report_digest_mismatch')
    if 'a6_import' in doc:
        validate_admission(doc['a6_import'])
        if doc['a10']['stages'][5]['status'] != 'ND_DOCUMENTARY_ACCEPTED':
            raise CycleError('a6_import_not_visible')
    if doc.get('schema')!=FORMAT or doc.get('p8_operational')!='NO-GO':
        raise CycleError('report_schema_or_gate')
    if (doc.get('operational_dispatch') is not False or
        doc.get('vm_checks_executed') is not False or
        doc.get('final_risk') is not None or
        doc['a9']['published_generation'] is not None):
        raise CycleError('unauthorized_claim')
    if [s['algorithm'] for s in doc['a10']['stages']] != [f'A{i}' for i in range(1,11)]:
        raise CycleError('stages_not_complete')
    if len(doc['r26_units'])!=3 or len(set(x['service_id'] for x in doc['r26_units']))!=3:
        raise CycleError('units_invalid')
    return True
