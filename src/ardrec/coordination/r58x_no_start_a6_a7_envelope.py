"""R58-X: evidence-free A5 no-start -> A6 ND -> exact A7 uncertainty.

Read-only consumer of the verified R58-W SQLite event ledger and R58-V handoff.
No source can attest a technical outcome from a synthetic no-start. The A7
result is a mathematical envelope, never a confirmed risk or A9 publication.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import sqlite3
from typing import Any
from urllib.parse import quote

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination import r58w_declared_a5_model_ledger as w
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge, verify_unit_bridge,
)

SCHEMA = 'ardrec-r58x-a5-no-start-a6-nd-a7-exact-envelope-v1'
MODE = 'SYNTHETIC_NO_START_MATHEMATICAL_ONLY'
BASE = '890fb1c0bc553430ca3f03e6cdd88bb994ea34f7'
MAX_CASES = 54
PHASES = frozenset(('PREPARADO','PENDIENTE','PAUSADO','DETENIDO'))
FIELDS = frozenset((
    'schema','mode','source_base_commit','session_id','source_r58v_handoff_sha256',
    'source_r58w_ledger_head_sha256','source_r58s_denial_sha256',
    'source_catalog_sha256','source_thesis_sha256','case_count','family_count',
    'simulated_phase_counts','model_intents_declared','model_intents_open',
    'model_no_start_resolutions','model_event_count','model_no_start_case_count',
    'a6_unaccredited_count','a6_classification','a7_mathematical_envelope_sha256',
    'a7_unresolved_unit_count','a7_weights','cases','technical_truth_accredited',
    'a6_accredited_evidence_count','confirmed_final_risk','operational_dispatch',
    'operational_transitions_applied','a5_attempts_started','published_generation',
    'p8_operational','sha256',
))
CASE_FIELDS = frozenset((
    'service_id','session_id','derived_case_id','assessment_index','case_id_a7',
    'family_id','model_phase','a5_model_resolution','a6_classification',
    'a6_technical_truth_accredited','a7_rf_lower','a7_rf_upper',
    'a7_evidence_status','confirmed_rf',
))


class NoStartEnvelopeError(ValueError):
    """A5-A7 sources, replay, or claimed authority are not trustworthy."""


def need(value: bool, reason: str) -> None:
    if not value:
        raise NoStartEnvelopeError(reason)


def _model_rows(path: Path) -> list[tuple[Any, ...]]:
    """Read only; independently reject changes while querying SQLite."""
    before = w._private_file_fingerprint(path)
    db = sqlite3.connect('file:'+quote(str(path),safe='/')+'?mode=ro',
                         uri=True, timeout=5)
    try:
        db.execute('PRAGMA query_only=ON')
        rows = db.execute('SELECT case_id,status,declare_request,resolve_request '
                          'FROM intents ORDER BY case_id').fetchall()
    finally:
        db.close()
    need(before == w._private_file_fingerprint(path),
         'MODEL_LEDGER_CHANGED_DURING_READ')
    return rows


def build_no_start_envelope(model_root: Path, handoff_root: Path,
                            *source: Any) -> dict[str, Any]:
    """Use real R58-W replay and R58-E/R58-D interval kernel. No writes."""
    need(len(source) == 8, 'SOURCE_COUNT')
    w._roots(model_root,handoff_root,source)
    handoff = w._source(handoff_root,source)
    model = w.inspect_model_ledger(model_root,handoff_root,*source)
    need(type(handoff) is dict and type(model) is dict and
         handoff.get('schema') == 'ardrec-r58v-sandbox-a5-a6-readonly-handoff-v1' and
         model.get('schema') == w.SCHEMA and
         model.get('mode') == w.MODE and
         model.get('source_handoff_sha256') == handoff.get('sha256') and
         type(handoff.get('case_count')) is int and
         0 < handoff['case_count'] <= MAX_CASES and
         len(handoff['cases']) == handoff['case_count'] and
         model.get('case_count') == handoff['case_count'] and
         model.get('family_count') == handoff['family_count'] and
         handoff.get('all_source_requests_denied') is True and
         model.get('source_denials_preserved') is True and
         handoff.get('a6_classification') == 'ND' and
         model.get('a6_classification') == 'ND' and
         handoff.get('a6_accredited_evidence_count') == 0 and
         handoff.get('a5_attempts_started') == 0 and
         handoff.get('a5_attempts_reserved') == 0 and
         handoff.get('operational_dispatch') is False and
         model.get('a6_accredited_evidence_count') == 0 and
         model.get('a5_attempts_started') == 0 and
         model.get('a5_operational_reservations') == 0 and
         model.get('operational_dispatch') is False and
         model.get('confirmed_final_risk') is None and
         model.get('published_generation') is None and
         model.get('p8_operational') == 'NO-GO',
         'SOURCE_NOT_UNACCREDITED_AND_DENIED')
    need(model['model_intents_declared'] ==
         model['model_intents_open'] + model['model_no_start_resolutions'] and
         model['model_event_count'] ==
         model['model_intents_declared'] + model['model_no_start_resolutions'],
         'MODEL_COUNTS_UNRECONCILED')
    rows = _model_rows(w._path(model_root,handoff))
    need(len(rows) == model['model_intents_declared'],
         'INTENT_ROW_COUNT_DRIFT')
    intent_status: dict[str,str] = {}
    for cid, status, declared, resolved in rows:
        need(type(cid) is str and w.CASE.fullmatch(cid) is not None and
             cid not in intent_status and
             type(declared) is str and w.REQ.fullmatch(declared) is not None and
             (status == 'DECLARED' and resolved is None or
              status == 'RESOLVED_NO_START' and
              type(resolved) is str and w.REQ.fullmatch(resolved) is not None),
             'INTENT_ROW_INVALID')
        intent_status[cid] = status
    need(sum(v == 'DECLARED' for v in intent_status.values()) ==
         model['model_intents_open'] and
         sum(v == 'RESOLVED_NO_START' for v in intent_status.values()) ==
         model['model_no_start_resolutions'], 'INTENT_STATUSES_MISMATCH')

    scenario = normalize_scenario(source[5])
    need(scenario['session_id'] == handoff['session_id'],
         'SCENARIO_SESSION_MISMATCH')
    services = {s['id']:s for s in scenario['services']}
    unit_inputs = []
    by_id = {}
    for case in handoff['cases']:
        need(type(case) is dict and
             case.get('session_id') == handoff['session_id'] and
             case.get('service_id') in services and
             type(case.get('case_id_a7')) is str and
             w.CASE.fullmatch(case['case_id_a7']) is not None and
             case['case_id_a7'] not in by_id and
             case.get('current_model_phase') in PHASES and
             case.get('a6_classification') == 'ND' and
             case.get('evidence_accredited') is False and
             case.get('a5_start_count') == 0 and
             case.get('a5_intent_submitted') is False and
             type(case.get('assessment_index')) is int and
             0 <= case['assessment_index'] < 2**31,
             'HANDOFF_CASE_UNSAFE')
        cid = case['case_id_a7']
        by_id[cid] = case
        need(cid not in intent_status or
             (case['current_model_phase'] == 'PENDIENTE' and
              case.get('logical_candidate') is True and
              case.get('deny_reason') ==
                  'INDEPENDENT_APPROVAL_AND_COMMIT_NOT_ATTESTED'),
             'MODEL_INTENT_NOT_PENDING_AND_DENIED')
        unit_inputs.append({
            'service_id':case['service_id'],
            'case_id':cid,
            'assessment_index':case['assessment_index'],
            'initial_risk':services[case['service_id']]['initial_risk'],
            'normalized_criticality':services[case['service_id']]['normalized_criticality'],
            # No verified remediation, so no unearned reduction of baseline.
            'replacement_risk':services[case['service_id']]['initial_risk'],
            'evidence': [],
        })
    need(len(by_id) == model['case_count'] and
         set(intent_status).issubset(by_id),
         'CASE_IDENTITY_OR_INTENT_UNBOUND')
    math = build_unit_bridge(unit_inputs, [])
    verify_unit_bridge(math)
    need(math['unit_count'] == model['case_count'] and
         math['documentary_admission_count'] == 0 and
         math['missing_documentary_admission_count'] == model['case_count'] and
         math['all_a6_nd'] is True and
         math['technical_truth_accredited'] is False and
         math['confirmed_final_risk'] is None and
         math['published_generation'] is None and
         math['p8_operational'] == 'NO-GO',
         'MATHEMATICAL_ORACLE_FALSE_AUTHORITY')
    cases = []
    for item in math['decisions']:
        source_case = by_id[item['case_id']]
        need(item['service_id'] == source_case['service_id'] and
             item['assessment_index'] == source_case['assessment_index'] and
             item['a6_classification'] == 'ND' and
             item['a6_status'] == 'MISSING_DOCUMENTARY_ADMISSION' and
             item['a7_interval_source'] == 'MATHEMATICAL_ONLY_FULL_UNRESOLVED' and
             item['technical_truth_accredited'] is False and
             item['confirmed_rf'] is None and
             item['a8_applied_transition'] is None,
             'A6_A7_SOURCE_BOUNDARY_INVALID')
        cid = source_case['case_id_a7']
        outcome = intent_status.get(cid)
        row = {
            'service_id':source_case['service_id'],
            'session_id':source_case['session_id'],
            'derived_case_id':source_case['derived_case_id'],
            'assessment_index':source_case['assessment_index'],
            'case_id_a7':cid,
            'family_id':source_case['family_id'],
            'model_phase':source_case['current_model_phase'],
            'a5_model_resolution':outcome or 'NO_MODEL_INTENT',
            'a6_classification':'ND',
            'a6_technical_truth_accredited':False,
            'a7_rf_lower':item['a7_rf_lower'],
            'a7_rf_upper':item['a7_rf_upper'],
            'a7_evidence_status':'FULLY_UNRESOLVED_MATHEMATICAL_ONLY',
            'confirmed_rf':None,
        }
        need(set(row) == CASE_FIELDS,'CASE_RESULT_SCHEMA')
        cases.append(row)
    cases.sort(key=lambda r:(r['service_id'],r['case_id_a7'],r['assessment_index']))
    need(len(cases) == model['case_count'], 'MATH_CASE_MAPPING_INCOMPLETE')
    report = {
        'schema':SCHEMA,
        'mode':MODE,
        'source_base_commit':BASE,
        'session_id':handoff['session_id'],
        'source_r58v_handoff_sha256':handoff['sha256'],
        'source_r58w_ledger_head_sha256':model['last_event_sha256'],
        'source_r58s_denial_sha256':handoff['source_r58s_deny_sha256'],
        'source_catalog_sha256':handoff['source_catalog_sha256'],
        'source_thesis_sha256':handoff['source_thesis_sha256'],
        'case_count':len(cases),
        'family_count':handoff['family_count'],
        'simulated_phase_counts':handoff['simulated_phase_counts'],
        'model_intents_declared':model['model_intents_declared'],
        'model_intents_open':model['model_intents_open'],
        'model_no_start_resolutions':model['model_no_start_resolutions'],
        'model_event_count':model['model_event_count'],
        'model_no_start_case_count':sum(x['a5_model_resolution']=='RESOLVED_NO_START' for x in cases),
        'a6_unaccredited_count':len(cases),
        'a6_classification':'ND',
        'a7_mathematical_envelope_sha256':math['a7']['sha256'],
        'a7_unresolved_unit_count':math['unit_count'],
        'a7_weights':math['weights'],
        'cases':cases,
        'technical_truth_accredited':False,
        'a6_accredited_evidence_count':0,
        'confirmed_final_risk':None,
        'operational_dispatch':False,
        'operational_transitions_applied':0,
        'a5_attempts_started':0,
        'published_generation':None,
        'p8_operational':'NO-GO',
    }
    need(len(canonical(report)) <= 131072,'REPORT_OVER_SIZE_LIMIT')
    need(set(report) == FIELDS - {'sha256'},'REPORT_FIELDS_INVALID')
    report['sha256'] = digest(report)
    return report


def verify_no_start_envelope(report: dict[str,Any], model_root: Path,
                             handoff_root: Path, *source: Any) -> bool:
    need(type(report) is dict and set(report) == FIELDS and
         type(report.get('sha256')) is str and
         w.HEX.fullmatch(report['sha256']) is not None and
         digest({k:v for k,v in report.items() if k!='sha256'})==report['sha256'],
         'REPORT_DIGEST_OR_SCHEMA_INVALID')
    expected = build_no_start_envelope(model_root,handoff_root,*source)
    need(canonical(report)==canonical(expected),'REPORT_NOT_REPRODUCIBLE_OR_SOURCE_CHANGED')
    return True
