"""R58-L: deterministic A4 selection + A5 attempt-intent review over R58-K.

All cases are SYNTHETIC. Neither the A4 winner nor an A5 intent may be
interpreted as an operational authorization, reservation, attempt, or evidence.
A6/7/8 retain the conservative R58-K results; A9/P8 never run.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58k_unified_family_bridge import (
    build_unified_preview, verify_unified_preview,
)
from ardrec.selection.greedy_development import select_development, verify_selection

SCHEMA = 'ardrec-r58l-a4-a5-a6-a8-synthetic-review-v1'
REPO_BASE = '8aad0fd43e451de2c33a1e42fe9b6240fcd23c8f'
MAX_UNITS = 54
MAX_BYTES = 1048576
ENTRY_FIELDS = frozenset(('service_id', 'unit', 'risk', 'applicable'))
IDENTITY_FIELDS = frozenset(('service_id', 'session_id', 'derived_case_id', 'assessment_index'))
HISTORY_FIELDS = IDENTITY_FIELDS | {'attempt_id', 'state'}
INTENT_FIELDS = IDENTITY_FIELDS | {'attempt_id', 'action'}
ATTEMPT_ID = re.compile(r'ATT_[A-Z0-9_]{1,76}\Z', re.ASCII)
SESSION = re.compile(r'[A-Za-z0-9_:-]{1,80}\Z', re.ASCII)
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
HISTORY_STATES = frozenset(('RESERVED', 'START_INTENT', 'RECOVERY_UNCERTAIN',
                            'RECORDED_LIMITED'))


class CoordinationError(ValueError):
    """Refuse ambiguous, ungrounded, or promoted review inputs."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise CoordinationError(reason)


def _identity(row: dict[str, Any]) -> tuple[str, str, str, int]:
    return (row['service_id'], row['session_id'], row['derived_case_id'],
            row['assessment_index'])


def _validation_identity(row: Any, fields: frozenset[str]) -> tuple[str, str, str, int]:
    need(type(row) is dict and set(row) == fields, 'ATTEMPT_RECORD_SCHEMA')
    need(type(row['service_id']) is str and row['service_id'] in
         ('SSH_DEV','FTP_DEV','SMB_DEV'), 'ATTEMPT_SERVICE')
    need(type(row['session_id']) is str and SESSION.fullmatch(row['session_id']) is not None,
         'ATTEMPT_SESSION')
    need(type(row['derived_case_id']) is str and 1 <= len(row['derived_case_id']) <= 80,
         'ATTEMPT_CASE')
    need(type(row['assessment_index']) is int and 0 <= row['assessment_index'] < 2**31,
         'ATTEMPT_ASSESSMENT')
    need(type(row['attempt_id']) is str and ATTEMPT_ID.fullmatch(row['attempt_id']) is not None,
         'ATTEMPT_ID')
    return _identity(row)


def _selected_identity(rows: list[dict[str, Any]], selected: Any) -> dict[str, Any] | None:
    if selected is None:
        return None
    matches = [d for d in rows if d['service_id'] == selected['service_id'] and
               d['case_id_a7'] == selected['case_id']]
    need(len(matches) == 1, 'A4_CASE_BINDING_AMBIGUOUS')
    d = matches[0]
    return {k: d[k] for k in ('service_id','session_id','derived_case_id','assessment_index')}


def build_a4_a5_review(
    entries: list[dict[str, Any]],
    *,
    attempt_intent: dict[str, Any] | None = None,
    attempt_history: list[dict[str, Any]] | None = None,
    weights: tuple[str, str, str] = ('1/3', '1/3', '1/3'),
) -> dict[str, Any]:
    """Review a single synthetic session, never executing or reserving anything.

    `applicable` is an explicit *simulated* assumption, not authorization.
    A4 evidence is fixed to zero because A6 has no accredited evidence.
    A5 history and intent are untrusted simulation inputs, not a durable journal.
    """
    need(type(entries) is list and 0 < len(entries) <= MAX_UNITS, 'ENTRY_COUNT')
    need(type(weights) is tuple and len(weights) == 3, 'WEIGHTS_SCHEMA')
    history = [] if attempt_history is None else attempt_history
    need(type(history) is list and len(history) <= MAX_UNITS, 'HISTORY_COUNT')
    normalized: list[dict[str, Any]] = []
    family_inputs: list[dict[str, Any]] = []
    applicant: dict[tuple[str, str, str, int], bool] = {}
    sessions: set[str] = set()
    for row in entries:
        need(type(row) is dict and set(row) == ENTRY_FIELDS, 'ENTRY_SCHEMA')
        applicable = row['applicable']
        need(type(applicable) is bool, 'APPLICABILITY_MUST_BE_BOOLEAN')
        need(type(row['unit']) is dict and type(row['service_id']) is str,
             'UNIT_SERVICE_SCHEMA')
        unit = row['unit']
        need(type(unit.get('session_id')) is str and
             SESSION.fullmatch(unit['session_id']) is not None, 'SESSION_FORMAT')
        need(type(unit.get('derived_case_id')) is str and
             type(unit.get('assessment_index')) is int, 'IDENTITY_SCHEMA')
        key = (row['service_id'], unit['session_id'], unit['derived_case_id'],
               unit['assessment_index'])
        need(key not in applicant, 'DUPLICATE_APPLICABILITY')
        applicant[key] = applicable
        sessions.add(unit['session_id'])
        family_inputs.append({'service_id': row['service_id'],
                              'unit': deepcopy(unit), 'risk': deepcopy(row['risk'])})
        normalized.append(deepcopy(row))
    need(len(sessions) == 1, 'MIXED_SESSIONS_A4_SELECTION_UNSUPPORTED')
    session_id = next(iter(sessions))
    unified = build_unified_preview(family_inputs, weights=weights)
    verify_unified_preview(unified)
    need(unified['unit_count'] == len(entries) and
         unified['a6_classification'] == 'ND' and
         unified['p8_operational'] == 'NO-GO' and
         unified['operational_dispatch'] is False and
         unified['technical_truth_accredited'] is False and
         unified['confirmed_final_risk'] is None and
         unified['published_generation'] is None,
         'UNIFIED_AUTHORITY_VIOLATION')
    decisions = unified['decisions']
    decision_keys = {_identity(d) for d in decisions}
    need(decision_keys == set(applicant), 'A4_A6_IDENTITIES_MISMATCH')
    # The A4 'session' is a SHA-bound synthetic context, never a signed
    # physical session. Exact A4 greedy order is reused, not reimplemented.
    session_sha = digest({'schema': SCHEMA, 'session_id': session_id,
                          'unified_sha256': unified['sha256'],
                          'applicability': sorted((list(k) + [v]
                                                 for k, v in applicant.items()))})
    risk_by_case = {(e['service_id'], e['unit']['session_id'],
                     e['unit']['derived_case_id'], e['unit']['assessment_index']):
                    e['risk'] for e in unified['inputs']}
    candidates: list[dict[str, Any]] = []
    for d in decisions:
        key = _identity(d)
        risk = risk_by_case[key]
        need(d['a6_classification'] == 'ND' and
             d['technical_truth_accredited'] is False and
             d['confirmed_rf'] is None and
             d['applied_transition'] is None and
             d['published_generation'] is None,
             'A6_DECISION_PROMOTED')
        candidates.append({
            'service_id': d['service_id'], 'case_id': d['case_id_a7'],
            'phase': d['phase_assumed'], 'guard': d['guard_simulated'],
            'applicable': applicant[key], 'precedence': d['precedence'],
            'initial_risk': risk['initial_risk'],
            'evidence': '0',
            'criticality': risk['normalized_criticality'],
        })
    a4 = select_development(candidates, session_sha, weights=weights)
    verify_selection(a4, candidates)
    need(a4['selection_is_operational'] is False and
         a4['operational_dispatch'] is False and
         a4['published_generation'] is None and
         a4['p8_operational'] == 'NO-GO', 'A4_AUTHORITY_VIOLATION')
    selected = _selected_identity(decisions, a4['selected'])
    normalized.sort(key=lambda x: (x['service_id'], x['unit']['session_id'],
                                   x['unit']['derived_case_id'],
                                   x['unit']['assessment_index']))
    histories: list[dict[str, Any]] = []
    used_attempt_ids: set[str] = set()
    prior_by_key: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for record in history:
        key = _validation_identity(record, HISTORY_FIELDS)
        need(key in decision_keys, 'HISTORY_UNBOUND_CASE')
        need(record['state'] in HISTORY_STATES and type(record['state']) is str,
             'HISTORY_STATE_INVALID')
        need(record['attempt_id'] not in used_attempt_ids, 'DUPLICATE_ATTEMPT_ID')
        need(key not in prior_by_key, 'ORDINARY_BUDGET_EXCEEDED_NO_RETRY')
        used_attempt_ids.add(record['attempt_id'])
        prior_by_key[key] = record
        histories.append(dict(record))
    histories.sort(key=lambda r: _identity(r))
    intent_copy = None
    if attempt_intent is not None:
        intent_key = _validation_identity(attempt_intent, INTENT_FIELDS)
        need(attempt_intent['action'] == 'SYNTHETIC_REVIEW_ONLY' and
             type(attempt_intent['action']) is str, 'INTENT_MUST_BE_REVIEW_ONLY')
        need(selected is not None, 'INTENT_WITHOUT_A4_WINNER')
        need(intent_key == _identity(selected), 'INTENT_NOT_A4_WINNER')
        need(attempt_intent['attempt_id'] not in used_attempt_ids,
             'ATTEMPT_ID_REPLAY')
        intent_copy = dict(attempt_intent)
    if selected is None:
        disposition = 'NO_ELIGIBLE_CASE'
    elif intent_copy is None:
        disposition = 'NO_ATTEMPT_INTENT'
    elif _identity(selected) in prior_by_key:
        disposition = 'BLOCKED_ORDINARY_BUDGET_CONSUMED_NO_RETRY'
    else:
        disposition = 'SYNTHETIC_INTENT_REVIEWED_NO_RESERVATION'
    rows = []
    a4_by_key = {(d['service_id'], d['case_id']): d for d in a4['candidates']}
    need(len(a4_by_key) == len(decisions), 'A4_ROW_BINDING_MISMATCH')
    for d in decisions:
        a4_row = a4_by_key[(d['service_id'], d['case_id_a7'])]
        rows.append({
            'service_id': d['service_id'], 'session_id': d['session_id'],
            'derived_case_id': d['derived_case_id'],
            'assessment_index': d['assessment_index'],
            'family_id': d['family_id'], 'variant': d['variant'],
            'case_id_a7': d['case_id_a7'],
            'a4_applicable_simulated': applicant[_identity(d)],
            'a4_guard_simulated': d['guard_simulated'],
            'a4_priority': a4_row['priority'],
            'a4_precedence': d['precedence'],
            'a4_eligible_simulated': a4_row['eligible'],
            'a4_blocker': a4_row['blocker'],
            'a4_selected_simulated': selected is not None and
                                      _identity(d) == _identity(selected),
            'a5_history_is_synthetic': _identity(d) in prior_by_key,
            'a6_hypothetical_result': d['hypothetical_result_class'],
            'a6_classification': 'ND', 'technical_truth_accredited': False,
            'a7_rf_lower': d['a7_rf_lower'],
            'a7_rf_upper': d['a7_rf_upper'],
            'a8_recommendation': d['a8_recommendation'],
            'confirmed_rf': None, 'applied_transition': None,
            'published_generation': None,
        })
    report = {
        'schema': SCHEMA, 'mode': 'SYNTHETIC_A4_A5_REVIEW_ONLY',
        'source_base_commit': REPO_BASE,
        'source_catalog_sha256': unified['source_catalog_sha256'],
        'source_thesis_sha256': unified['source_thesis_sha256'],
        'session_id': session_id,
        'inputs': normalized, 'attempt_intent': intent_copy,
        'attempt_history': histories, 'weights': list(weights),
        'unified': unified, 'a4': a4, 'decisions': rows,
        'a4_selected_identity': selected,
        'a5': {
            'disposition': disposition,
            'ordinary_attempt_budget': 1,
            'synthetic_prior_attempt_count': len(histories),
            'attempt_intent_seen': intent_copy is not None,
            'actual_attempt_reservations': 0,
            'actual_attempts_started': 0,
            'real_attempt_budget_attested': False,
            'technical_result_generated': False,
            'operational_dispatch': False,
        },
        'unit_count': len(entries),
        'covered_family_count': unified['covered_family_count_in_batch'],
        'count_by_service': unified['count_by_service'],
        'a4_operational_selection': None,
        'a6_classification': 'ND',
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'vm_checks_executed': False,
        'host_mutations': 0,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) <= MAX_BYTES, 'REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify_a4_a5_review(report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str and
         HEX.fullmatch(report['sha256']) is not None, 'REPORT_SCHEMA')
    need(type(report.get('weights')) is list and len(report['weights']) == 3,
         'REPORT_WEIGHTS')
    expected = build_a4_a5_review(report.get('inputs'),
                                  attempt_intent=report.get('attempt_intent'),
                                  attempt_history=report.get('attempt_history'),
                                  weights=tuple(report['weights']))
    need(canonical(expected) == canonical(report), 'REPORT_NOT_REPRODUCIBLE')
    return True
