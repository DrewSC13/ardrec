"""R58-Q: A3-to-A4 logical transition *counterfactual*, never a state change.

Reuses R58-P case-typed guards and the authentic A4 greedy selector. The
current A2 phase is PREPARADO for all cases. A counterfactual PENDIENTE
proposal is computed separately and is NEVER operational authorization.
No persistence, execution, network, guest action or P8 dispatcher.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.r58l_a4_a5_family_review import verify_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import verify_family_a3_projection
from ardrec.selection.greedy_development import select_development, verify_selection

SCHEMA = 'ardrec-r58q-prepared-pending-a3-a4-counterfactual-v1'
BASE = '044a12b71080d5ec0a55a3301e3a659838df0b13'
MAX_UNITS = 54
MAX_REPORT_BYTES = 262144
KEYS = ('service_id', 'session_id', 'derived_case_id', 'assessment_index')
AUTHORITY_BLOCKER = 'AUTORIDAD_OPERACIONAL_NO_ACREDITADA'


class TransitionBridgeError(ValueError):
    """Refuse an unsupported transition or synthetic authority promotion."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise TransitionBridgeError(code)


def key(row: dict[str, Any]) -> tuple[str, str, str, int]:
    return tuple(row[field] for field in KEYS)


def _indexed(rows: list[dict[str, Any]], description: str) -> dict:
    need(type(rows) is list and 0 < len(rows) <= MAX_UNITS, description + '_COUNT')
    mapped = {}
    for row in rows:
        need(type(row) is dict, description + '_ROW_SCHEMA')
        k = key(row)
        need(k not in mapped, description + '_DUPLICATE_CASE')
        mapped[k] = row
    return mapped


def build_a3_a4_transition_audit(
    scenario: dict[str, Any], review: dict[str, Any],
    a3_report: dict[str, Any],
) -> dict[str, Any]:
    """Two exact A4 rankings: actual PREPARADO vs hypothetical PENDIENTE.

    The hypothetical branch is NOT an applied PREPARADO->PENDIENTE transition.
    Guard truth alone cannot satisfy source authenticity, authority, VM gates,
    execution budgets or independent physical provenance.
    """
    fixture = normalize_scenario(scenario)
    verify_a4_a5_review(review)
    verify_family_a3_projection(a3_report, fixture, review)
    need(type(review) is dict and type(a3_report) is dict and
         review['session_id'] == fixture['session_id'] == a3_report['session_id'] and
         a3_report['r58l_review_sha256'] == review['sha256'] and
         a3_report['source_catalog_sha256'] == review['source_catalog_sha256'] and
         a3_report['source_thesis_sha256'] == review['source_thesis_sha256'],
         'SOURCE_IDENTITY_OR_PIN_MISMATCH')
    need(review['unit_count'] == a3_report['control_reference_count'] and
         0 < review['unit_count'] <= MAX_UNITS and
         review['covered_family_count'] == a3_report['family_count'] and
         a3_report['a3_typed_case_references_constructed'] is True and
         a3_report['a3_case_guard_is_operational_authority'] is False and
         a3_report['a1_a3_to_family_case_authority_attested'] is False,
         'UNSUPPORTED_A3_COVERAGE_OR_AUTHORITY')
    need(review['a6_classification'] == a3_report['a6_classification'] == 'ND' and
         review['technical_truth_accredited'] is False and
         review['operational_dispatch'] is False and
         a3_report['operational_dispatch'] is False and
         review['p8_operational'] == a3_report['p8_operational'] == 'NO-GO' and
         review['confirmed_final_risk'] is None and
         a3_report['confirmed_final_risk'] is None and
         review['published_generation'] is None and
         a3_report['published_generation'] is None and
         review['applied_state_transition'] is None and
         a3_report['applied_transition'] is None,
         'UNACCREDITED_AUTHORITY_CLAIM')
    need(review['a5']['actual_attempts_started'] == 0 and
         review['a5']['actual_attempt_reservations'] == 0,
         'A5_ACTUAL_EXECUTION_UNEXPECTED')
    a3 = _indexed(a3_report['control_cases'], 'A3')
    decisions = _indexed(review['decisions'], 'A4')
    need(set(a3) == set(decisions), 'A3_A4_CASE_IDS_NOT_BIJECTIVE')
    inputs = review['unified']['inputs']
    need(type(inputs) is list and len(inputs) == len(decisions), 'RISK_INPUT_COUNT')
    risks = {}
    for item in inputs:
        need(type(item) is dict and type(item.get('unit')) is dict,
             'RISK_ENVELOPE_SCHEMA')
        row = {'service_id': item['service_id'], **{
            field: item['unit'][field] for field in KEYS[1:]}}
        k = key(row)
        need(k not in risks and type(item['risk']) is dict,
             'RISK_DUPLICATE_OR_SCHEMA')
        risks[k] = item['risk']
    need(set(risks) == set(a3), 'A3_A4_RISK_IDENTITY_MISMATCH')
    baseline_candidates, hypothetical_candidates, projections = [], [], []
    phase_counts: Counter[str] = Counter()
    guard_counts: Counter[str] = Counter()
    for k in sorted(a3):
        control = a3[k]
        decision = decisions[k]
        need(control['case_id_a7'] == decision['case_id_a7'] and
             control['family_id'] == decision['family_id'] and
             control['variant'] == decision['variant'] and
             control['precedence'] == decision['a4_precedence'] and
             control['a3_phase'] == 'PREPARADO' and
             type(control['a3_blockers']) is list and
             AUTHORITY_BLOCKER in control['a3_blockers'] and
             control['a3_guard_truth'] in ('VERDADERO', 'FALSO', 'ND') and
             control['a3_table_status'] in ('VERDADERO', 'FALSO', 'ND') and
             decision['a4_applicable_simulated'] in (True, False) and
             type(decision['a4_applicable_simulated']) is bool and
             control['a4_guard_simulated'] == decision['a4_guard_simulated'] and
             control['a4_eligible_simulated'] is decision['a4_eligible_simulated'] and
             control['operational_eligibility_attested'] is False and
             control['technical_truth_accredited'] is False,
             'A3_A4_CONTROL_CONTENT_DISAGREEMENT')
        unexpected = sorted(set(control['a3_blockers']) - {AUTHORITY_BLOCKER})
        # The rule MAY be logically true; only a hypothetical transition follows.
        logically_possible = (control['a3_guard_truth'] == 'VERDADERO' and
                              control['a3_table_status'] == 'VERDADERO' and
                              not unexpected and
                              decision['a4_applicable_simulated'] is True)
        phase = 'PENDIENTE' if logically_possible else 'PREPARADO'
        risk = risks[k]
        base = {
            'service_id': k[0], 'case_id': decision['case_id_a7'],
            'phase': 'PREPARADO', 'guard': control['a3_guard_truth'],
            'applicable': decision['a4_applicable_simulated'],
            'precedence': control['precedence'],
            'initial_risk': risk['initial_risk'],
            'evidence': '0',
            'criticality': risk['normalized_criticality'],
        }
        baseline_candidates.append(base)
        hypothetical_candidates.append({**base, 'phase': phase})
        guard_counts[control['a3_guard_truth']] += 1
        phase_counts[phase] += 1
        projections.append({
            **{field: k[i] for i, field in enumerate(KEYS)},
            'family_id': control['family_id'], 'variant': control['variant'],
            'case_id_a7': control['case_id_a7'],
            'control_id_a3': control['control_id_a3'],
            'a3_phase_confirmed_by_fixture': 'PREPARADO',
            'a3_guard_truth': control['a3_guard_truth'],
            'a3_table_status': control['a3_table_status'],
            'a3_blockers': list(control['a3_blockers']),
            'a4_original_guard_simulated': decision['a4_guard_simulated'],
            'a4_original_eligible_simulated': decision['a4_eligible_simulated'],
            'a4_applicable_simulated': decision['a4_applicable_simulated'],
            'logical_pending_counterfactual': logically_possible,
            'counterfactual_phase': phase,
            'confirmed_transition': None,
            'current_confirmed_phase_change': False,
            'case_authority_attested': False,
        })
    need(len(projections) == len(a3), 'PROJECTION_COUNT')
    # Use the original A4 implementation twice. Never convert either output
    # into an operational selection, persisted state or actual intent.
    source_sha = digest({'schema': SCHEMA, 'a3_sha256': a3_report['sha256'],
                         'review_sha256': review['sha256'],
                         'scenario': fixture})
    weights = tuple(review['weights'])
    before = select_development(baseline_candidates, source_sha, weights=weights)
    hypothetical = select_development(hypothetical_candidates, source_sha,
                                     weights=weights)
    verify_selection(before, baseline_candidates)
    verify_selection(hypothetical, hypothetical_candidates)
    need(before['selected'] is None and before['eligible_count'] == 0 and
         before['selection_is_operational'] is False and
         hypothetical['selection_is_operational'] is False and
         before['operational_dispatch'] is False and
         hypothetical['operational_dispatch'] is False and
         before['published_generation'] is None and
         hypothetical['published_generation'] is None and
         before['p8_operational'] == hypothetical['p8_operational'] == 'NO-GO',
         'A4_SELECT_MUST_REMAIN_NONOPERATIONAL')
    need(hypothetical['eligible_count'] == phase_counts['PENDIENTE'],
         'COUNTERFACTUAL_ELIGIBILITY_COUNT')
    report = {
        'schema': SCHEMA,
        'source_base_commit': BASE,
        'mode': 'DUAL_A4_RANKING_NO_STATE_CHANGE',
        'session_id': fixture['session_id'],
        'source_catalog_sha256': review['source_catalog_sha256'],
        'source_thesis_sha256': review['source_thesis_sha256'],
        'r58l_review_sha256': review['sha256'],
        'r58p_a3_projection_sha256': a3_report['sha256'],
        'transition_context_sha256': source_sha,
        'unit_count': len(projections),
        'family_count': a3_report['family_count'],
        'case_count_by_service': a3_report['case_count_by_service'],
        'a3_guard_truth_counts': {k: guard_counts[k]
                                  for k in ('VERDADERO', 'FALSO', 'ND')},
        'hypothetical_phase_counts': {k: phase_counts[k]
                                      for k in ('PREPARADO', 'PENDIENTE')},
        'control_cases': projections,
        'a4_actual_prepared_selection': before,
        'a4_counterfactual_pending_selection': hypothetical,
        'a4_original_assumed_selection': review['a4_selected_identity'],
        'a3_a4_original_guard_mismatch_count': a3_report['a3_a4_guard_mismatch_count'],
        'a3_case_controls_are_typed': True,
        'a3_to_a4_logical_case_mapping': True,
        'a3_to_a4_operational_authority_attested': False,
        'prepared_to_pending_transitions_applied': 0,
        'confirmed_pending_case_count': 0,
        'a5_operational_attempts_started': 0,
        'a6_classification': 'ND',
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'applied_state_transition': None,
        'published_generation': None,
        'a1_a10_implementation_complete': False,
        'experimental_hypothesis_validated': False,
        'vm_checks_executed': False,
        'host_mutations': 0,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) <= MAX_REPORT_BYTES, 'REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify_a3_a4_transition_audit(report: dict[str, Any], scenario: dict[str, Any],
                                  review: dict[str, Any],
                                  a3_report: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str,
         'REPORT_SCHEMA')
    expected = build_a3_a4_transition_audit(scenario, review, a3_report)
    need(canonical(expected) == canonical(report), 'REPORT_NOT_REPRODUCIBLE')
    return True
