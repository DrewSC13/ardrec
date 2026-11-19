"""R109: execute/reconcile offline A4/A6/A7/A8 decision kernels for 54 cases.

Not a complete operational A1-A10 executor. A1-A3 and A5/A9 remain
unattested. The counterfactual T8-T10 ledger is not an A8 operational act.
Inputs are already independently verified R104/R107/R108 private receipts.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.analytics.exact_preview import rational
from ardrec.analytics.r58d_interval_kernel import verify_intervals
from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r107_offline_a1_a10_orchestrator as r107
from ardrec.coordination import r108_offline_state_execution as r108
from ardrec.coordination.r58k_unified_family_bridge import (
    build_unified_preview, verify_unified_preview,
)
from ardrec.coordination.r58e_evidence_risk_bridge import verify_unit_bridge
from ardrec.state import Truth
from ardrec.stopping.development_stop import preview_stop, verify_stop

SCHEMA = 'ardrec-r109-executable-offline-decision-chain-v1'
MODE = 'OFFLINE_RECOMPUTED_A4_A6_A7_A8_WITH_MODEL_REPLAY_NO_AUTHORITY'
ALGOS = tuple('A' + str(i) for i in range(1, 11))
ACTIVE_MATH = frozenset(('A4', 'A6', 'A7', 'A8', 'A10'))
MAX_BYTES = 900_000


class ChainError(ValueError):
    """Fail closed on a changed case, mathematical result, or authority claim."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise ChainError(code)


def _unique(rows: list[dict], key: str, code: str) -> dict[str, dict]:
    result = {}
    need(type(rows) is list, code)
    for row in rows:
        need(type(row) is dict and type(row.get(key)) is str
             and row[key] not in result, code)
        result[row[key]] = row
    return result


def build(unified: dict[str, Any], trace: dict[str, Any],
          model: dict[str, Any]) -> dict[str, Any]:
    """Actually run deterministic rule, risk, stop and model replay kernels."""
    verify_unified_preview(unified)
    r108.verify(model, trace)
    need(unified.get('sha256') == trace.get('r104_report_sha256')
         and trace.get('sha256') == model.get('r107_trace_sha256')
         and len(unified['decisions']) == 54 and len(trace['cases']) == 54
         and len(model['cases']) == 54 and len(model['events']) == 72,
         'SOURCE_DAG_OR_COVERAGE_DRIFT')

    # Recalculate A4 family logic, A6 conservative intake and A7/A8 bridge
    # from original synthetic inputs; compare the entire canonical result.
    repeated = build_unified_preview(unified['inputs'],
                                     weights=tuple(unified['weights']))
    need(repeated == unified, 'A4_RULE_OR_SOURCE_NOT_REPRODUCIBLE')
    bridge = unified['a6_a7_a8_bridge']
    verify_unit_bridge(bridge)
    math = bridge['a7']
    verify_intervals(math)
    need(len(math['results']) == 54 and len(bridge['decisions']) == 54
         and len(bridge['a6_inputs']) == 0
         and bridge['documentary_admission_count'] == 0,
         'A6_A7_INPUTS_UNEXPECTED')

    cases = _unique(trace['cases'], 'case_id_a7', 'TRACE_ID_DUPLICATE')
    phases = _unique(model['cases'], 'case_id_a7', 'MODEL_ID_DUPLICATE')
    decisions = _unique(unified['decisions'], 'case_id_a7', 'A4_ID_DUPLICATE')
    a7 = _unique(math['results'], 'case_id', 'A7_ID_DUPLICATE')
    bridge_rows = _unique(bridge['decisions'], 'case_id', 'BRIDGE_ID_DUPLICATE')
    need(set(cases) == set(phases) == set(decisions) == set(a7) == set(bridge_rows),
         'ONE_TO_ONE_CASE_BINDING')

    results = []
    previous = None
    counts = Counter()
    execution_count = Counter()
    for cid in sorted(cases):
        case, phase, dec, interval, b = (
            cases[cid], phases[cid], decisions[cid], a7[cid], bridge_rows[cid])
        need(case['family_id'] == dec['family_id'] == phase['family_id']
             and case['service_id'] == dec['service_id'] == phase['service_id']
             and case['case_sha256'] == phase['r107_case_sha256']
             and case['a7_interval_lower'] == dec['a7_rf_lower'] == interval['rf_lower']
             and case['a7_interval_upper'] == dec['a7_rf_upper'] == interval['rf_upper']
             and b['a7_rf_lower'] == interval['rf_lower']
             and b['a7_rf_upper'] == interval['rf_upper']
             and b['a8_stop_sha256'] == dec['a8_stop_sha256']
             and b['a6_classification'] == dec['a6_classification'] == 'ND'
             and b['a6_status'] == 'MISSING_DOCUMENTARY_ADMISSION'
             and b['a6_admission_sha256'] is None,
             'CROSS_KERNEL_DECISION_DRIFT')
        lo, hi = rational(interval['rf_lower']), rational(interval['rf_upper'])
        need(lo <= hi and interval['evidence_lower'] == '0'
             and interval['evidence_upper'] == '1'
             and interval['point_identified'] is False
             and interval['confirmed_rf'] is None,
             'A7_UNACCREDITED_INTERVAL_DRIFT')
        # A6 is a three-valued decision, not false/zero when support is absent.
        technical_guard = Truth.ND
        need(technical_guard is Truth.ND
             and dec['technical_truth_accredited'] is False
             and case['a5_operational_starts'] == 0
             and phase['operational_transition_applied'] is False,
             'A6_A5_AUTHORITY_PROMOTION')
        pause = preview_stop(a6_classification=technical_guard.value,
                             accredited=False, vm_checked=False,
                             operational_dispatch=False,
                             source_sha256=b['a8_source_sha256'])
        verify_stop(pause)
        need(pause['sha256'] == b['a8_stop_sha256']
             and pause['recommendation'] == dec['a8_recommendation']
             and pause['recommendation'] == 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'
             and pause['applied_transition'] is None,
             'A8_STOP_KERNEL_MISMATCH')
        need(phase['final_model_phase'] in ('PAUSADO', 'PENDIENTE', 'DETENIDO')
             and phase['model_branch'] in r108.PATTERNS
             and phase['a9_published_generation'] is None
             and dec['published_generation'] is None,
             'MODEL_PHASE_OR_A9_PROMOTION')

        # Ten hash-bound decision checkpoints; only the documented subset
        # actually invokes kernels. Others explicitly record a barrier.
        stage_inputs = (
            ('SOURCE_REGISTERED', case['case_sha256']),
            ('CATALOG_PINNED', unified['source_catalog_sha256']),
            ('AUTHORITY_NOT_ATTESTED', trace['sha256']),
            ('FAMILY_RULE_COMPUTED', a5.digest({
                'family': dec['family_id'],
                'hypothetical_class': dec['hypothetical_result_class'],
                'hypothetical_truth': dec['hypothetical_condition_truth'],
                'guard': dec['guard_simulated']})),
            ('NO_OPERATIONAL_START', trace['r106_link_sha256']
             if case['r106_provenance_association_only'] else trace['sha256']),
            ('THREE_VALUED_ND_COMPUTED', a5.digest({
                'truth': technical_guard.value, 'documentary_admission': None})),
            ('EXACT_RATIONAL_INTERVAL_COMPUTED', a5.digest(interval)),
            ('CONSERVATIVE_STOP_COMPUTED_NOT_APPLIED', pause['sha256']),
            ('NO_GENERATION_PUBLISHED', a5.digest({'generation': None})),
            ('REPLAY_AUDITED', phase['sha256']),
        )
        chain = []
        stage_head = None
        for algorithm, (status, output_sha) in zip(ALGOS, stage_inputs):
            executable = algorithm in ACTIVE_MATH
            item = {'algorithm': algorithm, 'status': status,
                    'kind': 'OFFLINE_KERNEL_EXECUTED' if executable else 'NOT_OPERATIONAL',
                    'result_sha256': output_sha,
                    'previous_stage_sha256': stage_head}
            item['sha256'] = a5.digest(item)
            chain.append(item)
            stage_head = item['sha256']
            if executable:
                execution_count[algorithm] += 1
        row = {
            'case_id_a7': cid, 'service_id': dec['service_id'],
            'family_id': dec['family_id'],
            'hypothetical_result_class': dec['hypothetical_result_class'],
            'a6_truth': technical_guard.value,
            'a7_rf_lower': str(lo), 'a7_rf_upper': str(hi),
            'a7_rf_confirmed': None,
            'a8_recommendation': pause['recommendation'],
            'a8_operational_transition': None,
            'counterfactual_final_phase': phase['final_model_phase'],
            'counterfactual_model_revision': phase['model_revision'],
            'counterfactual_model_event_sha256': phase['model_event_sha256'],
            'a9_published_generation': None,
            'r106_fixture_association_only': case['r106_provenance_association_only'],
            'stage_chain': chain, 'stage_head_sha256': stage_head,
            'previous_case_sha256': previous,
        }
        row['sha256'] = a5.digest(row)
        previous = row['sha256']
        results.append(row)
        counts[dec['service_id']] += 1
    need(len(results) == 54 and sum(counts.values()) == 54
         and dict(counts) == r107.COUNTS
         and execution_count == Counter({a: 54 for a in ACTIVE_MATH})
         and sum(c['r106_fixture_association_only'] for c in results) == 1,
         'OFFLINE_KERNEL_COVERAGE_DRIFT')
    result = {
        'schema': SCHEMA, 'mode': MODE,
        'r104_sha256': unified['sha256'],
        'r107_sha256': trace['sha256'],
        'r108_sha256': model['sha256'],
        'r108_model_event_head_sha256': model['model_event_head_sha256'],
        'source_catalog_sha256': unified['source_catalog_sha256'],
        'source_thesis_sha256': unified['source_thesis_sha256'],
        'case_count': 54, 'family_count': 25,
        'protocol_counts': dict(counts),
        'status_stage_count': len(results) * 10,
        'offline_case_checks_by_stage': dict(execution_count),
        'rechecked_r108_model_events': 72,
        'mathematical_interval_count': len(results),
        'model_phase_counts': model['model_phase_counts'],
        'case_chain_head_sha256': previous,
        'cases': results,
        'a1_a10_operational_implementation_complete': False,
        'a5_operational_starts': 0, 'a6_classification': 'ND',
        'a7_confirmed_rf': None, 'a8_operational_transitions': 0,
        'a9_published_generations': 0,
        'operational_dispatch': False, 'vm_starts': 0,
        'host_mutations': 0, 'p8_operational': 'NO-GO',
    }
    need(len(a5.canonical(result)) < MAX_BYTES, 'R109_REPORT_TOO_LARGE')
    result['sha256'] = a5.digest(result)
    return result


def verify(receipt: dict[str, Any], unified: dict[str, Any],
           trace: dict[str, Any], model: dict[str, Any]) -> bool:
    need(type(receipt) is dict and receipt == build(unified, trace, model),
         'OFFLINE_DECISION_REPLAY_DRIFT')
    return True
