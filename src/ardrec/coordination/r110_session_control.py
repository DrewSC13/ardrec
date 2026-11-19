"""R110: executable offline A1-A3 control graph for 54 synthetic windows.

Reuses R17-R22 and the genuine state T1 contract. R26's THREE frozen
service facts are projected to R104's TWO synthetic sessions. This is NOT
an independent A1-A3 authorization for either synthetic or real sessions.
Operational authority stays ND; no service transition, process or dispatch.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r109_executable_decision_chain as r109
from ardrec.coordination.demo_session import build_development_session, normalize_scenario
from ardrec.initialization.rule_preflight import FORMAT as RULE_FORMAT, preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as INITIAL_FORMAT, prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DEPENDENCY_FORMAT, prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CONTROL_FORMAT, prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards
from ardrec.state import (
    ConfirmedState, GlobalState, GuardFact, ServicePhase, ServiceState,
    StateError, Transition, TransitionContext, TransitionRecord, Truth,
    transition_service,
)

SCHEMA = 'ardrec-r110-offline-54-case-a1-a3-session-control-v1'
MODE = 'R26_SERVICE_FACTS_PROJECTED_NO_INDEPENDENT_SECOND_SESSION_AUTHORITY'
COUNTS = {'SSH_DEV': 16, 'FTP_DEV': 20, 'SMB_DEV': 18}
MAX_BYTES = 250_000


class SessionControlError(ValueError):
    """Incompatible immutable input, control guard or model authority claim."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise SessionControlError(code)


def build(unified: dict[str, Any], trace: dict[str, Any],
          model: dict[str, Any], decisions: dict[str, Any],
          scenario: dict[str, Any]) -> dict[str, Any]:
    """Re-execute actual R17-R22 kernels; reject T1 under ND authority."""
    r109.verify(decisions, unified, trace, model)
    fixture = normalize_scenario(scenario)
    r26 = build_development_session(fixture)
    r26.verify()
    need(fixture['session_id'] == 'DEV_TUTOR_001'
         and decisions.get('case_count') == 54
         and decisions.get('p8_operational') == 'NO-GO', 'SOURCE_SCOPE_INVALID')

    # Each case is identified by its A7 ID, not just the three service IDs.
    by_service = {sid: [] for sid in COUNTS}
    expected = {d['case_id_a7']: d for d in unified['decisions']}
    need(len(expected) == 54, 'CASE_ID_NOT_UNIQUE')
    for item in decisions['cases']:
        original = expected.get(item['case_id_a7'])
        need(original is not None and item['service_id'] == original['service_id']
             and item['family_id'] == original['family_id']
             and item['a6_truth'] == 'ND'
             and item['a9_published_generation'] is None,
             'CROSS_STAGE_CASE_DRIFT')
        by_service[item['service_id']].append(original)
    need({k: len(v) for k, v in by_service.items()} == COUNTS,
         'THREE_SERVICE_COVERAGE_DRIFT')
    for rows in by_service.values():
        rows.sort(key=lambda x: x['case_id_a7'])
    services = {s['id']: s for s in fixture['services']}
    service_ids = sorted(COUNTS)
    rules = preflight_rule_configuration({
        'format': RULE_FORMAT, 'fields': {'FACT': 'LOGICO'},
        'services': [{'id': sid, 'initial_state': 'PREPARADO', 'rules': [
            {'id': 'ALLOW', 'salida': 'CASE_POLICY',
             'condicion': {'op': 'CAMPO', 'nombre': 'FACT'}},
            {'id': 'DENY', 'salida': 'CASE_REFERENCE',
             'condicion': {'op': 'NO', 'arg': {'op': 'CAMPO', 'nombre': 'FACT'}}},
        ]} for sid in service_ids],
    })
    need(rules.sha256 == r26.document['sources_sha256']['rules'],
         'R26_A1_RULE_SOURCE_NOT_IDENTICAL')
    initial = prepare_initial_preview(rules, {
        'format': INITIAL_FORMAT, 'rule_source_sha256': rules.sha256,
        'services': [{'id': sid,
                      'initial_risk': services[sid]['initial_risk'],
                      'normalized_criticality': services[sid]['normalized_criticality'],
                      'cases': [{'id': d['case_id_a7'], 'max_repetitions': 0}
                                for d in by_service[sid]]}
                     for sid in service_ids],
    })
    dependencies = prepare_dependency_preview(rules, initial, {
        'format': DEPENDENCY_FORMAT, 'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'services': [{'id': sid, 'protocol': services[sid]['protocol'],
                      'cases': [{'id': d['case_id_a7'], 'requires': []}
                                for d in by_service[sid]]}
                     for sid in service_ids],
    })
    controls = prepare_control_preview(rules, initial, dependencies, {
        'format': CONTROL_FORMAT, 'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'dependency_snapshot_sha256': dependencies.sha256,
        'services': [{'id': sid,
                      'controls': [{'id': 'CTRL_' + d['case_id_a7'][5:],
                                    'guard_rule_id': 'ALLOW',
                                    'target_case_id': d['case_id_a7'],
                                    'precedence': d['precedence'], 'requires': []}
                                   for d in by_service[sid]]}
                     for sid in service_ids],
    })
    integrated = assemble_integrated_preview(rules, initial, dependencies, controls)
    need(integrated.verify(rules, initial, dependencies, controls),
         'A2_INTEGRATION_INVALID')
    environments = {
        sid: ({} if services[sid]['fact'] == 'AUSENTE'
              else {'FACT': Truth[services[sid]['fact']]})
        for sid in service_ids
    }
    guards = diagnose_guards(rules, initial, dependencies, controls,
                             integrated, environments)
    need(guards.verify(rules, initial, dependencies, controls,
                       integrated, environments), 'A3_GUARDS_INVALID')
    r26_units = {x['service_id']: x for x in r26.document['units']}
    control_lookup = {}
    for unit in guards.units:
        need(unit.table_status.name == r26_units[unit.service_id]['a3']['table_status'],
             'A1_A3_TABLE_BASELINE_DISAGREEMENT')
        for control in unit.controls:
            need(control.target_case_id not in control_lookup,
                 'CONTROL_TARGET_DUPLICATED')
            control_lookup[control.target_case_id] = control
    need(set(control_lookup) == set(expected), 'CONTROL_COVERAGE_INVALID')

    # Crucial: the actual GlobalState authority is ND, even if a diagnostic
    # service guard is VERDADERO. The real state machine must reject every T1.
    config_sha = integrated.sha256
    initial_states = tuple(ServiceState(cid, ServicePhase.PREPARADO)
                           for cid in sorted(expected))
    confirmed = ConfirmedState(
        record_id='R110_SYNTHETIC_RECORD', generation=0,
        generation_reference='R110_GENERATION_ZERO',
        configuration_sha256=config_sha,
        versions_reference='R110_FROZEN_A2', services=initial_states,
    )
    state = GlobalState(confirmed=confirmed, execution_id='R110_OFFLINE_MODEL',
                        services=initial_states, authority=Truth.ND,
                        simulation=True)
    need('authority_unverified' in state.dispatch_blockers,
         'OPERATIONAL_AUTHORITY_NOT_BLOCKED')

    by_decision = {x['case_id_a7']: x for x in decisions['cases']}
    rows, previous = [], None
    truths = Counter()
    hypothetical_candidates = 0
    for number, cid in enumerate(sorted(expected), 1):
        original, control, row = expected[cid], control_lookup[cid], by_decision[cid]
        need(control.control_id == 'CTRL_' + cid[5:]
             and control.guard_rule_id == 'ALLOW'
             and control.truth in Truth
             and 'AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in control.blockers,
             'CASE_A3_GUARD_INVALID')
        preconditions_truth = control.truth
        truths[preconditions_truth.name] += 1
        context = TransitionContext(
            record_id=confirmed.record_id, execution_id=state.execution_id,
            generation=0, configuration_sha256=config_sha,
            event_reference=f'SIM_T1_REJECT_{number:03d}',
            facts=(
                GuardFact('preparation_authorized', Truth.ND,
                          f'UNATTESTED_AUTH_{number:03d}'),
                GuardFact('preconditions_valid', preconditions_truth,
                          f'R110_A3_GUARD_{number:03d}'),
            ),
        )
        try:
            transition_service(state, cid, Transition.PREPARAR, context)
        except StateError as error:
            need(error.code == 'authority_unverified',
                 'UNEXPECTED_T1_BLOCK_REASON')
        else:
            raise SessionControlError('T1_OPERATIONAL_TRANSITION_ESCAPED')
        # Pure T1 record is possible ONLY after injecting explicit fictional
        # authorization AND if the A3 logical guard is genuinely true.
        candidate_sha = None
        if preconditions_truth is Truth.VERDADERO:
            assumptions = TransitionContext(
                record_id=confirmed.record_id, execution_id=state.execution_id,
                generation=0, configuration_sha256=config_sha,
                event_reference=f'SIM_T1_PROPOSE_{number:03d}',
                facts=(
                    GuardFact('preparation_authorized', Truth.VERDADERO,
                              f'SYNTH_AUTH_ASSUMPTION_{number:03d}'),
                    GuardFact('preconditions_valid', Truth.VERDADERO,
                              f'SYNTH_PRECOND_ASSUMPTION_{number:03d}'),
                ),
            )
            proposal = TransitionRecord(Transition.PREPARAR,
                                        ServicePhase.PREPARADO,
                                        ServicePhase.PENDIENTE, assumptions)
            need(proposal.after is ServicePhase.PENDIENTE,
                 'T1_MODEL_RECORD_INVALID')
            candidate_sha = a5.digest({
                'case': cid, 'transition': 'T1',
                'assumptions': 'FICTIONAL_NO_AUTHORITY',
                'source_control': control.control_id,
                'a3_truth': preconditions_truth.name,
                'a2_sha256': config_sha,
            })
            hypothetical_candidates += 1
        item = {
            'case_id_a7': cid,
            'service_id': original['service_id'],
            'session_id': original['session_id'],
            'family_id': original['family_id'],
            'r109_case_sha256': row['sha256'],
            'a1_rule_source_sha256': rules.sha256,
            'a2_integrated_sha256': config_sha,
            'a3_diagnostic_sha256': guards.sha256,
            'control_id_a3': control.control_id,
            'a3_table_truth': next(u.table_status.name for u in guards.units
                                   if u.service_id == original['service_id']),
            'a3_guard_truth': preconditions_truth.name,
            'a3_blockers': list(control.blockers),
            't1_counterfactual_candidate_sha256': candidate_sha,
            't1_rejected_reason': 'authority_unverified',
            't1_operational_applied': False,
            'a5_operational_starts': 0,
            'a6_technical_truth': 'ND',
            'a9_published_generation': None,
            'previous_case_sha256': previous,
        }
        item['sha256'] = a5.digest(item)
        previous = item['sha256']
        rows.append(item)
    need(dict(truths) == {'VERDADERO': 16, 'FALSO': 18, 'ND': 20}
         and hypothetical_candidates == 16
         and len(rows) == 54
         and all(s.phase is ServicePhase.PREPARADO for s in state.services),
         'T1_OR_GUARD_COUNTS_DRIFT')
    result = {
        'schema': SCHEMA, 'mode': MODE,
        'r26_fixed_scenario_sha256': a5.digest(fixture),
        'r26_a1_a3_session_sha256': r26.sha256,
        'r104_unified_sha256': unified['sha256'],
        'r107_trace_sha256': trace['sha256'],
        'r108_model_sha256': model['sha256'],
        'r109_decision_sha256': decisions['sha256'],
        'a1_a3_source_hashes': {
            'rules': rules.sha256, 'initial': initial.sha256,
            'dependencies': dependencies.sha256, 'controls': controls.sha256,
            'integrated': integrated.sha256, 'guards': guards.sha256,
        },
        'case_count': len(rows), 'family_count': 25,
        'session_ids': sorted({x['session_id'] for x in rows}),
        'counts_by_service': COUNTS,
        'a3_truth_counts': dict(truths),
        't1_counterfactual_candidates': hypothetical_candidates,
        't1_denied_by_authority': len(rows),
        'operational_t1_transitions': 0,
        'a1_a3_independent_session_authority': False,
        'r26_second_session_observed': False,
        'a1_a10_operational_implementation_complete': False,
        'case_chain_head_sha256': previous,
        'cases': rows,
        'a5_operational_starts': 0, 'a6_classification': 'ND',
        'a7_confirmed_rf': None, 'a8_operational_transitions': 0,
        'a9_published_generations': 0, 'operational_dispatch': False,
        'host_mutations': 0, 'vm_starts': 0, 'p8_operational': 'NO-GO',
    }
    need(len(a5.canonical(result)) <= MAX_BYTES, 'DOCUMENT_TOO_LARGE')
    result['sha256'] = a5.digest(result)
    return result


def verify(receipt: dict[str, Any], unified: dict[str, Any],
           trace: dict[str, Any], model: dict[str, Any],
           decisions: dict[str, Any], scenario: dict[str, Any]) -> bool:
    need(type(receipt) is dict and receipt == build(unified, trace, model,
                                                   decisions, scenario),
         'R110_REPLAY_MISMATCH')
    return True
