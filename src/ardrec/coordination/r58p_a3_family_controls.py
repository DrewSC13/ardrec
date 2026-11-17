"""R58-P: expand real A2/A3 synthetic controls onto each of 25 family cases.

The R26 A3 source only had policy/reference controls on three services.
This module uses R17-R22 to build a NEW, synthetic typed A2 case graph and
A3 diagnostic for all R58-L 25-family cases. It does not amend, ratify or
retroactively authorize R26's operational controls. A4 remains an independent
PENDIENTE-state simulation. No operating systems, P8, VM or journal calls.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.demo_session import (
    build_development_session, normalize_scenario,
)
from ardrec.coordination.r58l_a4_a5_family_review import verify_a4_a5_review
from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, preflight_rule_configuration,
)
from ardrec.initialization.initial_preview import (
    FORMAT as INITIAL_FORMAT, prepare_initial_preview,
)
from ardrec.initialization.dependency_preview import (
    FORMAT as DEPENDENCY_FORMAT, prepare_dependency_preview,
)
from ardrec.initialization.control_preview import (
    FORMAT as CONTROL_FORMAT, prepare_control_preview,
)
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards
from ardrec.state import Truth

SCHEMA = 'ardrec-r58p-a3-25-family-typed-synthetic-control-projection-v1'
BASE = 'ed0bd75f9388c2f0c61166d1a895cb62e64d8438'
SERVICES = {'SSH_DEV': 'SSH', 'FTP_DEV': 'FTP', 'SMB_DEV': 'SMB'}
MAX_CASES = 54
MAX_REPORT_BYTES = 131072


class ProjectionError(ValueError):
    """A3 family-case projection is inconsistent or claims authority."""


def need(predicate: bool, code: str) -> None:
    if not predicate:
        raise ProjectionError(code)


def _case_key(row: dict[str, Any]) -> tuple[str, str, str, int]:
    return (row['service_id'], row['session_id'], row['derived_case_id'],
            row['assessment_index'])


def _control_id(case_id_a7: str) -> str:
    need(type(case_id_a7) is str and len(case_id_a7) == 53 and
         case_id_a7.startswith('CASE_') and
         all(c in '0123456789ABCDEF' for c in case_id_a7[5:]),
         'A7_CASE_ID_INVALID')
    return 'CTRL_' + case_id_a7[5:]


def build_family_a3_projection(scenario: dict[str, Any],
                               review: dict[str, Any]) -> dict[str, Any]:
    """Run genuine R17-R22 rules, A2 references and A3 diagnostic for each case.

    Only creates in-memory state PREPARADO. The A4 PENDIENTE assumptions are
    retained as separate, never authoritative, comparison values.
    """
    fixture = normalize_scenario(scenario)
    r26 = build_development_session(fixture)
    r26.verify()
    verify_a4_a5_review(review)
    need(type(review) is dict and review['session_id'] == fixture['session_id'],
         'SESSION_MISMATCH')
    need(review['unit_count'] == len(review['decisions']) and
         0 < review['unit_count'] <= MAX_CASES and
         review['covered_family_count'] <= 25,
         'CASE_COUNT_INVALID')
    need(review['a6_classification'] == 'ND' and
         review['technical_truth_accredited'] is False and
         review['operational_dispatch'] is False and
         review['p8_operational'] == 'NO-GO' and
         review['confirmed_final_risk'] is None and
         review['published_generation'] is None,
         'REVIEW_FALSE_AUTHORITY')

    rows = sorted(review['decisions'], key=_case_key)
    unique_keys: set[tuple[str, str, str, int]] = set()
    unique_a7: set[str] = set()
    service_rows: dict[str, list[dict[str, Any]]] = {k: [] for k in SERVICES}
    for row in rows:
        need(type(row) is dict and row.get('service_id') in SERVICES and
             row.get('session_id') == fixture['session_id'],
             'CASE_SERVICE_OR_SESSION')
        key = _case_key(row)
        case_id = row['case_id_a7']
        need(key not in unique_keys and case_id not in unique_a7,
             'DUPLICATE_CASE')
        unique_keys.add(key)
        unique_a7.add(case_id)
        _control_id(case_id)
        need(row['a6_classification'] == 'ND' and
             row['technical_truth_accredited'] is False and
             row['confirmed_rf'] is None and
             row['applied_transition'] is None and
             row['published_generation'] is None,
             'CASE_FALSE_AUTHORITY')
        need(type(row['a4_precedence']) is int and
             0 <= row['a4_precedence'] <= 1023 and
             type(row['a4_guard_simulated']) is str and
             row['a4_guard_simulated'] in ('VERDADERO', 'FALSO', 'ND'),
             'CASE_A4_DOMAIN')
        service_rows[row['service_id']].append(row)
    need(all(service_rows.values()), 'THREE_SERVICES_REQUIRED')

    rules = preflight_rule_configuration({
        'format': RULE_FORMAT,
        'fields': {'FACT': 'LOGICO'},
        'services': [{'id': sid, 'initial_state': 'PREPARADO', 'rules': [
            {'id': 'ALLOW', 'salida': 'CASE_POLICY',
             'condicion': {'op': 'CAMPO', 'nombre': 'FACT'}},
            {'id': 'DENY', 'salida': 'CASE_REFERENCE', 'condicion': {
                'op': 'NO', 'arg': {'op': 'CAMPO', 'nombre': 'FACT'}}},
        ]} for sid in sorted(SERVICES)],
    })
    initial = prepare_initial_preview(rules, {
        'format': INITIAL_FORMAT,
        'rule_source_sha256': rules.sha256,
        'services': [{'id': s['id'], 'initial_risk': s['initial_risk'],
                      'normalized_criticality': s['normalized_criticality'],
                      'cases': [
                          {'id': d['case_id_a7'], 'max_repetitions': 0}
                          for d in service_rows[s['id']]
                      ]} for s in fixture['services']],
    })
    deps = prepare_dependency_preview(rules, initial, {
        'format': DEPENDENCY_FORMAT,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'services': [{'id': sid, 'protocol': SERVICES[sid],
                      'cases': [{'id': d['case_id_a7'], 'requires': []}
                                for d in service_rows[sid]]}
                     for sid in sorted(SERVICES)],
    })
    controls = prepare_control_preview(rules, initial, deps, {
        'format': CONTROL_FORMAT,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'dependency_snapshot_sha256': deps.sha256,
        'services': [{'id': sid,
                      'controls': [{'id': _control_id(d['case_id_a7']),
                                    'guard_rule_id': 'ALLOW',
                                    'target_case_id': d['case_id_a7'],
                                    'precedence': d['a4_precedence'],
                                    'requires': []}
                                   for d in service_rows[sid]]}
                     for sid in sorted(SERVICES)],
    })
    integrated = assemble_integrated_preview(rules, initial, deps, controls)
    need(integrated.verify(rules, initial, deps, controls),
         'A2_INTEGRATED_INVALID')
    environments = {s['id']: ({} if s['fact'] == 'AUSENTE' else
                              {'FACT': Truth[s['fact']]})
                    for s in fixture['services']}
    guards = diagnose_guards(rules, initial, deps, controls,
                             integrated, environments)
    need(guards.verify(rules, initial, deps, controls, integrated, environments),
         'A3_DIAGNOSTIC_INVALID')
    need(rules.sha256 == r26.document['sources_sha256']['rules'],
         'R26_RULE_SOURCE_MISMATCH')
    r26_by_service = {r['service_id']: r for r in r26.document['units']}
    guards_by_service = {g.service_id: g for g in guards.units}
    initial_by_service = {u.id: u for u in initial.units}
    need(set(r26_by_service) == set(guards_by_service) == set(SERVICES),
         'SERVICE_COVERAGE_INVALID')
    for sid, g in guards_by_service.items():
        reference = r26_by_service[sid]
        need(g.table_status.name == reference['a3']['table_status'] and
             g.table_selected == reference['a3']['table_selected'] and
              g.table_status.name == reference['a1']['status'] and
              getattr(g, 'table_output', None) == reference['a1'].get('selected_output') and
              getattr(g, 'table_output', None) == reference['a3'].get('table_output'),
             'R26_A3_TABLE_DISAGREEMENT')
        need(initial_by_service[sid].phase.value == 'PREPARADO' and
             all(c.starts_confirmed == 0 for c in initial_by_service[sid].cases),
             'INITIAL_CASES_NOT_PREPARED')
        need(len(g.controls) == len(service_rows[sid]),
             'CONTROL_COUNT_MISMATCH')

    out: list[dict[str, Any]] = []
    for sid in sorted(SERVICES):
        g = guards_by_service[sid]
        lookup = {c.target_case_id: c for c in g.controls}
        need(len(lookup) == len(service_rows[sid]), 'DUPLICATE_CONTROL_TARGET')
        for row in service_rows[sid]:
            target = row['case_id_a7']
            need(target in lookup, 'MISSING_A3_CONTROL')
            c = lookup[target]
            need(c.control_id == _control_id(target) and
                 c.guard_rule_id == 'ALLOW' and
                 c.truth.name in ('VERDADERO', 'FALSO', 'ND') and
                 'AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c.blockers,
                 'CONTROL_REFERENCES_INVALID')
            out.append({
                'service_id': sid, 'session_id': row['session_id'],
                'derived_case_id': row['derived_case_id'],
                'assessment_index': row['assessment_index'],
                'family_id': row['family_id'], 'variant': row['variant'],
                'case_id_a7': target, 'control_id_a3': c.control_id,
                'precedence': row['a4_precedence'],
                'a3_phase': 'PREPARADO',
                'a3_table_status': g.table_status.name,
                'a3_guard_truth': c.truth.name,
                'a3_blockers': list(c.blockers),
                'a4_phase_assumed': 'PENDIENTE' if row['a4_eligible_simulated']
                                    else 'SIMULATED_OTHER_OR_BLOCKED',
                'a4_guard_simulated': row['a4_guard_simulated'],
                'a4_eligible_simulated': row['a4_eligible_simulated'],
                'a3_a4_guard_matches': c.truth.name == row['a4_guard_simulated'],
                'case_reference_is_a3_diagnostic': True,
                'operational_eligibility_attested': False,
                'technical_truth_accredited': False,
                'a6_classification': 'ND',
            })
    out.sort(key=_case_key)
    need(len(out) == len(rows), 'DROPPED_CASE_CONTROL')
    truth_counts = Counter(row['a3_guard_truth'] for row in out)
    mismatches = sum(not row['a3_a4_guard_matches'] for row in out)
    report = {
        'schema': SCHEMA,
        'source_base_commit': BASE,
        'mode': 'GENUINE_R17_R22_A3_SYNTHETIC_CASE_DIAGNOSTICS_ONLY',
        'session_id': fixture['session_id'],
        'r26_session_sha256': r26.sha256,
        'r58l_review_sha256': review['sha256'],
        'source_catalog_sha256': review['source_catalog_sha256'],
        'source_thesis_sha256': review['source_thesis_sha256'],
        'a1_a3_source_sha256': {
            'rules': rules.sha256,
            'initial': initial.sha256,
            'dependencies': deps.sha256,
            'controls': controls.sha256,
            'integrated': integrated.sha256,
            'guard_diagnostic': guards.sha256,
        },
        'control_cases': out,
        'control_reference_count': len(out),
        'family_count': review['covered_family_count'],
        'case_count_by_service': {k: len(service_rows[k]) for k in sorted(SERVICES)},
        'a3_guard_truth_counts': {k: truth_counts[k] for k in
                                  ('VERDADERO','FALSO','ND')},
        'a3_a4_guard_mismatch_count': mismatches,
        'a3_typed_case_references_constructed': True,
        'r26_a3_control_targets_replaced_in_source': False,
        'a3_case_guard_is_operational_authority': False,
        'a4_projection_is_operational': False,
        'a1_a3_to_family_case_authority_attested': False,
        'a1_a10_implementation_complete': False,
        'experimental_hypothesis_validated': False,
        'a6_classification': 'ND',
        'confirmed_final_risk': None,
        'applied_transition': None,
        'published_generation': None,
        'operational_dispatch': False,
        'host_mutations': 0,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) <= MAX_REPORT_BYTES,
         'REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify_family_a3_projection(report: dict[str, Any],
                                scenario: dict[str, Any],
                                review: dict[str, Any]) -> bool:
    need(type(report) is dict and type(report.get('sha256')) is str,
         'REPORT_SCHEMA')
    expected = build_family_a3_projection(scenario, review)
    need(canonical(expected) == canonical(report),
         'REPORT_NOT_REPRODUCIBLE_OR_TAMPERED')
    return True
