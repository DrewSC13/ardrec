#!/usr/bin/env python3
"""R23: orden sintético de controles A3 en 54 servicios, sin despacho."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.state import Truth
from ardrec.initialization.rule_preflight import FORMAT as RF, preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as IF, prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DF, prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CF, prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards
from ardrec.scheduling.agenda_preview import plan_candidate_order


def sample(n: int = 54):
    ids = [f'{p}_{i:02d}' for p in ('SSH', 'FTP', 'SMB') for i in range(1, 19)][:n]
    rules = preflight_rule_configuration({'format': RF, 'fields': {'FACT': 'LOGICO'},
        'services': [{'id': sid, 'initial_state': 'PREPARADO', 'rules': [
            {'id': 'ALLOW', 'condicion': {'op': 'CAMPO', 'nombre': 'FACT'}},
            {'id': 'NEVER', 'condicion': {'op': 'CONSTANTE', 'tipo': 'LOGICO', 'valor': 'FALSO'}}
        ]} for sid in ids]})
    initial = prepare_initial_preview(rules, {'format': IF,
        'rule_source_sha256': rules.sha256,
        'services': [{'id': sid, 'initial_risk': '1/4', 'normalized_criticality': '1/2',
            'cases': [{'id': 'CHECK_A', 'max_repetitions': 0},
                      {'id': 'CHECK_B', 'max_repetitions': 1}]}
            for sid in ids]})
    dependencies = prepare_dependency_preview(rules, initial, {'format': DF,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'services': [{'id': sid, 'protocol': sid.split('_')[0], 'cases': [
            {'id': 'CHECK_A', 'requires': []},
            {'id': 'CHECK_B', 'requires': ['CHECK_A']}]}
            for sid in ids]})
    controls = prepare_control_preview(rules, initial, dependencies, {'format': CF,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'dependency_snapshot_sha256': dependencies.sha256,
        'services': [{'id': sid, 'controls': [
            {'id': 'CONTROL_A', 'guard_rule_id': 'ALLOW', 'target_case_id': 'CHECK_A',
             'precedence': 20, 'requires': []},
            {'id': 'CONTROL_B', 'guard_rule_id': 'ALLOW', 'target_case_id': 'CHECK_B',
             'precedence': 10, 'requires': ['CONTROL_A']}]} for sid in ids]})
    integrated = assemble_integrated_preview(rules, initial, dependencies, controls)
    environments = {}
    for sid in ids:
        group = int(sid.rsplit('_', 1)[1]) % 3
        environments[sid] = {} if group == 0 else {
            'FACT': Truth.VERDADERO if group == 1 else Truth.FALSO}
    diagnostic = diagnose_guards(rules, initial, dependencies, controls,
                                  integrated, environments)
    return (rules, initial, dependencies, controls, integrated, diagnostic, environments)


def main() -> int:
    args = sample()
    plan = plan_candidate_order(*args)
    assert plan.verify(*args)
    candidate_count = sum(len(u.candidates) for u in plan.units)
    excluded_count = sum(len(u.excluded) for u in plan.units)
    assert len(plan.units) == 54 and candidate_count == 36 and excluded_count == 72
    assert all(not c.executable for u in plan.units for c in u.candidates)
    assert plan.executable_agenda is None and not plan.operational_dispatch_allowed
    out = {
        'schema': 'ardrec-p14-r23-a3-candidate-order-demo-v1',
        'scope': 'SYNTHETIC_NON_EXECUTABLE_CANDIDATE_ORDER',
        'service_count': len(plan.units),
        'protocol_counts': {p: sum(u.protocol == p for u in plan.units)
                            for p in ('SSH', 'FTP', 'SMB')},
        'case_count': sum(len(u.cases) for u in args[4].units),
        'control_count': sum(len(u.controls) for u in args[4].units),
        'trivalent_table_counts': {v.name:sum(u.table_status is v for u in args[5].units)
                                   for v in Truth},
        'candidate_count': candidate_count, 'excluded_count': excluded_count,
        'first_candidate_control_order': [c.control_id for c in next(
            u for u in plan.units if u.candidates).candidates],
        'all_candidates_unexecutable': all(not c.executable for u in plan.units
                                            for c in u.candidates),
        'all_candidates_authority_blocked': all(
            'AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c.blockers
            for u in plan.units for c in u.candidates),
        'initial_all_prepared': all(u.phase.value == 'PREPARADO' for u in args[1].units),
        'initial_all_evidence_zero': all(u.accumulated_evidence == 0 for u in args[1].units),
        'integrated_sha256': args[4].sha256,
        'diagnostic_sha256': args[5].sha256,
        'candidate_order_sha256': plan.sha256,
        'executable_agenda': plan.executable_agenda,
        'generation_published': plan.published_generation is not None,
        'operational_dispatch': plan.operational_dispatch_allowed,
        'p8_operational': 'NO-GO',
        'a1_full': False, 'a2_full': False, 'a3_full': False,
    }
    print(json.dumps(out, sort_keys=True, separators=(',', ':')))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
