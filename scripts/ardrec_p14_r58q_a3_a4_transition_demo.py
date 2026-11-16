#!/usr/bin/env python3
"""R58-Q: compare real PREPARADO and hypothetical PENDIENTE, with no transitions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
from ardrec.coordination.r58q_transition_guard_bridge import (
    build_a3_a4_transition_audit, verify_a3_a4_transition_audit,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58Q=BLOCKED:EXPLICIT_OFFLINE_MODE_AND_REPO_ROOT_REQUIRED',
              file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO / 'lab/p14-r26-session-v1/scenario.json')
        review = build_a4_a5_review(synthetic_entries())
        a3 = build_family_a3_projection(scenario, review)
        trace = build_a3_a4_transition_audit(scenario, review, a3)
        verify_a3_a4_transition_audit(trace, scenario, review, a3)
        assert trace['unit_count'] == 29
        assert trace['family_count'] == 25
        assert trace['a4_actual_prepared_selection']['eligible_count'] == 0
        assert trace['a4_actual_prepared_selection']['selected'] is None
        assert trace['a4_counterfactual_pending_selection']['eligible_count'] == 8
        assert trace['prepared_to_pending_transitions_applied'] == 0
        assert trace['a3_to_a4_operational_authority_attested'] is False
        assert trace['a6_classification'] == 'ND'
        assert trace['p8_operational'] == 'NO-GO'
        summary = {
            'schema': trace['schema'], 'sha256': trace['sha256'],
            'case_count': trace['unit_count'],
            'family_count': trace['family_count'],
            'case_count_by_service': trace['case_count_by_service'],
            'a3_guard_truth_counts': trace['a3_guard_truth_counts'],
            'a3_a4_guard_mismatch_count': trace['a3_a4_original_guard_mismatch_count'],
            'actual_a4_eligible_count': trace['a4_actual_prepared_selection']['eligible_count'],
            'actual_a4_selected': trace['a4_actual_prepared_selection']['selected'],
            'hypothetical_pending_count': trace['hypothetical_phase_counts']['PENDIENTE'],
            'hypothetical_a4_eligible_count': trace['a4_counterfactual_pending_selection']['eligible_count'],
            'hypothetical_a4_selected': trace['a4_counterfactual_pending_selection']['selected'],
            'original_r58l_assumed_selection': trace['a4_original_assumed_selection'],
            'transitions_applied': trace['prepared_to_pending_transitions_applied'],
            'operational_authority_attested': trace['a3_to_a4_operational_authority_attested'],
            'a6_classification': trace['a6_classification'],
            'confirmed_final_risk': trace['confirmed_final_risk'],
            'published_generation': trace['published_generation'],
            'operational_dispatch': trace['operational_dispatch'],
            'p8_operational': trace['p8_operational'],
        }
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except (ValueError, KeyError, TypeError, OSError, RuntimeError,
            AssertionError, RecursionError) as exc:
        print('R58Q=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180],
              file=sys.stderr)
        print('R58Q_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
