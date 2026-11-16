#!/usr/bin/env python3
"""R58-R: create/replay/verify a temporary immutable A3/A4 proposal ONLY."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))

from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
from ardrec.coordination.r58q_transition_guard_bridge import build_a3_a4_transition_audit
from ardrec.coordination.r58r_durable_transition_proposal import (
    build_proposal, persist_proposal, verify_persisted_proposal,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    options = parser.parse_args()
    if not options.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58R=BLOCKED:OFFLINE_AND_REPO_ROOT_REQUIRED', file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO / 'lab/p14-r26-session-v1/scenario.json')
        review = build_a4_a5_review(synthetic_entries())
        a3 = build_family_a3_projection(scenario, review)
        trace = build_a3_a4_transition_audit(scenario, review, a3)
        proposal = build_proposal(trace, scenario, review, a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58r-proposal-') as tmp:
            root = Path(tmp).resolve()
            created = persist_proposal(root, trace, scenario, review, a3)
            replay = persist_proposal(root, trace, scenario, review, a3)
            verified = verify_persisted_proposal(root, trace, scenario, review, a3)
            assert created['persist_status'] == 'CREATED'
            assert replay['persist_status'] == 'REPLAY_IDENTICAL'
            assert verified['verification'] == 'PASS_DECLARED_LOCAL_PROPOSAL_NO_TRANSITION'
            assert verified['receipt_sha256'] == proposal['sha256']
            assert proposal['case_count'] == 29
            assert proposal['family_count'] == 25
            assert proposal['current_prepared_count'] == 29
            assert proposal['counterfactual_pending_count'] == 8
            assert proposal['a4_current_eligible_count'] == 0
            assert proposal['a4_counterfactual_eligible_count'] == 8
            assert proposal['transitions_applied'] == 0
            assert proposal['confirmed_pending_case_count'] == 0
            assert proposal['technical_truth_accredited'] is False
            assert proposal['operational_dispatch'] is False
            assert proposal['p8_operational'] == 'NO-GO'
            print(json.dumps({
                'schema': proposal['schema'],
                'sha256': proposal['sha256'],
                'case_count': proposal['case_count'],
                'family_count': proposal['family_count'],
                'current_prepared_count': proposal['current_prepared_count'],
                'counterfactual_pending_count': proposal['counterfactual_pending_count'],
                'a4_current_eligible_count': proposal['a4_current_eligible_count'],
                'a4_counterfactual_eligible_count': proposal['a4_counterfactual_eligible_count'],
                'create_status': created['persist_status'],
                'replay_status': replay['persist_status'],
                'verification': verified['verification'],
                'receipt_file_count': len(list(root.iterdir())),
                'transitions_applied': proposal['transitions_applied'],
                'state_machine_mutated': verified['state_machine_mutated'],
                'technical_truth_accredited': verified['technical_truth_accredited'],
                'a6_classification': 'ND',
                'confirmed_final_risk': proposal['confirmed_final_risk'],
                'published_generation': proposal['published_generation'],
                'operational_dispatch': proposal['operational_dispatch'],
                'p8_operational': proposal['p8_operational'],
            }, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError, AssertionError,
            RuntimeError, RecursionError) as exc:
        print('R58R=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58R_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
