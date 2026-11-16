#!/usr/bin/env python3
"""R58-S: local durable denial for A3/A4 requests; zero state transitions."""
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
from ardrec.coordination.r58r_durable_transition_proposal import persist_proposal
from ardrec.coordination.r58s_transition_deny_gate import (
    build_deny_gate, persist_deny_gate, verify_persisted_deny_gate,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58S=BLOCKED:OFFLINE_AND_REPOSITORY_ROOT_REQUIRED',file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
        review = build_a4_a5_review(synthetic_entries())
        a3 = build_family_a3_projection(scenario,review)
        trace = build_a3_a4_transition_audit(scenario,review,a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58s-synthetic-') as work:
            proposal_root = Path(work) / 'proposal'
            gate_root = Path(work) / 'gate'
            proposal_root.mkdir(mode=0o700)
            gate_root.mkdir(mode=0o700)
            r58r = persist_proposal(proposal_root,trace,scenario,review,a3)
            gate = build_deny_gate(proposal_root,trace,scenario,review,a3)
            first = persist_deny_gate(gate_root,proposal_root,trace,scenario,review,a3)
            replay = persist_deny_gate(gate_root,proposal_root,trace,scenario,review,a3)
            verified = verify_persisted_deny_gate(gate_root,proposal_root,
                                                  trace,scenario,review,a3)
            assert r58r['persist_status'] == 'CREATED'
            assert first['persist_status'] == 'CREATED'
            assert replay['persist_status'] == 'REPLAY_IDENTICAL'
            assert verified['verification'] == 'PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION'
            assert verified['receipt_sha256'] == gate['sha256']
            assert gate['case_count'] == 29
            assert gate['family_count'] == 25
            assert gate['request_count'] == 8
            assert gate['not_eligible_count'] == 21
            assert gate['all_requests_denied'] is True
            assert gate['transitions_applied'] == 0
            assert gate['p8_operational'] == 'NO-GO'
            assert len(list(proposal_root.iterdir())) == 1
            assert len(list(gate_root.iterdir())) == 1
            output = {
                'schema': gate['schema'], 'sha256': gate['sha256'],
                'case_count': gate['case_count'], 'family_count': gate['family_count'],
                'logical_candidate_requests': gate['request_count'],
                'not_eligible_count': gate['not_eligible_count'],
                'denials_by_reason': gate['denials_by_reason'],
                'all_requests_denied': gate['all_requests_denied'],
                'proposal_receipt': r58r['persist_status'],
                'gate_first': first['persist_status'],
                'gate_replay': replay['persist_status'],
                'gate_verification': verified['verification'],
                'gate_receipt_count': len(list(gate_root.iterdir())),
                'transitions_applied': gate['transitions_applied'],
                'state_machine_mutated': gate['state_machine_mutated'],
                'independent_authority_attested': gate['independent_authority_attested'],
                'signed_approval_attested': gate['signed_approval_attested'],
                'transition_commit_attested': gate['transition_commit_attested'],
                'a6_classification': gate['a6_classification'],
                'confirmed_final_risk': gate['confirmed_final_risk'],
                'published_generation': gate['published_generation'],
                'operational_dispatch': gate['operational_dispatch'],
                'p8_operational': gate['p8_operational'],
            }
            print(json.dumps(output,ensure_ascii=True,indent=2,sort_keys=True))
        return 0
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,
            AssertionError,RecursionError) as exc:
        print('R58S=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R58S_P8=NO-GO',file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
