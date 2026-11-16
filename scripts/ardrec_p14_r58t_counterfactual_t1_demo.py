#!/usr/bin/env python3
"""R58-T: demonstrate private SQLite atomic *simulated* T1 without A5 or P8."""
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
from ardrec.coordination.r58s_transition_deny_gate import build_deny_gate, persist_deny_gate
from ardrec.coordination.r58t_counterfactual_state_store import (
    initialize_simulator, inspect_simulator, simulate_t1, SimulatorError,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58T=BLOCKED:OFFLINE_AND_REPOSITORY_ROOT_REQUIRED', file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO / 'lab/p14-r26-session-v1/scenario.json')
        review = build_a4_a5_review(synthetic_entries())
        a3 = build_family_a3_projection(scenario, review)
        trace = build_a3_a4_transition_audit(scenario, review, a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58t-sandbox-') as tmp:
            root = Path(tmp).resolve()
            proposal_root, gate_root, simulator_root = (root/x for x in ('proposal','gate','simulator'))
            for d in (proposal_root,gate_root,simulator_root):
                d.mkdir(mode=0o700)
            persist_proposal(proposal_root, trace, scenario, review, a3)
            gate = build_deny_gate(proposal_root, trace, scenario, review, a3)
            persist_deny_gate(gate_root, proposal_root, trace, scenario, review, a3)
            inputs = (simulator_root,gate_root,proposal_root,trace,scenario,review,a3)
            first = initialize_simulator(*inputs)
            replay = initialize_simulator(*inputs)
            eligible = [case for case in gate['cases'] if case['logical_candidate']]
            ineligible = [case for case in gate['cases'] if not case['logical_candidate']]
            assert len(eligible) == 8 and len(ineligible) == 21
            a = simulate_t1(*inputs, case_id_a7=eligible[0]['case_id_a7'], request_id='SIM_DEMO_A')
            repeated = simulate_t1(*inputs, case_id_a7=eligible[0]['case_id_a7'], request_id='SIM_DEMO_A')
            b = simulate_t1(*inputs, case_id_a7=eligible[1]['case_id_a7'], request_id='SIM_DEMO_B')
            denied = False
            try:
                simulate_t1(*inputs,case_id_a7=ineligible[0]['case_id_a7'],request_id='SIM_DENIED_FTP')
            except SimulatorError as exc:
                denied = str(exc) == 'SIM_T1_NOT_LOGICALLY_ELIGIBLE'
            final = inspect_simulator(*inputs)
            assert first['persist_status'] == 'CREATED'
            assert replay['persist_status'] == 'REPLAY_IDENTICAL'
            assert a['persist_status'] == b['persist_status'] == 'COMMITTED_IN_SANDBOX_ONLY'
            assert repeated['persist_status'] == 'REPLAY_IDENTICAL'
            assert denied
            assert final['case_count'] == 29
            assert final['simulated_t1_count'] == 2
            assert final['simulated_pending_count'] == 2
            assert final['operational_transitions_applied'] == 0
            assert final['operational_dispatch'] is False
            assert final['p8_operational'] == 'NO-GO'
            print(json.dumps({
                **final,
                'family_count':gate['family_count'],
                'logical_candidate_count':len(eligible),
                'source_requests_all_denied':gate['all_requests_denied'],
                'initial_create_status':first['persist_status'],
                'initial_replay_status':replay['persist_status'],
                'event_replay_status':repeated['persist_status'],
                'ineligible_t1_rejected':denied,
                'sha256':final['last_event_sha256'],
            }, sort_keys=True, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError,
            AssertionError, RecursionError) as exc:
        print('R58T=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160], file=sys.stderr)
        print('R58T_P8=NO-GO',file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
