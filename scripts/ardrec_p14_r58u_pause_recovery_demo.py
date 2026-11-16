#!/usr/bin/env python3
"""R58-U: verified R58-T source, then offline-only simulated T8/T9/T10."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
sys.path.insert(0, str(REPO))

from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
from ardrec.coordination.r58q_transition_guard_bridge import build_a3_a4_transition_audit
from ardrec.coordination.r58r_durable_transition_proposal import persist_proposal
from ardrec.coordination.r58s_transition_deny_gate import build_deny_gate, persist_deny_gate
from ardrec.coordination.r58t_counterfactual_state_store import initialize_simulator, simulate_t1, inspect_simulator
from ardrec.coordination.r58u_counterfactual_pause_recovery import (
    initialize_overlay, inspect_overlay, simulate_transition, OverlayError,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline',action='store_true')
    args=parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve()!=REPO:
        print('R58U=BLOCKED:OFFLINE_AND_REPO_ROOT_REQUIRED',file=sys.stderr)
        return 23
    try:
        scenario=read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
        review=build_a4_a5_review(synthetic_entries())
        a3=build_family_a3_projection(scenario,review)
        trace=build_a3_a4_transition_audit(scenario,review,a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58u-offline-') as tmp:
            root=Path(tmp).resolve()
            proposal,gate_root,sim,overlay=(root/p for p in ('proposal','gate','t1','overlay'))
            for p in (proposal,gate_root,sim,overlay):p.mkdir(mode=0o700)
            persist_proposal(proposal,trace,scenario,review,a3)
            gate=build_deny_gate(proposal,trace,scenario,review,a3)
            persist_deny_gate(gate_root,proposal,trace,scenario,review,a3)
            assert gate['all_requests_denied'] is True
            t1_args=(sim,gate_root,proposal,trace,scenario,review,a3)
            initialize_simulator(*t1_args)
            eligible=[row for row in gate['cases'] if row['logical_candidate']]
            assert len(eligible)==8
            for index,item in enumerate(eligible[:2]):
                simulate_t1(*t1_args,case_id_a7=item['case_id_a7'],
                            request_id=f'SIM_U_T1_{index}')
            verified_t1=inspect_simulator(*t1_args)
            assert verified_t1['simulated_t1_count']==2
            assert verified_t1['operational_transitions_applied']==0
            source_args=(overlay,*t1_args)
            created=initialize_overlay(*source_args)
            repeated_init=initialize_overlay(*source_args)
            cid=eligible[0]['case_id_a7']
            pause={'external_wait_registered':'SIM_WAIT_ONE',
                   'pause_authorized':'SIM_AUTH_ONE','precedence_resolved':'SIM_PRECEDENCE'}
            resume={'new_authorization':'SIM_AUTH_TWO',
                    'wait_resolved':'SIM_WAIT_ONE','preconditions_valid':'SIM_PRECONDITIONS'}
            stop={'cause_verified':'SIM_STOP_CAUSE','effect_processable':'SIM_EFFECT'}
            paused=simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_U_PAUSE',
                                       transition_code='T8',model_condition_references=pause,
                                       expected_revision=0)
            paused_replay=simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_U_PAUSE',
                                              transition_code='T8',model_condition_references=pause,
                                              expected_revision=0)
            resumed=simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_U_RESUME',
                                        transition_code='T9',model_condition_references=resume,
                                        expected_revision=1)
            stopped=simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_U_STOP',
                                        transition_code='T10',model_condition_references=stop,
                                        expected_revision=2,stop_cause='SEGURIDAD')
            rejected=False
            try:
                simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_U_RESTART',
                                    transition_code='T9',model_condition_references=resume,
                                    expected_revision=3)
            except OverlayError as exc:
                rejected=str(exc)=='TERMINAL_PHASE_IMMUTABLE'
            status=inspect_overlay(*source_args)
            assert created['persist_status']=='CREATED'
            assert repeated_init['persist_status']=='REPLAY_IDENTICAL'
            assert paused['persist_status']=='COMMITTED_IN_SANDBOX_ONLY'
            assert paused_replay['persist_status']=='REPLAY_IDENTICAL'
            assert resumed['persist_status']==stopped['persist_status']=='COMMITTED_IN_SANDBOX_ONLY'
            assert rejected
            assert status['case_count']==29
            assert status['source_t1_count']==2
            assert status['simulated_event_count']==3
            assert status['simulated_phase_counts']=={
                'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1}
            assert status['operational_transitions_applied']==0
            assert status['p8_operational']=='NO-GO'
            print(json.dumps({**status,
                'family_count':gate['family_count'],
                'source_denials_preserved':gate['all_requests_denied'],
                'init_status':created['persist_status'],
                'init_replay_status':repeated_init['persist_status'],
                'event_replay_status':paused_replay['persist_status'],
                'terminal_reentry_denied':rejected,
                'r58t_source_unchanged':verified_t1==inspect_simulator(*t1_args),
                'sha256':status['last_event_sha256']},
                sort_keys=True,indent=2,ensure_ascii=True))
        return 0
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,
            AssertionError,RecursionError) as exc:
        print('R58U=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160],file=sys.stderr)
        print('R58U_P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
