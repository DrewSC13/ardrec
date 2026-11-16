#!/usr/bin/env python3
"""R58-V: immutable read-only A5/A6 handoff of the verified sandbox history."""
from __future__ import annotations

import argparse
import json
import sqlite3
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
    initialize_overlay, simulate_transition, inspect_overlay,
)
from ardrec.coordination.r58v_a5_a6_readonly_handoff import (
    build_handoff, persist_handoff, verify_persisted_handoff,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58V=BLOCKED:OFFLINE_AND_REPO_ROOT_REQUIRED',file=sys.stderr)
        return 23
    try:
        scenario=read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
        review=build_a4_a5_review(synthetic_entries())
        a3=build_family_a3_projection(scenario,review)
        trace=build_a3_a4_transition_audit(scenario,review,a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58v-readonly-') as tmp:
            root=Path(tmp).resolve()
            proposal,gate_dir,sim,overlay,handoff=(root/name for name in
                       ('proposal','gate','t1','overlay','handoff'))
            for directory in (proposal,gate_dir,sim,overlay,handoff):
                directory.mkdir(mode=0o700)
            persist_proposal(proposal,trace,scenario,review,a3)
            gate=build_deny_gate(proposal,trace,scenario,review,a3)
            persist_deny_gate(gate_dir,proposal,trace,scenario,review,a3)
            assert gate['all_requests_denied'] is True
            t1_args=(sim,gate_dir,proposal,trace,scenario,review,a3)
            initialize_simulator(*t1_args)
            eligible=[row for row in gate['cases'] if row['logical_candidate']]
            assert len(eligible)==8
            for index,item in enumerate(eligible[:2]):
                simulate_t1(*t1_args,case_id_a7=item['case_id_a7'],
                            request_id=f'SIM_V_T1_{index}')
            before=inspect_simulator(*t1_args)
            source_args=(overlay,*t1_args)
            initialize_overlay(*source_args)
            cid=eligible[0]['case_id_a7']
            pause={'external_wait_registered':'SIM_WAIT_ONE',
                   'pause_authorized':'SIM_AUTH_ONE','precedence_resolved':'SIM_PRECEDENCE'}
            resume={'new_authorization':'SIM_AUTH_TWO',
                    'wait_resolved':'SIM_WAIT_ONE','preconditions_valid':'SIM_PRECONDITIONS'}
            stop={'cause_verified':'SIM_STOP_CAUSE','effect_processable':'SIM_EFFECT'}
            simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_V_PAUSE',
                transition_code='T8',model_condition_references=pause,
                expected_revision=0)
            simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_V_RESUME',
                transition_code='T9',model_condition_references=resume,
                expected_revision=1)
            simulate_transition(*source_args,case_id_a7=cid,request_id='SIM_V_STOP',
                transition_code='T10',model_condition_references=stop,
                expected_revision=2,stop_cause='SEGURIDAD')
            overlay_before=inspect_overlay(*source_args)
            report=build_handoff(*source_args)
            created=persist_handoff(handoff,*source_args)
            repeated=persist_handoff(handoff,*source_args)
            verified=verify_persisted_handoff(handoff,*source_args)
            assert before==inspect_simulator(*t1_args)
            assert overlay_before==inspect_overlay(*source_args)
            assert report['simulated_phase_counts']=={
                'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1}
            assert report['model_a5_review_candidate_count']==1
            assert report['a5_intents_submitted']==0
            assert report['a5_attempts_reserved']==0
            assert report['a5_attempts_started']==0
            assert report['a6_accredited_evidence_count']==0
            assert report['a6_classification']=='ND'
            assert created['persist_status']=='CREATED'
            assert repeated['persist_status']=='REPLAY_IDENTICAL'
            assert verified['verification']=='PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6'
            assert verified['receipt_sha256']==report['sha256']
            print(json.dumps({
                'schema':report['schema'],'sha256':report['sha256'],
                'case_count':report['case_count'],
                'family_count':report['family_count'],
                'simulated_phase_counts':report['simulated_phase_counts'],
                'source_t1_event_count':report['source_t1_event_count'],
                'source_overlay_event_count':report['source_overlay_event_count'],
                'a5_model_review_candidates':report['model_a5_review_candidate_count'],
                'a5_status':report['a5_status'],
                'a5_intents_submitted':report['a5_intents_submitted'],
                'a5_attempts_reserved':report['a5_attempts_reserved'],
                'a5_attempts_started':report['a5_attempts_started'],
                'a6_classification':report['a6_classification'],
                'a6_accredited_evidence_count':report['a6_accredited_evidence_count'],
                'source_denials_preserved':report['all_source_requests_denied'],
                'handoff_first':created['persist_status'],
                'handoff_replay':repeated['persist_status'],
                'handoff_verification':verified['verification'],
                'handoff_receipt_count':len(list(handoff.iterdir())),
                'source_t1_unchanged':before==inspect_simulator(*t1_args),
                'source_overlay_unchanged':overlay_before==inspect_overlay(*source_args),
                'operational_transitions_applied':report['operational_transitions_applied'],
                'operational_dispatch':report['operational_dispatch'],
                'confirmed_final_risk':report['confirmed_final_risk'],
                'published_generation':report['published_generation'],
                'p8_operational':report['p8_operational'],
            },sort_keys=True,ensure_ascii=True,indent=2))
        return 0
    except (OSError,RuntimeError,ValueError,KeyError,TypeError,
            AssertionError,RecursionError,sqlite3.Error) as exc:
        print('R58V=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160],file=sys.stderr)
        print('R58V_P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
