#!/usr/bin/env python3
"""R58-W: single declared model A5 intent and no-start; no operational A5/A6."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO))

from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
from ardrec.coordination.r58q_transition_guard_bridge import build_a3_a4_transition_audit
from ardrec.coordination.r58r_durable_transition_proposal import persist_proposal
from ardrec.coordination.r58s_transition_deny_gate import build_deny_gate,persist_deny_gate
from ardrec.coordination.r58t_counterfactual_state_store import (
    initialize_simulator,simulate_t1,inspect_simulator,
)
from ardrec.coordination.r58u_counterfactual_pause_recovery import (
    initialize_overlay,simulate_transition,inspect_overlay,
)
from ardrec.coordination.r58v_a5_a6_readonly_handoff import (
    build_handoff,persist_handoff,verify_persisted_handoff,
)
from ardrec.coordination.r58w_declared_a5_model_ledger import (
    initialize_model_ledger,inspect_model_ledger,
    declare_model_intent,resolve_model_no_start,verified_model_source_batch,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline',action='store_true')
    args=parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve()!=REPO:
        print('R58W=BLOCKED:OFFLINE_AND_REPO_ROOT_REQUIRED',file=sys.stderr)
        return 23
    try:
        scenario=read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
        review=build_a4_a5_review(synthetic_entries())
        a3=build_family_a3_projection(scenario,review)
        trace=build_a3_a4_transition_audit(scenario,review,a3)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58w-') as temp:
            base=Path(temp).resolve()
            proposal,gate_root,t1_root,overlay,handoff,model=(
                base/name for name in ('proposal','gate','t1','overlay','handoff','model'))
            for directory in (proposal,gate_root,t1_root,overlay,handoff,model):
                directory.mkdir(mode=0o700)
            persist_proposal(proposal,trace,scenario,review,a3)
            gate=build_deny_gate(proposal,trace,scenario,review,a3)
            persist_deny_gate(gate_root,proposal,trace,scenario,review,a3)
            assert gate['all_requests_denied'] is True
            t1_args=(t1_root,gate_root,proposal,trace,scenario,review,a3)
            initialize_simulator(*t1_args)
            eligible=[row for row in gate['cases'] if row['logical_candidate']]
            assert len(eligible)==8
            for i,row in enumerate(eligible[:2]):
                simulate_t1(*t1_args,case_id_a7=row['case_id_a7'],
                            request_id=f'SIM_W_T1_{i}')
            overlay_args=(overlay,*t1_args)
            initialize_overlay(*overlay_args)
            c=eligible[0]['case_id_a7']
            simulate_transition(*overlay_args,case_id_a7=c,
                request_id='SIM_W_PAUSE',transition_code='T8',
                model_condition_references={'external_wait_registered':'SIM_WAIT_ONE',
                    'pause_authorized':'SIM_AUTH_ONE','precedence_resolved':'SIM_PRECEDENCE'},
                expected_revision=0)
            simulate_transition(*overlay_args,case_id_a7=c,
                request_id='SIM_W_RESUME',transition_code='T9',
                model_condition_references={'new_authorization':'SIM_AUTH_TWO',
                    'wait_resolved':'SIM_WAIT_ONE','preconditions_valid':'SIM_PRECONDITIONS'},
                expected_revision=1)
            simulate_transition(*overlay_args,case_id_a7=c,
                request_id='SIM_W_STOP',transition_code='T10',
                model_condition_references={'cause_verified':'SIM_STOP_CAUSE',
                    'effect_processable':'SIM_EFFECT'},
                expected_revision=2,stop_cause='SEGURIDAD')
            handoff_args=(overlay,*t1_args)
            t1_before=inspect_simulator(*t1_args)
            overlay_before=inspect_overlay(*overlay_args)
            report=build_handoff(*handoff_args)
            persist_handoff(handoff,*handoff_args)
            verified=verify_persisted_handoff(handoff,*handoff_args)
            assert verified['verification']=='PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6'
            assert report['simulated_phase_counts']=={
                'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1}
            assert report['model_a5_review_candidate_count']==1
            pending=[row for row in report['cases'] if row['current_model_phase']=='PENDIENTE']
            assert len(pending)==1
            key=pending[0]['case_id_a7']
            ledger_args=(model,handoff,*handoff_args)
            with verified_model_source_batch(*ledger_args):
                created=initialize_model_ledger(*ledger_args)
                replay=initialize_model_ledger(*ledger_args)
                declared=declare_model_intent(*ledger_args,case_id_a7=key,
                                              request_id='SIM_W_DECLARE')
                declaration_replay=declare_model_intent(*ledger_args,case_id_a7=key,
                                                        request_id='SIM_W_DECLARE')
                closed=resolve_model_no_start(*ledger_args,case_id_a7=key,
                                              request_id='SIM_W_NO_START')
                closing_replay=resolve_model_no_start(*ledger_args,case_id_a7=key,
                                                      request_id='SIM_W_NO_START')
                final=inspect_model_ledger(*ledger_args)
            assert created['persist_status']=='CREATED'
            assert replay['persist_status']=='REPLAY_IDENTICAL'
            assert declared['persist_status']=='COMMITTED_IN_MODEL_ONLY'
            assert declaration_replay['persist_status']=='REPLAY_IDENTICAL'
            assert closed['persist_status']=='COMMITTED_IN_MODEL_ONLY'
            assert closing_replay['persist_status']=='REPLAY_IDENTICAL'
            assert final['model_intents_declared']==1
            assert final['model_intents_open']==0
            assert final['model_no_start_resolutions']==1
            assert final['model_event_count']==2
            assert final['a5_attempts_started']==0
            assert final['a5_operational_reservations']==0
            assert final['a6_accredited_evidence_count']==0
            assert final['a6_classification']=='ND'
            assert final['p8_operational']=='NO-GO'
            assert t1_before==inspect_simulator(*t1_args)
            assert overlay_before==inspect_overlay(*overlay_args)
            print(json.dumps({
                'schema':final['schema'],'sha256':final['last_event_sha256'],
                'case_count':final['case_count'],
                'family_count':final['family_count'],
                'simulated_phase_counts':report['simulated_phase_counts'],
                'model_review_candidate_count':final['model_review_candidate_count'],
                'model_intents_declared':final['model_intents_declared'],
                'model_intents_open':final['model_intents_open'],
                'model_no_start_resolutions':final['model_no_start_resolutions'],
                'model_event_count':final['model_event_count'],
                'initial_status':created['persist_status'],
                'initial_replay':replay['persist_status'],
                'declare_status':declared['persist_status'],
                'declare_replay':declaration_replay['persist_status'],
                'resolution_status':closed['persist_status'],
                'resolution_replay':closing_replay['persist_status'],
                'source_t1_unchanged':t1_before==inspect_simulator(*t1_args),
                'source_overlay_unchanged':overlay_before==inspect_overlay(*overlay_args),
                'source_denials_preserved':final['source_denials_preserved'],
                'a5_attempts_started':final['a5_attempts_started'],
                'a5_operational_reservations':final['a5_operational_reservations'],
                'a6_accredited_evidence_count':final['a6_accredited_evidence_count'],
                'a6_classification':final['a6_classification'],
                'confirmed_final_risk':final['confirmed_final_risk'],
                'published_generation':final['published_generation'],
                'operational_dispatch':final['operational_dispatch'],
                'p8_operational':final['p8_operational'],
            },ensure_ascii=True,sort_keys=True,indent=2))
        return 0
    except (OSError,ValueError,RuntimeError,AssertionError,
            KeyError,TypeError,sqlite3.Error,RecursionError) as exc:
        print('R58W=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R58W_P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
