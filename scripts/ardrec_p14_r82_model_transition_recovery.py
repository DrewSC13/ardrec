#!/usr/bin/env python3
"""R82: offline SQLite model-state transitions with rollback/replay, bound to R81.

The 29 R58-Q/S model cases are NOT the 25 R76/R78 family assessments or
R81's 54 synthetic units. Only simulated model state changes, NEVER ARDREC
operational state, A6 evidence, A7 confirmed risk, A9 or P8.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / 'scripts'))

from ardrec.persistence.codec import canonical, digest
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import build_family_a3_projection
from ardrec.coordination.r58q_transition_guard_bridge import build_a3_a4_transition_audit
from ardrec.coordination.r58r_durable_transition_proposal import persist_proposal
from ardrec.coordination.r58s_transition_deny_gate import (build_deny_gate, persist_deny_gate, verify_persisted_deny_gate)
from ardrec.coordination.r58t_counterfactual_state_store import (initialize_simulator, simulate_t1, inspect_simulator, SimulatorError)
from ardrec.coordination.r58u_counterfactual_pause_recovery import (initialize_overlay, simulate_transition, inspect_overlay, OverlayError)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries
import ardrec_p14_r81_functional_smoke as r81
import ardrec_p14_r77_signed_a5_a8_bridge as r77

SCHEMA = 'ardrec-p14-r82-model-state-rollback-replay-dev-v1'
SOURCE = 'COUNTERFACTUAL_MODEL_TRANSITIONS_ONLY_R81_SOURCE_READONLY'
SUBDIRS = ('proposal', 'gate', 't1', 'overlay')
MAX_BYTES = 100_000

PAUSE = {'external_wait_registered':'SIM_WAIT_R82', 'pause_authorized':'SIM_AUTH_R82_A',
         'precedence_resolved':'SIM_PRECEDENCE_R82'}
RESUME = {'new_authorization':'SIM_AUTH_R82_B', 'wait_resolved':'SIM_WAIT_R82',
          'preconditions_valid':'SIM_PRECONDITIONS_R82'}
STOP = {'cause_verified':'SIM_CAUSE_R82', 'effect_processable':'SIM_EFFECT_R82'}

class R82Error(ValueError):
    pass

def need(condition: bool, code: str) -> None:
    if not condition:
        raise R82Error(code)

def context(root: Path):
    """Recreate exact model declarations (never dispatch or change other files)."""
    scenario = read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
    review = build_a4_a5_review(synthetic_entries())
    a3 = build_family_a3_projection(scenario, review)
    trace = build_a3_a4_transition_audit(scenario, review, a3)
    proposal, gate_root, sim, overlay = (root/x for x in SUBDIRS)
    common = (gate_root, proposal, trace, scenario, review, a3)
    model = (sim, *common)
    supermodel = (overlay, *model)
    return scenario,review,a3,trace,proposal,gate_root,sim,overlay,common,model,supermodel

def r81_source(r81_root: Path) -> dict[str,Any]:
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO, 'NONROOT_CANONICAL_REPO_REQUIRED')
    document=r81.verify(r81_root)
    need(document['software_dev_smoke']=='PASS' and
         document['stage_count']==10 and
         document['synthetic_units']==54 and
         document['family_count']==25 and
         document['local_benign_starts']==1 and
         document['physical_executions']==0 and
         document['a6']=='ND' and
         document['confirmed_rf'] is None and
         document['a8_applied_transitions']==0 and
         document['a9_new_generations']==0 and
         document['p8_operational']=='NO-GO' and
         document['system_functional_acceptance']=='PENDING' and
         document['experimental_validation']=='NOT_RUN',
         'R81_BASE_NOT_EXACT_OR_AUTHORITY_DRIFT')
    return document

def checked_root(root: Path, *, existing: bool) -> None:
    r81.r75.check_directory(root, existing=existing)
    if existing:
        for folder in SUBDIRS:
            p=root/folder
            st=p.lstat()
            need(not p.is_symlink() and stat.S_ISDIR(st.st_mode) and
                 st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,
                 'MODEL_DIRECTORY_UNSAFE_'+folder)

def _case_keys(gate: dict[str,Any]) -> list[str]:
    eligible=sorted((r['case_id_a7'] for r in gate['cases'] if r['logical_candidate']))
    need(len(eligible)==8 and len(set(eligible))==8 and gate['case_count']==29 and
         gate['all_requests_denied'] is True and
         gate['transitions_applied']==0 and gate['p8_operational']=='NO-GO',
         'R58S_DENIAL_OR_CASE_COUNT_DRIFT')
    return eligible

def build_report(root:Path, r81_doc:dict[str,Any]) -> dict[str,Any]:
    (_,review,a3,trace,proposal,gate_root,sim,overlay,common,model,supermodel)=context(root)
    gate=build_deny_gate(proposal, trace,
                         read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json'),review,a3)
    verified=verify_persisted_deny_gate(gate_root,proposal,trace,
                         read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json'),review,a3)
    need(verified['verification']=='PASS_DOCUMENTARY_DENIAL_ONLY_NO_TRANSITION',
         'MODEL_GATE_NOT_AUTHENTICATED')
    eligible=_case_keys(gate)
    t1=inspect_simulator(*model)
    overlay_state=inspect_overlay(*supermodel)
    need(t1['case_count']==29 and t1['simulated_t1_count']==2 and
         t1['simulated_pending_count']==2 and
         t1['operational_transitions_applied']==0 and t1['p8_operational']=='NO-GO' and
         overlay_state['case_count']==29 and overlay_state['source_t1_count']==2 and
         overlay_state['simulated_event_count']==3 and
         overlay_state['simulated_phase_counts']=={'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1} and
         overlay_state['operational_transitions_applied']==0 and
         overlay_state['a6_classification']=='ND' and
         overlay_state['confirmed_final_risk'] is None and
         overlay_state['published_generation'] is None and
         overlay_state['operational_dispatch'] is False and
         overlay_state['p8_operational']=='NO-GO', 'MODEL_REPLAY_STATUS_INVALID')
    body={
        'schema':SCHEMA,'source_kind':SOURCE,
        'r81_software_smoke_sha256':r81_doc['sha256'],
        'r81_synthetic_units':54,'r81_family_count':25,
        'r58_model_cases':29,'r58_denied_operational_requests':gate['request_count'],
        'populations_are_distinct':True,
        'r58_gate_sha256':gate['sha256'],
        'r58_t1_head_sha256':t1['last_event_sha256'],
        'r58_overlay_head_sha256':overlay_state['last_event_sha256'],
        'model_t1_count':2,'model_t8_pause_count':1,
        'model_t9_resume_count':1,'model_t10_stop_count':1,
        'model_cases':eligible[:2],
        'model_phase_counts':overlay_state['simulated_phase_counts'],
        'atomic_rollback_checks':2,'idempotent_replay_checks':2,
        'terminal_reentry_rejected':True,
        'operational_transitions_applied':0,
        'operational_state_mutated':False,
        'technical_truth_accredited':False,
        'a6':'ND','confirmed_rf':None,
        'a9_new_generations':0,'physical_executions':0,
        'operational_dispatch':False,'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
    }
    need(len(canonical(body))<MAX_BYTES,'REPORT_OVERSIZE')
    body['sha256']=digest(canonical(body))
    return body

def create(root:Path,r81_root:Path) -> dict[str,Any]:
    source=r81_source(r81_root)
    checked_root(root,existing=False)
    root.mkdir(mode=0o700)
    for label in SUBDIRS:(root/label).mkdir(mode=0o700)
    scenario,review,a3,trace,proposal,gate_root,sim,overlay,common,model,supermodel=context(root)
    persist_proposal(proposal,trace,scenario,review,a3)
    gate=build_deny_gate(proposal,trace,scenario,review,a3)
    persist_deny_gate(gate_root,proposal,trace,scenario,review,a3)
    eligible=_case_keys(gate)
    initialized=initialize_simulator(*model)
    need(initialized['persist_status']=='CREATED','T1_INIT_NOT_NEW')
    before=inspect_simulator(*model)
    try:
        simulate_t1(*model,case_id_a7=eligible[0],request_id='SIM_R82_T1_FIRST',
                    fault_before_commit=True)
    except SimulatorError as exc:
        need(str(exc)=='INJECTED_ROLLBACK_BEFORE_COMMIT','T1_FAULT_MISMATCH')
    else:raise R82Error('T1_EXPECTED_FAULT_NOT_RAISED')
    need(inspect_simulator(*model)==before,'T1_ATOMIC_ROLLBACK_FAILED')
    t1a=simulate_t1(*model,case_id_a7=eligible[0],request_id='SIM_R82_T1_FIRST')
    need(t1a['persist_status']=='COMMITTED_IN_SANDBOX_ONLY','T1_FIRST_NOT_COMMITTED')
    t1_replay=simulate_t1(*model,case_id_a7=eligible[0],request_id='SIM_R82_T1_FIRST')
    need(t1_replay['persist_status']=='REPLAY_IDENTICAL' and
         t1_replay['last_event_sha256']==t1a['last_event_sha256'],'T1_REPLAY_CHANGED_STATE')
    simulate_t1(*model,case_id_a7=eligible[1],request_id='SIM_R82_T1_SECOND')
    initial_overlay=initialize_overlay(*supermodel)
    need(initial_overlay['persist_status']=='CREATED','OVERLAY_INIT_NOT_NEW')
    before=inspect_overlay(*supermodel)
    try:
        simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_PAUSE',
                            transition_code='T8',model_condition_references=PAUSE,
                            expected_revision=0,fault_before_commit=True)
    except OverlayError as exc:
        need(str(exc)=='INJECTED_ROLLBACK_BEFORE_COMMIT','OVERLAY_FAULT_MISMATCH')
    else:raise R82Error('OVERLAY_EXPECTED_FAULT_NOT_RAISED')
    need(inspect_overlay(*supermodel)==before,'OVERLAY_ATOMIC_ROLLBACK_FAILED')
    paused=simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_PAUSE',
                            transition_code='T8',model_condition_references=PAUSE,expected_revision=0)
    need(paused['persist_status']=='COMMITTED_IN_SANDBOX_ONLY','OVERLAY_PAUSE_NOT_COMMITTED')
    replay=simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_PAUSE',
                            transition_code='T8',model_condition_references=PAUSE,expected_revision=0)
    need(replay['persist_status']=='REPLAY_IDENTICAL' and
         replay['last_event_sha256']==paused['last_event_sha256'], 'OVERLAY_REPLAY_NOT_IDEMPOTENT')
    simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_RESUME',
                            transition_code='T9',model_condition_references=RESUME,expected_revision=1)
    simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_STOP',
                            transition_code='T10',model_condition_references=STOP,expected_revision=2,
                            stop_cause='SEGURIDAD')
    try:
        simulate_transition(*supermodel,case_id_a7=eligible[0],request_id='SIM_R82_REENTER',
                            transition_code='T9',model_condition_references=RESUME,expected_revision=3)
    except OverlayError as exc:
        need(str(exc)=='TERMINAL_PHASE_IMMUTABLE','TERMINAL_DENIAL_MISMATCH')
    else:raise R82Error('TERMINAL_REENTRY_NOT_REJECTED')
    result=build_report(root,source)
    r81.r75.write_file(root/'MANIFEST.json',canonical(result)+b'\n')
    return verify(root,r81_root)

def verify(root:Path,r81_root:Path)->dict[str,Any]:
    source=r81_source(r81_root)
    checked_root(root,existing=True)
    need({p.name for p in root.iterdir()}==set(SUBDIRS)|{'MANIFEST.json'},
         'UNEXPECTED_TOP_LEVEL_ARTIFACT')
    report=r77.read_canonical(root/'MANIFEST.json')
    derived=build_report(root,source)
    need(type(report) is dict and canonical(report)==canonical(derived),
         'R82_MANIFEST_REPLAY_DRIFT')
    # Model stores verify SQLite hash chains; reject extra database copies.
    for label in SUBDIRS:
        actual=list((root/label).iterdir())
        need(len(actual)==1 and actual[0].is_file() and not actual[0].is_symlink(),
             'MODEL_FILE_SET_DRIFT_'+label)
    return report

def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--create',action='store_true')
    group.add_argument('--verify',action='store_true')
    parser.add_argument('--work-dir',type=Path,required=True)
    parser.add_argument('--r81-receipt',type=Path,required=True)
    parser.add_argument('--expected-r81-sha256',required=True)
    options=parser.parse_args(argv)
    try:
        need(len(options.expected_r81_sha256)==64 and
             all(ch in '0123456789abcdef' for ch in options.expected_r81_sha256) and
             r81_source(options.r81_receipt)['sha256']==options.expected_r81_sha256,
             'EXPECTED_R81_SHA_MISMATCH')
        if options.create:
            mask=os.umask(0o077)
            try: report=create(options.work_dir,options.r81_receipt)
            finally:os.umask(mask)
        else:report=verify(options.work_dir,options.r81_receipt)
    except (ValueError,RuntimeError,OSError,TypeError,KeyError,OverflowError) as exc:
        print('R82=BLOCKED:'+type(exc).__name__+':'+str(exc)[:170],file=sys.stderr)
        print('R82_P8=NO-GO',file=sys.stderr)
        return 23
    print('R82='+('PASS_NEW_MODEL_SANDBOX' if options.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R82_MODEL_CASES=29_SEPARATE_FROM_R81_25_AND_54')
    print('R82_SIMULATED_T1=2')
    print('R82_SIMULATED_T8_T9_T10=1_EACH')
    print('R82_ATOMIC_ROLLBACK=2_CHECKS')
    print('R82_REPLAY=2_IDEMPOTENT_CHECKS')
    print('R82_TERMINAL_REENTRY=DENIED')
    print('R82_SHA256='+report['sha256'])
    print('R82_OPERATIONAL_TRANSITIONS=0')
    print('R82_A6=ND')
    print('R82_RF_CONFIRMED=NULL')
    print('R82_SYSTEM_ACCEPTANCE=PENDING')
    print('R82_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R82_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
