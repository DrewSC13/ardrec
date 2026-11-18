#!/usr/bin/env python3
"""R83: independently reconstruct a non-authoritative R81/R82 cross-population map.

Read existing DEV receipts, never execute A5, create a VM, admit A6,
apply an operational transition, or publish confirmed final risk. A family
label joins *catalog coverage only*, never distinct experiment identities.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))
from ardrec.persistence.codec import canonical, digest
from ardrec.coordination.r58s_transition_deny_gate import build_deny_gate
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r81_functional_smoke as r81
import ardrec_p14_r82_model_transition_recovery as r82

SCHEMA = 'ardrec-p14-r83-cross-population-integrity-offline-v1'
SOURCE = 'FAMILY_CATALOG_CROSSWALK_ONLY_DISTINCT_ASSESSMENTS'
FAMILY_COUNTS = {'SSH_DEV':8, 'FTP_DEV':8, 'SMB_DEV':9}
MODEL_COUNTS = {'SSH_DEV':8, 'FTP_DEV':10, 'SMB_DEV':11}
MAX_REPORT_BYTES = 200_000

class R83Error(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise R83Error(code)

def reconcile(software:dict[str,Any], model:dict[str,Any], r76:dict[str,Any],
              r79:dict[str,Any], gate:dict[str,Any]) -> dict[str,Any]:
    """Pure cross-contract validator: no filesystem, no process or state mutation."""
    need(type(software) is dict and type(model) is dict and
         type(r76) is dict and type(r79) is dict and type(gate) is dict,
         'INPUT_TYPES_INVALID')
    need(software.get('software_dev_smoke')=='PASS' and
         software.get('stage_count')==10 and software.get('synthetic_units')==54 and
         software.get('family_count')==25 and software.get('local_benign_starts')==1 and
         software.get('a6')=='ND' and software.get('confirmed_rf') is None and
         software.get('a8_applied_transitions')==0 and
         software.get('a9_new_generations')==0 and
         software.get('physical_executions')==0 and
         software.get('p8_operational')=='NO-GO' and
         software.get('system_functional_acceptance')=='PENDING' and
         software.get('experimental_validation')=='NOT_RUN',
         'R81_AUTHORITY_OR_COUNTS_DRIFT')
    need(model.get('r81_software_smoke_sha256')==software.get('sha256') and
         model.get('r81_synthetic_units')==54 and
         model.get('r81_family_count')==25 and
         model.get('r58_model_cases')==29 and
         model.get('populations_are_distinct') is True and
         model.get('model_t1_count')==2 and
         model.get('model_t8_pause_count')==1 and
         model.get('model_t9_resume_count')==1 and
         model.get('model_t10_stop_count')==1 and
         model.get('atomic_rollback_checks')==2 and
         model.get('idempotent_replay_checks')==2 and
         model.get('terminal_reentry_rejected') is True and
         model.get('operational_transitions_applied')==0 and
         model.get('operational_state_mutated') is False and
         model.get('technical_truth_accredited') is False and
         model.get('confirmed_rf') is None and model.get('a6')=='ND' and
         model.get('physical_executions')==0 and model.get('p8_operational')=='NO-GO' and
         model.get('system_functional_acceptance')=='PENDING' and
         model.get('experimental_validation')=='NOT_RUN',
         'R82_AUTHORITY_OR_RECOVERY_DRIFT')
    need(r79.get('sha256')==software.get('r79_sha256') and
         r76.get('sha256')==software.get('r76_sha256') and
         r79.get('stage_count')==10 and
         type(r79.get('stages')) is list and
         [x.get('algorithm') for x in r79['stages']]==[f'A{i}' for i in range(1,11)] and
         r79.get('r75_synthetic_units')==54 and
         r79.get('r78_mathematical_family_count')==25 and
         r79.get('family_counts')==FAMILY_COUNTS and
         r79.get('a6_classification')=='ND' and
         r79.get('a7_confirmed_rf') is None and
         r79.get('a8_applied_transitions')==0 and
         r79.get('p8_operational')=='NO-GO',
         'R79_SOURCE_OR_AUTHORITY_DRIFT')
    need(r76.get('family_count')==25 and
         r76.get('a6_classification')=='ND' and
         r76.get('a7_confirmed_rf') is None and
         r76.get('physical_a5_starts_accredited')==0 and
         r76.get('p8_operational')=='NO-GO' and
         type(r76.get('candidates')) is list and
         len(r76['candidates'])==25,
         'R76_CANDIDATES_INVALID')
    need(gate.get('sha256')==model.get('r58_gate_sha256') and
         gate.get('case_count')==29 and
         gate.get('family_count')==25 and
         gate.get('all_requests_denied') is True and
         gate.get('transitions_applied')==0 and
         gate.get('state_machine_mutated') is False and
         gate.get('independent_authority_attested') is False and
         gate.get('signed_approval_attested') is False and
         gate.get('transition_commit_attested') is False and
         gate.get('confirmed_final_risk') is None and
         gate.get('p8_operational')=='NO-GO' and
         type(gate.get('cases')) is list and len(gate['cases'])==29,
         'R58_GATE_NOT_DENY_ONLY')
    candidates={(c['service_id'],c['family_id']):c for c in r76['candidates']}
    analytic={(f['service_id'],f['family_id']):f for f in r79['families']}
    need(len(candidates)==25 and len(analytic)==25 and
         set(candidates)==set(analytic), 'R76_R79_FAMILY_IDENTITY_DRIFT')
    model_by_family:dict[tuple[str,str],list[dict[str,Any]]]={}
    model_identities=set()
    for row in gate['cases']:
        need(type(row) is dict and row.get('review_outcome')=='DENIED' and
             row.get('state_committed') is None and
             row.get('independent_authority_attested') is False and
             row.get('signed_approval_attested') is False and
             row.get('transition_commit_attested') is False and
             row.get('current_phase')=='PREPARADO',
             'MODEL_CASE_FALSE_AUTHORITY')
        identity=(row['service_id'],row['session_id'],row['derived_case_id'],
                  row['assessment_index'])
        need(identity not in model_identities,'DUPLICATED_MODEL_CASE_IDENTITY')
        model_identities.add(identity)
        family=(row['service_id'],row['family_id'])
        need(family in analytic,'MODEL_FAMILY_NOT_IN_CANONICAL_CATALOG')
        model_by_family.setdefault(family,[]).append(row)
    need(set(model_by_family)==set(analytic), 'INCOMPLETE_MODEL_COVERAGE')
    need({service:sum(r['service_id']==service for r in gate['cases'])
          for service in MODEL_COUNTS}==MODEL_COUNTS,
         'MODEL_SERVICE_COUNTS_DRIFT')
    selected=set(model.get('model_cases',[]))
    need(type(model.get('model_cases')) is list and len(selected)==2 and
         all(x in {r['case_id_a7'] for r in gate['cases']} for x in selected),
         'MODEL_SELECTED_CASES_INVALID')
    coverage=[]
    for key in sorted(analytic):
        c=candidates[key]; a=analytic[key]
        need(c.get('a6_classification')=='ND' and
             c.get('physical_start_accredited') is False and
             a.get('a6')=='ND' and a.get('confirmed_rf') is None and
             a.get('operational_authority') is False and
             c.get('a7_case_id')==a.get('case_id'),
             'A5_A7_BINDING_INVALID')
        rows=sorted(model_by_family[key],key=lambda r:(r['case_id_a7'],r['variant']))
        need(all(type(x.get('logical_candidate')) is bool for x in rows),
             'MODEL_GUARD_UNTYPED')
        coverage.append({
            'service_id':key[0], 'family_id':key[1],
            'r76_a7_case_id':c['a7_case_id'],
            'r76_assessment_index':c['a5_intent']['assessment_index'],
            'r79_hypothetical_E0':a['hypothetical_rf_E0'],
            'r79_hypothetical_Ehalf':a['hypothetical_rf_Ehalf'],
            'r79_hypothetical_E1':a['hypothetical_rf_E1'],
            'model_variant_count':len(rows),
            'model_cases':[
                {'case_id_a7':x['case_id_a7'], 'variant':x['variant'],
                 'logical_candidate':x['logical_candidate'],
                 'denied':True,
                 'simulated_recovery_case':x['case_id_a7'] in selected}
                for x in rows],
            'cross_population_join':'CATALOG_FAMILY_ONLY',
            'same_assessment_attested':False,
            'technical_truth_accredited':False,
            'confirmed_final_risk':None,
        })
    need(len(coverage)==25 and sum(x['model_variant_count'] for x in coverage)==29,
         'COVERAGE_COUNTS_INVALID')
    need(sum(sum(x['simulated_recovery_case'] for x in r['model_cases'])
             for r in coverage)==2,'RECOVERY_SELECTION_DRIFT')
    body={
        'schema':SCHEMA,'source_kind':SOURCE,
        'r81_manifest_sha256':software['sha256'],
        'r82_manifest_sha256':model['sha256'],
        'r76_report_sha256':r76['sha256'],
        'r79_report_sha256':r79['sha256'],
        'r58_gate_sha256':gate['sha256'],
        'a1_a10_stages':[f'A{i}' for i in range(1,11)],
        'population_sizes':{'synthetic_a2':54,'analytical_families':25,'model_variants':29},
        'family_catalog_coverage':25,
        'model_coverage':29,
        'model_denied_requests':gate['request_count'],
        'model_simulated_t1':2,'model_simulated_t8':1,
        'model_simulated_t9':1,'model_simulated_t10':1,
        'model_replay_idempotent':True,'model_rollback_atomic':True,
        'families':coverage,
        'cross_population_authoritative_join_count':0,
        'operational_transitions_applied':0,
        'technical_truth_accredited':False,
        'a6':'ND','confirmed_rf':None,'a9_new_generations':0,
        'physical_executions':0,'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
        'open_findings':['AL-06','AL-07'],
    }
    need(len(canonical(body))<MAX_REPORT_BYTES-1000,'REPORT_OVERSIZE')
    body['sha256']=digest(canonical(body))
    return body


def inputs(r81_root:Path,r82_root:Path) -> tuple[dict[str,Any],...]:
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    software=r81.verify(r81_root)
    model=r82.verify(r82_root,r81_root)
    sources=r81_root/'sources'
    r76=r77.read_canonical(sources/'r76.json')
    r79=r77.read_canonical(sources/'r79.json')
    (_,review,a3,trace,proposal,gate_root,sim,overlay,common,state,superset)=r82.context(r82_root)
    scenario=r82.read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
    gate=build_deny_gate(proposal,trace,scenario,review,a3)
    return software,model,r76,r79,gate


def compute(r81_root:Path,r82_root:Path)->dict[str,Any]:
    return reconcile(*inputs(r81_root,r82_root))


def create(dest:Path,r81_root:Path,r82_root:Path)->dict[str,Any]:
    r81.checked_root(dest,existing=False)
    report=compute(r81_root,r82_root)
    old=os.umask(0o077)
    try:
        dest.mkdir(mode=0o700)
        r81.write(dest,'MANIFEST.json',canonical(report)+b'\n')
    finally:os.umask(old)
    return verify(dest,r81_root,r82_root)


def verify(dest:Path,r81_root:Path,r82_root:Path)->dict[str,Any]:
    r81.r75.check_directory(dest,existing=True)
    need({p.name for p in dest.iterdir()}=={'MANIFEST.json'},
         'RECEIPT_FILESET_DRIFT')
    existing=r77.read_canonical(dest/'MANIFEST.json')
    expected=compute(r81_root,r82_root)
    need(type(existing) is dict and canonical(existing)==canonical(expected),
         'RECEIPT_RECONSTRUCTION_DRIFT')
    return existing


def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--create',action='store_true')
    group.add_argument('--verify',action='store_true')
    ap.add_argument('--r81-receipt',type=Path,required=True)
    ap.add_argument('--r82-receipt',type=Path,required=True)
    ap.add_argument('--work-dir',type=Path,required=True)
    ap.add_argument('--expected-r81-sha256',required=True)
    ap.add_argument('--expected-r82-sha256',required=True)
    options=ap.parse_args(argv)
    try:
        need(len(options.expected_r81_sha256)==64 and
             len(options.expected_r82_sha256)==64,'EXPECTED_HASH_LENGTH')
        need(r77.read_canonical(options.r81_receipt/'MANIFEST.json')['sha256'] ==
             options.expected_r81_sha256,'EXPECTED_R81_PIN_MISMATCH')
        need(r77.read_canonical(options.r82_receipt/'MANIFEST.json')['sha256'] ==
             options.expected_r82_sha256,'EXPECTED_R82_PIN_MISMATCH')
        report=(create(options.work_dir,options.r81_receipt,options.r82_receipt)
                if options.create else
                verify(options.work_dir,options.r81_receipt,options.r82_receipt))
    except (ValueError,TypeError,KeyError,OSError,RuntimeError,OverflowError) as exc:
        print('R83=BLOCKED:'+type(exc).__name__+':'+str(exc)[:170],file=sys.stderr)
        print('R83_P8=NO-GO',file=sys.stderr)
        return 23
    print('R83='+('PASS_CROSSWALK_CREATED' if options.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R83_A1_A10=10_STAGES')
    print('R83_POPULATIONS=54_A2_25_FAMILIES_29_MODEL_CASES')
    print('R83_CATALOG_COVERAGE=25_OF_25')
    print('R83_MODEL_DENIAL=29_CASES_0_OPERATIONAL_TRANSITIONS')
    print('R83_SIMULATED_T1=2_T8=1_T9=1_T10=1')
    print('R83_AUTHORITATIVE_CROSS_POPULATION_JOIN=0')
    print('R83_SHA256='+report['sha256'])
    print('R83_A6=ND')
    print('R83_RF_CONFIRMED=NULL')
    print('R83_SYSTEM_ACCEPTANCE=PENDING')
    print('R83_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R83_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
