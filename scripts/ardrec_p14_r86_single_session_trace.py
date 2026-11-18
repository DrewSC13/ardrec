#!/usr/bin/env python3
"""R86: 25 typed A1-A10 DEV trails rooted in ONE R81 synthetic session.

This is a replayable software trace, NOT a real penetration test or A5-A8
operational workflow. R82's 29 model cases remain a DIFFERENT population.
No process start, external I/O, host change or P8 authorization.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
sys.path.insert(0, str(REPO/'scripts'))
from ardrec.persistence.codec import canonical, digest
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r81_functional_smoke as r81
import ardrec_p14_r84_dev_acceptance_gate as r84
import ardrec_p14_r85_dev_adversarial_campaign as r85

SCHEMA = 'ardrec-p14-r86-typed-single-dev-session-stage-ledger-v1'
SOURCE = 'R81_SYNTHETIC_SESSION_TYPED_SOFTWARE_TRACE_ONLY'
STAGES = tuple('A'+str(n) for n in range(1,11))
MAX_BYTES = 600_000

class R86Error(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise R86Error(code)

def sha_field(doc: dict[str,Any], key: str) -> str:
    value = doc.get(key)
    need(type(value) is str and len(value)==64 and
         all(ch in '0123456789abcdef' for ch in value), 'INVALID_SHA_'+key)
    return value

def _event(a: str, case: dict[str,Any], source: dict[str,Any],
           gen1: str, trace: dict[str,Any]) -> tuple[str,dict[str,Any]]:
    """Conservative per-stage projection: no invented operational events."""
    if a == 'A1':
        return 'DEV_SHARED_GEN1_SOURCE',{'gen1_head_sha256':gen1,
                                         'case_execution_accredited':False}
    if a == 'A2':
        return 'SYNTHETIC_54_SEPARATE_UNITS',{'unit_count':54,
                                               'case_unit_identity_attested':False}
    if a == 'A3':
        return 'HYPOTHETICAL_GUARD_NO_DISPATCH',{'guard_authority':False}
    if a == 'A4':
        return 'HYPOTHETICAL_SELECTION_ONLY',{'selection_authority':False}
    if a == 'A5':
        return case['a5_review_state'],{
            'attempt_id':case['attempt_id'], 'intent_sha256':case['intent_sha256'],
            'declared_outcome':case['declared_outcome'],
            'physical_start_accredited':False}
    if a == 'A6':
        return 'NOT_ADMITTED_ND',{'classification':'ND',
                                  'technical_truth_accredited':False}
    if a == 'A7':
        lo,hi=case['a7_uncertainty_interval']; mid=case['a7_hypothetical_midpoint']
        return 'EXACT_UNRESOLVED',{'interval':[lo,hi],
                                    'hypothetical_e_half':mid,'confirmed_rf':None}
    if a == 'A8':
        return 'HOLD_NO_AUTHORITY',{'applied_transition':None,
                                     'separate_model_variants_denied':case['a8_model_variants_denied'],
                                     'same_assessment_as_model':False}
    if a == 'A9':
        return 'GEN1_UNCHANGED',{'new_generations':0,'published_technical_evidence':False}
    return 'ORIGINAL_READONLY_R38_VIEW',{'presentation_count':trace['presentation_count'],
                                        'new_technical_evidence':False}

def validate_ledger(report:dict[str,Any]) -> bool:
    need(type(report) is dict and report.get('schema')==SCHEMA and
         report.get('source_kind')==SOURCE and report.get('session_count')==1 and
         report.get('case_count')==25 and report.get('stage_events')==250 and
         report.get('software_dev_criteria')==13 and report.get('external_criteria_pending')==6 and
         report.get('negative_faults_rejected')==156 and
         report.get('operational_cross_population_joins')==0 and
         report.get('a6')=='ND' and report.get('confirmed_rf') is None and
         report.get('operational_transitions_applied')==0 and
         report.get('new_generations')==0 and report.get('physical_executions')==0 and
         report.get('p8_operational')=='NO-GO' and
         report.get('system_functional_acceptance')=='PENDING' and
         report.get('experimental_validation')=='NOT_RUN', 'R86_AUTHORITY_OR_SCHEMA_INVALID')
    sessions=set(); identities=set(); last_digests=[]
    need(type(report.get('cases')) is list and len(report['cases'])==25,'R86_CASE_COUNT')
    for row in report['cases']:
        need(type(row) is dict and type(row.get('events')) is list and
             len(row['events'])==10 and row.get('cross_population_join')=='CATALOG_ONLY' and
             row.get('technical_truth_accredited') is False and
             row.get('confirmed_rf') is None, 'R86_CASE_SCHEMA_INVALID')
        identity=(row.get('session_id'),row.get('service_id'),row.get('derived_case_id'),
                  row.get('assessment_index'),row.get('attempt_id'))
        need(identity not in identities and
             all(type(identity[i]) is str and identity[i] for i in (0,1,2,4)) and
             type(identity[3]) is int and identity[3]>=0,
             'R86_DUPLICATE_CASE_IDENTITY')
        identities.add(identity);sessions.add(row.get('session_id'))
        seed=sha_field(row,'seed_sha256')
        prev=seed
        for number, event in enumerate(row['events'],1):
            need(type(event) is dict and event.get('algorithm')=='A'+str(number) and
                 event.get('prev_sha256')==prev and type(event.get('result')) is str and
                 type(event.get('detail')) is dict,'R86_EVENT_ORDER_OR_PREV')
            event_body={k:v for k,v in event.items() if k!='event_sha256'}
            need(event.get('event_sha256')==digest(canonical(event_body)),
                 'R86_EVENT_HASH_DRIFT')
            prev=event['event_sha256']
        need(row.get('head_sha256')==prev,'R86_CASE_HEAD_DRIFT')
        last_digests.append(prev)
        need(row['events'][2]['result']=='HYPOTHETICAL_GUARD_NO_DISPATCH' and
             row['events'][3]['result']=='HYPOTHETICAL_SELECTION_ONLY' and
             row['events'][5]['result']=='NOT_ADMITTED_ND' and
             row['events'][6]['result']=='EXACT_UNRESOLVED' and
             row['events'][7]['result']=='HOLD_NO_AUTHORITY' and
             row['events'][8]['result']=='GEN1_UNCHANGED' and
             row['events'][9]['result']=='ORIGINAL_READONLY_R38_VIEW' and
             row['events'][4]['detail'].get('physical_start_accredited') is False and
             row['events'][5]['detail'].get('classification')=='ND' and
             row['events'][6]['detail'].get('confirmed_rf') is None and
             row['events'][7]['detail'].get('applied_transition') is None and
             row['events'][8]['detail'].get('new_generations')==0,
             'R86_FALSE_TECHNICAL_CLAIM')
        a7=row['events'][6]['detail'];lo,hi=(Fraction(x) for x in a7['interval'])
        mid=Fraction(a7['hypothetical_e_half'])
        need(0<=lo<=mid<=hi<=1,'R86_FRACTION_BOUNDS')
    need(len(sessions)==1 and None not in sessions and len(identities)==25,
         'R86_MORE_THAN_ONE_DEV_SESSION')
    need(report.get('single_session_id')==next(iter(sessions)) and
         report.get('ledger_head_sha256')==digest(canonical(last_digests)),
         'R86_FINAL_LEDGER_HEAD_DRIFT')
    body={k:v for k,v in report.items() if k!='sha256'}
    need(report.get('sha256')==digest(canonical(body)) and len(canonical(report))<=MAX_BYTES,
         'R86_REPORT_DIGEST_OR_SIZE')
    return True

def project(matrix:dict[str,Any], campaign:dict[str,Any],
            intent_source:dict[str,Any], session:dict[str,Any],
            r79:dict[str,Any]) -> dict[str,Any]:
    """One exact R81 DEV cohort, 25 assessment IDs, 10 stages each."""
    need(all(type(d) is dict for d in (matrix,campaign,intent_source,session,r79)),
         'R86_SOURCE_TYPES_INVALID')
    need(matrix.get('sha256')==campaign.get('r84_report_sha256') and
         campaign.get('fault_count')==156 and campaign.get('faults_rejected')==156 and
         campaign.get('faults_undetected')==0 and campaign.get('p8_operational')=='NO-GO' and
         matrix.get('case_count')==25 and matrix.get('model_variant_denials')==29 and
         matrix.get('a1_a10_stages')==list(STAGES) and
         matrix.get('software_contract_count')==13 and
         matrix.get('independent_acceptance_pending_count')==6 and
         matrix.get('source_links',{}).get('r81_sha256')==session.get('sha256') and
         matrix.get('source_links',{}).get('r76_sha256')==intent_source.get('sha256') and
         session.get('r79_sha256')==r79.get('sha256') and
         r79.get('stage_count')==10 and
         [r.get('algorithm') for r in r79.get('stages',[])]==list(STAGES) and
         r79.get('a6_classification')=='ND' and
         r79.get('a7_confirmed_rf') is None and
         r79.get('p8_operational')=='NO-GO' and
         session.get('software_dev_smoke')=='PASS' and
         session.get('stage_count')==10 and
         session.get('presentation_count')==8 and
         session.get('local_benign_starts')==1 and
         session.get('physical_executions')==0 and
         session.get('p8_operational')=='NO-GO',
         'R86_SOURCE_CONTRACT_DRIFT')
    gen1=sha_field(session,'r75_gen1_head')
    candidates={(c['service_id'],c['family_id']):c for c in intent_source['candidates']}
    need(len(candidates)==25 and len(intent_source['candidates'])==25,
         'R86_DUPLICATE_CANDIDATES')
    rows=[]; sessions=set(); seen=set()
    for case in matrix['cases']:
        key=(case['service_id'],case['family_id'])
        need(key in candidates,'R86_MISSING_INTENT')
        candidate=candidates[key];intent=candidate['a5_intent']
        identity=(intent['session_id'],intent['service_id'],intent['derived_case_id'],
                  intent['assessment_index'],intent['attempt_id'])
        need(identity not in seen and
             case['derived_case_id']==intent['derived_case_id'] and
             case['assessment_index']==intent['assessment_index'] and
             case['attempt_id']==intent['attempt_id'] and
             case['intent_sha256']==intent['sha256'] and
             case['service_id']==intent['service_id'] and
             case['family_id']==intent['family_id'] and
             case['configuration_sha256']==intent['configuration_sha256'] and
             case['a5_review_state'] in ('NOT_STARTED','UNVERIFIED_DECLARATION') and
             case['a6_classification']=='ND' and
             case['a6_admission']=='NOT_ADMITTED' and
             case['a7_confirmed_rf'] is None and
             case['a8_operational_transition'] is None and
             case['a8_decision']=='HOLD_NO_AUTHORITY' and
             case['same_assessment_as_model'] is False,
             'R86_ATTEMPT_PROVENANCE_DRIFT')
        lo,hi=case['a7_uncertainty_interval'];mid=case['a7_hypothetical_midpoint']
        need(0<=Fraction(lo)<=Fraction(mid)<=Fraction(hi)<=1,
             'R86_RATIONAL_ENVELOPE_INVALID')
        sessions.add(intent['session_id']);seen.add(identity)
        seed=digest(canonical({'schema':SCHEMA,'r84_sha256':matrix['sha256'],
                               'session_id':identity[0], 'service_id':identity[1],
                               'derived_case_id':identity[2],'assessment_index':identity[3],
                               'attempt_id':identity[4],'intent_sha256':case['intent_sha256']}))
        prev=seed; events=[]
        for a in STAGES:
            status,detail=_event(a,case,candidate,gen1,session)
            ev={'algorithm':a,'result':status,'detail':detail,'prev_sha256':prev}
            ev['event_sha256']=digest(canonical(ev))
            events.append(ev);prev=ev['event_sha256']
        rows.append({'session_id':identity[0],'service_id':identity[1],
                     'family_id':case['family_id'],'derived_case_id':identity[2],
                     'assessment_index':identity[3],'attempt_id':identity[4],
                     'cross_population_join':'CATALOG_ONLY',
                     'technical_truth_accredited':False,'confirmed_rf':None,
                     'seed_sha256':seed,'events':events,'head_sha256':prev})
    need(len(rows)==25 and len(sessions)==1,'R86_NON_UNIQUE_R81_SESSION')
    rows.sort(key=lambda x:(x['service_id'],x['family_id']))
    body={'schema':SCHEMA,'source_kind':SOURCE,
          'source_links':{'r81_sha256':session['sha256'],'r79_sha256':r79['sha256'],
                          'r76_sha256':intent_source['sha256'],'r84_sha256':matrix['sha256'],
                          'r85_sha256':campaign['sha256'],
                          'r82_separate_population_sha256':matrix['source_links']['r82_sha256']},
          'single_session_id':next(iter(sessions)),'session_count':1,
          'case_count':25,'stage_count':10,'stage_events':250,
          'cases':rows,'ledger_head_sha256':digest(canonical([r['head_sha256'] for r in rows])),
          'a2_synthetic_units_separate':54,'r82_model_cases_separate':29,
          'software_dev_criteria':13,'external_criteria_pending':6,
          'negative_faults_rejected':156,
          'operational_cross_population_joins':0,
          'a6':'ND','confirmed_rf':None,'operational_transitions_applied':0,
          'new_generations':0,'physical_executions':0,'p8_operational':'NO-GO',
          'system_functional_acceptance':'PENDING','experimental_validation':'NOT_RUN'}
    body['sha256']=digest(canonical(body))
    validate_ledger(body)
    return body

def compute(r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path,
            r85_root:Path)->dict[str,Any]:
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    saved,inputs=r85._sources(r81_root,r82_root,r83_root,r84_root)
    campaign=r77.read_canonical(r85_root/'MANIFEST.json')
    need(r85.r81.r75.check_directory(r85_root,existing=True) is None and
         {p.name for p in r85_root.iterdir()}=={'MANIFEST.json'},
         'R85_FILESET_INVALID')
    need(canonical(r85.campaign(saved,inputs))==canonical(campaign),
         'R85_REPLAY_INVALID')
    r79=r77.read_canonical(r81_root/'sources'/'r79.json')
    return project(saved,campaign,inputs[1],inputs[2],r79)

def create(dest:Path,*roots:Path)->dict[str,Any]:
    r81.checked_root(dest,existing=False)
    report=compute(*roots)
    previous=os.umask(0o077)
    try:
        dest.mkdir(mode=0o700)
        r81.write(dest,'MANIFEST.json',canonical(report)+b'\n')
    finally:
        os.umask(previous)
    return verify(dest,*roots)

def verify(dest:Path,*roots:Path)->dict[str,Any]:
    r81.r75.check_directory(dest,existing=True)
    need({p.name for p in dest.iterdir()}=={'MANIFEST.json'},
         'R86_UNEXPECTED_RECEIPT_MEMBER')
    report=r77.read_canonical(dest/'MANIFEST.json')
    validate_ledger(report)
    need(canonical(report)==canonical(compute(*roots)),
         'R86_SOURCE_REPLAY_OR_CUSTODY_DRIFT')
    return report

def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--create',action='store_true')
    modes.add_argument('--verify',action='store_true')
    for name in ('work-dir','r81-receipt','r82-receipt','r83-receipt','r84-receipt','r85-receipt'):
        ap.add_argument('--'+name,required=True,type=Path)
    ap.add_argument('--expected-r85-sha256',required=True)
    opt=ap.parse_args(argv)
    try:
        expected=r77.read_canonical(opt.r85_receipt/'MANIFEST.json')
        need(sha_field(expected,'sha256')==opt.expected_r85_sha256,
             'R86_UNEXPECTED_R85_SOURCE_PIN')
        paths=(opt.r81_receipt,opt.r82_receipt,opt.r83_receipt,opt.r84_receipt,opt.r85_receipt)
        doc=create(opt.work_dir,*paths) if opt.create else verify(opt.work_dir,*paths)
    except (ValueError,KeyError,TypeError,OSError,RuntimeError,OverflowError) as exc:
        print('R86=BLOCKED:'+type(exc).__name__+':'+str(exc)[:190],file=sys.stderr)
        print('R86_P8=NO-GO',file=sys.stderr)
        return 23
    print('R86='+('PASS_TYPED_LEDGER_CREATED' if opt.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R86_SINGLE_R81_DEV_SESSION=1')
    print('R86_TYPED_ATTEMPTS=25')
    print('R86_A1_A10_STAGE_EVENTS=250')
    print('R86_A6=ND')
    print('R86_RF_CONFIRMED=NULL')
    print('R86_R82_29_CASES=SEPARATE')
    print('R86_R85_FAULTS=156_REJECTED')
    print('R86_SYSTEM_ACCEPTANCE=PENDING')
    print('R86_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R86_SHA256='+doc['sha256'])
    print('R86_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
