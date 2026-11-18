#!/usr/bin/env python3
"""R87: deterministic golden-oracle DEV acceptance of the exact R86 25x10 ledger.

Offline replay only.  No A5 starts, VM, networks, state transitions, or P8 authority.
All observations remain synthetic/documentary and technical truth unaccredited.
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
import ardrec_p14_r86_single_session_trace as r86

SCHEMA='ardrec-p14-r87-single-cohort-golden-dev-acceptance-v1'
SOURCE='AUTHENTICATED_R86_SYNTHETIC_READONLY_REPLAY_NOT_EXPERIMENT'
RESULT='PASS_SOFTWARE_DEV_GOLDEN_SCOPE_ONLY'
STAGES=tuple('A'+str(i) for i in range(1,11))
EXPECTED={
 'A1':'DEV_SHARED_GEN1_SOURCE',
 'A2':'SYNTHETIC_54_SEPARATE_UNITS',
 'A3':'HYPOTHETICAL_GUARD_NO_DISPATCH',
 'A4':'HYPOTHETICAL_SELECTION_ONLY',
 'A6':'NOT_ADMITTED_ND',
 'A7':'EXACT_UNRESOLVED',
 'A8':'HOLD_NO_AUTHORITY',
 'A9':'GEN1_UNCHANGED',
 'A10':'ORIGINAL_READONLY_R38_VIEW',
}
CHECKS=(
 'G01_ONE_SYNTHETIC_SESSION',
 'G02_EXACT_25_IDENTITIES_AND_250_ORDERED_EVENTS',
 'G03_R81_TO_R86_CUSTODY_REPLAY',
 'G04_A1_GEN1_CONFIG_SOURCE',
 'G05_A2_54_SYNTHETIC_SEPARATE',
 'G06_A3_A4_DENY_DISPATCH',
 'G07_A5_3_UNVERIFIED_22_NOT_STARTED',
 'G08_A6_25_NOT_ADMITTED',
 'G09_A7_25_EXACT_RATIONAL_ENVELOPES',
 'G10_A8_NO_OPERATIONAL_TRANSITIONS',
 'G11_A9_GEN1_UNCHANGED',
 'G12_A10_R38_READONLY',
 'G13_R82_MODEL_29_CASES_SEPARATE',
 'G14_R85_156_REJECTED_NO_UNDETECTED',
 'G15_R84_13_DEV_CONTRACTS_ONLY',
 'G16_SIX_EXTERNAL_CRITERIA_STILL_PENDING',
 'G17_F11_AND_P8_NO_GO',
 'G18_NO_EXPERIMENTAL_OR_SYSTEM_ACCEPTANCE',
)
MAX_BYTES=160000

class R87Error(ValueError):
    pass

def need(ok:bool,code:str)->None:
    if not ok:raise R87Error(code)

def _digest_shape(doc:dict[str,Any])->bool:
    return type(doc) is dict and doc.get('sha256')==digest(canonical({k:v for k,v in doc.items() if k!='sha256'}))

def assess(ledger:dict[str,Any], matrix:dict[str,Any],
           faults:dict[str,Any]) -> dict[str,Any]:
    """Compare accepted DEV ledger against fixed, independent stage/branch oracles."""
    need(all(type(x) is dict for x in (ledger,matrix,faults)), 'INPUT_TYPE')
    need(r86.validate_ledger(ledger),'R86_LEDGER_INVALID')
    need(_digest_shape(matrix) and _digest_shape(faults),'R84_R85_HASH_INVALID')
    need(ledger['source_links']['r84_sha256']==matrix['sha256'] and
         ledger['source_links']['r85_sha256']==faults['sha256'] and
         faults['r84_report_sha256']==matrix['sha256'], 'SOURCE_CHAIN_DRIFT')
    need(ledger['session_count']==1 and ledger['case_count']==25 and
         ledger['stage_count']==10 and ledger['stage_events']==250 and
         ledger['a2_synthetic_units_separate']==54 and
         ledger['r82_model_cases_separate']==29 and
         ledger['operational_cross_population_joins']==0, 'POPULATION_DRIFT')
    need(matrix.get('case_count')==25 and matrix.get('model_variant_denials')==29 and
         matrix.get('unverified_declarations')==3 and matrix.get('no_start_count')==22 and
         matrix.get('software_contract_count')==13 and
         matrix.get('independent_acceptance_pending_count')==6, 'MATRIX_SCOPE_DRIFT')
    need([r.get('criterion') for r in matrix.get('criteria',[])] ==
         list(r84.SOFTWARE)+list(r84.EXPERIMENTAL) and
         all(c['result']=='PASS_DEV_CONTRACT_ONLY' for c in matrix['criteria'][:13]) and
         all(c['result']=='PENDING_EXTERNAL_ATTESTATION' for c in matrix['criteria'][13:]),
         'CRITERIA_FALSE_PROMOTION')
    need(faults.get('fault_count')==156 and faults.get('faults_rejected')==156 and
         faults.get('faults_undetected')==0 and
         ledger.get('negative_faults_rejected')==156, 'ADVERSARIAL_ORACLE_DRIFT')
    need(ledger['a6']=='ND' and ledger['confirmed_rf'] is None and
         ledger['operational_transitions_applied']==0 and ledger['new_generations']==0 and
         ledger['physical_executions']==0 and ledger['p8_operational']=='NO-GO' and
         ledger['system_functional_acceptance']=='PENDING' and
         ledger['experimental_validation']=='NOT_RUN', 'AUTHORITY_ESCALATION')
    expected_cases={(c['service_id'],c['family_id'],c['derived_case_id'],
                     c['assessment_index'],c['attempt_id']):c
                    for c in matrix['cases']}
    need(len(expected_cases)==25,'MATRIX_DUPLICATE_ID')
    result_rows=[]; counts={'UNVERIFIED_DECLARATION':0,'NOT_STARTED':0}
    for row in ledger['cases']:
        key=(row['service_id'],row['family_id'],row['derived_case_id'],
             row['assessment_index'],row['attempt_id'])
        need(key in expected_cases,'CASE_ID_OR_SOURCE_UNKNOWN')
        match=expected_cases.pop(key)
        events=row['events']
        need(len(events)==10 and
             [e['algorithm'] for e in events]==list(STAGES) and
             all(events[idx]['result']==EXPECTED[step]
                 for idx,step in enumerate(STAGES) if step!='A5'),
             'GOLDEN_STAGE_SEQUENCE_MISMATCH')
        need(type(events[0]['detail'].get('gen1_head_sha256')) is str and
             len(events[0]['detail']['gen1_head_sha256'])==64 and
             events[0]['detail']['case_execution_accredited'] is False,
             'A1_INVALID')
        need(events[1]['detail']=={'unit_count':54,'case_unit_identity_attested':False} and
             events[2]['detail']=={'guard_authority':False} and
             events[3]['detail']=={'selection_authority':False},'A2_A4_INVALID')
        state=events[4]['result']
        need(state in counts and state==match['a5_review_state'] and
             events[4]['detail']['attempt_id']==row['attempt_id'] and
             events[4]['detail']['intent_sha256']==match['intent_sha256'] and
             events[4]['detail']['physical_start_accredited'] is False,
             'A5_GOLDEN_REVIEW_MISMATCH')
        counts[state]+=1
        need(events[5]['detail']=={'classification':'ND','technical_truth_accredited':False},
             'A6_FALSE_ADMISSION')
        a7=events[6]['detail']
        lo,half,hi=(Fraction(a7['interval'][0]),Fraction(a7['hypothetical_e_half']),
                    Fraction(a7['interval'][1]))
        need((lo,half,hi)==(Fraction(1,4),Fraction(5,12),Fraction(7,12)) and
             a7['confirmed_rf'] is None and
             match['a7_uncertainty_interval']==[str(lo),str(hi)] and
             match['a7_hypothetical_midpoint']==str(half),
             'A7_GOLDEN_MATHEMATICAL_ORACLE')
        need(events[7]['detail']=={
            'applied_transition':None,
            'separate_model_variants_denied':match['a8_model_variants_denied'],
            'same_assessment_as_model':False} and
            events[8]['detail']=={'new_generations':0,'published_technical_evidence':False} and
            events[9]['detail']=={'presentation_count':8,'new_technical_evidence':False},
            'A8_A10_GOLDEN_ORACLE')
        need(row['cross_population_join']=='CATALOG_ONLY' and
             row['technical_truth_accredited'] is False and row['confirmed_rf'] is None,
             'MODEL_JOIN_PROMOTED')
        result_rows.append({'service_id':row['service_id'],
                            'family_id':row['family_id'],
                            'derived_case_id':row['derived_case_id'],
                            'assessment_index':row['assessment_index'],
                            'attempt_id':row['attempt_id'],
                            'a5_review_state':state,
                            'a6':'ND',
                            'a7_hypothetical':['1/4','5/12','7/12'],
                            'a8':'HOLD_NO_AUTHORITY',
                            'events_verified':10,
                            'result':'PASS_DEV_GOLDEN_ONLY',
                            'source_head_sha256':row['head_sha256']})
    need(not expected_cases and counts=={'UNVERIFIED_DECLARATION':3,'NOT_STARTED':22},
         'A5_BRANCH_COUNTS_MISMATCH')
    result_rows.sort(key=lambda x:(x['service_id'],x['family_id']))
    source={'r86_sha256':ledger['sha256'],'r84_sha256':matrix['sha256'],
            'r85_sha256':faults['sha256'],
            'r81_sha256':ledger['source_links']['r81_sha256'],
            'r82_separate_population_sha256':ledger['source_links']['r82_separate_population_sha256']}
    doc={'schema':SCHEMA,'source_kind':SOURCE,'result':RESULT,
         'source_links':source,
         'session_id':ledger['single_session_id'],
         'case_count':25,'stage_count':10,'stage_events_verified':250,
         'a5_unverified_declarations':3,'a5_nonstarts':22,
         'a6_not_admitted':25,'a7_exact_unresolved':25,
         'a8_model_denials_separate':29,'a8_operational_transitions':0,
         'a2_synthetic_units_separate':54,
         'r85_rejected_faults':156,
         'dev_checks':[{'id':item,'status':'PASS_SOFTWARE_DEV_ONLY'} for item in CHECKS],
         'dev_check_count':len(CHECKS),
         'r84_software_criteria':[c['criterion'] for c in matrix['criteria'][:13]],
         'r84_external_pending':[c['criterion'] for c in matrix['criteria'][13:]],
         'cases':result_rows,
         'authoritative_cross_population_joins':0,
         'a6':'ND','confirmed_rf':None,
         'physical_executions':0,'operational_dispatch':False,
         'system_functional_acceptance':'PENDING',
         'experimental_validation':'NOT_RUN','p8_operational':'NO-GO'}
    doc['sha256']=digest(canonical(doc))
    need(len(canonical(doc))<=MAX_BYTES,'REPORT_TOO_LARGE')
    return doc

def compute(r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path,
            r85_root:Path,r86_root:Path)->dict[str,Any]:
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    ledger=r86.verify(r86_root,r81_root,r82_root,r83_root,r84_root,r85_root)
    matrix=r77.read_canonical(r84_root/'MANIFEST.json')
    faults=r77.read_canonical(r85_root/'MANIFEST.json')
    return assess(ledger,matrix,faults)

def create(dest:Path,*roots:Path)->dict[str,Any]:
    r81.checked_root(dest,existing=False)
    doc=compute(*roots)
    previous=os.umask(0o077)
    try:
        dest.mkdir(mode=0o700)
        r81.write(dest,'MANIFEST.json',canonical(doc)+b'\n')
    finally:
        os.umask(previous)
    return verify(dest,*roots)

def verify(dest:Path,*roots:Path)->dict[str,Any]:
    r81.r75.check_directory(dest,existing=True)
    need({p.name for p in dest.iterdir()}=={'MANIFEST.json'},'UNEXPECTED_RECEIPT_MEMBER')
    observed=r77.read_canonical(dest/'MANIFEST.json')
    need(canonical(observed)==canonical(compute(*roots)),
         'R87_REPLAY_OR_CUSTODY_DRIFT')
    return observed

def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--create',action='store_true')
    modes.add_argument('--verify',action='store_true')
    for label in ('work-dir','r81-receipt','r82-receipt','r83-receipt',
                  'r84-receipt','r85-receipt','r86-receipt'):
        ap.add_argument('--'+label,required=True,type=Path)
    opt=ap.parse_args(argv)
    try:
        roots=(opt.r81_receipt,opt.r82_receipt,opt.r83_receipt,
               opt.r84_receipt,opt.r85_receipt,opt.r86_receipt)
        doc=create(opt.work_dir,*roots) if opt.create else verify(opt.work_dir,*roots)
    except (ValueError,KeyError,TypeError,OSError,RuntimeError,OverflowError,ZeroDivisionError) as e:
        print('R87=BLOCKED:'+type(e).__name__+':'+str(e)[:190],file=sys.stderr)
        print('R87_P8=NO-GO',file=sys.stderr)
        return 23
    print('R87='+('PASS_DEV_ACCEPTANCE_CREATED' if opt.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R87_DEV_CHECKS='+str(doc['dev_check_count'])+'_PASS_SOFTWARE_ONLY')
    print('R87_CASES=25_OF_25')
    print('R87_STAGE_EVENTS=250_VERIFIED')
    print('R87_A5=3_UNVERIFIED_22_NOT_STARTED')
    print('R87_A6=ND_25_NOT_ADMITTED')
    print('R87_A7=25_EXACT_HYPOTHETICAL_INTERVALS')
    print('R87_A8=29_MODEL_DENIALS_0_OPERATIONAL_TRANSITIONS')
    print('R87_R85_FAULTS=156_REJECTED')
    print('R87_SYSTEM_ACCEPTANCE=PENDING')
    print('R87_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R87_SHA256='+doc['sha256'])
    print('R87_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
