#!/usr/bin/env python3
"""R84: conservative A5-A8 software-readiness contract on authenticated R81-R83.

DEV-only, no physical attestation, A5 process, operational A8 or P8.
Reads all earlier receipts and regenerates the R83 map; creates a PRIVATE,
reproducible criteria matrix. Software-only checks are not system acceptance.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))
from ardrec.persistence.codec import canonical, digest
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r81_functional_smoke as r81
import ardrec_p14_r82_model_transition_recovery as r82
import ardrec_p14_r83_cross_population_integrity as r83

SCHEMA = 'ardrec-p14-r84-conservative-dev-a5-a8-acceptance-gate-v1'
SOURCE = 'MODEL_SOFTWARE_READINESS_ONLY_NO_TECHNICAL_ATTESTATION'
MAX_REPORT_BYTES = 250_000
CASE_COUNTS = {'SSH_DEV':8, 'FTP_DEV':8, 'SMB_DEV':9}
EXPERIMENTAL = (
    'INDEPENDENT_PHYSICAL_A5_START',
    'INDEPENDENT_A6_EVIDENCE_ADMISSION',
    'CONFIRMED_A7_FINAL_RISK',
    'AUTHORIZED_A8_OPERATIONAL_TRANSITION',
    'F11_PHYSICAL_CONTAINMENT_ACCEPTANCE',
    'SYSTEM_EXPERIMENTAL_VALIDATION',
)
SOFTWARE = (
    'REPRODUCIBLE_R81_DEV_SESSION',
    'R82_ATOMIC_ROLLBACK',
    'R82_IDEMPOTENT_RECOVERY',
    'R82_TERMINAL_PHASE_IMMUTABILITY',
    'R83_25_FAMILY_COVERAGE',
    'R83_29_MODEL_VARIANT_COVERAGE',
    'R83_NO_FALSE_ASSESSMENT_JOIN',
    'A5_EXACT_TYPED_INTENT_BINDING',
    'A6_UNACCREDITED_DECLARATION_QUARANTINE',
    'A7_EXACT_RATIONAL_UNCERTAINTY',
    'A8_DENY_ONLY_MODEL_BOUNDARY',
    'A9_GEN1_NO_FALSE_PUBLICATION',
    'A10_10_STAGE_TRACEABILITY',
)

class R84Error(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise R84Error(code)

def _safe_sha(doc: dict[str, Any], field: str) -> str:
    val = doc.get(field)
    need(type(val) is str and len(val) == 64 and all(c in '0123456789abcdef' for c in val),
         'INVALID_SHA256_' + field)
    return val

def evaluate(crosswalk:dict[str,Any], r76:dict[str,Any], software:dict[str,Any],
             model:dict[str,Any]) -> dict[str,Any]:
    """Pure, deterministic DEV acceptance analysis. No claims of physical truth."""
    need(all(type(x) is dict for x in (crosswalk,r76,software,model)), 'INPUT_TYPES')
    for doc in (crosswalk,r76,software,model):
        _safe_sha(doc, 'sha256')
    body={k:v for k,v in crosswalk.items() if k != 'sha256'}
    need(crosswalk['sha256'] == digest(canonical(body)), 'R83_MANIFEST_DIGEST_INVALID')
    need(crosswalk.get('schema') == r83.SCHEMA and
         crosswalk.get('source_kind') == r83.SOURCE and
         crosswalk.get('r81_manifest_sha256') == software['sha256'] and
         crosswalk.get('r82_manifest_sha256') == model['sha256'] and
         crosswalk.get('r76_report_sha256') == r76['sha256'] and
         crosswalk.get('cross_population_authoritative_join_count') == 0 and
         crosswalk.get('family_catalog_coverage') == 25 and
         crosswalk.get('model_coverage') == 29 and
         crosswalk.get('a1_a10_stages') == [f'A{i}' for i in range(1,11)] and
         crosswalk.get('model_denied_requests') == model.get('r58_denied_operational_requests') and
         crosswalk.get('operational_transitions_applied') == 0 and
         crosswalk.get('technical_truth_accredited') is False and
         crosswalk.get('confirmed_rf') is None and
         crosswalk.get('a6') == 'ND' and
         crosswalk.get('a9_new_generations') == 0 and
         crosswalk.get('physical_executions') == 0 and
         crosswalk.get('operational_dispatch') is False and
         crosswalk.get('p8_operational') == 'NO-GO' and
         crosswalk.get('system_functional_acceptance') == 'PENDING' and
         crosswalk.get('experimental_validation') == 'NOT_RUN' and
         crosswalk.get('open_findings') == ['AL-06','AL-07'],
         'R83_NO_AUTHORITY_BOUNDARY_DRIFT')
    need(software.get('software_dev_smoke') == 'PASS' and
         software.get('a6') == 'ND' and software.get('confirmed_rf') is None and
         software.get('local_benign_starts') == 1 and
         software.get('physical_executions') == 0 and
         software.get('p8_operational') == 'NO-GO' and
         software.get('system_functional_acceptance') == 'PENDING' and
         software.get('experimental_validation') == 'NOT_RUN',
         'R81_SOFTWARE_AUTHORITY_DRIFT')
    need(model.get('r81_software_smoke_sha256') == software['sha256'] and
         model.get('atomic_rollback_checks') == 2 and
         model.get('idempotent_replay_checks') == 2 and
         model.get('terminal_reentry_rejected') is True and
         model.get('operational_transitions_applied') == 0 and
         model.get('technical_truth_accredited') is False and
         model.get('confirmed_rf') is None and
         model.get('p8_operational') == 'NO-GO',
         'R82_STATE_AUTHORITY_DRIFT')
    need(r76.get('family_count') == 25 and
         r76.get('physical_a5_starts_accredited') == 0 and
         r76.get('a6_classification') == 'ND' and
         r76.get('a7_confirmed_rf') is None and
         r76.get('operational_dispatch') is False and
         r76.get('p8_operational') == 'NO-GO' and
         r76.get('synthetic_unverified_claim_count') == 3 and
         r76.get('synthetic_declared_nonstart_count') == 22 and
         type(r76.get('candidates')) is list and len(r76['candidates']) == 25,
         'R76_NO_AUTHORITY_BOUNDARY_DRIFT')
    candidate_map={}
    intent_keys=set()
    for candidate in r76['candidates']:
        need(type(candidate) is dict and type(candidate.get('a5_intent')) is dict and
             type(candidate.get('a5_candidate')) is dict,
             'A5_INTENT_SCHEMA')
        intent=candidate['a5_intent']; evidence=candidate['a5_candidate']
        key=(candidate.get('service_id'),candidate.get('family_id'))
        assessment=(intent.get('session_id'),intent.get('service_id'),
                    intent.get('derived_case_id'),intent.get('assessment_index'),
                    intent.get('attempt_id'))
        need(key not in candidate_map and assessment not in intent_keys and
             key == (intent.get('service_id'),intent.get('family_id')) and
             candidate.get('derived_case_id') == intent.get('derived_case_id') and
             candidate.get('a6_classification') == 'ND' and
             candidate.get('physical_start_accredited') is False and
             evidence.get('a5_physical_start_accredited') is False and
             evidence.get('a5_case_binding_independently_attested') is False and
             evidence.get('a6_classification') == 'ND' and
             evidence.get('a6_technical_truth_accredited') is False and
             evidence.get('a7_confirmed_rf') is None and
             evidence.get('p8_operational') == 'NO-GO' and
             evidence.get('operational_dispatch') is False and
             evidence.get('intent') == intent and
             evidence.get('receipt',{}).get('intent_sha256') == intent.get('sha256') and
             evidence.get('receipt',{}).get('declared_outcome') == candidate.get('declared_outcome'),
             'A5_ATTEMPT_ASSESSMENT_MISMATCH')
        need(type(intent.get('assessment_index')) is int and
             intent['assessment_index'] == 0 and
             type(intent.get('sha256')) is str and len(intent['sha256']) == 64,
             'A5_INDEX_OR_DIGEST_INVALID')
        candidate_map[key]=candidate; intent_keys.add(assessment)
    need(len(candidate_map)==25 and len(intent_keys)==25, 'A5_DUPLICATE_ATTEMPT')
    cases=[]; declared=0; nonstart=0; variants=0
    families=crosswalk.get('families')
    need(type(families) is list and len(families)==25, 'R83_FAMILY_SET_INVALID')
    found=set()
    for family in families:
        need(type(family) is dict and type(family.get('model_cases')) is list,
             'R83_FAMILY_SCHEMA')
        key=(family.get('service_id'),family.get('family_id'))
        need(key not in found and key in candidate_map, 'R83_FAMILY_IDENTITY_MISMATCH')
        found.add(key)
        candidate=candidate_map[key]; intent=candidate['a5_intent']
        need(family.get('r76_a7_case_id') == candidate.get('a7_case_id') and
             family.get('r76_assessment_index') == intent['assessment_index'] and
             family.get('same_assessment_attested') is False and
             family.get('cross_population_join') == 'CATALOG_FAMILY_ONLY' and
             family.get('technical_truth_accredited') is False and
             family.get('confirmed_final_risk') is None and
             family.get('model_variant_count') == len(family['model_cases']) and
             all(type(m) is dict and m.get('denied') is True and
                 type(m.get('logical_candidate')) is bool
                 for m in family['model_cases']),
             'MODEL_JOIN_FALSE_AUTHORITY')
        lo,mid,hi=(Fraction(family[k]) for k in
                    ('r79_hypothetical_E0','r79_hypothetical_Ehalf','r79_hypothetical_E1'))
        need(0 <= lo <= mid <= hi <= 1, 'A7_EXACT_BOUNDS_INVALID')
        outcome=candidate.get('declared_outcome')
        need(outcome in {'NO_START','OBSERVADO_POSITIVO','OBSERVADO_NEGATIVO','INCONCLUSO'},
             'A5_CLAIM_NOT_TYPED')
        status='NOT_STARTED' if outcome == 'NO_START' else 'UNVERIFIED_DECLARATION'
        if status=='NOT_STARTED': nonstart+=1
        else: declared+=1
        variants+=len(family['model_cases'])
        cases.append({
            'service_id':key[0], 'family_id':key[1],
            'derived_case_id':intent['derived_case_id'],
            'assessment_index':intent['assessment_index'],
            'attempt_id':intent['attempt_id'],
            'configuration_sha256':intent['configuration_sha256'],
            'method_id':intent['method_id'],
            'intent_sha256':intent['sha256'],
            'a7_case_id':family['r76_a7_case_id'],
            'declared_outcome':outcome, 'a5_review_state':status,
            'a6_admission':'NOT_ADMITTED', 'a6_classification':'ND',
            'a7_uncertainty_interval':[str(lo),str(hi)],
            'a7_hypothetical_midpoint':str(mid),
            'a7_confirmed_rf':None,
            'a8_decision':'HOLD_NO_AUTHORITY',
            'a8_model_variants_denied':len(family['model_cases']),
            'a8_operational_transition':None,
            'same_assessment_as_model':False,
            'independent_technical_evidence':False,
        })
    need(found==set(candidate_map) and declared==3 and nonstart==22 and
         variants==29 and
         {sid:sum(x['service_id']==sid for x in cases) for sid in CASE_COUNTS}==CASE_COUNTS,
         'A5_A8_COHORT_COUNT_DRIFT')
    cases.sort(key=lambda c:(c['service_id'],c['family_id']))
    criteria=[{'criterion':x,'result':'PASS_DEV_CONTRACT_ONLY'} for x in SOFTWARE]
    criteria += [{'criterion':x,'result':'PENDING_EXTERNAL_ATTESTATION'} for x in EXPERIMENTAL]
    result={
        'schema':SCHEMA,'source_kind':SOURCE,
        'source_links':{
            'r83_sha256':crosswalk['sha256'], 'r81_sha256':software['sha256'],
            'r82_sha256':model['sha256'],'r76_sha256':r76['sha256'],
        },
        'software_contract_count':len(SOFTWARE),
        'software_contract_result':'PASS_DEV_CONTRACT_ONLY',
        'independent_acceptance_pending_count':len(EXPERIMENTAL),
        'criteria':criteria,'cases':cases,
        'case_count':25,'model_variant_denials':29,
        'unverified_declarations':3,'no_start_count':22,
        'population_identity':'CATALOG_ONLY_NOT_EXPERIMENTAL',
        'a1_a10_stages':[f'A{i}' for i in range(1,11)],
        'a6_classification':'ND','technical_truth_accredited':False,
        'a7_confirmed_rf':None,'a8_operational_transitions':0,
        'a9_new_generations':0,'physical_executions':0,
        'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
        'open_findings':['AL-06','AL-07'],
    }
    need(len(canonical(result)) < MAX_REPORT_BYTES, 'R84_REPORT_OVERSIZE')
    result['sha256']=digest(canonical(result))
    return result


def sources(r81_root:Path,r82_root:Path,r83_root:Path):
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    crosswalk=r83.verify(r83_root,r81_root,r82_root)
    software=r81.verify(r81_root)
    model=r82.verify(r82_root,r81_root)
    r76=r77.read_canonical(r81_root/'sources'/'r76.json')
    return crosswalk,r76,software,model

def compute(r81_root:Path,r82_root:Path,r83_root:Path)->dict[str,Any]:
    return evaluate(*sources(r81_root,r82_root,r83_root))

def create(dest:Path,r81_root:Path,r82_root:Path,r83_root:Path)->dict[str,Any]:
    r81.checked_root(dest, existing=False)
    report=compute(r81_root,r82_root,r83_root)
    old=os.umask(0o077)
    try:
        dest.mkdir(mode=0o700)
        r81.write(dest,'MANIFEST.json',canonical(report)+b'\n')
    finally:os.umask(old)
    return verify(dest,r81_root,r82_root,r83_root)

def verify(dest:Path,r81_root:Path,r82_root:Path,r83_root:Path)->dict[str,Any]:
    r81.r75.check_directory(dest,existing=True)
    need({p.name for p in dest.iterdir()}=={'MANIFEST.json'}, 'R84_RECEIPT_FILESET')
    stored=r77.read_canonical(dest/'MANIFEST.json')
    derived=compute(r81_root,r82_root,r83_root)
    need(canonical(stored)==canonical(derived),'R84_REPLAY_OR_SOURCE_DRIFT')
    return stored

def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--create',action='store_true')
    modes.add_argument('--verify',action='store_true')
    ap.add_argument('--work-dir',type=Path,required=True)
    ap.add_argument('--r81-receipt',type=Path,required=True)
    ap.add_argument('--r82-receipt',type=Path,required=True)
    ap.add_argument('--r83-receipt',type=Path,required=True)
    ap.add_argument('--expected-r83-sha256',required=True)
    opt=ap.parse_args(argv)
    try:
        expected=r77.read_canonical(opt.r83_receipt/'MANIFEST.json')
        need(type(opt.expected_r83_sha256) is str and
             opt.expected_r83_sha256==_safe_sha(expected,'sha256'),
             'EXPECTED_R83_PIN_MISMATCH')
        doc=create(opt.work_dir,opt.r81_receipt,opt.r82_receipt,opt.r83_receipt) if opt.create else verify(
            opt.work_dir,opt.r81_receipt,opt.r82_receipt,opt.r83_receipt)
    except (ValueError,KeyError,OSError,TypeError,RuntimeError,OverflowError) as exc:
        print('R84=BLOCKED:'+type(exc).__name__+':'+str(exc)[:170],file=sys.stderr)
        print('R84_P8=NO-GO',file=sys.stderr)
        return 23
    print('R84='+('PASS_DEV_MATRIX_CREATED' if opt.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R84_A5=25_TYPED_ATTEMPTS_3_UNVERIFIED_22_NONSTART')
    print('R84_A6=25_NOT_ADMITTED_ND')
    print('R84_A7=25_EXACT_UNRESOLVED_INTERVALS')
    print('R84_A8=29_MODEL_DENIALS_0_OPERATIONAL_TRANSITIONS')
    print('R84_SOFTWARE_CONTRACTS='+str(doc['software_contract_count'])+'_PASS_DEV_ONLY')
    print('R84_EXTERNAL_CRITERIA='+str(doc['independent_acceptance_pending_count'])+'_PENDING')
    print('R84_SHA256='+doc['sha256'])
    print('R84_SYSTEM_ACCEPTANCE=PENDING')
    print('R84_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R84_RF_CONFIRMED=NULL')
    print('R84_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
