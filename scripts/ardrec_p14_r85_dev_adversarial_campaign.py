#!/usr/bin/env python3
"""R85: 156 deterministic fail-closed probes against the authenticated R84 DEV gate.

No host operations, service traffic, A5 execution, VM, SQLite mutations or P8.
The probes validate software rejection under synthetic perturbations; they are
NOT empirical cybersecurity observations or full functional acceptance.
"""
from __future__ import annotations

import argparse
import copy
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

SCHEMA = 'ardrec-p14-r85-adversarial-dev-acceptance-fail-closed-v1'
SOURCE = 'SYNTHETIC_DEV_CONTRACT_MUTATION_TEST_NOT_EXPERIMENTAL_EVIDENCE'
MAX_BYTES = 250_000
EXPECTED = {'A5_BINDING':25, 'A6_FALSE_ADMISSION':25, 'A7_FALSE_RF':25,
            'A7_OUT_OF_RANGE':25, 'A8_FALSE_APPROVAL':29,
            'AUTHORITY_FORGERY':10, 'RECOVERY_FAILURE':4,
            'DEV_SESSION_FORGERY':6, 'R76_SOURCE_FORGERY':7}
GLOBAL_FORGERIES = (
    ('cross_population_authoritative_join_count',1),
    ('p8_operational','GO'),
    ('confirmed_rf','1/2'),
    ('operational_transitions_applied',1),
    ('physical_executions',1),
    ('technical_truth_accredited',True),
    ('system_functional_acceptance','PASS'),
    ('experimental_validation','PASS'),
    ('open_findings',[]),
    ('a9_new_generations',1),
)
MODEL_FORGERIES = (
    ('atomic_rollback_checks',1),
    ('idempotent_replay_checks',1),
    ('terminal_reentry_rejected',False),
    ('operational_transitions_applied',1),
)
SOFTWARE_FORGERIES = (
    ('local_benign_starts',2),
    ('physical_executions',1),
    ('a6','CONFIRMADO'),
    ('confirmed_rf','1/2'),
    ('p8_operational','GO'),
    ('software_dev_smoke','FAIL'),
)
R76_FORGERIES = (
    ('physical_a5_starts_accredited',1),
    ('a6_classification','POSITIVE'),
    ('a7_confirmed_rf','1/2'),
    ('operational_dispatch',True),
    ('p8_operational','GO'),
    ('synthetic_unverified_claim_count',4),
    ('synthetic_declared_nonstart_count',21),
)

class R85Error(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise R85Error(code)

def _rehash(doc:dict[str,Any]) -> None:
    doc['sha256'] = digest(canonical({k:v for k,v in doc.items() if k!='sha256'}))

def _tasks(inputs:tuple[dict[str,Any], ...]):
    walk, r76, software, model = inputs
    need(len(walk.get('families',[]))==25 and len(r76.get('candidates',[]))==25,
         'WRONG_FAMILY_SOURCE_COUNT')
    for idx, candidate in enumerate(r76['candidates']):
        fid=candidate['family_id']
        yield ('A5_BINDING',fid,idx,None,'tamper_attempt_id')
        yield ('A6_FALSE_ADMISSION',fid,idx,None,'forge_a6_truth')
        yield ('A7_FALSE_RF',fid,idx,None,'forge_confirmed_risk')
    for idx, family in enumerate(walk['families']):
        fid=family['family_id']
        yield ('A7_OUT_OF_RANGE',fid,idx,None,'force_risk_outside_unit_interval')
        for var_idx, variant in enumerate(family['model_cases']):
            yield ('A8_FALSE_APPROVAL',fid,idx,var_idx,'approve_denied_variant')
    for key,_ in GLOBAL_FORGERIES:
        yield ('AUTHORITY_FORGERY',key,None,None,'forge_global_authority')
    for key,_ in MODEL_FORGERIES:
        yield ('RECOVERY_FAILURE',key,None,None,'forge_recovery_property')
    for key,_ in SOFTWARE_FORGERIES:
        yield ('DEV_SESSION_FORGERY',key,None,None,'forge_dev_session_state')
    for key,_ in R76_FORGERIES:
        yield ('R76_SOURCE_FORGERY',key,None,None,'forge_original_intent_source')

def _mutate(documents:list[dict[str,Any]], task:tuple[Any, ...]) -> None:
    group, label, index, variant, mutation=task
    walk, candidates, software, model=documents
    if group == 'A5_BINDING':
        candidates['candidates'][index]['a5_intent']['attempt_id']='FORGED_R85_ATTEMPT'
    elif group == 'A6_FALSE_ADMISSION':
        candidates['candidates'][index]['a5_candidate']['a6_technical_truth_accredited']=True
    elif group == 'A7_FALSE_RF':
        candidates['candidates'][index]['a5_candidate']['a7_confirmed_rf']='1/2'
    elif group == 'A7_OUT_OF_RANGE':
        walk['families'][index]['r79_hypothetical_Ehalf']='2'
        _rehash(walk)
    elif group == 'A8_FALSE_APPROVAL':
        walk['families'][index]['model_cases'][variant]['denied']=False
        _rehash(walk)
    elif group == 'AUTHORITY_FORGERY':
        walk[label]=dict(GLOBAL_FORGERIES)[label]
        _rehash(walk)
    elif group == 'RECOVERY_FAILURE':
        model[label]=dict(MODEL_FORGERIES)[label]
    elif group == 'DEV_SESSION_FORGERY':
        software[label]=dict(SOFTWARE_FORGERIES)[label]
    elif group == 'R76_SOURCE_FORGERY':
        candidates[label]=dict(R76_FORGERIES)[label]
    else:
        raise R85Error('UNKNOWN_MUTATION_GROUP')

def campaign(r84_document:dict[str,Any], inputs:tuple[dict[str,Any],...])->dict[str,Any]:
    """Evaluate original report then prove every one of 156 alterations is denied."""
    need(type(r84_document) is dict and type(inputs) is tuple and len(inputs)==4 and
         all(type(x) is dict for x in inputs),'INVALID_BASELINE_TYPES')
    original=r84.evaluate(*inputs)
    need(canonical(original)==canonical(r84_document), 'R84_BASELINE_NOT_REPRODUCIBLE')
    need(original['software_contract_count']==13 and
         original['independent_acceptance_pending_count']==6 and
         original['case_count']==25 and original['model_variant_denials']==29 and
         original['system_functional_acceptance']=='PENDING' and
         original['experimental_validation']=='NOT_RUN' and
         original['p8_operational']=='NO-GO','R84_CRITERIA_OR_AUTHORITY_DRIFT')
    records=[]; counts={key:0 for key in EXPECTED}
    baseline_fingerprints=[digest(canonical(x)) for x in inputs]
    for group, label, idx, variant, action in _tasks(inputs):
        changed=copy.deepcopy(list(inputs))
        _mutate(changed,(group,label,idx,variant,action))
        need(any(digest(canonical(x))!=baseline_fingerprints[i]
                 for i,x in enumerate(changed)), 'VACUOUS_MUTATION_'+group)
        try:
            r84.evaluate(*changed)
        except r84.R84Error as exc:
            rejection=str(exc)
            need(rejection and len(rejection)<160, 'INVALID_R84_REJECTION_CODE')
        else:
            raise R85Error('UNDETECTED_MUTATION:'+group+':'+label)
        counts[group]+=1
        records.append({'group':group,'target':label,'mutation':action,
                        'model_variant':variant,'result':'REJECTED_BY_R84',
                        'guard':rejection})
    need(counts==EXPECTED and len(records)==156,'INCOMPLETE_FAULT_CAMPAIGN')
    need(all(x['result']=='REJECTED_BY_R84' for x in records), 'UNBLOCKED_FORGERY')
    body={
        'schema':SCHEMA,'source_kind':SOURCE,
        'r84_report_sha256':r84_document['sha256'],
        'r84_receipt_source_links':r84_document['source_links'],
        'stage_count':10,'synthetic_units':54,
        'analytical_family_count':25,'state_model_variant_count':29,
        'software_criteria_pass_dev_only':13,
        'external_criteria_pending':6,
        'fault_count':len(records),'fault_groups':counts,
        'faults_rejected':len(records),'faults_undetected':0,
        'faults':records,
        'operational_cross_population_joins':0,
        'a6_classification':'ND','a7_confirmed_rf':None,
        'a8_operational_transitions':0,'a9_new_generations':0,
        'physical_executions':0,'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
        'open_findings':['AL-06','AL-07'],
    }
    need(len(canonical(body))<MAX_BYTES-200,'REPORT_TOO_LARGE')
    body['sha256']=digest(canonical(body))
    return body

def _sources(r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path):
    need(os.geteuid()!=0 and Path.cwd().resolve()==REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    r81.r75.check_directory(r84_root,existing=True)
    need({x.name for x in r84_root.iterdir()}=={'MANIFEST.json'},
         'R84_SOURCE_FILESET_INVALID')
    saved=r77.read_canonical(r84_root/'MANIFEST.json')
    inputs=r84.sources(r81_root,r82_root,r83_root)
    # R84 matrix re-evaluation is byte-exact; no trust in a self-asserted checksum.
    need(canonical(r84.evaluate(*inputs))==canonical(saved),
         'R84_SOURCE_RECONSTRUCTION_FAILED')
    return saved,inputs

def compute(r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path):
    return campaign(*_sources(r81_root,r82_root,r83_root,r84_root))

def create(dest:Path,r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path):
    r81.checked_root(dest,existing=False)
    doc=compute(r81_root,r82_root,r83_root,r84_root)
    old=os.umask(0o077)
    try:
        dest.mkdir(mode=0o700)
        r81.write(dest,'MANIFEST.json',canonical(doc)+b'\n')
    finally:
        os.umask(old)
    need(r77.read_canonical(dest/'MANIFEST.json')==doc,'R85_WRITE_REPLAY_FAILED')
    return doc

def verify(dest:Path,r81_root:Path,r82_root:Path,r83_root:Path,r84_root:Path):
    r81.r75.check_directory(dest,existing=True)
    need({x.name for x in dest.iterdir()}=={'MANIFEST.json'},
         'R85_RECEIPT_FILESET_INVALID')
    stored=r77.read_canonical(dest/'MANIFEST.json')
    expected=compute(r81_root,r82_root,r83_root,r84_root)
    need(canonical(stored)==canonical(expected),'R85_REPLAY_OR_SOURCE_DRIFT')
    return stored

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--create',action='store_true')
    modes.add_argument('--verify',action='store_true')
    for opt in ('work-dir','r81-receipt','r82-receipt','r83-receipt','r84-receipt'):
        ap.add_argument('--'+opt,type=Path,required=True)
    ap.add_argument('--expected-r84-sha256',required=True)
    args=ap.parse_args(argv)
    try:
        saved=r77.read_canonical(args.r84_receipt/'MANIFEST.json')
        need(args.expected_r84_sha256==saved.get('sha256'),
             'R84_EXPECTED_SOURCE_PIN_MISMATCH')
        f=(args.work_dir,args.r81_receipt,args.r82_receipt,args.r83_receipt,args.r84_receipt)
        doc=create(*f) if args.create else verify(*f)
    except (ValueError,KeyError,TypeError,OSError,OverflowError,RuntimeError) as exc:
        print('R85=BLOCKED:'+type(exc).__name__+':'+str(exc)[:170],file=sys.stderr)
        print('R85_P8=NO-GO',file=sys.stderr)
        return 23
    print('R85='+('PASS_ADVERSARIAL_CREATED' if args.create else 'PASS_REPLAY_NO_EXECUTION'))
    print('R85_FAULT_INJECTIONS='+str(doc['fault_count']))
    print('R85_ALL_REJECTED='+str(doc['faults_rejected']))
    print('R85_UNDETECTED='+str(doc['faults_undetected']))
    print('R85_R84_DEV_CRITERIA=13_PASS_ONLY_6_PENDING_EXTERNAL')
    print('R85_A6=ND')
    print('R85_RF_CONFIRMED=NULL')
    print('R85_OPERATIONAL_TRANSITIONS=0')
    print('R85_PHYSICAL_EXECUTIONS=0')
    print('R85_SYSTEM_ACCEPTANCE=PENDING')
    print('R85_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R85_SHA256='+doc['sha256'])
    print('R85_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
