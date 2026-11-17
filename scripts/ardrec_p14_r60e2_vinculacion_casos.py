#!/usr/bin/env python3
"""R60-E2: ledger A1-A10 con 29 identidades modelo realmente vinculadas R58-K/L.

OFFLINE: conserva P8 NO-GO, A6 ND y A9 sin publicar. No evalua hosts ni VM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

REPO = Path('/home/cicada/Development/GitHub/ardrec')
LAB = Path('/home/cicada/ardrec-lab')
PRIOR = LAB / 'r60e1r2-rrm9eg5z/integrated.json'
PRIOR_SHA256 = '8549b011224e19b6066a77c547e0c623ceced3a77ca7866aaf9899b0de5184f7'
BASE = 'ce9478eb04fb9e6607af534fa415542e7cbf24cd'
SCHEMA = 'ardrec-r60e2-per-case-model-binding-v1'
SELF_REL = 'scripts/ardrec_p14_r60e2_vinculacion_casos.py'
KNOWN = frozenset({
    'scripts/ardrec_p14_r60e1_integracion_offline.py',
    'lab/tests/test_p14_r60e1_integracion_offline.py',
    'docs/development/p14-r60e1-integracion-offline.md',
    SELF_REL,
    'lab/tests/test_p14_r60e2_vinculacion_casos.py',
    'docs/development/p14-r60e2-vinculacion-casos.md',
})
SOURCE_PINS = {
    'scripts/ardrec_p14_r58k_unified_family_demo.py':'a04cd14b9268386f5b5669974c84f3d0aee3a36b',
    'scripts/ardrec_p14_r58l_a4_a5_review_demo.py':None,
    'lab/operational-catalog-v1/catalog.json':'1f201f5559b589933e3dad3ac76de3d2e37a246d',
    'lab/p14-r26-session-v1/scenario.json':'cf64c0a279700e41c1719b5842540b03938338d6',
}
HEX = re.compile(r'[a-f0-9]{64}\Z',re.ASCII)
MAX_PRIOR = 512_000
MAX_REPORT = 220_000

class Blocked(ValueError):
    pass

def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Blocked(reason)

def canonical(o: Any) -> bytes:
    return (json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=True,
                       allow_nan=False)+'\n').encode()

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def check_sha(x: Any) -> bool:
    return type(x) is str and HEX.fullmatch(x) is not None

def strict_json(raw: bytes) -> dict:
    def unique_pairs(pairs):
        result={}
        for k,v in pairs:
            need(k not in result,'DUPLICATE_JSON_KEY')
            result[k]=v
        return result
    try:
        doc=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Blocked('NONFINITE_JSON')))
    except (UnicodeError,json.JSONDecodeError) as e:
        raise Blocked('INVALID_JSON') from e
    need(type(doc) is dict,'EXPECTED_JSON_OBJECT')
    return doc

def case_key(row: dict) -> tuple:
    need(type(row) is dict,'CASE_RECORD_NOT_OBJECT')
    keys=('service_id','session_id','derived_case_id','assessment_index')
    need(all(k in row for k in keys),'CASE_IDENTITY_FIELDS_MISSING')
    need(all(type(row[k]) is str and 0<len(row[k])<=80 for k in keys[:-1]),
         'CASE_STRING_FIELD')
    need(type(row['assessment_index']) is int and 0<=row['assessment_index']<=2**31-1,
         'CASE_INDEX_INVALID')
    return tuple(row[k] for k in keys)

def assert_nonpromotion(row: dict) -> None:
    need(row.get('a6_classification')=='ND','FALSE_A6_CLASSIFICATION')
    need(row.get('technical_truth_accredited') is False,'FALSE_A6_AUTHORITY')
    need(row.get('confirmed_rf') is None,'FALSE_RF')
    need(row.get('published_generation') is None,'FALSE_A9_PUBLICATION')
    need(row.get('applied_transition') is None,'FALSE_A8_TRANSITION')

def build_ledger(prior: dict, review: dict, scenario: dict,
                 *, session_sha256: str) -> dict:
    """Pure synthesis: model K/L exact identity, R26 service context, no authority."""
    need(check_sha(session_sha256),'R26_SOURCE_DIGEST_INVALID')
    need(prior.get('schema')=='ardrec-r60e1r2-e0-log-reconciliation-v1',
         'PRIOR_SCHEMA')
    integration=prior.get('integration')
    need(type(integration) is dict,'PRIOR_INTEGRATION_MISSING')
    need(integration.get('model_demo_case_count')==29 and
         type(integration.get('model_demo_case_count')) is int and
         integration.get('model_case_capacity')==54 and
         integration.get('remaining_capacity_not_demonstrated')==25 and
         integration.get('families_in_demos')==25 and
         integration.get('ten_stage_trace_present') is True and
         integration.get('per_case_cross_contract_identity_attested') is False and
         integration.get('p8_operational')=='NO-GO', 'PRIOR_CONTRACT_INVALID')
    summaries=integration.get('source_summaries')
    need(type(summaries) is dict and set(summaries)=={'R58K','R58V','R58O'},
         'PRIOR_SUMMARY_SET')
    k,v,o=(summaries[x] for x in ('R58K','R58V','R58O'))
    need(k.get('case_count')==v.get('case_count')==o.get('case_count')==29,
         'PREVIOUS_CASE_COUNT_DRIFT')
    need(k.get('families')==v.get('families')==o.get('families')==25,
         'PREVIOUS_FAMILY_DRIFT')
    need(o.get('stage_count')==10 and o.get('case_binding_attested') is False,
         'PREVIOUS_STAGE_AUTHORITY')
    need(check_sha(k.get('sha256')) and check_sha(v.get('sha256')) and
         check_sha(o.get('sha256')) and check_sha(o.get('stage_head_sha256')),
         'PRIOR_SOURCE_DIGESTS')
    need(prior.get('p8_operational')=='NO-GO' and
         prior.get('host_mutations')==0 and
         prior.get('vm_start_requests')==0 and
         prior.get('nft_writes')==0, 'PRIOR_HOST_AUTHORITY')
    services=scenario.get('services')
    need(type(services) is list and len(services)==3,'R26_SERVICE_COUNT')
    service_map={}
    for item in services:
        need(type(item) is dict and type(item.get('id')) is str,'R26_SERVICE_FORMAT')
        need(item['id'] not in service_map,'R26_DUPLICATE_SERVICE')
        service_map[item['id']]=item
    need(set(service_map)=={'SSH_DEV','FTP_DEV','SMB_DEV'} and
         scenario.get('session_id')=='DEV_TUTOR_001', 'R26_SESSION_OR_SERVICES')
    for name,protocol in (('SSH_DEV','SSH'),('FTP_DEV','FTP'),('SMB_DEV','SMB')):
        need(service_map[name].get('protocol')==protocol,'R26_PROTOCOL_MISMATCH')
    unified=review.get('unified')
    need(type(unified) is dict and check_sha(unified.get('sha256')) and
         unified['sha256']==k['sha256'],'EXACT_R58K_R58L_MODEL_SHA_MISMATCH')
    need(review.get('session_id')==scenario['session_id'] and
         review.get('source_catalog_sha256')==unified.get('source_catalog_sha256'),
         'REVIEW_CATALOG_OR_SESSION')
    need(review.get('unit_count')==29 and type(review.get('unit_count')) is int and
         review.get('covered_family_count')==25 and
         review.get('count_by_service')=={'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11},
         'REVIEW_FIXTURE_CARDINALITY')
    need(review.get('a4_operational_selection') is None and
         review.get('a6_classification')=='ND' and
         review.get('technical_truth_accredited') is False and
         review.get('confirmed_final_risk') is None and
         review.get('applied_state_transition') is None and
         review.get('published_generation') is None and
         review.get('operational_dispatch') is False and
         review.get('p8_operational')=='NO-GO', 'REVIEW_FALSE_AUTHORITY')
    a5=review.get('a5')
    need(type(a5) is dict and
         a5.get('actual_attempts_started')==0 and
         a5.get('actual_attempt_reservations')==0, 'A5_FALSE_ATTEMPTS')
    urows=unified.get('decisions')
    rrows=review.get('decisions')
    need(type(urows) is list and len(urows)==29 and
         type(rrows) is list and len(rrows)==29,'CASE_ROWS_NOT_29')
    uk={}
    rk={}
    for row in urows:
        key=case_key(row)
        need(key not in uk,'K_DUPLICATE_CASE')
        assert_nonpromotion(row)
        need(row.get('a8_recommendation')=='PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
             'K_A8_UNSAFE')
        uk[key]=row
    for row in rrows:
        key=case_key(row)
        need(key not in rk,'L_DUPLICATE_CASE')
        assert_nonpromotion(row)
        need(row.get('a8_recommendation')=='PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
             'L_A8_UNSAFE')
        rk[key]=row
    need(set(uk)==set(rk),'CASE_LEVEL_IDENTITY_MISMATCH')
    selected=review.get('a4_selected_identity')
    need(type(selected) is dict,'SELECTED_CASE_MISSING')
    selected_key=case_key(selected)
    need(selected_key in rk,'SELECTED_CASE_NOT_IN_REPORT')
    rows=[]
    covered=set()
    seen_case_ids=set()
    by_service={name:0 for name in service_map}
    for key in sorted(uk):
        a,b=uk[key],rk[key]
        for field in ('family_id','variant','case_id_a7','a6_classification',
                      'a7_rf_lower','a7_rf_upper','a8_recommendation'):
            need(a.get(field)==b.get(field),'MODEL_CASE_FIELD_MISMATCH:'+field)
        need(type(a.get('family_id')) is str and
             a['family_id'].startswith(key[0].split('_')[0]+'-'),
             'FAMILY_SERVICE_ID_MISMATCH')
        need(type(a.get('case_id_a7')) is str and
             a['case_id_a7'].startswith('CASE_'), 'A7_CASE_ID_INVALID')
        # A4 puede escoger exactamente un modelo; nunca es autorización operativa.
        flag=b.get('a4_selected_simulated')
        need(type(flag) is bool and flag==(key==selected_key),
             'A4_SELECTED_FLAG_DRIFT')
        need(type(b.get('a5_history_is_synthetic')) is bool and
             b.get('a6_hypothetical_result')==a.get('hypothetical_result_class'),
             'A5_OR_A6_CASE_BRIDGE_DRIFT')
        need(a['case_id_a7'] not in seen_case_ids,'A7_DUPLICATE_CASE_ID')
        seen_case_ids.add(a['case_id_a7'])
        covered.add(a['family_id'])
        by_service[key[0]]+=1
        rows.append({
            'service_id':key[0], 'session_id':key[1],
            'derived_case_id':key[2], 'assessment_index':key[3],
            'family_id':a['family_id'], 'variant':a.get('variant'),
            'a7_case_id':a['case_id_a7'],
            'a1_a3_service_context_fact':service_map[key[0]].get('fact'),
            'a1_a3_to_family_case_binding_attested':False,
            'a4_selected_simulated':flag,
            'a5_physical_execution':False,
            'a6_hypothetical_result_class':a.get('hypothetical_result_class'),
            'a6_classification':'ND',
            'a7_rf_lower':a['a7_rf_lower'],
            'a7_rf_upper':a['a7_rf_upper'],
            'a8_recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
            'a8_applied_transition':None,
            'a9_published_generation':None,
        })
    need(by_service=={'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11},'PER_SERVICE_CASE_COUNT')
    need(len(covered)==25,'FAMILY_COVERAGE_25')
    need(sum(r['a4_selected_simulated'] for r in rows)==1,'A4_SELECTION_CARDINALITY')
    stages=[{'algorithm':'A'+str(i),'model_scope':(
        'R26_THREE_SERVICES_NOT_CASE_AUTHORITY' if i<=3 else
        'R58L_CASE_MODEL_NOT_PHYSICAL' if i<=8 else
        'DECLARED_LOCAL_ONLY' if i==9 else
        'SYNTHETIC_LEDGER_ONLY')} for i in range(1,11)]
    report={
        'schema':SCHEMA,'source_base_commit':BASE,
        'source_prior_r60e1r2_sha256':PRIOR_SHA256,
        'source_r58k_unified_sha256':unified['sha256'],
        'source_r58l_review_sha256':review['sha256'],
        'source_r26_session_sha256':session_sha256,
        'source_r58o_stage_ledger_head_sha256':o['stage_head_sha256'],
        'case_count':29,'capacity_only':54,'missing_authentic_case_definitions':25,
        'covered_family_count':25,'case_count_by_service':by_service,
        'case_identity_binding_k_l':'EXACT_MODEL_SHA_AND_PER_CASE_FIELDS',
        'a1_a3_to_a4_a8_operational_identity_attested':False,
        'r58v_r58o_per_case_binding_attested':False,
        'ten_stage_ledger':stages,'ten_stage_count':10,
        'case_rows':rows,
        'a5_physical_attempts':0,'a6_classification':'ND',
        'technical_truth_accredited':False,
        'confirmed_final_risk':None,'a8_applied_transitions':0,
        'a9_published_generation':None,
        'a1_a10_full_execution_complete':False,
        'experimental_hypothesis_validated':False,
        'host_mutations':0,'vm_start_requests':0,'nft_writes':0,
        'operational_dispatch':False,'p8_operational':'NO-GO',
    }
    need(len(canonical(report))<MAX_REPORT,'REPORT_TOO_LARGE')
    report['sha256']=digest(canonical(report))
    return report

def check_dir(path: Path, uid: int) -> None:
    need(path.is_dir() and not path.is_symlink(),'PRIVATE_DIRECTORY_REQUIRED')
    s=path.stat()
    need(s.st_uid==uid and not (stat.S_IMODE(s.st_mode)&0o077),
         'PRIVATE_DIRECTORY_OWNER_OR_MODE')

def read_prior() -> dict:
    uid=os.geteuid()
    check_dir(LAB,uid)
    check_dir(PRIOR.parent,uid)
    need(PRIOR.parent.parent==LAB and PRIOR.name=='integrated.json','PRIOR_PATH')
    fd=os.open(PRIOR,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0))
    try:
        s=os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid==uid and
             not (stat.S_IMODE(s.st_mode)&0o077) and
             0<s.st_size<MAX_PRIOR,'PRIOR_PERMISSIONS_OR_SIZE')
        raw=os.read(fd,MAX_PRIOR+1)
        need(len(raw)==s.st_size and digest(raw)==PRIOR_SHA256,'PRIOR_SHA256_OR_SIZE_DRIFT')
        doc=strict_json(raw)
        need(doc.get('sha256')==digest(canonical({k:v for k,v in doc.items() if k!='sha256'})),
             'PRIOR_CANONICAL_DIGEST_DRIFT')
        return doc
    finally:
        os.close(fd)

def cmd_git(*args: str) -> str:
    cp=subprocess.run(['git','-C',str(REPO),*args],stdin=subprocess.DEVNULL,
                      capture_output=True,check=False,timeout=12)
    need(cp.returncode==0 and len(cp.stdout)<65536,'GIT_INSPECTION_FAILED')
    return cp.stdout.decode('utf-8').strip()

def check_environment() -> None:
    need(os.geteuid()!=0,'NON_ROOT_REQUIRED')
    need(Path.cwd().resolve()==REPO,'REPO_ROOT_REQUIRED')
    need(cmd_git('rev-parse','HEAD')==BASE,'BASE_HEAD_CHANGED')
    status=cmd_git('status','--porcelain=v1','--untracked-files=all')
    for line in status.splitlines():
        need(line.startswith('?? ') and line[3:] in KNOWN,
             'CHECKOUT_DIRTY_OR_UNEXPECTED_SOURCE:'+line[:90])
    for path,pin in SOURCE_PINS.items():
        need((REPO/path).is_file() and not (REPO/path).is_symlink(),'SOURCE_ABSENT:'+path)
        observed=cmd_git('hash-object','--',path)
        if pin is not None:
            need(observed==pin,'GIT_BLOB_CHANGED:'+path)
        else:
            need(observed==cmd_git('rev-parse',f'HEAD:{path}'),
                 'R58L_SOURCE_NOT_IN_BASE')

def actual_model_report(prior: dict) -> dict:
    # Modo -I: insertar rutas concretas del checkout sin confiar en PYTHONPATH externo.
    sys.path.insert(0,str(REPO/'src'))
    sys.path.insert(0,str(REPO))
    from ardrec.coordination.demo_session import read_fixed_scenario, build_development_session
    from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review, verify_a4_a5_review
    from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries
    scenario=read_fixed_scenario(REPO/'lab/p14-r26-session-v1/scenario.json')
    session=build_development_session(scenario)
    need(session.verify() is True,'R26_SESSION_VERIFY_FAILED')
    review=build_a4_a5_review(synthetic_entries())
    need(verify_a4_a5_review(review) is True,'R58L_MODEL_VERIFY_FAILED')
    return build_ledger(prior,review,scenario,session_sha256=session.sha256)

def write_one(directory: Path, filename: str, raw: bytes) -> None:
    fd=os.open(directory/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)

def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight',action='store_true')
    modes.add_argument('--capture',action='store_true')
    args=parser.parse_args(argv)
    try:
        check_environment()
        prior=read_prior()
        report=actual_model_report(prior)
        print('R60E2_R58K_R58L=PASS_EXACT_MODEL_SHA_AND_29_IDENTITIES')
        print('R60E2_R26=PASS_THREE_MODEL_SERVICE_CONTEXTS')
        print('R60E2_PREVIOUS_R60E1_R2=PASS_PINNED_REPORT')
        print('R60E2_MODEL_SHA256='+report['sha256'])
        if args.preflight:
            print('R60E2=READY_EXPLICIT_PRIVATE_CAPTURE_NO_PHYSICAL_EXECUTION')
            return 21
        parent=LAB
        check_dir(parent,os.geteuid())
        os.umask(0o077)
        directory=Path(tempfile.mkdtemp(prefix='r60e2-',dir=str(parent)))
        payload=canonical(report)
        write_one(directory,'case_ledger.json',payload)
        manifest={'schema':'ardrec-r60e2-manifest-v1',
                  'case_ledger_sha256':digest(payload),
                  'model_cases':29,'model_families':25,'model_stages':10,
                  'source_prior_report_sha256':PRIOR_SHA256,'p8_operational':'NO-GO'}
        write_one(directory,'manifest.json',canonical(manifest))
        need((directory/'case_ledger.json').read_bytes()==payload,'READBACK_MISMATCH')
        print('R60E2=PASS_29_CASES_MODEL_LINKED_NO_REAL_CASE_AUTHORITY')
        print('R60E2_CASES=29; CAPACITY=54; AUTHENTIC_54=NOT_ATTESTED; FAMILIES=25; STAGES=10')
        print('R60E2_A5=NO_REAL_START; A6=ND; A9=NOT_PUBLISHED; P8=NO-GO')
        print('R60E2_LEDGER='+str(directory/'case_ledger.json'))
        print('R60E2_LEDGER_SHA256='+digest(payload))
        print('R60E2_MANIFEST='+str(directory/'manifest.json'))
        print('R60E2_HOST_MUTATIONS=0; VM_STARTS=0; NFT_WRITES=0; P8=NO-GO')
        return 0
    except (Blocked,ValueError,KeyError,TypeError,OSError,UnicodeError,
            subprocess.SubprocessError,RecursionError,AssertionError) as e:
        print('R60E2=BLOCKED:'+type(e).__name__+':'+str(e)[:180],file=sys.stderr)
        print('R60E2_NO_HOST_MUTATION; P8=NO-GO',file=sys.stderr)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
