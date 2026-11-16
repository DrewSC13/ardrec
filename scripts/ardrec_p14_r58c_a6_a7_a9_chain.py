#!/usr/bin/env python3
"""R58-C: A6 -> A7 -> A8 -> A9 documentary pipeline, no VM dispatch.

A6 admits only evidence for documentary review. A7 is *mathematical preview*
and A9 is a development receipt (not a published technical generation).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))

from ardrec.analytics.exact_preview import digest, canonical, preview_bounds, verify_bounds
from ardrec.coordination.demo_session import read_fixed_scenario, build_development_session
from ardrec.coordination.benign_review import analyze_selection
from ardrec.evidence.defensive_import import (
    read_observation, admit_defensive_observation, validate_admission)
from ardrec.stopping.development_stop import preview_stop, verify_stop
from ardrec.persistence.development_receipt import build_receipt, verify_receipt, persist_receipt

SCHEMA = 'ardrec-r58c-a6-a7-a8-a9-documentary-chain-v1'
SCENARIO = REPO/'lab/p14-r26-session-v1/scenario.json'
SYNTHETIC_RECEIPT = REPO/'lab/p14-r37-a6-defensive-import-v1/synthetic-receipt.json'
SYNTHETIC_SUPPORT = REPO/'lab/p14-r37-a6-defensive-import-v1/synthetic-support.txt'
SYNTHETIC_ASOF = '2026-11-14T20:00:00Z'

class ChainError(ValueError):
    pass


def require(ok: bool, reason: str):
    if not ok:
        raise ChainError(reason)


def build_documentary_chain(admission: dict, *, scenario: dict,
                            output_dir: Path | None = None) -> dict:
    """Bind real A6 hash to exact A7, conservative A8 and durable A9.

    The only possible write is opt-in A9 local receipt under output_dir.
    No A6 claim, even OPERATOR_DEV_RECEIPT, is treated as technical truth.
    """
    validate_admission(admission)
    session = build_development_session(scenario)
    session.verify()
    require(admission['session_id'] == session.document['session_id'],
            'SESSION_BINDING_MISMATCH')
    review = analyze_selection(scenario)
    require(review['session_sha256'] == session.sha256 and
            review['a4_confirmed']['selected'] is None, 'A4_A6_REVIEW_BINDING_UNSAFE')
    unit = next(u for u in session.document['units'] if u['service_id']=='SSH_DEV')
    require(unit['a2']['initial_phase']=='PREPARADO' and
            unit['technical_evidence'] is None and unit['final_risk'] is None,
            'UNAUTHORIZED_SESSION_STATE')
    r0 = unit['a2']['initial_risk']
    cn = unit['a2']['normalized_criticality']
    # No verified contribution or replacement risk is introduced by A6 ND.
    a7 = preview_bounds(r0,cn,[],r0)
    verify_bounds(a7)
    a8 = preview_stop(a6_classification='ND', accredited=False, vm_checked=False,
                      operational_dispatch=False, source_sha256=admission['sha256'])
    verify_stop(a8)
    r27_sha = digest(review)
    a9 = build_receipt(session_sha=session.sha256, r27_sha=r27_sha,
                       a7_sha=a7['sha256'], a8_sha=a8['sha256'])
    verify_receipt(a9)
    # No storage changes unless the user explicitly chose --write-development-receipt.
    if output_dir is not None:
        require(isinstance(output_dir,Path), 'OUTPUT_DIRECTORY_INVALID')
        resolved=output_dir.resolve()
        require(resolved != REPO and REPO not in resolved.parents,
                'A9_RECEIPT_MUST_BE_OUTSIDE_GIT')
        require(output_dir.exists() and output_dir.is_dir() and not output_dir.is_symlink(),
                'A9_PRIVATE_DIRECTORY_REQUIRED')
        target = persist_receipt(output_dir,a9)
        require(target.read_bytes() == canonical(a9)+b'\n',
                'A9_PERSISTED_READBACK_DIFFERS')
    report = {
        'schema': SCHEMA,
        'session_id': admission['session_id'],
        'service_id': admission['service_id'],
        'case_id': admission['case_id'],
        'evidence_scope': 'DOCUMENTARY_ONLY_NO_INDEPENDENT_PHYSICAL_ATTESTATION',
        'a4_confirmed_selected': None,
        'a5_technical_execution': 'NOT_EXECUTED',
        'a6': {
            'classification': 'ND',
            'source_kind': admission['source_kind'],
            'receipt_sha256': admission['receipt_sha256'],
            'support_sha256_verified': admission['support_sha256_verified'],
            'admission_sha256': admission['sha256'],
            'technical_truth_accredited': False,
        },
        'a7': {
            'mode': 'EXACT_BOUNDS_ONLY',
            'oracle_sha256': a7['sha256'],
            'hypothetical_rf': a7['hypothetical_rf'],
            'evidence_contributions': [],
            'confirmed_rf': None,
        },
        'a8': {
            'stop_sha256': a8['sha256'],
            'recommendation': a8['recommendation'],
            'applied_transition': None,
        },
        'a9': {
            'development_receipt_sha256': a9['sha256'],
            'local_development_receipt_written': output_dir is not None,
            'published_generation': None,
            'technical_generation_published': False,
        },
        'chain': {
            'r26_session_sha256': session.sha256,
            'r27_review_sha256': r27_sha,
            'a6_admission_sha256': admission['sha256'],
            'a7_oracle_sha256': a7['sha256'],
            'a8_stop_sha256': a8['sha256'],
            'a9_development_receipt_sha256': a9['sha256'],
            'a8_source_is_a6': a8['source_sha256']==admission['sha256'],
        },
        'final_risk': None,
        'vm_checks_executed': False,
        'operational_dispatch': False,
        'p8': 'NO-GO',
    }
    report['sha256'] = digest(report)
    return report


def verify_documentary_chain(report: dict, admission: dict, *, scenario: dict) -> bool:
    require(type(report) is dict and type(report.get('sha256')) is str,
            'CHAIN_REPORT_NOT_VALID')
    require(report['a9']['local_development_receipt_written'] in (True,False),
            'INVALID_WRITE_FLAG')
    expected=build_documentary_chain(admission, scenario=scenario, output_dir=None)
    expected['a9']['local_development_receipt_written'] = report['a9']['local_development_receipt_written']
    expected['sha256']=digest({k:v for k,v in expected.items() if k!='sha256'})
    require(canonical(expected)==canonical(report), 'CHAIN_REPORT_TAMPERED')
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline',action='store_true')
    parser.add_argument('--receipt',type=Path)
    parser.add_argument('--support',type=Path)
    parser.add_argument('--as-of-utc')
    parser.add_argument('--write-development-receipt',type=Path)
    args = parser.parse_args()
    try:
        require(Path.cwd().resolve() == REPO,'MUST_RUN_FROM_REPOSITORY')
        if args.synthetic_offline:
            require(args.receipt is None and args.support is None and args.as_of_utc is None
                    and args.write_development_receipt is None, 'SYNTHETIC_MODE_NO_OTHER_ARGS')
            receipt_path, support_path, asof = SYNTHETIC_RECEIPT,SYNTHETIC_SUPPORT,SYNTHETIC_ASOF
        else:
            require(args.receipt is not None and args.support is not None and
                    args.as_of_utc is not None,'THREE_INPUTS_REQUIRED')
            receipt_path,support_path,asof=args.receipt,args.support,args.as_of_utc
        source, raw = read_observation(receipt_path)
        admission = admit_defensive_observation(source,raw,support_path,as_of_utc=asof)
        scenario=read_fixed_scenario(SCENARIO)
        report=build_documentary_chain(admission,scenario=scenario,
                output_dir=args.write_development_receipt)
        verify_documentary_chain(report,admission,scenario=scenario)
        print(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=True))
    except (ChainError,ValueError,TypeError,KeyError,OSError,UnicodeError) as exc:
        print('R58C_CHAIN=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160])
        print('R58C_CHAIN_P8=NO-GO')
        return 23
    return 0

if __name__=='__main__':
    raise SystemExit(main())
