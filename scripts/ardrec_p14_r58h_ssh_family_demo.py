#!/usr/bin/env python3
"""R58-H deterministic, synthetic SSH-T01..T08 A6 tri-valued preview; no I/O to host."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
from ardrec.evidence.r58h_ssh_family_logic import (
    load_pinned_catalog,build_ssh_simulation,verify_ssh_simulation,
)


def synthetic_ssh_cases(families: list[dict]) -> list[dict]:
    result=[]
    for i,f in enumerate(families,1):
        result.append({
            'family_id':f['id'], 'derived_case_id':f['id']+'-S01-01',
            'assessment_index':0,'session_id':'DEV_TUTOR_001','phase':'PENDIENTE',
            'preconditions':{k:'VERDADERO' for k in f['preconditions']},
            'supports':{k:'VERDADERO' for k in f['required_supports']},
            'integrity':'VERDADERO','provenance':'VERDADERO',
            'cleanup':'VERDADERO' if f['id']=='SSH-T07' else 'NO_APLICA',
            'outcome':('OBSERVADO_POSITIVO' if i%3==1 else
                       'OBSERVADO_NEGATIVO' if i%3==2 else 'INCONCLUSO'),
        })
    return result


def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline',action='store_true')
    args=parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve()!=REPO:
        print('R58H=BLOCKED:EXPLICIT_SYNTHETIC_MODE_AND_REPO_REQUIRED')
        print('R58H_P8=NO-GO')
        return 23
    try:
        specs=load_pinned_catalog()
        report=build_ssh_simulation(synthetic_ssh_cases(specs))
        verify_ssh_simulation(report)
        print(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=True))
    except (ValueError,TypeError,OSError,KeyError,RecursionError) as exc:
        print('R58H=BLOCKED:'+type(exc).__name__+':'+str(exc)[:130])
        print('R58H_P8=NO-GO')
        return 23
    return 0

if __name__=='__main__':
    raise SystemExit(main())
