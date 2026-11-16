#!/usr/bin/env python3
"""R58-I synthetic FTP-T01..T08 and CONTROL/DATA, READ/WRITE variants; NO-GO."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src'))
from ardrec.evidence.r58i_ftp_family_logic import (
    load_pinned_ftp_catalog, build_ftp_simulation, verify_ftp_simulation,
    _requirements,
)


def synthetic_ftp_cases(families: list[dict]) -> list[dict]:
    units=[]
    for i,f in enumerate(families,1):
        variants = ('CONTROL','DATA') if f['id']=='FTP-T02' else (
                   ('READ','WRITE') if f['id']=='FTP-T08' else (None,))
        for ordinal,variant in enumerate(variants,1):
            pre,supports,_,_,cleanup = _requirements(f,variant)
            units.append({
                'family_id':f['id'], 'derived_case_id':f['id']+f'-S01-{ordinal:02}',
                'assessment_index':0,'session_id':'DEV_TUTOR_001',
                'phase':'PENDIENTE','variant':variant,
                'preconditions':{k:'VERDADERO' for k in pre},
                'supports':{k:'VERDADERO' for k in supports},
                'integrity':'VERDADERO','provenance':'VERDADERO',
                'cleanup':'VERDADERO' if cleanup else 'NO_APLICA',
                'outcome':('OBSERVADO_POSITIVO' if i%3==1 else
                           'OBSERVADO_NEGATIVO' if i%3==2 else 'INCONCLUSO'),
            })
    return units


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline',action='store_true')
    args=parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve()!=REPO:
        print('R58I=BLOCKED:EXPLICIT_SYNTHETIC_MODE_AND_REPO_REQUIRED')
        print('R58I_P8=NO-GO')
        return 23
    try:
        families=load_pinned_ftp_catalog()
        report=build_ftp_simulation(synthetic_ftp_cases(families))
        verify_ftp_simulation(report)
        print(json.dumps(report,sort_keys=True,indent=2,ensure_ascii=True))
    except (OSError,TypeError,ValueError,KeyError,RecursionError) as exc:
        print('R58I=BLOCKED:'+type(exc).__name__+':'+str(exc)[:160])
        print('R58I_P8=NO-GO')
        return 23
    return 0

if __name__=='__main__':
    raise SystemExit(main())
