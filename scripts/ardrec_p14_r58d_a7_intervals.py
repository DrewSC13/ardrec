#!/usr/bin/env python3
"""R58-D A7 exact batch risk envelopes, only offline synthetic test inputs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
from ardrec.analytics.r58d_interval_kernel import build_intervals, verify_intervals, IntervalError


def synthetic_units() -> list[dict]:
    shared={'assessment_index':0,'initial_risk':'1/4',
            'normalized_criticality':'1/2','replacement_risk':'1/4'}
    return [
        dict(shared,service_id='SSH_DEV',case_id='CASE_REFERENCE',evidence=[
            {'evidence_id':'E_UNKNOWN','kind':'UNRESOLVED','lower':'0','upper':'1'}]),
        dict(shared,service_id='FTP_DEV',case_id='CASE_REFERENCE',evidence=[
            {'evidence_id':'E_SYNTH','kind':'SYNTHETIC_FIXED','lower':'1/2','upper':'1/2'}]),
        dict(shared,service_id='SMB_DEV',case_id='CASE_REFERENCE',evidence=[]),
    ]


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--synthetic-offline',action='store_true',required=True)
    p.parse_args()
    try:
        report=build_intervals(synthetic_units())
        verify_intervals(report)
        assert report['operational_dispatch'] is False
        print(json.dumps(report,sort_keys=True,ensure_ascii=True,indent=2))
    except (IntervalError, ValueError, TypeError, KeyError, AssertionError) as exc:
        print('R58D_A7=BLOCKED:'+type(exc).__name__+':'+str(exc)[:120])
        print('R58D_P8=NO-GO')
        return 23
    return 0

if __name__=='__main__':
    raise SystemExit(main())
