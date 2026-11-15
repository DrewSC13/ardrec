#!/usr/bin/env python3
"""R42.1: SSH guest-agent one-packet attempt; authorization is mandatory."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from ardrec.coordination import r421_bounded_negative_probe as r421


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description='R42.1: one bounded negative guest probe; P8 NO-GO')
    p.add_argument('--r420-baseline',type=Path,required=True)
    p.add_argument('--r411-observation',type=Path,required=True)
    p.add_argument('--r41-preflight',type=Path,required=True)
    p.add_argument('--r40-preflight',type=Path,required=True)
    p.add_argument('--r39-reconciliation',type=Path,required=True)
    p.add_argument('--r365-preflight',type=Path,required=True)
    p.add_argument('--r365-first-boot',type=Path,required=True)
    p.add_argument('--receipt-dir',type=Path,required=True)
    x=p.add_mutually_exclusive_group(required=True)
    x.add_argument('--preflight-only',action='store_true')
    x.add_argument('--execute-one-icmp',action='store_true')
    p.add_argument('--i-authorize-r421-guest-agent',action='store_true')
    a=p.parse_args(argv)
    if a.preflight_only and a.i_authorize_r421_guest_agent:
        p.error('preflight does not accept guest execution authorization')
    if a.execute_one_icmp and not a.i_authorize_r421_guest_agent:
        p.error('explicit guest action authorization required')
    try:
        if a.preflight_only:
            r421.source_chain(a.r420_baseline,a.r411_observation,a.r41_preflight,
                              a.r40_preflight,a.r39_reconciliation,
                              a.r365_preflight,a.r365_first_boot)
            result=r421.preflight()
            print('R421_STATUS='+result['status'])
            print('R421_GUEST_AGENT_CONTACTED=NO')
            print('R421_PACKET_ATTEMPTED=NO')
            print('R421_P8=NO-GO')
            return 0
        result=r421.attempt(r420_dir=a.r420_baseline,r411_dir=a.r411_observation,
                             r41_dir=a.r41_preflight,r40_dir=a.r40_preflight,
                             r39_dir=a.r39_reconciliation,pre_dir=a.r365_preflight,
                             boot_dir=a.r365_first_boot,receipt_dir=a.receipt_dir,
                             authorized=True)
    except Exception as exc:
        print('R421_STATUS=BLOCKED_OR_REVIEW_REQUIRED')
        print('R421_ERROR='+type(exc).__name__+':'+str(exc)[:220])
        print('R421_P8=NO-GO')
        return 2
    print('R421_STATUS='+result['status'])
    print('R421_RECEIPT_DIR='+str(a.receipt_dir))
    print('R421_REPORT_SHA256='+result['sha256'])
    print('R421_GUEST_REPORTED_TRANSMITTED='+str(result['agent_evidence']['exit']['transmitted']))
    print('R421_GUEST_REPORTED_RECEIVED='+str(result['agent_evidence']['exit']['received']))
    print('R421_ISOLATION_PROVEN=NO')
    print('R421_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
