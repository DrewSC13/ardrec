#!/usr/bin/env python3
"""P14-R42.2: dual passive witness preflight or explicitly authorized probe."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r422_independent_packet_witness as r422


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='R42.2: TAP/bridge witnesses for one bounded guest ICMP')
    p.add_argument('--r421-result',required=True,type=Path)
    p.add_argument('--r420-baseline',required=True,type=Path)
    p.add_argument('--r411-observation',required=True,type=Path)
    p.add_argument('--r41-preflight',required=True,type=Path)
    p.add_argument('--r40-preflight',required=True,type=Path)
    p.add_argument('--r39-reconciliation',required=True,type=Path)
    p.add_argument('--r365-preflight',required=True,type=Path)
    p.add_argument('--r365-first-boot',required=True,type=Path)
    p.add_argument('--receipt-dir',required=True,type=Path)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preflight-only',action='store_true')
    mode.add_argument('--execute-observed-one-icmp',action='store_true')
    p.add_argument('--i-authorize-r422-captured-guest-agent',action='store_true')
    args=p.parse_args(argv)
    if args.preflight_only and args.i_authorize_r422_captured_guest_agent:
        p.error('authorization_is_for_execute_mode_only')
    if args.execute_observed_one_icmp and not args.i_authorize_r422_captured_guest_agent:
        p.error('explicit_new_authorization_required')
    try:
        r422.load_source(args.r421_result,args.r420_baseline,args.r411_observation,
                         args.r41_preflight,args.r40_preflight,args.r39_reconciliation,
                         args.r365_preflight,args.r365_first_boot)
        if args.preflight_only:
            result=r422.preflight()
            print('R422_STATUS='+result['status'])
            print('R422_GUEST_AGENT_CONTACTED=NO')
            print('R422_CAPTURE_STARTED=NO')
            print('R422_PACKET_ATTEMPTED=NO')
            print('R422_P8=NO-GO')
            return 0
        result=r422.attempt(r421_dir=args.r421_result,r420_dir=args.r420_baseline,
                           r411_dir=args.r411_observation,r41_dir=args.r41_preflight,
                           r40_dir=args.r40_preflight,r39_dir=args.r39_reconciliation,
                           pre_dir=args.r365_preflight,boot_dir=args.r365_first_boot,
                           receipt_dir=args.receipt_dir,authorized=True)
    except Exception as exc:
        print('R422_STATUS=BLOCKED_OR_REVIEW_REQUIRED')
        print('R422_ERROR='+type(exc).__name__+':'+str(exc)[:220])
        print('R422_P8=NO-GO')
        return 2
    print('R422_STATUS='+result['status'])
    print('R422_RECEIPT_DIR='+str(args.receipt_dir))
    print('R422_REPORT_SHA256='+result['sha256'])
    for label in ('tap','bridge'):
        obs=result['capture_files'][label]['observed']
        print('R422_'+label.upper()+'_ARP='+str(obs['matching_arp_requests']))
        print('R422_'+label.upper()+'_MARKED_ICMP='+str(obs['marked_icmp_echo_requests']))
    print('R422_ISOLATION_PROVEN=NO')
    print('R422_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
