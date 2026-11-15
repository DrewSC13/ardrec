#!/usr/bin/env python3
"""R42.3: authorized, fixed guest proc/sysfs reads; no packet injection."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.r423_guest_path_inventory import perform


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='R42.3: inspección de ruta/ARP sin emitir paquetes')
    for name in ('r422-result','r421-result','r420-baseline','r411-observation',
                 'r41-preflight','r40-preflight','r39-reconciliation',
                 'r365-preflight','r365-first-boot','receipt-dir'):
        p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--preflight-only',action='store_true')
    p.add_argument('--i-authorize-r423-guest-readonly',action='store_true')
    a=p.parse_args(argv)
    if a.preflight_only==a.i_authorize_r423_guest_readonly:
        p.error('choose_exactly_one_mode')
    try:
        out=perform(r422_dir=a.r422_result,r421_dir=a.r421_result,
            r420_dir=a.r420_baseline,r411_dir=a.r411_observation,
            r41_dir=a.r41_preflight,r40_dir=a.r40_preflight,
            r39_dir=a.r39_reconciliation,pre_dir=a.r365_preflight,
            boot_dir=a.r365_first_boot,receipt_dir=a.receipt_dir,
            authorized=a.i_authorize_r423_guest_readonly,preflight_only=a.preflight_only)
    except Exception as exc:
        print('R423_STATUS=BLOCKED_OR_REVIEW_REQUIRED')
        print('R423_ERROR='+type(exc).__name__+':'+str(exc)[:200])
        print('R423_P8=NO-GO')
        return 2
    print('R423_STATUS='+out['status'])
    if not a.preflight_only:
        print('R423_RECEIPT_DIR='+str(a.receipt_dir))
        print('R423_REPORT_SHA256='+out['sha256'])
        print('R423_ROUTE='+out['guest_route_state'])
        print('R423_ARP='+out['guest_arp_state'])
        print('R423_TX_PACKETS_SNAPSHOT='+str(out['guest_tx_packets_snapshot']))
        print('R423_RX_PACKETS_SNAPSHOT='+str(out['guest_rx_packets_snapshot']))
        print('R423_GUEST_CAT_EXECUTED=YES')
    else:
        print('R423_QGA_CONTACTED=NO')
    print('R423_PACKET_INJECTION=NO')
    print('R423_ISOLATION_PROVEN=NO')
    print('R423_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
