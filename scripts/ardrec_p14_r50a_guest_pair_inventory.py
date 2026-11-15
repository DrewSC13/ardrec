#!/usr/bin/env python3
"""R50-A: SSH and runner QGA network inventory, no guest-exec, P8=NO-GO."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r50_guest_pair_inventory as r50

def main(argv=None)->int:
    p=argparse.ArgumentParser(description='R50-A SSH+runner QGA readonly inventory')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--preflight-readonly',action='store_true')
    mode.add_argument('--capture-guest-pair-readonly',action='store_true')
    mode.add_argument('--verify-receipt',action='store_true')
    mode.add_argument('--verify-historical-receipt-offline',action='store_true')
    mode.add_argument('--reconcile-prefix-offline',action='store_true')
    mode.add_argument('--verify-prefix-reconciliation',action='store_true')
    for name in ('r45-dir','r46-dir','r47-dir','r48-dir',
                 'definition-receipt-dir','boot-receipt-dir'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--reconciliation-dir',type=Path)
    p.add_argument('--i-authorize-two-qga-readonly-guest-inventories',action='store_true')
    a=p.parse_args(argv)
    dirs={'r45':a.r45_dir,'r46':a.r46_dir,'r47':a.r47_dir,'r48':a.r48_dir,
          'definition':a.definition_receipt_dir,'boot':a.boot_receipt_dir}
    try:
        if (a.reconciliation_dir is not None and not
            (a.reconcile_prefix_offline or a.verify_prefix_reconciliation)):
            raise r50.R50Error('unexpected_reconciliation_dir')
        if a.preflight_readonly:
            if a.receipt_dir is not None or a.i_authorize_two_qga_readonly_guest_inventories:
                raise r50.R50Error('invalid_preflight_args')
            report=r50.preflight(dirs)
            print(r50.canon(report).decode('ascii'))
            print('R50A_PREFLIGHT=PASS_HOST_READONLY')
        elif a.capture_guest_pair_readonly:
            if a.receipt_dir is None or not a.i_authorize_two_qga_readonly_guest_inventories:
                raise r50.R50Error('explicit_qga_read_authorization_required')
            report=r50.capture(dirs,a.receipt_dir)
            print('R50A_CAPTURE='+report['status'])
            print('R50A_RECEIPT='+str(a.receipt_dir))
            print('R50A_SHA256='+report['sha256'])
            for role in ('ssh','runner'):
                print('R50A_'+role.upper()+'='+report['roles'][role]['status'])
        elif a.verify_receipt:
            if a.receipt_dir is None or a.i_authorize_two_qga_readonly_guest_inventories:
                raise r50.R50Error('invalid_verify_args')
            report=r50.verify(dirs,a.receipt_dir)
            print('R50A_VERIFICATION=PASS')
            print('R50A_STATUS='+report['status'])
        elif a.verify_historical_receipt_offline:
            if a.receipt_dir is None or a.i_authorize_two_qga_readonly_guest_inventories:
                raise r50.R50Error('historical_offline_verify_args_invalid')
            report=r50.verify_historical_offline(a.receipt_dir)
            print('R50A_HISTORICAL_OFFLINE_VERIFICATION=PASS')
            print('R50A_HISTORICAL_SHA256='+report['sha256'])
            print('R50A_HISTORICAL_STATUS='+report['status'])
            print('R50A_LIVE_HOST_VERIFIED=NO')
        elif a.reconcile_prefix_offline:
            if (a.receipt_dir is None or a.reconciliation_dir is None or
                a.i_authorize_two_qga_readonly_guest_inventories):
                raise r50.R50Error('reconciliation_args_invalid')
            report=r50.reconcile_prefix(dirs,a.receipt_dir,a.reconciliation_dir)
            print('R50A_RECONCILIATION='+report['status'])
            print('R50A_RECONCILIATION_SHA256='+report['sha256'])
            print('R50A_ORIGINAL_RECEIPT_UNCHANGED=YES')
        else:
            if (a.receipt_dir is None or a.reconciliation_dir is None or
                a.i_authorize_two_qga_readonly_guest_inventories):
                raise r50.R50Error('reconciliation_verify_args_invalid')
            report=r50.verify_prefix_reconciliation(dirs,a.receipt_dir,a.reconciliation_dir)
            print('R50A_RECONCILIATION_VERIFICATION=PASS')
            print('R50A_RECONCILIATION_SHA256='+report['sha256'])
        print('R50A_P8=NO-GO')
        return 0
    except (ValueError,OSError,RuntimeError) as e:
        print('R50A_BLOCKED='+str(e)[:200],file=sys.stderr)
        print('R50A_P8=NO-GO',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
