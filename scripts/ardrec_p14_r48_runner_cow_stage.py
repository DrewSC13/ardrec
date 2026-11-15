#!/usr/bin/env python3
"""P14-R48: stage one disposable runner qcow2 under explicit operator approval."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r48_runner_cow_stage as r48

def main(argv=None):
    p=argparse.ArgumentParser(description='ARDREC R48 runner disposable qcow2; P8=NO-GO')
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight-readonly',action='store_true')
    modes.add_argument('--stage-one-overlay',action='store_true')
    modes.add_argument('--verify-overlay',action='store_true')
    p.add_argument('--r45-dir',type=Path,required=True)
    p.add_argument('--r46-dir',type=Path,required=True)
    p.add_argument('--r47-dir',type=Path,required=True)
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--i-authorize-one-new-runner-qcow2-only',action='store_true')
    x=p.parse_args(argv)
    try:
        if x.preflight_readonly:
            if x.receipt_dir or x.i_authorize_one_new_runner_qcow2_only:
                raise r48.R48Error('preflight_arguments_invalid')
            result=r48.preflight(x.r45_dir,x.r46_dir,x.r47_dir)
            print(r48.canon(result).decode())
            print('R48_PREFLIGHT=PASS_READONLY')
        elif x.stage_one_overlay:
            if not x.i_authorize_one_new_runner_qcow2_only or x.receipt_dir is None:
                raise r48.R48Error('explicit_disk_creation_authorization_required')
            result=r48.stage(x.r45_dir,x.r46_dir,x.r47_dir,x.receipt_dir)
            print('R48_STAGE='+result['mode'])
            print('R48_RECEIPT_DIR='+str(x.receipt_dir))
            print('R48_REPORT_SHA256='+result['sha256'])
        else:
            if x.receipt_dir is None or x.i_authorize_one_new_runner_qcow2_only:
                raise r48.R48Error('verify_arguments_invalid')
            result=r48.verify(x.r45_dir,x.r46_dir,x.r47_dir,x.receipt_dir)
            print('R48_VERIFICATION=PASS')
            print('R48_REPORT_SHA256='+result['sha256'])
        print('R48_VM_STARTED=NO')
        print('R48_P8=NO-GO')
        return 0
    except (ValueError, OSError, RuntimeError) as ex:
        print('R48_STATUS=BLOCKED:'+type(ex).__name__+':'+str(ex)[:150],file=sys.stderr)
        print('R48_P8=NO-GO',file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
