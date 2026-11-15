#!/usr/bin/env python3
"""R47: explicitly staged unused R45 libvirt filters; no VM or packets."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r47_filter_stage as r47

def main(argv=None):
    p=argparse.ArgumentParser(description='R47: staged unused nwfilters, P8=NO-GO')
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan',action='store_true')
    modes.add_argument('--stage-new-unused-filters',action='store_true')
    modes.add_argument('--verify-staged',action='store_true')
    p.add_argument('--r45-dir',type=Path,required=True)
    p.add_argument('--r46-dir',type=Path,required=True)
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--i-authorize-two-unique-unused-nwfilter-definitions-only',action='store_true')
    x=p.parse_args(argv)
    try:
        if x.plan:
            if x.receipt_dir is not None or x.i_authorize_two_unique_unused_nwfilter_definitions_only:
                raise r47.R47Error('plan_arguments_invalid')
            print(r47.canon(r47.plan(x.r45_dir,x.r46_dir)).decode())
        elif x.stage_new_unused_filters:
            if not x.i_authorize_two_unique_unused_nwfilter_definitions_only or x.receipt_dir is None:
                raise r47.R47Error('explicit_filter_definition_authorization_required')
            d=r47.stage(x.r45_dir,x.r46_dir,x.receipt_dir)
            print('R47_STATUS='+d['status'])
            print('R47_RECEIPT_DIR='+str(x.receipt_dir))
            print('R47_REPORT_SHA256='+d['sha256'])
        else:
            if x.receipt_dir is None or x.i_authorize_two_unique_unused_nwfilter_definitions_only:
                raise r47.R47Error('verify_arguments_invalid')
            d=r47.verify_receipt(x.r45_dir,x.r46_dir,x.receipt_dir)
            print('R47_VERIFICATION=PASS')
            print('R47_STATUS='+d['status'])
        print('R47_P8=NO-GO')
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print('R47_STATUS=BLOCKED:'+type(exc).__name__+':'+str(exc)[:140],file=sys.stderr)
        print('R47_P8=NO-GO',file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
