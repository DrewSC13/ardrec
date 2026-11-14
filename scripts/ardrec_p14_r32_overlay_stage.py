#!/usr/bin/env python3
"""P14-R32: --plan only, or explicit materialization of NEW QCOW2 overlays.

Do not execute as root; sudo -n is restricted to exact system binaries.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))

from ardrec.coordination.overlay_stage import (
    StageError, load_r31, build_plan, execute_staging, validate_receipt_path, write_receipt, canonical,
)


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--r31-report', type=Path, required=True)
    p.add_argument('--r31-file-sha256', required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan',action='store_true')
    mode.add_argument('--stage-new-overlays',action='store_true')
    p.add_argument('--i-authorize-four-new-overlays',action='store_true')
    p.add_argument('--receipt-dir',type=Path)
    args=p.parse_args()
    if args.plan and (args.i_authorize_four_new_overlays or args.receipt_dir):
        p.error('Plan must not request authorization or receipt directory')
    if args.stage_new_overlays and (not args.i_authorize_four_new_overlays or not args.receipt_dir):
        p.error('Storage changes require explicit opt-in and private receipt directory')
    if hasattr(__import__('os'), 'geteuid') and __import__('os').geteuid()==0:
        p.error('Run Python as unprivileged operator, never root')
    source,digest=load_r31(args.r31_report,args.r31_file_sha256)
    plan=build_plan(source,digest)
    if args.plan:
        sys.stdout.buffer.write(canonical(plan)+b'\n')
        return 0
    validate_receipt_path(args.receipt_dir/'r32_staging.json')
    report=execute_staging(plan)
    path=write_receipt(args.receipt_dir/'r32_staging.json',report)
    sys.stdout.buffer.write(canonical(report)+b'\n')
    sys.stderr.write('R32_RECEIPT='+str(path)+'\n')
    return 0 if report['storage_prepared'] is True else 2


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (StageError, ValueError) as e:
        sys.stderr.write('R32_REFUSED='+str(e)+'\n')
        raise SystemExit(2)
