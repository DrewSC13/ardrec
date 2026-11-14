#!/usr/bin/env python3
"""R31: non-mutating fixed-path QCOW2 audit, explicit sudo opt-in required."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))

from ardrec.coordination.qcow2_readonly_attestation import (
    load_r30, build_report, verify_report, canonical,
)


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--r30-report',required=True,type=Path)
    p.add_argument('--r30-file-sha256',required=True)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan',action='store_true')
    mode.add_argument('--inspect-with-sudo',action='store_true')
    p.add_argument('--i-authorize-readonly-sudo-inspection',action='store_true')
    args=p.parse_args()
    if args.inspect_with_sudo and not args.i_authorize_readonly_sudo_inspection:
        p.error('Explicit read-only sudo authorization flag is required')
    if args.plan and args.i_authorize_readonly_sudo_inspection:
        p.error('Plan mode does not accept sudo authorization')
    r30, digest=load_r30(args.r30_report,args.r30_file_sha256)
    doc=build_report(r30,digest,mode='PLAN_ONLY' if args.plan else 'EXPLICIT_SUDO_READONLY')
    verify_report(doc)
    sys.stdout.buffer.write(canonical(doc)+b'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
