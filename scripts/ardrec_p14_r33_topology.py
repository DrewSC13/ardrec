#!/usr/bin/env python3
"""Generate bounded XML for a new *inactive* ARDREC development topology.

No virsh, no network, no VM start and no elevated process.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.r33_offline_topology import (
    TopologyError, read_r32, make_report, prepare_xml, canon,
)


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--r32-report',required=True,type=Path)
    p.add_argument('--r32-file-sha256',required=True)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan',action='store_true')
    modes.add_argument('--prepare-xml',action='store_true')
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--i-authorize-writing-offline-xml',action='store_true')
    args=p.parse_args()
    if args.plan and (args.receipt_dir is not None or args.i_authorize_writing_offline_xml):
        p.error('Plan cannot write or request authorization')
    if args.prepare_xml and (args.receipt_dir is None or
                             not args.i_authorize_writing_offline_xml):
        p.error('Offline XML writing requires explicit opt-in and private receipt directory')
    if args.prepare_xml and hasattr(os,'geteuid') and os.geteuid()==0:
        p.error('Do not create receipt files as root')
    src,sha=read_r32(args.r32_report,args.r32_file_sha256)
    report=(make_report(src,sha) if args.plan
            else prepare_xml(args.receipt_dir,src,sha))
    sys.stdout.buffer.write(canon(report)+b'\n')
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (TopologyError,OSError,ValueError) as e:
        sys.stderr.write('R33_REFUSED='+str(e)+'\n')
        raise SystemExit(2)
