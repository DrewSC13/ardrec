#!/usr/bin/env python3
"""R45 offline-only SSH/runner candidate generation; no host modifications."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r45_ssh_positive_candidate as r45


def main(argv=None)->int:
    p=argparse.ArgumentParser(description='R45 candidate; does not enable network or change VM')
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--plan',action='store_true')
    g.add_argument('--prepare-offline',action='store_true')
    g.add_argument('--verify-offline',action='store_true')
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--i-authorize-private-local-files-only',action='store_true')
    x=p.parse_args(argv)
    try:
        if x.plan:
            if x.receipt_dir is not None or x.i_authorize_private_local_files_only:
                raise r45.CandidateError('mixed_mode')
            report=r45.build_files()['r45_candidate.json'].decode('ascii').strip()
            print(report)
        elif x.prepare_offline:
            if x.receipt_dir is None or not x.i_authorize_private_local_files_only:
                raise r45.CandidateError('explicit_local_write_authorization_required')
            report=r45.prepare(x.receipt_dir)
            print('R45_STATUS='+report['status'])
            print('R45_RECEIPT_DIR='+str(x.receipt_dir))
            print('R45_REPORT_SHA256='+report['sha256'])
            print('R45_P8=NO-GO')
        else:
            if x.receipt_dir is None or x.i_authorize_private_local_files_only:
                raise r45.CandidateError('verify_mode_invalid')
            report=r45.verify_directory(x.receipt_dir)
            print('R45_VERIFICATION=PASS')
            print('R45_STATUS='+report['status'])
            print('R45_REPORT_SHA256='+report['sha256'])
            print('R45_P8=NO-GO')
    except (OSError,ValueError,RuntimeError) as ex:
        print('R45_STATUS=BLOCKED_OFFLINE:'+type(ex).__name__+':'+str(ex)[:150],file=sys.stderr)
        print('R45_P8=NO-GO',file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
