#!/usr/bin/env python3
"""R34: produce deny-first nftables and nwfilter policies OFFLINE, no root actions."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.r34_containment import (
    source_load,report,prepare,host_preflight,canon,ContainmentError,
)

def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument('--r33-report',type=Path,required=True)
    p.add_argument('--r33-file-sha256',required=True)
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--plan',action='store_true')
    modes.add_argument('--prepare-offline',action='store_true')
    modes.add_argument('--host-preflight',action='store_true')
    p.add_argument('--receipt-dir',type=Path)
    p.add_argument('--policies-dir',type=Path)
    p.add_argument('--i-authorize-readonly-host-preflight',action='store_true')
    p.add_argument('--i-authorize-writing-offline-policies',action='store_true')
    a=p.parse_args()
    if a.plan and (a.receipt_dir or a.policies_dir or a.i_authorize_writing_offline_policies or
                   a.i_authorize_readonly_host_preflight):
        p.error('Plan mode has no output or authorization')
    if a.prepare_offline and (a.receipt_dir is None or a.policies_dir is not None or
                              a.i_authorize_readonly_host_preflight or
                              not a.i_authorize_writing_offline_policies):
        p.error('Offline preparation requires private directory and explicit authorization')
    if a.host_preflight and (a.policies_dir is None or a.receipt_dir is not None or
                              a.i_authorize_writing_offline_policies or
                              not a.i_authorize_readonly_host_preflight):
        p.error('Readonly host preflight requires existing policies and explicit authorization')
    source,_=source_load(a.r33_report,a.r33_file_sha256)
    d=(report(source) if a.plan else
       prepare(a.receipt_dir,source) if a.prepare_offline else
       host_preflight(source,a.policies_dir))
    sys.stdout.buffer.write(canon(d)+b'\n')
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (ContainmentError,OSError,ValueError) as e:
        print('R34_REFUSED='+str(e),file=sys.stderr)
        raise SystemExit(2)
