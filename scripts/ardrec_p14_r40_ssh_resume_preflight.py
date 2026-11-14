#!/usr/bin/env python3
"""P14-R40 read-only QCOW2 postboot preflight (NOT permission to resume)."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.r40_ssh_resume_preflight import perform

def main(argv=None) -> int:
    p=argparse.ArgumentParser(description='R40: preflight físico SSH en solo lectura; P8 NO-GO')
    p.add_argument('--source-archive',required=True,type=Path)
    p.add_argument('--r39-reconciliation',required=True,type=Path)
    p.add_argument('--r365-preflight',required=True,type=Path)
    p.add_argument('--r365-first-boot',required=True,type=Path)
    p.add_argument('--receipt-dir',required=True,type=Path)
    a=p.parse_args(argv)
    try:
        result=perform(source_archive=a.source_archive,r39_dir=a.r39_reconciliation,
                       r365_preflight_dir=a.r365_preflight,
                       r365_boot_dir=a.r365_first_boot,receipt_dir=a.receipt_dir)
    except Exception as exc:
        print('R40_STATUS=BLOCKED_NO_MUTATION')
        print('R40_ERROR='+type(exc).__name__+':'+str(exc)[:200])
        print('R40_P8=NO-GO')
        return 2
    print('R40_STATUS='+result['status'])
    print('R40_RECEIPT_DIR='+str(a.receipt_dir))
    print('R40_REPORT_SHA256='+result['sha256'])
    print('R40_STORAGE_ROLES='+str(result['storage']['verified_roles']))
    print('R40_VM_STARTED=NO')
    print('R40_NETWORK_STARTED=NO')
    print('R40_RESUME_AUTHORIZED=NO')
    print('R40_ISOLATION_TESTED=NO')
    print('R40_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
