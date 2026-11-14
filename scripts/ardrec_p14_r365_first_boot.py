#!/usr/bin/env python3
"""R36.5 first-boot limited to SSH; explicit opt-in required for writes."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.coordination.r365_first_boot import perform, BootError


def main(argv=None):
    p=argparse.ArgumentParser()
    for name in ('source-archive','receipt-dir','r35-receipts','r36-snapshot',
                 'r361-receipts','r363-receipts','r364-receipts'):
        p.add_argument('--'+name, type=Path, required=True)
    m=p.add_mutually_exclusive_group(required=True)
    m.add_argument('--preflight-only',action='store_true')
    m.add_argument('--first-boot-ssh',action='store_true')
    p.add_argument('--prior-r365-preflight',type=Path)
    p.add_argument('--i-authorize-r365-first-boot',action='store_true')
    a=p.parse_args(argv)
    if a.first_boot_ssh != a.i_authorize_r365_first_boot:
        p.error('first boot requires explicit R365 authorization; preflight forbids it')
    if a.first_boot_ssh != (a.prior_r365_preflight is not None):
        p.error('first boot requires an authenticated prior R365 preflight; preflight forbids it')
    try:
        result=perform(archive=a.source_archive,receipt_dir=a.receipt_dir,
                       r35_dir=a.r35_receipts,r36_dir=a.r36_snapshot,
                       r361_dir=a.r361_receipts,r363_dir=a.r363_receipts,
                       r364_dir=a.r364_receipts,
                       preflight_dir=a.prior_r365_preflight,
                       authorized=a.first_boot_ssh)
    except (ValueError, OSError) as exc:
        print('R365_PREFLIGHT_OR_BOOT=BLOCKED_BEFORE_RUN')
        print('R365_ERROR='+str(exc)[:250])
        print('R365_P8=NO-GO')
        return 2
    print('R365_RECEIPTS='+str(a.receipt_dir))
    print('R365_STATUS='+result['status'])
    print('R365_NETWORK_STARTED='+str(result['network_started']))
    print('R365_VM_STARTED='+str(result['vm_started']))
    print('R365_GUEST_ISOLATION_TESTED=NO')
    print('R365_P8=NO-GO')
    if result['failure_code']:
        print('R365_FAILURE='+result['failure_code'])
    if result['status'] in ('READY_FOR_EXPLICIT_FIRST_BOOT','FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED'):
        return 0
    return 3 if result['status']=='PARTIAL_NO_GO_REVIEW_REQUIRED' else 2

if __name__=='__main__':
    raise SystemExit(main())
