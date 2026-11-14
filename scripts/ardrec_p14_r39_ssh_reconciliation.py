#!/usr/bin/env python3
"""R39 SSH postboot reconciliation; read-only on libvirt/nft; local receipt write."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.coordination.r39_ssh_reconciliation import (
    capture_current, read_r365_chain, reconcile, persist_private, R39Error)


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description='R39: sólo lectura del host SSH y fuentes R36.5')
    p.add_argument('--r365-preflight', type=Path, required=True)
    p.add_argument('--r365-first-boot', type=Path, required=True)
    p.add_argument('--receipt-dir', type=Path, required=True)
    a=p.parse_args(argv)
    try:
        chain=read_r365_chain(a.r365_preflight,a.r365_first_boot)
        current=capture_current()
        timestamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        report=reconcile(chain,current,captured_at_utc=timestamp)
        persist_private(a.receipt_dir,report)
    except Exception as exc:
        print('R39_STATUS=BLOCKED_NO_MUTATION')
        print('R39_ERROR='+type(exc).__name__+':'+str(exc)[:200])
        print('R39_P8=NO-GO')
        return 2
    print('R39_STATUS='+report['status'])
    print('R39_RECEIPT_DIR='+str(a.receipt_dir))
    print('R39_RECEIPT_SHA256='+report['sha256'])
    print('R39_VM_STARTED=NO')
    print('R39_NETWORK_STARTED=NO')
    print('R39_ISOLATION_TESTED=NO')
    print('R39_SHUTDOWN_ORIGIN=NOT_ATTESTED')
    print('R39_P8=NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
