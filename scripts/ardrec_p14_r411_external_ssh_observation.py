#!/usr/bin/env python3
"""R41.1 — read-only evidence of an externally started SSH VM. No VM start."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination.r411_external_ssh_observation import observe


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='ARDREC R41.1: read-only SSH_RUNNING reconciliation, NO-GO')
    p.add_argument('--r365-preflight', required=True, type=Path)
    p.add_argument('--r365-first-boot', required=True, type=Path)
    p.add_argument('--r39-reconciliation', required=True, type=Path)
    p.add_argument('--r40-preflight', required=True, type=Path)
    p.add_argument('--r41-preflight', required=True, type=Path)
    p.add_argument('--receipt-dir', required=True, type=Path)
    p.add_argument('--acknowledge-start-outside-r41', action='store_true', required=True)
    a = p.parse_args(argv)
    try:
        result = observe(r365_preflight_dir=a.r365_preflight,
                         r365_boot_dir=a.r365_first_boot,
                         r39_dir=a.r39_reconciliation,
                         r40_dir=a.r40_preflight,
                         r41_preflight_dir=a.r41_preflight,
                         receipt_dir=a.receipt_dir,
                         operator_acknowledged=a.acknowledge_start_outside_r41)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print('R411_STATUS=BLOCKED_READONLY')
        print('R411_ERROR='+type(exc).__name__+':'+str(exc)[:160])
        print('R411_P8=NO-GO')
        return 2
    print('R411_STATUS='+result['status'])
    print('R411_RECEIPT_DIR='+str(a.receipt_dir))
    print('R411_REPORT_SHA256='+result['sha256'])
    print('R411_EXTERNAL_START_OPERATOR_ACKNOWLEDGED=TRUE')
    print('R411_ORIGIN_INDEPENDENTLY_ATTESTED=FALSE')
    print('R411_VM_STARTED_BY_R411=FALSE')
    print('R411_ISOLATION_TESTED=FALSE')
    print('R411_P8=NO-GO')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
