#!/usr/bin/env python3
"""P14-R42.0: read-only SSH drop-counter snapshot, no packet tests."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination.r42_isolation_baseline import perform


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description='R42.0: línea de base de contadores (solo lectura)')
    p.add_argument('--r411-observation', required=True, type=Path)
    p.add_argument('--r41-preflight', required=True, type=Path)
    p.add_argument('--r40-preflight', required=True, type=Path)
    p.add_argument('--r39-reconciliation', required=True, type=Path)
    p.add_argument('--r365-preflight', required=True, type=Path)
    p.add_argument('--r365-first-boot', required=True, type=Path)
    p.add_argument('--receipt-dir', required=True, type=Path)
    args = p.parse_args(argv)
    try:
        out = perform(r411_dir=args.r411_observation,
                      r41_dir=args.r41_preflight, r40_dir=args.r40_preflight,
                      r39_dir=args.r39_reconciliation,
                      r365_preflight_dir=args.r365_preflight,
                      r365_boot_dir=args.r365_first_boot,
                      receipt_dir=args.receipt_dir)
    except Exception as exc:
        print('R420_STATUS=BLOCKED_NO_MUTATION')
        print('R420_ERROR=' + type(exc).__name__ + ':' + str(exc)[:200])
        print('R420_P8=NO-GO')
        return 2
    print('R420_STATUS=' + out['status'])
    print('R420_RECEIPT_DIR=' + str(args.receipt_dir))
    print('R420_REPORT_SHA256=' + out['sha256'])
    for name, delta in out['counter_delta_unattributed'].items():
        print('R420_COUNTER_' + name.upper().replace(':','_') +
              '_DELTA_PACKETS=' + str(delta['packets']))
    print('R420_ACTIVE_TEST=NO')
    print('R420_ISOLATION_PROVEN=NO')
    print('R420_P8=NO-GO')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
