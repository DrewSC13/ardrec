#!/usr/bin/env python3
"""R46: read-only live SSH/runner baseline; private immutable rollback snapshots."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r46_ssh_transition_audit as r46


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='R46: NO-GO, inspection and private receipts only')
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--inspect-readonly', action='store_true')
    modes.add_argument('--verify-receipt', action='store_true')
    parser.add_argument('--r45-dir', type=Path, required=True)
    parser.add_argument('--receipt-dir', type=Path, required=True)
    parser.add_argument('--i-authorize-readonly-inspection-and-private-receipt', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.inspect_readonly:
            if not args.i_authorize_readonly_inspection_and_private_receipt:
                raise r46.R46AuditError('explicit_readonly_and_receipt_authorization_required')
            report = r46.prepare_receipt(args.receipt_dir, args.r45_dir)
            print('R46_AUDIT=PASS_READONLY_SNAPSHOT')
        else:
            if args.i_authorize_readonly_inspection_and_private_receipt:
                raise r46.R46AuditError('verify_mode_must_be_readonly_no_host_commands')
            report = r46.verify_receipt(args.receipt_dir, args.r45_dir)
            print('R46_VERIFICATION=PASS')
        print('R46_REPORT_SHA256=' + report['sha256'])
        print('R46_SSH=' + report['domain_states']['ssh'])
        print('R46_RUNNER=' + report['domain_states']['runner'])
        print('R46_SNAPSHOT_DIR=' + str(args.receipt_dir))
        print('R46_FILTERS_INSTALLED=NO')
        print('R46_HOST_MUTATIONS=NO')
        print('R46_ROLLBACK_TESTED=NO')
        print('R46_P8=NO-GO')
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print('R46_STATUS=BLOCKED_READONLY:' + type(exc).__name__ + ':' + str(exc)[:150],
              file=sys.stderr)
        print('R46_P8=NO-GO', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
