#!/usr/bin/env python3
"""R35: install only scoped deny-first containment and define inactive lab resources."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination.r35_inactive_deployment import (  # noqa: E402
    R35Error, run, verify_deployment_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--receipt-dir', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight-only', action='store_true')
    modes.add_argument('--install-deny-first-inactive', action='store_true')
    parser.add_argument('--i-authorize-r35-installation', action='store_true')
    args = parser.parse_args()

    if args.preflight_only and args.i_authorize_r35_installation:
        parser.error('Preflight-only mode does not accept installation authorization')
    if args.install_deny_first_inactive and not args.i_authorize_r35_installation:
        parser.error('Installation requires --i-authorize-r35-installation')
    if not args.source_archive.is_absolute() or not args.receipt_dir.is_absolute():
        parser.error('Archive and receipt paths must be absolute')

    try:
        result = run(args.source_archive, args.receipt_dir,
                     install=args.install_deny_first_inactive)
        verify_deployment_report(result)
    except (R35Error, OSError, ValueError, TypeError, KeyError) as exc:
        print('R35_RESULT=BLOCKED_NO_CHANGE_OR_REVIEW_REQUIRED')
        print('R35_FAILURE=' + (str(exc)[:180] or type(exc).__name__))
        return 2

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print('R35_RECEIPTS=' + str(args.receipt_dir))
    if result['status'] == 'PREFLIGHT_PASS_NOT_INSTALLED':
        print('R35_PREFLIGHT=PASS')
        print('R35_INSTALLATION=NOT_PERFORMED')
        return 0
    if result['status'] == 'DEPLOYMENT_COMPLETE_INACTIVE':
        print('R35_INSTALLATION=PASS_DENY_FIRST_AND_LIBVIRT_INACTIVE')
        print('R35_NFT_TABLE=INSTALLED_AND_VERIFIED')
        print('R35_NWFILTER=DEFINED_DENY_ALL')
        print('R35_NETWORKS=3_DEFINED_INACTIVE')
        print('R35_DOMAINS=4_DEFINED_SHUT_OFF')
        print('R35_VM_STARTED=NO')
        print('R35_NETWORK_STARTED=NO')
        print('R35_P8=NO-GO')
        return 0
    print('R35_INSTALLATION=PARTIAL_NO_GO_REVIEW_REQUIRED')
    print('R35_VM_STARTED=NO')
    print('R35_NETWORK_STARTED=NO')
    print('R35_P8=NO-GO')
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
