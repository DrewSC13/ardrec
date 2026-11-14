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
    modes.add_argument('--resume-verified-nft-partial', action='store_true')
    modes.add_argument('--preflight-verified-nft-partial', action='store_true')
    modes.add_argument('--preflight-existing-nft-filter-ssh', action='store_true')
    modes.add_argument('--resume-existing-nft-filter-ssh', action='store_true')
    parser.add_argument('--prior-partial-receipts', type=Path)
    parser.add_argument('--second-partial-receipts', type=Path)
    parser.add_argument('--i-authorize-r35-installation', action='store_true')
    args = parser.parse_args()

    old_recovery = args.resume_verified_nft_partial or args.preflight_verified_nft_partial
    new_recovery = args.resume_existing_nft_filter_ssh or args.preflight_existing_nft_filter_ssh
    install_requested = (args.install_deny_first_inactive or args.resume_verified_nft_partial or
                         args.resume_existing_nft_filter_ssh)
    if install_requested != args.i_authorize_r35_installation:
        parser.error('Installation requires explicit authorization; preflight forbids it')
    if new_recovery:
        if args.prior_partial_receipts is None or args.second_partial_receipts is None:
            parser.error('R35.3 requires both prior partial receipt directories')
    elif old_recovery:
        if args.prior_partial_receipts is None or args.second_partial_receipts is not None:
            parser.error('R35.2 requires only first partial receipt')
    elif args.prior_partial_receipts is not None or args.second_partial_receipts is not None:
        parser.error('Fresh installation does not accept prior receipts')
    if args.prior_partial_receipts is not None and not args.prior_partial_receipts.is_absolute():
        parser.error('First partial receipt path must be absolute')
    if args.second_partial_receipts is not None and not args.second_partial_receipts.is_absolute():
        parser.error('Second partial receipt path must be absolute')
    if not args.source_archive.is_absolute() or not args.receipt_dir.is_absolute():
        parser.error('Archive and receipt paths must be absolute')

    try:
        result = run(args.source_archive, args.receipt_dir,
                     install=install_requested,
                     resume_partial_dir=args.prior_partial_receipts,
                     resume_second_partial_dir=args.second_partial_receipts)
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
    if result['status'] == 'RESUME_PREFLIGHT_PASS_EXISTING_NFT':
        print('R352_RECOVERY_PREFLIGHT=PASS_EXISTING_NFT_VERIFIED')
        print('R35_INSTALLATION=NOT_PERFORMED')
        return 0
    if result['status'] == 'RESUME_PREFLIGHT_PASS_EXISTING_NFT_FILTER_SSH':
        print('R353_RECOVERY_PREFLIGHT=PASS_EXISTING_NFT_FILTER_SSH_VERIFIED')
        print('R35_INSTALLATION=NOT_PERFORMED')
        return 0
    if result['status'] == 'DEPLOYMENT_COMPLETE_INACTIVE':
        print('R35_INSTALLATION=PASS_DENY_FIRST_AND_LIBVIRT_INACTIVE')
        if result.get('recovery_mode') == 'EXISTING_NFT_VERIFIED_JSON':
            print('R352_RECOVERY=PASS_EXISTING_NFT_VERIFIED')
        if result.get('recovery_mode') == 'EXISTING_NFT_FILTER_SSH_VERIFIED':
            print('R353_RECOVERY=PASS_REUSED_NFT_FILTER_SSH')
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
