#!/usr/bin/env python3
"""R49: deliberate isolated runner definition/first boot, no P8 dispatch."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r49_runner_first_boot as r49


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description='P14 R49: SSH-only runner guarded redefine / boot')
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight-readonly',action='store_true')
    modes.add_argument('--define-ssh-only-runner',action='store_true')
    modes.add_argument('--verify-defined',action='store_true')
    modes.add_argument('--start-isolated-runner',action='store_true')
    modes.add_argument('--verify-first-boot',action='store_true')
    modes.add_argument('--restore-original-when-shutoff',action='store_true')
    modes.add_argument('--verify-restored',action='store_true')
    for option in ('r45-dir','r46-dir','r47-dir','r48-dir'):
        p.add_argument('--'+option,type=Path,required=True)
    p.add_argument('--definition-receipt-dir',type=Path)
    p.add_argument('--boot-receipt-dir',type=Path)
    p.add_argument('--restore-receipt-dir',type=Path)
    p.add_argument('--i-authorize-runner-domain-definition-only',action='store_true')
    p.add_argument('--i-authorize-runner-first-boot-under-r33-r34-deny',action='store_true')
    p.add_argument('--i-authorize-restore-original-runner-definition-only',action='store_true')
    args=p.parse_args(argv)
    try:
        src=(args.r45_dir,args.r46_dir,args.r47_dir,args.r48_dir)
        define_flag=args.i_authorize_runner_domain_definition_only
        start_flag=args.i_authorize_runner_first_boot_under_r33_r34_deny
        restore_flag=args.i_authorize_restore_original_runner_definition_only
        if (not args.restore_original_when_shutoff and not args.verify_restored) and (args.restore_receipt_dir is not None or restore_flag):
            raise r49.R49Error('restore_arguments_in_wrong_mode')
        if args.preflight_readonly:
            if args.definition_receipt_dir or args.boot_receipt_dir or define_flag or start_flag:
                raise r49.R49Error('preflight_unexpected_arguments')
            report=r49.plan(*src)
            print(r49.canon(report).decode('ascii'))
            print('R49_PREFLIGHT=PASS_READONLY')
        elif args.define_ssh_only_runner:
            if not define_flag or start_flag or args.definition_receipt_dir is None or args.boot_receipt_dir:
                raise r49.R49Error('separate_definition_authorization_required')
            report=r49.define(*src,args.definition_receipt_dir)
            print('R49_DEFINE='+report['mode'])
            print('R49_DEFINITION_REPORT_SHA256='+report['sha256'])
            print('R49_DEFINITION_RECEIPT_DIR='+str(args.definition_receipt_dir))
        elif args.verify_defined:
            if args.definition_receipt_dir is None or args.boot_receipt_dir or define_flag or start_flag:
                raise r49.R49Error('definition_verify_arguments_invalid')
            report=r49.verify_defined(*src,args.definition_receipt_dir)
            print('R49_DEFINITION_VERIFICATION=PASS')
            print('R49_DEFINITION_REPORT_SHA256='+report['sha256'])
        elif args.start_isolated_runner:
            if not start_flag or define_flag or args.definition_receipt_dir is None or args.boot_receipt_dir is None:
                raise r49.R49Error('separate_first_boot_authorization_required')
            report=r49.boot(*src,args.definition_receipt_dir,args.boot_receipt_dir)
            print('R49_BOOT='+report['mode'])
            print('R49_BOOT_REPORT_SHA256='+report['sha256'])
            print('R49_BOOT_RECEIPT_DIR='+str(args.boot_receipt_dir))
        elif args.verify_first_boot:
            if args.definition_receipt_dir is None or args.boot_receipt_dir is None or define_flag or start_flag:
                raise r49.R49Error('boot_verify_arguments_invalid')
            report=r49.verify_boot(*src,args.definition_receipt_dir,args.boot_receipt_dir)
            print('R49_BOOT_VERIFICATION=PASS')
            print('R49_BOOT_REPORT_SHA256='+report['sha256'])
        elif args.restore_original_when_shutoff:
            if not restore_flag or define_flag or start_flag or args.boot_receipt_dir or args.definition_receipt_dir is None or args.restore_receipt_dir is None:
                raise r49.R49Error('separate_restore_authorization_required')
            report=r49.restore_original(*src,args.definition_receipt_dir,args.restore_receipt_dir)
            print('R49_RESTORE='+report['mode'])
            print('R49_RESTORE_REPORT_SHA256='+report['sha256'])
        else:
            if restore_flag or define_flag or start_flag or args.boot_receipt_dir or args.definition_receipt_dir is None or args.restore_receipt_dir is None:
                raise r49.R49Error('restore_verify_arguments_invalid')
            report=r49.verify_restored(*src,args.definition_receipt_dir,args.restore_receipt_dir)
            print('R49_RESTORE_VERIFICATION=PASS')
            print('R49_RESTORE_REPORT_SHA256='+report['sha256'])
        print('R49_R33_R34_UNCHANGED=REQUIRED')
        print('R49_P8=NO-GO')
        return 0
    except (OSError, ValueError, RuntimeError) as ex:
        print('R49_STATUS=BLOCKED:'+type(ex).__name__+':'+str(ex)[:170],file=sys.stderr)
        print('R49_P8=NO-GO',file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
