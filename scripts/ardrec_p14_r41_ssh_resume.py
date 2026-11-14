#!/usr/bin/env python3
"""ARDREC P14-R41: separate preflight and explicit SSH-only resume."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.r41_ssh_resume import preflight,resume

def main(argv=None)->int:
    p=argparse.ArgumentParser(description='P14-R41: SSH-only resume, P8 NO-GO')
    p.add_argument('--source-archive',type=Path,required=True)
    p.add_argument('--r365-preflight',type=Path,required=True)
    p.add_argument('--r365-first-boot',type=Path,required=True)
    p.add_argument('--r39-reconciliation',type=Path,required=True)
    p.add_argument('--r40-preflight',type=Path,required=True)
    p.add_argument('--receipt-dir',type=Path,required=True)
    m=p.add_mutually_exclusive_group(required=True)
    m.add_argument('--preflight-only',action='store_true')
    m.add_argument('--resume-ssh',action='store_true')
    p.add_argument('--prior-r41-preflight',type=Path)
    p.add_argument('--i-authorize-r41-ssh-resume',action='store_true')
    a=p.parse_args(argv)
    if a.resume_ssh != a.i_authorize_r41_ssh_resume:
        p.error('explicit SSH resume requires its dedicated authorization; preflight forbids it')
    if a.resume_ssh != (a.prior_r41_preflight is not None):
        p.error('authorized resume requires an independent R41 preflight; preflight forbids it')
    params=dict(source_archive=a.source_archive,
                r365_preflight_dir=a.r365_preflight,r365_boot_dir=a.r365_first_boot,
                r39_dir=a.r39_reconciliation,r40_dir=a.r40_preflight,
                receipt_dir=a.receipt_dir)
    try:
        result=(resume(**params,prior_r41_dir=a.prior_r41_preflight,authorized=True)
                if a.resume_ssh else preflight(**params))
    except (ValueError,OSError,TypeError,KeyError,RuntimeError) as exc:
        print('R41_STATUS='+('REVIEW_REQUIRED_ACTION_POSSIBLE' if a.resume_ssh else 'BLOCKED_NO_ACTIVATION_ATTEMPT'))
        print('R41_ERROR='+type(exc).__name__+':'+str(exc)[:160])
        print('R41_P8=NO-GO')
        return 2
    print('R41_STATUS='+result['status'])
    print('R41_RECEIPT_DIR='+str(a.receipt_dir))
    print('R41_REPORT_SHA256='+result['sha256'])
    print('R41_ATTEMPT_ID='+result['attempt_id'])
    print('R41_VM_STARTED_BY_R41='+str(result['vm_started_by_r41']).upper())
    print('R41_NETWORK_STARTED_BY_R41=FALSE')
    print('R41_ISOLATION_TESTED=FALSE')
    print('R41_P8=NO-GO')
    if result['failure_code']:
        print('R41_FAILURE='+result['failure_code'])
    return 0 if result['status'] in ('READY_FOR_SEPARATE_EXPLICIT_SSH_RESUME',
                                    'SSH_RESUMED_DENY_FIRST_UNTESTED') else 3

if __name__=='__main__':
    raise SystemExit(main())
