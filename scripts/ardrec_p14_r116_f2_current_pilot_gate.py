#!/usr/bin/env python3
"""R116-F2 real read-only F5/F1/signed P7 pilot preflight (NEVER dispatch)."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r116_f2_current_pilot_gate as gate

GUARD='/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py'

def root_readback():
    cmd=['/usr/bin/sudo','-n','--','/usr/bin/python3',GUARD,'--check']
    p=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,
                     check=False,timeout=75,shell=False,
                     env={'PATH':'/usr/sbin:/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
    gate.need(p.returncode==0 and len(p.stdout)<20000 and
              len(p.stderr)<20000,'F1_ROOT_CHECK_NOT_ATTESTED')
    result=f1.load(p.stdout)
    return gate.check_root_guard(result)

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--inspect-current',action='store_true')
    for name in ('contract','authorization','pilot','ftp-plan','ftp-boot'):
        ap.add_argument('--'+name,type=Path)
    args=ap.parse_args(argv)
    if args.capabilities:
        if any(getattr(args,x) is not None for x in ('contract','authorization',
                            'pilot','ftp_plan','ftp_boot')):
            ap.error('--capabilities takes no evidence paths')
        print(json.dumps(gate.capabilities(),sort_keys=True))
        return 0
    try:
        gate.need(os.geteuid()!=0,'NONROOT_READONLY_CLI_REQUIRED')
        paths=(args.contract,args.authorization,args.pilot,args.ftp_plan,args.ftp_boot)
        gate.need(all(x is not None and x.is_absolute() for x in paths),
                  'COMPLETE_ABSOLUTE_EVIDENCE_PATHS_REQUIRED')
        now=datetime.now(timezone.utc)
        head=f7.git_guard(for_boot=True)
        catalog=(Path(__file__).resolve().parents[1]/'lab/operational-catalog-v1/catalog.json').read_bytes()
        # No unsigned decisions: scope, permit and revocation are all verified
        # by versioned R116 current-HEAD reviewer with fixed root trust files.
        report=gate.preflight(head=head,catalog_raw=catalog,now=now,
            capture=f5.capture(),contract_raw=f2.private_read(args.contract),
            authorization_raw=f2.private_read(args.authorization),
            pilot_raw=f2.private_read(args.pilot),
            ftp_plan_dir=args.ftp_plan,ftp_boot_dir=args.ftp_boot,
            root_guard_readback=root_readback())
    except (gate.Stop,f1.Rejected,f5.Stop,f7.Stop,f2.Stop,
            subprocess.SubprocessError,KeyError,ValueError,OSError,TypeError) as exc:
        print('R116_F2_PREFLIGHT=NO-GO')
        print('R116_F2_STOP='+type(exc).__name__+':'+str(exc)[:140])
        print('R116_F2_A6=ND')
        print('R116_F2_P8=NO-GO')
        return 23
    # No GO claim. This review is a snapshot, not a root capability.
    print('R116_F2_PREFLIGHT=SOURCE_AND_PHYSICAL_PRECONDITIONS_AT_REVIEW_ONLY')
    print('R116_F2_REPORT_SHA256='+f1.digest(f1.canonical(report)))
    print('R116_F2_PILOT_SHA256='+report['pilot_sha256'])
    print('R116_F2_ROOT_DISPATCH=NOT_IMPLEMENTED')
    print('R116_F2_A6=ND')
    print('R116_F2_P8=NO-GO')
    print(json.dumps(report,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
