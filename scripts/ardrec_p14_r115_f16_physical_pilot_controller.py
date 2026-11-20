#!/usr/bin/env python3
"""R115-F16: live pilot-boundary inspection only; NO physical dispatch."""
from __future__ import annotations
import argparse
import json
from datetime import datetime,timezone
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f16_physical_pilot_controller as f16
from ardrec.coordination import r115_f2_a3_current_sources as f2


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities',action='store_true')
    mode.add_argument('--inspect-current',action='store_true')
    ap.add_argument('--contract',type=Path)
    ap.add_argument('--authorization',type=Path)
    ap.add_argument('--pilot',type=Path)
    ap.add_argument('--ftp-plan',type=Path)
    ap.add_argument('--ftp-boot',type=Path)
    args=ap.parse_args(argv)
    if args.capabilities:
        if any(x is not None for x in (args.contract,args.authorization,args.pilot,
                                       args.ftp_plan,args.ftp_boot)):
            ap.error('capabilities accepts no evidence input')
        print(json.dumps(f16.capabilities(),sort_keys=True))
        return 0
    try:
        head=f7.git_guard(for_boot=True)
        current=f5.capture()
        kwargs={}
        for k,path in (('contract_raw',args.contract),
                       ('authorization_raw',args.authorization),
                       ('pilot_raw',args.pilot)):
            if path is not None:kwargs[k]=f2.private_read(path)
        if args.ftp_plan is not None:kwargs['ftp_plan_dir']=args.ftp_plan
        if args.ftp_boot is not None:kwargs['ftp_boot_dir']=args.ftp_boot
        report=f16.assess(head=head,catalog_raw=f16.CATALOG.read_bytes(),
                          capture=current,now=datetime.now(timezone.utc),**kwargs)
        folder=f16.persist(report)
    except (f16.Stop,f7.Stop,f5.Stop,f1.Rejected,f2.Stop,OSError,KeyError,
            ValueError,TypeError) as exc:
        print('R115_F16_STOP='+type(exc).__name__+':'+str(exc)[:140])
        print('R115_F16_P8=NO-GO')
        return 2
    print('R115_F16_RECEIPT='+str(folder))
    print('R115_F16_VM_STATES='+json.dumps(report['observed_vm_states'],sort_keys=True))
    print('R115_F16_PHYSICAL_DENY='+('MATCH_4_ACTIVE_2_OFFLINE'
          if report['physical_deny'] else 'ND'))
    print('R115_F16_BOOT_CHAIN='+('REPLAY_ATTESTED' if report['boot_chain'] else 'ND'))
    print('R115_F16_PILOT_DOCUMENT='+report['independent_pilot_document']['status'])
    print('R115_F16_BLOCKERS='+','.join(report['blockers']))
    print('R115_F16_A5=NO-GO')
    print('R115_F16_A6=ND')
    print('R115_F16_P8=NO-GO')
    print('R115_F16_NETWORK_CONNECTIONS=0')
    print('R115_F16_VM_STARTS=0')
    print('R115_F16_INSPECTION=PASS_READONLY')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
