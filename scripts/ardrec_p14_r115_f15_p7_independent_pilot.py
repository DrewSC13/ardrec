#!/usr/bin/env python3
"""R115-F15 independent P7 pilot scope request; never an execution command."""
import argparse
import json
import os
from pathlib import Path
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f15_p7_independent_pilot as m


def main(argv=None):
    parser=argparse.ArgumentParser(description='R115 F15 P7 separately signed pilot preparation; NO-GO')
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare',action='store_true')
    mode.add_argument('--capabilities',action='store_true')
    parser.add_argument('--contract',type=Path)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--pilot-permit',type=Path)
    args=parser.parse_args(argv)
    if args.capabilities:
        if any((args.contract,args.authorization,args.pilot_permit)):
            parser.error('capabilities does not accept documents')
        print(json.dumps(m.capabilities(),sort_keys=True))
        return 0
    try:
        if os.geteuid()==0:
            raise m.Stop('ROOT_SHELL_FORBIDDEN')
        head=f7.git_guard()
        paths=(args.contract,args.authorization,args.pilot_permit)
        if any(x is None for x in paths) and any(x is not None for x in paths):
            raise m.Stop('PARTIAL_SIGNED_DOCUMENT_SET')
        raw=[f2.private_read(x) for x in paths] if all(paths) else [None]*3
        report=m.overview(head=head,catalog_raw=f6.CATALOG.read_bytes(),
                          contract_raw=raw[0],authorization_raw=raw[1],
                          pilot_raw=raw[2])
        folder=m.persist(report)
        print('R115_F15_RECEIPT='+str(folder))
        print('R115_F15_HEAD='+head)
        print('R115_F15_DOCUMENT_STATUS='+report['pilot_documents']['status'])
        print('R115_F15_BLOCKERS='+','.join(report['blockers']))
        print('R115_F15_P7_PILOT_COMPLETED=False')
        print('R115_F15_A5=NO-GO')
        print('R115_F15_A6=ND')
        print('R115_F15_P8=NO-GO')
        print('R115_F15_VM_STARTS=0')
        print('R115_F15_NETWORK_CONNECTIONS=0')
        return 0
    except (m.Stop,f1.Rejected,f7.Stop,f2.Stop,OSError,KeyError,TypeError,ValueError) as exc:
        print('R115_F15_STOP='+type(exc).__name__+':'+str(exc)[:128])
        print('R115_F15_P8=NO-GO')
        return 23

if __name__=='__main__':
    sys.exit(main())
