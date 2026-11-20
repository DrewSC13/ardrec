#!/usr/bin/env python3
"""F14 local A5-to-A6 audit; no VM/network/permit commands."""
import argparse
import json
from pathlib import Path

from ardrec.coordination import r115_f14_a5_a6_handoff as m
from ardrec.coordination import r115_dev_admission_contract as f1


def main():
    p=argparse.ArgumentParser(description='ARDREC F14 FTP-T01 A5/A6 quarantine bridge; NO-GO')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities',action='store_true')
    mode.add_argument('--review-receipt',type=Path)
    mode.add_argument('--verify-report',type=Path)
    args=p.parse_args()
    try:
        if args.capabilities:
            print(json.dumps(m.capabilities(),sort_keys=True))
            return 0
        catalog_raw=m.CATALOG.read_bytes()
        if args.review_receipt is not None:
            report=m.build(args.review_receipt,catalog_raw)
            folder=m.persist(report)
            print('R115_F14_REPORT='+str(folder))
            print('R115_F14_SOURCE_STATUS='+report['source_status'])
            print('R115_F14_ACCEPTED_SUPPORTS=0')
            print('R115_F14_A6=ND')
            print('R115_F14_A9=NOT_PUBLISHED')
            print('R115_F14_P8=NO-GO')
            return 0
        report=m.verify_persisted(args.verify_report,catalog_raw)
        print('R115_F14_REPLAY=PASS_SOURCE_AND_REPORT')
        print('R115_F14_REPORT_SHA256='+f1.digest(f1.canonical(report)))
        print('R115_F14_A6=ND')
        print('R115_F14_P8=NO-GO')
        return 0
    except (m.Stop,f1.Rejected,OSError,ValueError,KeyError,TypeError) as exc:
        print('R115_F14_STOP='+type(exc).__name__+':'+str(exc)[:120])
        print('R115_F14_A6=ND')
        print('R115_F14_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
