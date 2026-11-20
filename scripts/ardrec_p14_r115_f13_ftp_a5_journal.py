#!/usr/bin/env python3
"""R115-F13 CLI: static capabilities or PRIVATE receipt readback only.

No CLI option for reservation, socket transport, retries or P8 authorization.
The library API is for a future independently authorized root/P8 dispatcher.
"""
import argparse
import json
from pathlib import Path
from ardrec.coordination import r115_f13_ftp_a5_journal as j


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--inspect-receipt',type=Path)
    args=parser.parse_args()
    if args.capabilities:
        result=j.capabilities()
    else:
        result=j.inspect(args.inspect_receipt)
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
