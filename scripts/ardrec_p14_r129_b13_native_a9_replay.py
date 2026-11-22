#!/usr/bin/env python3
"""R129 B13 capabilities only: no real A9 publication or root execution."""
from __future__ import annotations
import argparse
import json
from ardrec.coordination.r129_b13_native_a9_replay import capabilities

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capabilities',action='store_true',required=True)
    p.parse_args()
    print(json.dumps(capabilities(),sort_keys=True,separators=(',',':')))
    return 0

if __name__=='__main__':raise SystemExit(main())
