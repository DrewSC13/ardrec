#!/usr/bin/env python3
"""R129-B12: inspect only, never use mutable Git code for root attestation."""
from __future__ import annotations
import argparse
import json
from ardrec.coordination import r129_b12_calibration_a9 as b12

def main()->int:
    p=argparse.ArgumentParser(description='ARDREC R129-B12 document/mathematics A7 + native A9 preflight')
    p.add_argument('--capabilities',action='store_true')
    a=p.parse_args()
    if not a.capabilities:p.error('ONLY_SOURCE_CAPABILITIES_AVAILABLE')
    print(json.dumps(b12.capabilities(),sort_keys=True,separators=(',',':')))
    return 0

if __name__=='__main__':raise SystemExit(main())
