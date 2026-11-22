#!/usr/bin/env python3
"""B11 source-only capabilities. No privileged A6 admission from a Git checkout."""
from __future__ import annotations

import argparse
import json
import os
from ardrec.coordination import r129_b11_independent_a6 as a6


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capabilities',action='store_true',required=True)
    args=parser.parse_args(argv)
    if args.capabilities:
        print(json.dumps(a6.capabilities(),sort_keys=True,separators=(',',':')))
        return 0
    return 2


if __name__=='__main__':
    raise SystemExit(main())
