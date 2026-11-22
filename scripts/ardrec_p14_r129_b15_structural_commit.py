#!/usr/bin/env python3
"""R129-B15 CLI: capabilities in source; commit only by installed approved bundle."""
from __future__ import annotations
import argparse
import json
import sys
from ardrec.coordination import r129_b15_structural_commit as b15

def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    modes=ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--capabilities',action='store_true')
    modes.add_argument('--commit-structural',action='store_true')
    args=ap.parse_args(argv)
    try:
        if args.capabilities:
            print(json.dumps(b15.capabilities(),sort_keys=True,separators=(',',':')))
            return 0
        # Source tree is NEVER an authorized operational publisher.
        b15.need(b15.Path(b15.__file__).resolve()==b15.PUBLISHER,
                 'INDEPENDENT_IMMUTABLE_B15_INSTALL_REQUIRED')
        value=b15.execute_installed()
        print(json.dumps(value,sort_keys=True,separators=(',',':')))
        return 0
    except (b15.Stop,OSError,ValueError,TypeError,KeyError) as exc:
        print('R129_B15_STOP='+type(exc).__name__+':'+str(exc)[:220])
        print('R129_B15_P8=NO-GO')
        return 2

if __name__=='__main__':sys.exit(main())
