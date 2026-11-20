#!/usr/bin/env python3
"""Only static capabilities are CLI exposed. Operational socket is never opened."""
import argparse
import json
from ardrec.coordination.r115_f10_ftp_a5_transport import declared_capabilities

def main(argv=None):
    parser = argparse.ArgumentParser(description='ARDREC F10 bounded FTP receive-only kernel')
    parser.add_argument('--capabilities', action='store_true', required=True)
    parser.parse_args(argv)
    print(json.dumps(declared_capabilities(), sort_keys=True, separators=(',', ':')))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
