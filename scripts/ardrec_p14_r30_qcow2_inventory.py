#!/usr/bin/env python3
"""R30: consulta QCOW2 read-only, no necesita root y nunca restaura VMs."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.restoration_inventory import collect,canonical


def main() -> int:
    parser=argparse.ArgumentParser()
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--historical-only',action='store_true')
    mode.add_argument('--scan-host',action='store_true')
    parser.add_argument('--r29-report',required=True,type=Path)
    parser.add_argument('--r29-file-sha256',required=True)
    view=parser.add_mutually_exclusive_group(required=True)
    view.add_argument('--json',action='store_true')
    view.add_argument('--texto',action='store_true')
    arg=parser.parse_args()
    profile=ROOT/'lab/p14-r30-restoration-inventory-v1/expected.json'
    report=collect(profile,arg.r29_report,arg.r29_file_sha256,scan=arg.scan_host)
    if arg.json:
        sys.stdout.buffer.write(canonical(report)+b'\n')
    else:
        print('ARDREC R30 | INVENTARIO QCOW2 | NO-GO')
        print('MODO:',report['mode'],'| RESULTADO:',report['summary'])
        for role in report['roles']:
            print(role['role'].upper(),
                  'BASE=',role['base']['state'],
                  'OVERLAY=',role['runtime']['state'],
                  'QCOW2_METADATA=',role['metadata_matches_historical'])
        print('CONTENIDO SHA256 ACTUAL: NO VERIFICADO')
        print('RESTAURACION: NO | VM ARRANCADAS: NO | P8: NO-GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
