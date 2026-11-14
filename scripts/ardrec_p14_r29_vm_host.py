#!/usr/bin/env python3
"""R29: panel de libvirt SOLO LECTURA, nunca ejecuta un check de VM."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.development_cycle import verify_development_cycle
from ardrec.coordination.vm_host_preflight import (
    collect,canonical,verify_report,VMPreflightError)
from ardrec.coordination.vm_preflight_view import render_combined,run_combined_tui


def _unique(pairs):
    result={}
    for k,v in pairs:
        if k in result: raise ValueError('duplicate_cycle_key')
        result[k]=v
    return result


def load_previous_cycle(path: Path) -> dict:
    if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 262144:
        raise VMPreflightError('previous_cycle_invalid')
    try:
        doc=json.loads(path.read_bytes(),object_pairs_hook=_unique)
    except (ValueError,TypeError,UnicodeError) as exc:
        raise VMPreflightError('previous_cycle_invalid') from exc
    verify_development_cycle(doc)
    return doc


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cycle-report',type=Path,required=True,
                    help='ciclo.json validado R28, no ejecuta fixtures de nuevo')
    source=ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--historical-only',action='store_true')
    source.add_argument('--observe-local-libvirt',action='store_true')
    view=ap.add_mutually_exclusive_group(required=True)
    view.add_argument('--json',action='store_true')
    view.add_argument('--texto',action='store_true')
    view.add_argument('--tui',action='store_true')
    opts=ap.parse_args()
    cycle=load_previous_cycle(opts.cycle_report)
    vm=collect(ROOT/'lab/p14-r29-vm-preflight-v1/expected.json',
               ROOT/'lab/services-v1/evidence.json',
               observe=opts.observe_local_libvirt)
    verify_report(vm)
    if opts.json:
        doc={'schema':'ardrec-p14-r29-linked-lab-view-v1',
             'previous_cycle_sha256':cycle['sha256'],
             'vm_host_preflight':vm,
             'p8_operational':'NO-GO','guest_checks_executed':False}
        doc['sha256']=hashlib.sha256(canonical(doc)).hexdigest()
        sys.stdout.buffer.write(canonical(doc)+b'\n')
    elif opts.texto:
        sys.stdout.write(render_combined(cycle,vm))
    else:
        run_combined_tui(cycle,vm)
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except VMPreflightError as error:
        sys.stderr.write('R29_FAIL_CLOSED='+str(error)+'\n')
        raise SystemExit(2)
