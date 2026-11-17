#!/usr/bin/env python3
"""R59-C: verify F11 sources and exercise rollback in PRIVATE sandbox only."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r59c_f11_stage as m

def main()->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true',required=True)
    parser.add_argument('--scratch-parent',type=Path)
    args=parser.parse_args()
    try:
        if Path.cwd().resolve()!=ROOT:
            raise m.StageError('REQUIRES_REPOSITORY_CWD')
        doc=m.plan(ROOT)
        print('R59C_SOURCES=PINNED_FOUR_VERIFIED')
        if args.scratch_parent is not None:
            m._private_root(args.scratch_parent)
            with tempfile.TemporaryDirectory(prefix='r59c-',dir=args.scratch_parent) as tmp:
                sandbox=Path(tmp)
                sources=m.verified_sources(ROOT)
                result=m.simulate(sandbox,sources)
                replay=m.verify_simulation(sandbox,sources)
                if result['status']!='STAGED_ONLY_IN_PRIVATE_SANDBOX' or replay['status']!='REPLAY_IDENTICAL':
                    raise m.StageError('SIMULATION_OR_REPLAY_INVALID')
                print('R59C_SANDBOX_STAGE=PASS_AND_REPLAY_IDENTICAL')
                print('R59C_SIMULATION_RECEIPT_SHA256='+result['receipt_sha256'])
        print(json.dumps({"schema":doc['schema'],"files":len(doc['target_files']),
            "host_mutations":0,"f11_accepted":False,"p8":"NO-GO",
            "status":"PASS_SOURCE_ONLY_NOT_INSTALLED"},sort_keys=True))
        return 0
    except (m.StageError,OSError,ValueError,TypeError) as exc:
        print('R59C=BLOCKED:'+str(exc)[:160])
        print('R59C_HOST_MUTATIONS=0 R59C_P8=NO-GO')
        return 23
if __name__=='__main__':
    raise SystemExit(main())
