#!/usr/bin/env python3
"""Optional A5 v2 source-verified case in R38; no execution or accreditation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO=Path(__file__).resolve().parents[1]
if str(REPO/'src') not in sys.path:sys.path.insert(0,str(REPO/'src'))

from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r59h_r38_verified_a5_view as h

DEFAULT_DB=Path('/home/cicada/ardrec-lab/r58y/observations.sqlite3')
DEFAULT_V2=Path('/home/cicada/ardrec-lab/r59f/v2')
DEFAULT_A5=Path('/home/cicada/ardrec-lab/r59f/a5')
DEFAULT_A6=Path('/home/cicada/ardrec-lab/r59f/a6')
DEFAULT_ATTEMPT='ATT_R59F_FTP_T02_DATA'


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--tui',action='store_true')
    mode.add_argument('--render',action='store_true')
    mode.add_argument('--verify',action='store_true')
    parser.add_argument('--database',type=Path,default=DEFAULT_DB)
    parser.add_argument('--v2-root',type=Path,default=DEFAULT_V2)
    parser.add_argument('--a5-root',type=Path,default=DEFAULT_A5)
    parser.add_argument('--a6-root',type=Path,default=DEFAULT_A6)
    parser.add_argument('--attempt-id',default=DEFAULT_ATTEMPT)
    parser.add_argument('--service',choices=z.SERVICES,default='FTPS')
    parser.add_argument('--stage',choices=z.STAGES,default='A5')
    parser.add_argument('--width',type=int,default=120)
    parser.add_argument('--height',type=int,default=32)
    args=parser.parse_args(argv)
    try:
        if Path.cwd().resolve()!=REPO:
            raise h.CaseViewError('REPO_ROOT_REQUIRED')
        paths=(args.database,args.v2_root,args.a5_root,args.a6_root)
        for path in paths:
            if not path.is_absolute() or path==REPO or REPO in path.parents:
                raise h.CaseViewError('PRIVATE_SOURCE_PATH_OUTSIDE_GIT_REQUIRED')
        if len(set(paths))!=len(paths):
            raise h.CaseViewError('SOURCE_PATHS_MUST_DIFFER')
        view=h.load_view(database=args.database,v2_root=args.v2_root,
                         a5_root=args.a5_root,a6_root=args.a6_root,
                         attempt_id=args.attempt_id)
        if args.tui:
            h.run_tui(view)
        elif args.render:
            from ardrec.coordination import dashboard_tui as r38
            state=r38.DashboardState(selected=z.STAGES.index(args.stage))
            frame=h.render_frame(view,z.SERVICES.index(args.service),state,
                                 args.width,args.height)
            print('\n'.join(frame))
        else:
            print(json.dumps({
                'r59h':'PASS_VERIFIED_A5_V2_R38_VIEW',
                'source_v2_sha256':view.source_v2_sha256,
                'source_bridge_sha256':view.bridge_sha256,
                'historical_workspace_sha256':view.workspace['sha256'],
                'service':view.service,'family_id':view.family,
                'variant':view.variant,'attempt_id':view.attempt,
                'declared_outcome':view.outcome,
                'model_family_class':view.hypothetical_class,
                'a5_physical_start_accredited':False,
                'a6_classification':'ND',
                'published_generation':None,
                'operational_dispatch':False,
                'p8_operational':'NO-GO',
                'host_mutations':0,
            },sort_keys=True,ensure_ascii=True))
        return 0
    except (ValueError,TypeError,KeyError,RuntimeError,OSError) as exc:
        print('R59H=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R59H_A5_PHYSICAL=NOT_ATTESTED; R59H_A6=ND; P8=NO-GO',file=sys.stderr)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
