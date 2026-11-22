#!/usr/bin/env python3
"""R127-B6: read-only physical R116 session timer observer, no root writes.

Run from the configured ARDREC repository with sudo credential cache already
established by the operator; the script itself uses only R124's fixed sudo -n
read-only commands. --watch requires a session already armed INDEPENDENTLY.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import subprocess
import sys
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r127_failure_observer as m

REPO=Path('/home/cicada/Development/GitHub/ardrec')


def main(argv=None)->int:
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--snapshot',action='store_true')
    group.add_argument('--watch',action='store_true')
    group.add_argument('--verify-folder',type=Path)
    ap.add_argument('--head')
    ap.add_argument('--session')
    args=ap.parse_args(argv)
    try:
        if args.capabilities:
            m.need(args.head is None and args.session is None,'CAPABILITIES_NO_OPERATIONAL_INPUT')
            print(f1.canonical(m.capabilities()).decode().strip())
            return 0
        if args.verify_folder is not None:
            m.need(args.head is None and args.session is None,'REPLAY_NO_LIVE_INPUT')
            result=m.verify_persisted(args.verify_folder)
            print('R127_B6_REPLAY=PASS')
            print('R127_B6_SHA256='+result['sha256'])
            print('R127_B6_P8=NO-GO')
            return 0
        m.need(Path.cwd().resolve()==REPO and args.head is not None,
               'WRONG_REPO_OR_HEAD_REQUIRED')
        proc=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=8,check=False)
        m.need(proc.returncode==0 and proc.stdout.decode('ascii').strip()==args.head,
               'GIT_HEAD_CHANGED')
        if args.snapshot:
            m.need(args.session is None,'SNAPSHOT_NO_SESSION')
            one=m.current_sample(head=args.head)
            report=m.assemble(head=args.head,records=[one],session=None)
        else:
            m.need(args.watch and args.session is not None,'WATCH_SESSION_REQUIRED')
            report=m.watch(head=args.head,session=args.session,
                sample=lambda:m.current_sample(head=args.head))
        folder=m.persist(report)
        m.verify_persisted(folder)
        print('R127_B6_STATUS='+report['status'])
        print('R127_B6_SAMPLES='+str(report['sample_count']))
        print('R127_B6_SESSION_TIMER_SEEN_ACTIVE='+str(report['session_timer_seen_active']))
        print('R127_B6_SESSION_TIMER_SEEN_INACTIVE='+str(report['session_timer_seen_inactive_after_active']))
        print('R127_B6_PRIVATE_EVIDENCE='+str(folder))
        print('R127_B6_SHA256='+report['sha256'])
        print('R127_B6_CRASH_PHYSICAL_VERIFIED=NO')
        print('R127_B6_PHYSICAL_RESTORATION_60S_VERIFIED=NO')
        print('R127_B6_P8=NO-GO')
        return 0
    except (m.Stop,OSError,ValueError,TypeError,KeyError,
            subprocess.TimeoutExpired) as exc:
        print('R127_B6_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R127_B6_P8=NO-GO')
        return 2

if __name__=='__main__':sys.exit(main())
