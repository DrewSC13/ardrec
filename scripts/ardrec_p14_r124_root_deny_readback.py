#!/usr/bin/env python3
"""ARDREC R124: only read installed root R116 DENY and systemd timer state."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
from ardrec.coordination import r124_root_deny_readback as r124

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capabilities',action='store_true')
    mode.add_argument('--inspect',action='store_true')
    p.add_argument('--head',default=None)
    a=p.parse_args(argv)
    if a.capabilities:
        print(r124.canonical(r124.capabilities()).decode().strip())
        return 0
    try:
        r124.need(os.geteuid()!=0,'ROOT_SHELL_NOT_ALLOWED')
        r124.need(Path.cwd().resolve()==Path('/home/cicada/Development/GitHub/ardrec'),
                  'WRONG_WORKSPACE')
        local=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],capture_output=True,
                             check=False,stdin=subprocess.DEVNULL,timeout=5)
        r124.need(local.returncode==0 and local.stdout.decode('ascii').strip()==a.head,
                  'HEAD_NOT_CURRENT')
        r124.need(a.head is not None,'HEAD_REQUIRED')
        report=r124.inspect(head=a.head,now=datetime.now(timezone.utc))
    except (r124.Stop,OSError,UnicodeError,subprocess.TimeoutExpired) as exc:
        print('R124_STOP='+str(exc))
        print('R124_P8=NO-GO')
        return 2
    print('R124_ROOT_GUARD='+report['root_guard'])
    print('R124_STATES='+json.dumps(report['host']['states'],sort_keys=True))
    print('R124_DENY='+report['host']['stage'])
    print('R124_R34_TIMER='+report['r34_timer_state'])
    print('R124_SESSION_MARKER_CONSUMED='+str(report['session_marker_consumed']).upper())
    print('R124_SESSION_TIMER='+str(report['session_timer_state']))
    print('R124_60S_PHYSICAL_CLOSURE_VERIFIED=NO')
    print('R124_ROOT_AUDIT_SHA256='+report['sha256'])
    print('R124_BLOCKERS='+','.join(report['blockers']))
    print('R124_NETWORK_ACTIONS=0')
    print('R124_VM_STARTS=0')
    print('R124_NFT_WRITES=0')
    print('R124_P8=NO-GO')
    return 0
if __name__=='__main__':raise SystemExit(main())
