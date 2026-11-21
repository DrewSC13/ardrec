#!/usr/bin/env python3
"""R125: live read-only guard + provenance + coverage audit. No dispatch."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import os
from pathlib import Path
import subprocess

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125

REPO=Path('/home/cicada/Development/GitHub/ardrec')
CATALOG=Path('lab/operational-catalog-v1/catalog.json')


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    opts=p.add_mutually_exclusive_group(required=True)
    opts.add_argument('--capabilities',action='store_true')
    opts.add_argument('--inspect',action='store_true')
    opts.add_argument('--verify-audit',type=Path)
    p.add_argument('--head')
    p.add_argument('--capture',type=Path)
    p.add_argument('--save',action='store_true')
    a=p.parse_args(argv)
    if a.capabilities:
        print(f1.canonical(r125.capabilities()).decode().strip())
        return 0
    try:
        r125.need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
        r125.need(Path.cwd().resolve()==REPO,'WRONG_REPOSITORY')
        catalog=CATALOG.read_bytes()
        r125.coverage(catalog)
        if a.verify_audit is not None:
            report=r125.verify_persisted(a.verify_audit,catalog)
            print('R125_AUDIT=SOURCE_REPLAY_VERIFIED')
            print('R125_SHA256='+report['sha256'])
            print('R125_P8=NO-GO')
            return 0
        r125.need(a.inspect and a.capture is not None and a.head is not None,
                  'HEAD_AND_CAPTURE_REQUIRED')
        r125.need(a.capture.is_absolute(),'CAPTURE_ABSOLUTE_PATH_REQUIRED')
        sha=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],check=False,
                           stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        r125.need(sha.returncode==0 and sha.stdout.decode('ascii').strip()==a.head,
                  'CURRENT_GIT_HEAD_CHANGED')
        now=datetime.now(timezone.utc).replace(microsecond=0)
        boundary=r122.build(capture_folder=a.capture,catalog_raw=catalog,
                            head=a.head,now=now)
        plan=r123.plan(boundary=boundary,catalog_raw=catalog,now=now)
        guard=r124.inspect(head=a.head,now=now)
        report=r125.build(head=a.head,catalog_raw=catalog,now=now,
                          boundary=boundary,plan=plan,root_report=guard)
        r125.verify(report,catalog_raw=catalog,boundary=boundary,
                    plan=plan,root_report=guard)
        print('R125_HEAD='+report['head'])
        print('R125_ROOT_STATUS='+report['root_status']['status'])
        print('R125_ROOT_GUARD_PIN='+report['root_status']['guard_sha256'])
        print('R125_FTP_CASE='+str(report['ftp_case_id']))
        print('R125_COVERAGE=54_PLANNED_0_REAL_ASSIGNED')
        print('R125_FAMILIES=SSH:8,FTP:8,SMB:9')
        print('R125_A5='+report['a5'])
        print('R125_A6='+report['a6'])
        print('R125_RF='+str(report['a7_confirmed_rf']))
        print('R125_A9='+str(report['a9_global_generation']))
        print('R125_60S_PHYSICAL_CLOSURE=NOT_ATTESTED')
        print('R125_SHA256='+report['sha256'])
        print('R125_BLOCKERS='+','.join(report['blockers']))
        if a.save:
            folder=r125.persist(report,catalog_raw=catalog,boundary=boundary,
                               plan=plan,root_report=guard)
            r125.verify_persisted(folder,catalog)
            print('R125_PRIVATE_AUDIT='+str(folder))
            print('R125_PRIVATE_AUDIT=REPLAY_PASS')
        print('R125_NETWORK_ACTIONS=0')
        print('R125_VM_STARTS=0')
        print('R125_NFT_WRITES=0')
        print('R125_P8=NO-GO')
        return 0
    except (r125.Stop,r122.Stop,r123.Stop,r124.Stop,
            ValueError,KeyError,OSError,TypeError,UnicodeError,
            subprocess.TimeoutExpired) as exc:
        print('R125_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R125_P8=NO-GO')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
