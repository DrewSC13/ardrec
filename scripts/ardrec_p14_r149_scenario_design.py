#!/usr/bin/env python3
"""ARDREC R149: prepare/audit a private 54-scenario design sheet, OFFLINE ONLY."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess

from ardrec.experiments import r148_paired_register as r148
from ardrec.experiments import r149_scenario_design as r149

REPO = Path('/home/cicada/Development/GitHub/ardrec')
BRANCH = 'feat/ardrec-cierre-operacional-experimental'
R148_HEAD = 'cca70b5044d363bc03a31716bb9c65e29de365f0'
MAIN = '95a6d57b8241101c7a8fa3aedc07fb779b088d9f'
REGISTRY = Path('/home/cicada/ardrec-lab/r148-paired-study-v1')
CATALOG = Path('lab/operational-catalog-v1/catalog.json')

def git(*args):
    p=subprocess.run(('/usr/bin/git',*args),cwd=REPO,
      stdin=subprocess.DEVNULL,capture_output=True,timeout=15,check=False)
    r149.need(p.returncode==0,'GIT_PREFLIGHT_FAILED')
    return p.stdout.decode().strip()

def guard():
    r149.need(os.geteuid()!=0,'ROOT_FORBIDDEN')
    r149.need(Path.cwd()==REPO,'REPO_ROOT_REQUIRED')
    r149.need(git('branch','--show-current')==BRANCH,'BRANCH_CHANGED')
    r149.need(git('rev-parse','main')==MAIN,'MAIN_CHANGED')
    r149.need(git('status','--porcelain=v1','--untracked-files=all')=='',
              'DIRTY_REPO')
    r149.need(subprocess.run(('/usr/bin/git','verify-commit','HEAD'),cwd=REPO,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        timeout=15).returncode==0,'UNSIGNED_HEAD')
    r149.need(subprocess.run(('/usr/bin/git','merge-base','--is-ancestor',R148_HEAD,'HEAD'),
        cwd=REPO,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,timeout=15).returncode==0,
        'R148_BASE_NOT_ANCESTOR')
    r149.need(CATALOG.is_file() and not CATALOG.is_symlink(),
              'CATALOG_UNSAFE')
    c=CATALOG.read_bytes()
    protocol,registry=r148.read(REGISTRY,c)
    r149.need(protocol['head']==R148_HEAD,'R148_REGISTER_PROVENANCE_CHANGED')
    r149.need(registry['data_authority']=='UNVERIFIED_INPUTS_ONLY',
              'R148_REGISTER_AUTHORITY_CHANGED')
    return c,protocol,registry

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--prepare',action='store_true')
    action.add_argument('--audit',action='store_true')
    parser.add_argument('--folder',type=Path,required=True)
    args=parser.parse_args()
    try:
        c,p,r=guard()
        if args.prepare:
            report=r149.create(args.folder,c,p,r)
            print('R149_PREPARE=PASS_54_DRAFT_SLOTS_25_CANDIDATE_FAMILIES')
        else:
            report=r149.read(args.folder,c,p,r)
            print('R149_AUDIT=PASS_STRUCTURAL_READONLY')
        print('R149_FOLDER='+str(args.folder))
        print('R149_PLAN_SHA256='+report['plan_sha256'])
        print('R149_SELECTION_SHA256='+report['working_sha256'])
        print('R149_PLANNED='+str(report['slots']))
        print('R149_EMPTY='+str(report['statuses']['EMPTY']))
        print('R149_PARTIAL='+str(report['statuses']['PARTIAL']))
        print('R149_CANDIDATE_COMPLETE='+str(report['statuses']['COMPLETE']))
        print('R149_FAMILY_COVERAGE_CANDIDATE='+str(report['candidate_family_coverage']))
        print('R149_READINESS='+report['readiness'])
        print('R149_CONFIRMED_PHYSICAL_OBSERVATIONS=0')
        print('R149_P7=DRAFT_NOT_FROZEN R149_P8=NO-GO')
        print('R149_A6=ND R149_A9=NOT_PUBLISHED')
        print('R149_VM_STARTS=0 R149_TRAFFIC=0 R149_ROOT_INSTALL=NO')
        return 0
    except (r149.Stop,r148.Stop,OSError,ValueError,TypeError,
            subprocess.SubprocessError) as exc:
        print('R149_STOP='+type(exc).__name__+':'+str(exc)[:160])
        return 23

if __name__=='__main__':
    raise SystemExit(main())
