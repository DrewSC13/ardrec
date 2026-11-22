#!/usr/bin/env python3
"""ARDREC R148 — prepare/audit offline private 54-unit paired experiment ledger.

No root privileges, VM start, network, token generation, P8/A6/A9 admission.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys

from ardrec.experiments import r148_paired_register as r148

REPO=Path('/home/cicada/Development/GitHub/ardrec')
HEAD='04e49d26f5dc32cebaa6b911fb9781428bba104f'
BRANCH='feat/ardrec-cierre-operacional-experimental'
CATALOG='lab/operational-catalog-v1/catalog.json'


def guard()->tuple[bytes,str]:
    r148.need(os.geteuid()!=0,'ROOT_FORBIDDEN')
    r148.need(Path.cwd()==REPO,'REPO_ROOT_REQUIRED')
    def git(*args):
        out=subprocess.run(('/usr/bin/git',*args),cwd=REPO,
           stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
           stderr=subprocess.DEVNULL,check=False,timeout=15)
        r148.need(out.returncode==0,'GIT_PREFLIGHT_FAILED')
        return out.stdout.decode('utf-8').strip()
    head=git('rev-parse','HEAD')
    r148.need(git('branch','--show-current')==BRANCH,'BRANCH_CHANGED')
    r148.need(git('rev-parse','main')=='95a6d57b8241101c7a8fa3aedc07fb779b088d9f',
         'MAIN_CHANGED')
    r148.need(git('status','--porcelain=v1','--untracked-files=all')=='','WORKTREE_NOT_CLEAN')
    r148.need(subprocess.run(('/usr/bin/git','verify-commit','HEAD'),
         cwd=REPO,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
         stderr=subprocess.DEVNULL,timeout=15).returncode==0,'UNSIGNED_HEAD')
    path=REPO/CATALOG
    r148.need(path.is_file() and not path.is_symlink(),'CATALOG_PATH_UNSAFE')
    raw=path.read_bytes()
    r148.r125_coverage(raw)
    return raw,head


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    operations=parser.add_mutually_exclusive_group(required=True)
    operations.add_argument('--prepare',action='store_true')
    operations.add_argument('--audit',action='store_true')
    operations.add_argument('--analysis',action='store_true')
    parser.add_argument('--folder',required=True,type=Path)
    args=parser.parse_args()
    try:
        catalog,head=guard()
        target=args.folder
        r148.need(target.is_absolute() and '..' not in target.parts,
             'PRIVATE_ABSOLUTE_FOLDER_REQUIRED')
        if args.prepare:
            result=r148.initialize(target,catalog,head)
            print('R148_PREPARE=PASS_54_EMPTY_SLOTS')
            print('R148_FOLDER='+str(target))
        else:
            protocol,registry=r148.read(target,catalog)
            r148.need(protocol['head']==head,'EXPERIMENT_HEAD_MISMATCH')
            result=r148.validate(protocol,registry,catalog)
            if args.analysis:
                report=r148.analyze(protocol,registry,catalog)
                print('R148_ANALYSIS_STATUS='+report['claim'])
                print('R148_RECORDED_UNVERIFIED='+str(report['recorded_unverified']))
                print('R148_WILCOXON_P='+str(report['primary_comparison']['p_one_sided_exact']))
                print('R148_WILCOXON_DECISION='+report['primary_comparison']['decision'])
                print('R148_REPORT_SHA256='+report['sha256'])
            else:
                print('R148_AUDIT=PASS_PRIVATE_STRUCTURAL_ONLY')
        print('R148_PLANNED=54')
        print('R148_ASSIGNED_UNVERIFIED='+str(sum(result['statuses'][key] for key in ('RECORDED_UNVERIFIED','EXCLUDED_UNVERIFIED'))))
        print('R148_RECORDED_UNVERIFIED='+str(result['statuses']['RECORDED_UNVERIFIED']))
        print('R148_CONFIRMED_PHYSICAL_OBSERVATIONS=0')
        print('R148_INDEPENDENT_RUBRIC=NOT_ATTESTED')
        print('R148_P7=NOT_FROZEN')
        print('R148_A6=ND R148_A9=NOT_PUBLISHED R148_P8=NO-GO')
        print('R148_VM_STARTS=0 R148_TRAFFIC=0 R148_ROOT_INSTALL=NO')
        return 0
    except (r148.Stop,OSError,ValueError,TypeError,subprocess.SubprocessError) as exc:
        print('R148_STOP='+type(exc).__name__+':'+str(exc)[:180])
        return 23

if __name__=='__main__':
    raise SystemExit(main())
