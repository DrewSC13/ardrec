#!/usr/bin/env python3
"""ARDREC R113-F8R: immutable corrected offline candidate and deterministic replay."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO/'scripts'))
from ardrec.coordination import r113_f8r_arp_correction as p
import ardrec_p14_r113_f8_policy as f8_cli


def get_sources():
    original = f8_cli.inspect(p.OLD_PLAN)
    report = f8_cli.secure_file(p.F9_REPORT)
    p.validate_f9_report(report, original)
    return original,report


def inspect(folder):
    p.require(folder.is_absolute() and folder.parent == p.DEST and
              folder.name.startswith('plan-'), 'F8R_PLAN_PATH_INVALID')
    f8_cli.check_directory(p.DEST)
    f8_cli.check_directory(folder)
    meta = json.loads(f8_cli.secure_file(folder/'manifest.json'))
    p.require(meta.get('schema')==p.SCHEMA, 'F8R_PLAN_SCHEMA_CHANGED')
    expected = set(meta['sha256']) | {'manifest.json'}
    p.require({x.name for x in folder.iterdir()}==expected, 'F8R_PLAN_SCOPE_CHANGED')
    actual = {name:f8_cli.secure_file(folder/name) for name in expected}
    for name,digest in meta['sha256'].items():
        p.require(p.old.sha(actual[name])==digest, 'F8R_PLAN_HASH_CHANGED_'+name)
    p.require(actual == p.prepare(*get_sources()), 'F8R_DETERMINISM_FAILED')
    return actual


def create():
    os.umask(0o077)
    if not p.DEST.exists(): p.DEST.mkdir(mode=0o700)
    f8_cli.check_directory(p.DEST)
    data = p.prepare(*get_sources())
    folder=Path(tempfile.mkdtemp(dir=p.DEST,prefix='plan-'))
    f8_cli.check_directory(folder)
    for name,raw in sorted(data.items()):
        f8_cli.put(folder/name,raw)
    p.require(inspect(folder)==data, 'F8R_POST_CREATE_VALIDATION_FAILED')
    return folder


def main():
    parser=argparse.ArgumentParser()
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--plan',action='store_true')
    action.add_argument('--replay',type=Path)
    args=parser.parse_args()
    try:
        if args.plan:
            folder=create()
            print('R113_F8R_POLICY_SESSION='+str(folder),flush=True)
        else:
            inspect(args.replay)
            print('R113_F8R_POLICY_REPLAY=PASS',flush=True)
        print('R113_F8R_HISTORICAL_F8=REPLAY_AND_HASHES_VERIFIED',flush=True)
        print('R113_F8R_REJECTED_F9=PINNED_REPORT_VERIFIED',flush=True)
        print('R113_F8R_ARP_XML=12_CORRECTED_RULES',flush=True)
        print('R113_F8R_NFT_POLICY=BYTE_FOR_BYTE_UNCHANGED',flush=True)
        print('R113_F8R_TRAFFIC=NOT_AUTHORIZED',flush=True)
        print('R113_F8R_P8=NO-GO',flush=True)
        return 0
    except Exception as exc:
        print('R113_F8R_STOP='+type(exc).__name__+':'+str(exc)[:200],flush=True)
        print('R113_F8R_NO_AUTO_RETRY=TRUE',flush=True)
        print('R113_F8R_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
