#!/usr/bin/env python3
"""R112-F2: measure real F11 readiness without VM start, policy change, or network traffic."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT_REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(ROOT_REPO/'src'),str(ROOT_REPO/'scripts')]

from ardrec.coordination import r112_f11_live_readiness as core
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as r112

ROOT = Path('/home/cicada/ardrec-lab/r112-f11-live-readiness-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
PARENT = '8d46223ee39fb66305c40c24cdf7e0ce0078ce88'
FILES = frozenset({'snapshot.json','units.json','readiness.json','manifest.json'})


def need(condition: bool, code: str) -> None:
    core.need(condition, code)


def _git_source():
    need(Path.cwd().resolve() == ROOT_REPO, 'REPOSITORY_REQUIRED')
    result = legacy.run(('git', 'rev-parse', 'HEAD'))
    branch = legacy.run(('git', 'branch', '--show-current'))
    need(result['rc'] == branch['rc'] == 0
         and result['stdout'].strip() == PARENT
         and branch['stdout'].strip() == BRANCH, 'GIT_PARENT_OR_BRANCH_DRIFT')


def _provenance(plan_dir: Path, receipt_dir: Path) -> tuple[str, str, dict]:
    plan, pre = r112.verify_plan(plan_dir)
    need(receipt_dir.name.startswith('apply-'), 'PHYSICAL_RECEIPT_NOT_APPLY')
    r112.verify_physical(plan_dir, receipt_dir)
    receipt = r112.read_json(receipt_dir/'receipt.json')
    need(receipt['operation'] == 'APPLY' and receipt['define_rc'] == 0
         and receipt['vm_starts'] == 0 and receipt['p8_operational'] == 'NO-GO',
         'ORIGINAL_PHYSICAL_APPLY_NOT_VERIFIED')
    plan_sha = r112.sha(r112.core.canonical(plan))
    receipt_sha = r112.sha(r112.core.canonical(receipt))
    return plan_sha, receipt_sha, pre


def unit_commands() -> dict[str, tuple[str, ...]]:
    fields = ('LoadState', 'ActiveState', 'SubState', 'Result',
              'Requires', 'After', 'DropInPaths', 'ExecMainStatus',
              'ExecMainStartTimestamp', 'LastTriggerUSec',
              'NextElapseUSecRealtime')
    # systemctl show is an inspection, never enable/start/restart.
    return {unit: ('systemctl','show',unit,*('--property='+p for p in fields))
            for unit in core.EXTRA_UNITS}


def _manifest(snapshot: dict, units: dict, report: dict) -> dict:
    body = {'schema': core.SCHEMA + '-private-manifest-v1',
            'mode': core.MODE,
            'files': {'snapshot.json':core.sha(core.canonical(snapshot)),
                      'units.json':core.sha(core.canonical(units)),
                      'readiness.json':core.sha(core.canonical(report))},
            'read_only_original_probes': 29,
            'read_only_systemd_probes': len(unit_commands()),
            'physical_mutations': 0,
            'vm_starts': 0, 'p8_operational': 'NO-GO'}
    body['sha256'] = core.sha(core.canonical(body))
    return body


def read_private(path: Path) -> dict:
    raw = r112.private_bytes(path)
    value = json.loads(raw)
    need(type(value) is dict and core.canonical(value) == raw,
         'PRIVATE_CANONICAL_JSON')
    return value


def verify_private(directory: Path, *, plan_sha: str,
                   receipt_sha: str) -> tuple[dict, dict]:
    need(directory.is_absolute() and directory.parent == ROOT
         and directory.name.startswith('run-') and not directory.is_symlink(),
         'PRIVATE_PATH_INVALID')
    r112.directory(directory)
    need({p.name for p in directory.iterdir()} == FILES,
         'PRIVATE_FILE_INVENTORY')
    snapshot = read_private(directory/'snapshot.json')
    units = read_private(directory/'units.json')
    report = read_private(directory/'readiness.json')
    manifest = read_private(directory/'manifest.json')
    core.verify(report, snapshot, units, legacy,
                plan_sha256=plan_sha,
                applied_receipt_sha256=receipt_sha,
                source_head=PARENT)
    need(manifest == _manifest(snapshot, units, report),
         'PRIVATE_MANIFEST_DRIFT')
    return report, manifest


def store(snapshot: dict, units: dict, report: dict,
          *, plan_sha: str, receipt_sha: str) -> tuple[Path,dict]:
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    r112.directory(ROOT)
    manifest = _manifest(snapshot,units,report)
    session = Path(tempfile.mkdtemp(prefix='run-',dir=ROOT))
    r112.directory(session)
    for filename, value in (
        ('snapshot.json',snapshot),('units.json',units),
        ('readiness.json',report),('manifest.json',manifest),
    ):
        r112.store(session/filename,core.canonical(value))
    fd = os.open(session,os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(verify_private(session,plan_sha=plan_sha,receipt_sha=receipt_sha)
         == (report,manifest), 'IMMEDIATE_DURABLE_REPLAY_FAILED')
    return session,manifest


def display(session: Path, doc: dict, manifest: dict):
    print('R112_F2_REAL_HOST=READONLY_MEASURED')
    print('R112_F2_RUNNER_NICS=3')
    print('R112_F2_VMS_SHUTOFF=4')
    print('R112_F2_NET_STATES='+json.dumps(doc['network_states_observed'],sort_keys=True))
    print('R112_F2_F11_BOOT_UNIT=ACTIVE')
    print('R112_F2_F11_TIMER=ACTIVE')
    print('R112_F2_F11_WATCHDOG_SERVICE='+doc['f11_watchdog_service_state'].upper())
    print('R112_F2_F11_REQUIRES='+str(doc['f11_libvirtd_requires_boot_service']).upper())
    print('R112_F2_F11_AFTER='+str(doc['f11_libvirtd_after_boot_service']).upper())
    print('R112_F2_F11_HOOK_DENIES_START=TRUE')
    print('R112_F2_OPERATIONAL_ADMISSION='+doc['operational_admission'])
    print('R112_F2_REPORT_SHA256='+doc['sha256'])
    print('R112_F2_MANIFEST_SHA256='+manifest['sha256'])
    print('R112_F2_SESSION='+str(session))
    print('R112_F2_VM_STARTS=0')
    print('R112_F2_P8=NO-GO')
    print('R112_F2_RESULT=DURABLE_REAL_HOST_READINESS_REPLAY_VERIFIED')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capture-readonly',action='store_true')
    group.add_argument('--verify',type=Path)
    parser.add_argument('--r112-plan',type=Path,required=True)
    parser.add_argument('--r112-apply',type=Path,required=True)
    args = parser.parse_args()
    try:
        _git_source()
        plan_sha,receipt_sha,baseline = _provenance(args.r112_plan,args.r112_apply)
        if args.verify is not None:
            report,manifest = verify_private(args.verify,
                plan_sha=plan_sha,receipt_sha=receipt_sha)
            display(args.verify,report,manifest)
            return 0
        snapshot = r112.capture() # existing 29 read-only probes
        # Every live host observation must retain the successfully applied
        # R112 snapshot, differing only in counters/expected dynamic fields.
        r112.core.snapshot_equivalent(baseline,snapshot,legacy,after_definition=True)
        units = {unit:legacy.run(cmd) for unit,cmd in unit_commands().items()}
        doc = core.build(snapshot,units,legacy,plan_sha256=plan_sha,
                         applied_receipt_sha256=receipt_sha,source_head=PARENT)
        session,manifest = store(snapshot,units,doc,
                                 plan_sha=plan_sha,receipt_sha=receipt_sha)
        display(session,doc,manifest)
        return 0
    except (ValueError,KeyError,TypeError,OSError,RecursionError) as exc:
        print('R112_F2_STOP='+type(exc).__name__+':'+str(exc)[:200])
        print('R112_F2_P8=NO-GO')
        return 23


if __name__=='__main__':
    raise SystemExit(main())
