#!/usr/bin/env python3
"""R109 CLI: durable offline rule/risk/stop execution over verified R104-R108.

No SSH/FTP/SMB client calls, subprocess, sudo, privileged operations, or VMs.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r109_executable_decision_chain as engine
import ardrec_p14_r108_counterfactual_state as r108_cli

ROOT = Path('/home/cicada/ardrec-lab/r109-offline-executable-decision-v1')
MANIFEST_SCHEMA = 'ardrec-r109-private-executable-decision-replay-v1'
FILES = frozenset({'decision.json', 'manifest.json'})


def need(ok: bool, code: str) -> None:
    engine.need(ok, code)


def _unique(pairs):
    obj = {}
    for key, value in pairs:
        need(key not in obj, 'DUPLICATE_JSON_KEY')
        obj[key] = value
    return obj


def _doc(root: Path, name: str) -> dict:
    raw = a5._read_private(root / name, a5.MAX_SUPPORT)
    result = json.loads(raw, object_pairs_hook=_unique)
    need(type(result) is dict and raw == a5.canonical(result) + b'\n',
         'PRIVATE_NONCANONICAL_JSON')
    return result


def sources(r104: Path, r106: Path, r107: Path,
            r108: Path, f11: Path) -> tuple[dict, dict, dict]:
    """Reopen every original private chain; no digest-only trust shortcuts."""
    unified, manifest104, link, manifest106 = (
        r108_cli.r107_cli.source_documents(r104, r106, f11))
    need(r107.is_absolute() and r107.parent == r108_cli.r107_cli.ROOT
         and r107.name.startswith('run-') and not r107.is_symlink(),
         'R107_SESSION_PATH_INVALID')
    trace, _ = r108_cli.r107_cli.verify(
        r107, unified, manifest104, link, manifest106)
    need(r108.is_absolute() and r108.parent == r108_cli.ROOT
         and r108.name.startswith('run-') and not r108.is_symlink(),
         'R108_SESSION_PATH_INVALID')
    model, _ = r108_cli.verify(r108, trace)
    return unified, trace, model


def manifest_for(doc: dict) -> dict:
    need(doc.get('schema') == engine.SCHEMA
         and doc.get('case_count') == 54
         and doc.get('mathematical_interval_count') == 54
         and doc.get('rechecked_r108_model_events') == 72
         and doc.get('offline_case_checks_by_stage') ==
         {'A4': 54, 'A6': 54, 'A7': 54, 'A8': 54, 'A10': 54}
         and doc.get('a5_operational_starts') == 0
         and doc.get('a6_classification') == 'ND'
         and doc.get('a7_confirmed_rf') is None
         and doc.get('a9_published_generations') == 0
         and doc.get('p8_operational') == 'NO-GO',
         'R109_MANIFEST_SOURCE_INVALID')
    result = {
        'schema': MANIFEST_SCHEMA, 'mode': engine.MODE,
        'decision_sha256': doc['sha256'],
        'decision_file_sha256': a5.sha(a5.canonical(doc) + b'\n'),
        'r104_sha256': doc['r104_sha256'],
        'r107_sha256': doc['r107_sha256'],
        'r108_sha256': doc['r108_sha256'],
        'case_count': 54, 'offline_case_checks': 270,
        'model_event_count_reverified': 72,
        'case_chain_head_sha256': doc['case_chain_head_sha256'],
        'a5_operational_starts': 0, 'a6_classification': 'ND',
        'a7_confirmed_rf': None, 'a8_operational_transitions': 0,
        'a9_published_generations': 0, 'dispatch_allowed': False,
        'vm_starts': 0, 'p8_operational': 'NO-GO',
    }
    result['sha256'] = a5.digest(result)
    return result


def verify(directory: Path, unified: dict, trace: dict,
           model: dict) -> tuple[dict, dict]:
    a5._private_root(directory)
    need({p.name for p in directory.iterdir()} == FILES,
         'R109_SESSION_INVENTORY')
    report, manifest = _doc(directory, 'decision.json'), _doc(directory, 'manifest.json')
    engine.verify(report, unified, trace, model)
    need(manifest == manifest_for(report), 'R109_MANIFEST_REPLAY_MISMATCH')
    return report, manifest


def persist(unified: dict, trace: dict, model: dict,
            root: Path) -> tuple[Path, dict, dict]:
    need(isinstance(root, Path) and root.is_absolute(), 'ROOT_ABSOLUTE_REQUIRED')
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    a5._private_root(root)
    report = engine.build(unified, trace, model)
    manifest = manifest_for(report)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=root))
    a5._private_root(directory)
    for name, doc in (('decision.json', report), ('manifest.json', manifest)):
        a5._store_once(directory / name, a5.canonical(doc) + b'\n',
                       a5.MAX_SUPPORT)
    fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    need(verify(directory, unified, trace, model) == (report, manifest),
         'R109_DURABLE_READBACK_MISMATCH')
    return directory, report, manifest


def show(directory: Path, doc: dict, manifest: dict, *, table: bool) -> None:
    print('R109_CASES=' + str(doc['case_count']))
    print('R109_FAMILIES=' + str(doc['family_count']))
    print('R109_SERVICES=' + json.dumps(doc['protocol_counts'], sort_keys=True))
    print('R109_STAGE_CHECKPOINTS=' + str(doc['status_stage_count']))
    print('R109_OFFLINE_CASE_CHECKS=270')
    print('R109_CASE_CHECKS_BY_STAGE=' + json.dumps(doc['offline_case_checks_by_stage'], sort_keys=True))
    print('R109_A7_MATHEMATICAL_INTERVALS=' + str(doc['mathematical_interval_count']))
    print('R109_R108_TRANSITIONS_REPLAYED=' + str(doc['rechecked_r108_model_events']))
    print('R109_COUNTERFACTUAL_PHASES=' + json.dumps(doc['model_phase_counts'], sort_keys=True))
    print('R109_REPORT_SHA256=' + doc['sha256'])
    print('R109_MANIFEST_SHA256=' + manifest['sha256'])
    print('R109_SESSION=' + str(directory))
    print('R109_A1_A10_OPERATIONAL_COMPLETE=FALSE')
    print('R109_A5=NO_OPERATIONAL_START')
    print('R109_A6=ND')
    print('R109_A7_RF=NOT_CONFIRMED')
    print('R109_A8=PAUSE_RECOMMENDED_NOT_APPLIED')
    print('R109_A9=PUBLISHED_0')
    print('R109_VM_STARTS=0')
    print('R109_P8=NO-GO')
    if table:
        print('R109_TABLE=CASE|SERVICE|FAMILY|A7_LO|A7_HI|MODEL_PHASE')
        for case in doc['cases']:
            print('R109_ROW=' + '|'.join((
                case['case_id_a7'], case['service_id'], case['family_id'],
                case['a7_rf_lower'], case['a7_rf_upper'],
                case['counterfactual_final_phase'])))
    print('R109_RESULT=DURABLE_OFFLINE_EXECUTABLE_DECISION_REPLAY_VERIFIED')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-evaluate', action='store_true')
    parser.add_argument('--r104-session', type=Path, required=True)
    parser.add_argument('--r106-session', type=Path, required=True)
    parser.add_argument('--r107-session', type=Path, required=True)
    parser.add_argument('--r108-session', type=Path, required=True)
    parser.add_argument('--f11-review', type=Path, required=True)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--table', action='store_true')
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or (args.verify is None) != args.offline_evaluate:
        print('R109_STOP=EXPLICIT_OFFLINE_MODE_AND_REPO_REQUIRED')
        return 23
    try:
        unified, trace, model = sources(
            args.r104_session, args.r106_session,
            args.r107_session, args.r108_session, args.f11_review)
        if args.verify is None:
            directory, report, manifest = persist(unified, trace, model, ROOT)
        else:
            need(args.verify.is_absolute() and args.verify.parent == ROOT
                 and args.verify.name.startswith('run-')
                 and not args.verify.is_symlink(), 'R109_VERIFY_PATH_INVALID')
            directory = args.verify
            report, manifest = verify(directory, unified, trace, model)
        show(directory, report, manifest, table=args.table)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('R109_STOP=' + type(error).__name__ + ':' + str(error)[:180])
        print('R109_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
