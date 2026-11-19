#!/usr/bin/env python3
"""R110: durable, replayable A1-A3 offline 54-window session control."""
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
from ardrec.coordination import r101_ssh_authority as r101
from ardrec.coordination import r110_session_control as engine
from ardrec.coordination.demo_session import read_fixed_scenario
import ardrec_p14_r109_executable_decision_chain as r109_cli

ROOT = Path('/home/cicada/ardrec-lab/r110-offline-session-control-v1')
SCENARIO_PATH = REPO / 'lab/p14-r26-session-v1/scenario.json'
MANIFEST_SCHEMA = 'ardrec-r110-offline-private-session-control-v1'
FILES = frozenset({'control.json', 'manifest.json'})


def need(ok: bool, code: str) -> None:
    engine.need(ok, code)


def sources(r104: Path, r106: Path, r107: Path, r108: Path,
            r109: Path, f11: Path) -> tuple[dict, dict, dict, dict, dict]:
    """Reopen the complete R104-R109 DAG; no trust in a bare supplied SHA."""
    unified, trace, model = r109_cli.sources(r104, r106, r107, r108, f11)
    need(isinstance(r109, Path) and r109.is_absolute()
         and r109.parent == r109_cli.ROOT
         and r109.name.startswith('run-') and not r109.is_symlink(),
         'R109_SESSION_PATH_INVALID')
    decisions, _ = r109_cli.verify(r109, unified, trace, model)
    scenario = read_fixed_scenario(SCENARIO_PATH)
    return unified, trace, model, decisions, scenario


def manifest_for(document: dict) -> dict:
    need(document.get('schema') == engine.SCHEMA
         and document.get('case_count') == 54
         and document.get('a3_truth_counts') ==
         {'VERDADERO': 16, 'FALSO': 18, 'ND': 20}
         and document.get('t1_denied_by_authority') == 54
         and document.get('t1_counterfactual_candidates') == 16
         and document.get('operational_t1_transitions') == 0
         and document.get('a6_classification') == 'ND'
         and document.get('p8_operational') == 'NO-GO',
         'MANIFEST_SOURCE_PROMOTED')
    result = {
        'schema': MANIFEST_SCHEMA, 'mode': engine.MODE,
        'report_sha256': document['sha256'],
        'report_file_sha256': a5.sha(a5.canonical(document) + b'\n'),
        'r109_decision_sha256': document['r109_decision_sha256'],
        'r26_session_sha256': document['r26_a1_a3_session_sha256'],
        'case_count': 54, 'family_count': 25,
        'a3_truth_counts': document['a3_truth_counts'],
        't1_rejected_by_authority': 54,
        't1_counterfactual_candidates': 16,
        'operational_t1_transitions': 0,
        'a5_operational_starts': 0, 'a6_classification': 'ND',
        'a7_confirmed_rf': None, 'a9_published_generations': 0,
        'dispatch_allowed': False, 'vm_starts': 0,
        'p8_operational': 'NO-GO',
    }
    result['sha256'] = a5.digest(result)
    return result


def _doc(directory: Path, filename: str) -> dict:
    return r101.parse_private(a5._read_private(directory / filename, a5.MAX_SUPPORT))


def verify(directory: Path, unified: dict, trace: dict, model: dict,
           decisions: dict, scenario: dict) -> tuple[dict, dict]:
    a5._private_root(directory)
    need({p.name for p in directory.iterdir()} == FILES,
         'PRIVATE_INVENTORY_INVALID')
    document = _doc(directory, 'control.json')
    manifest = _doc(directory, 'manifest.json')
    engine.verify(document, unified, trace, model, decisions, scenario)
    need(manifest == manifest_for(document), 'PRIVATE_MANIFEST_DRIFT')
    return document, manifest


def persist(unified: dict, trace: dict, model: dict, decisions: dict,
            scenario: dict, base: Path) -> tuple[Path, dict, dict]:
    need(isinstance(base, Path) and base.is_absolute() and not base.is_symlink(),
         'PRIVATE_ROOT_INVALID')
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    a5._private_root(base)
    document = engine.build(unified, trace, model, decisions, scenario)
    manifest = manifest_for(document)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    a5._private_root(directory)
    for name, item in (('control.json', document), ('manifest.json', manifest)):
        a5._store_once(directory / name, a5.canonical(item) + b'\n', a5.MAX_SUPPORT)
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    need(verify(directory, unified, trace, model, decisions, scenario)
         == (document, manifest), 'R110_DURABLE_REPLAY_FAILED')
    return directory, document, manifest


def display(directory: Path, doc: dict, manifest: dict, table: bool = False) -> None:
    print('R110_CASES=' + str(doc['case_count']))
    print('R110_FAMILIES=' + str(doc['family_count']))
    print('R110_SERVICES=' + json.dumps(doc['counts_by_service'], sort_keys=True))
    print('R110_A3_TRUTH=' + json.dumps(doc['a3_truth_counts'], sort_keys=True))
    print('R110_T1_COUNTERFACTUAL_CANDIDATES=' + str(doc['t1_counterfactual_candidates']))
    print('R110_T1_DENIED_BY_AUTHORITY=' + str(doc['t1_denied_by_authority']))
    print('R110_T1_OPERATIONAL=0')
    print('R110_R26_SECOND_SESSION_OBSERVED=FALSE')
    print('R110_REPORT_SHA256=' + doc['sha256'])
    print('R110_MANIFEST_SHA256=' + manifest['sha256'])
    print('R110_SESSION=' + str(directory))
    print('R110_A1_A10_OPERATIONAL_COMPLETE=FALSE')
    print('R110_A5=NO_OPERATIONAL_START')
    print('R110_A6=ND')
    print('R110_A7_RF=NOT_CONFIRMED')
    print('R110_A9=PUBLISHED_0')
    print('R110_VM_STARTS=0')
    print('R110_P8=NO-GO')
    if table:
        print('R110_TABLE=CASE|SERVICE|SESSION|GUARD|T1_CANDIDATE|T1_OPERATIONAL')
        for x in doc['cases']:
            print('R110_ROW=' + '|'.join((
                x['case_id_a7'], x['service_id'], x['session_id'],
                x['a3_guard_truth'],
                'SIMULATED' if x['t1_counterfactual_candidate_sha256'] else 'NONE',
                'DENIED',
            )))
    print('R110_RESULT=DURABLE_A1_A3_CONTROL_REPLAY_VERIFIED')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-control', action='store_true')
    for name in ('r104', 'r106', 'r107', 'r108', 'r109'):
        parser.add_argument(f'--{name}-session', type=Path, required=True)
    parser.add_argument('--f11-review', type=Path, required=True)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--table', action='store_true')
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or (args.verify is None) != args.offline_control:
        print('R110_STOP=EXPLICIT_OFFLINE_MODE_AND_REPO_REQUIRED')
        return 23
    try:
        unified, trace, model, decisions, scenario = sources(
            args.r104_session, args.r106_session, args.r107_session,
            args.r108_session, args.r109_session, args.f11_review,
        )
        if args.verify is None:
            directory, document, manifest = persist(
                unified, trace, model, decisions, scenario, ROOT)
        else:
            need(args.verify.is_absolute() and args.verify.parent == ROOT
                 and args.verify.name.startswith('run-')
                 and not args.verify.is_symlink(), 'VERIFY_PATH_INVALID')
            directory = args.verify
            document, manifest = verify(
                directory, unified, trace, model, decisions, scenario)
        display(directory, document, manifest, table=args.table)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('R110_STOP=' + type(error).__name__ + ':' + str(error)[:180])
        print('R110_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
