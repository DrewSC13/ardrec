#!/usr/bin/env python3
"""R104: executable 29/54-case ARDREC synthetic prototype, with durable replay.

No host/VM/network operations, no P8 authority, no real A6 or confirmed Rf.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r101_ssh_authority as r101
from ardrec.coordination.r58k_unified_family_bridge import (
    build_unified_preview, verify_unified_preview,
)
from ardrec_p14_r58k_unified_family_demo import synthetic_unified_inputs

ROOT = Path('/home/cicada/ardrec-lab/r104-functional-offline-v1')
SCHEMA = 'ardrec-r104-54-unit-functional-offline-v1'


class PrototypeError(ValueError):
    """Fail-closed prototype/receipt validation."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise PrototypeError(reason)


def fixtures(n: int) -> list[dict]:
    need(type(n) is int and n in (29, 54), 'CASE_COUNT_UNSUPPORTED')
    base = synthetic_unified_inputs()
    need(len(base) == 29, 'PINNED_FIXTURE_DRIFT')
    if n == 29:
        return base
    extra = deepcopy(base[:25])
    for item in extra:
        item['unit']['session_id'] = 'DEV_TUTOR_002'
        item['unit']['assessment_index'] = 1
    return base + extra


def build(n: int) -> dict:
    report = build_unified_preview(fixtures(n))
    verify_unified_preview(report)
    need(
        report['unit_count'] == n
        and report['covered_family_count_in_batch'] == 25
        and report['supported_family_count'] == 25
        and report['a6_classification'] == 'ND'
        and report['technical_truth_accredited'] is False
        and report['confirmed_final_risk'] is None
        and report['published_generation'] is None
        and report['applied_state_transition'] is None
        and report['operational_dispatch'] is False
        and report['p8_operational'] == 'NO-GO'
        and all(
            d['a6_classification'] == 'ND'
            and d['confirmed_rf'] is None
            and d['technical_truth_accredited'] is False
            and d['applied_transition'] is None
            and d['published_generation'] is None
            and d['a8_recommendation'] == 'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'
            for d in report['decisions']
        ),
        'PROTOTYPE_RESULT_NOT_CONSERVATIVE',
    )
    return report


def _doc(root: Path, name: str) -> dict:
    raw = a5._read_private(root / name, a5.MAX_SUPPORT)
    return r101.parse_private(raw)


def verify(root: Path) -> dict:
    a5._private_root(root)
    need({p.name for p in root.iterdir()} == {'report.json', 'manifest.json'},
         'SESSION_FILE_INVENTORY')
    report = _doc(root, 'report.json')
    manifest = _doc(root, 'manifest.json')
    need(type(manifest) is dict and manifest.get('schema') == SCHEMA,
         'MANIFEST_SCHEMA')
    need(manifest.get('sha256') == a5.digest({k: v for k, v in manifest.items()
                                               if k != 'sha256'}), 'MANIFEST_SHA')
    need(manifest.get('case_count') in (29, 54), 'MANIFEST_COUNT')
    need(manifest.get('report_sha256') == report.get('sha256'), 'REPORT_BINDING')
    need(manifest.get('report_file_sha256') == a5.sha(
         a5._read_private(root / 'report.json', a5.MAX_SUPPORT)), 'REPORT_FILE_SHA')
    need(manifest.get('mode') == 'SYNTHETIC_OFFLINE_NO_AUTHORITY'
         and manifest.get('p8_operational') == 'NO-GO'
         and manifest.get('a6_classification') == 'ND'
         and manifest.get('confirmed_rf') is None, 'AUTHORITY_DRIFT')
    verify_unified_preview(report)
    need(report == build(manifest['case_count']), 'FIXTURE_OR_RESULT_DRIFT')
    return manifest


def persist(report: dict, base: Path) -> tuple[Path, dict]:
    need(isinstance(base, Path) and base.is_absolute(), 'ROOT_NOT_ABSOLUTE')
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    a5._private_root(base)
    session = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    a5._private_root(session)
    raw = a5.canonical(report) + b'\n'
    a5._store_once(session / 'report.json', raw, a5.MAX_SUPPORT)
    manifest = {
        'schema': SCHEMA,
        'mode': 'SYNTHETIC_OFFLINE_NO_AUTHORITY',
        'case_count': report['unit_count'],
        'family_count': report['covered_family_count_in_batch'],
        'count_by_service': report['count_by_service'],
        'report_sha256': report['sha256'],
        'report_file_sha256': a5.sha(raw),
        'a6_classification': 'ND',
        'confirmed_rf': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
        'vm_starts': 0,
        'host_mutations': 0,
    }
    manifest['sha256'] = a5.digest(manifest)
    a5._store_once(session / 'manifest.json', a5.canonical(manifest) + b'\n',
                   a5.MAX_SUPPORT)
    descriptor = os.open(session, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    need(verify(session) == manifest, 'REOPEN_REPLAY_FAILED')
    return session, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline-synthetic', action='store_true')
    parser.add_argument('--cases', type=int, choices=(29, 54), default=54)
    parser.add_argument('--verify', type=Path)
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or not args.offline_synthetic:
        print('R104_STOP=REPO_AND_EXPLICIT_OFFLINE_MODE_REQUIRED')
        return 23
    try:
        if args.verify is not None:
            need(args.verify.is_absolute() and args.verify.is_relative_to(ROOT)
                 and args.verify.parent == ROOT, 'VERIFY_PATH_OUTSIDE_PRIVATE_ROOT')
            manifest = verify(args.verify)
            session = args.verify
        else:
            session, manifest = persist(build(args.cases), ROOT)
        print('R104_CASES=' + str(manifest['case_count']))
        print('R104_FAMILIES=' + str(manifest['family_count']))
        print('R104_PROTOCOLS=' + json.dumps(manifest['count_by_service'], sort_keys=True))
        print('R104_A6=ND')
        print('R104_A7_RF=NOT_CONFIRMED')
        print('R104_A8=PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
        print('R104_REPORT_SHA256=' + manifest['report_sha256'])
        print('R104_MANIFEST_SHA256=' + manifest['sha256'])
        print('R104_SESSION=' + str(session))
        print('R104_VM_STARTS=0')
        print('R104_P8=NO-GO')
        print('R104_RESULT=OFFLINE_PROTOTYPE_REPLAY_VERIFIED')
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print('R104_STOP=' + type(exc).__name__ + ':' + str(exc)[:180])
        print('R104_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
