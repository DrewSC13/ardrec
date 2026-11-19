#!/usr/bin/env python3
"""R111-F1: private, immutable re-interpretation of a REAL R111 host receipt.

No commands against libvirt, no sudo, no probes, no VM activation.
Preserves the original receipt and fixes locale-specific false findings.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]

import ardrec_p14_r111_legacy_host_snapshot as legacy
from ardrec.coordination import r111_real_host_reconciliation as engine

ROOT = Path('/home/cicada/ardrec-lab/r111-real-host-reconciled-v1')
FILES = {'report.json', 'manifest.json'}
MANIFEST_SCHEMA = 'ardrec-r111-f1-private-reconciliation-manifest-v1'


def need(ok: bool, code: str):
    engine.need(ok, code)


def source(directory: Path):
    need(directory.is_absolute() and directory.parent == legacy.ROOT
         and directory.name.startswith('run-') and not directory.is_symlink(),
         'LEGACY_SOURCE_PATH')
    manifest = legacy.verify(directory)
    raw = (directory / 'snapshot.json').read_bytes()
    need(legacy.sha(raw) == manifest['snapshot_sha256'],
         'LEGACY_SOURCE_BYTES_CHANGED')
    record = json.loads(raw)
    need(legacy.canonical(record) == raw, 'LEGACY_CANONICAL')
    return record, manifest['snapshot_sha256']


def _private_read(directory: Path, name: str) -> dict:
    path = directory / name
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
         and st.st_uid == os.geteuid() and st.st_nlink == 1
         and st.st_size <= engine.MAX_SOURCE_BYTES, 'PRIVATE_FILE_POLICY')
    raw = path.read_bytes()
    doc = json.loads(raw)
    need(raw == engine.canonical(doc), 'PRIVATE_NONCANONICAL_JSON')
    return doc


def manifest_for(report: dict) -> dict:
    content = {
        'schema': MANIFEST_SCHEMA,
        'source_r111_snapshot_sha256': report['source_snapshot_sha256'],
        'report_sha256': report['sha256'],
        'report_file_sha256': engine.sha(engine.canonical(report)),
        'source_kind': report['source_kind'],
        'vm_starts': 0,
        'host_mutations': 0,
        'p8_operational': 'NO-GO',
    }
    content['sha256'] = engine.sha(engine.canonical(content))
    return content


def verify(directory: Path, original: Path):
    need(directory.is_absolute() and directory.parent == ROOT
         and directory.name.startswith('run-') and not directory.is_symlink(),
         'RECONCILIATION_PATH')
    legacy._private_directory(directory)
    need({p.name for p in directory.iterdir()} == FILES, 'PRIVATE_FILES_DRIFT')
    src, source_sha = source(original)
    report = _private_read(directory, 'report.json')
    manifest = _private_read(directory, 'manifest.json')
    engine.verify_report(report, src, source_sha, legacy.summarize)
    need(manifest == manifest_for(report), 'PRIVATE_MANIFEST_DRIFT')
    return report, manifest


def persist(original: Path):
    src, source_sha = source(original)
    report = engine.build(src, source_sha, legacy.summarize)
    manifest = manifest_for(report)
    ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
    legacy._private_directory(ROOT)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=ROOT))
    legacy._private_directory(directory)
    legacy.secure_write(directory / 'report.json', engine.canonical(report))
    legacy.secure_write(directory / 'manifest.json', engine.canonical(manifest))
    handle = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(handle)
    finally:
        os.close(handle)
    need(verify(directory, original) == (report, manifest),
         'PRIVATE_REOPEN_FAILURE')
    return directory, report, manifest


def show(directory: Path, report: dict, manifest: dict):
    print('R111_F1_SOURCE_REAL_SNAPSHOT_SHA256=' + report['source_snapshot_sha256'])
    print('R111_F1_NORMALIZED_STATES=' + json.dumps(report['domain_states_normalized'], sort_keys=True))
    print('R111_F1_FALSE_SHUTOFF_FINDINGS=' + str(len(report['reclassified_locale_findings'])))
    print('R111_F1_REMAINING_FINDINGS=' + ','.join(report['remaining_findings']))
    print('R111_F1_RUNNER_NICS_MISSING=' + ','.join(report['runner_networks_missing']))
    print('R111_F1_NETWORK_ACTIVE=' + json.dumps(report['network_active_at_snapshot'], sort_keys=True))
    print('R111_F1_REPORT_SHA256=' + report['sha256'])
    print('R111_F1_MANIFEST_SHA256=' + manifest['sha256'])
    print('R111_F1_SESSION=' + str(directory))
    print('R111_F1_ORIGINAL_SNAPSHOT=UNMODIFIED')
    print('R111_F1_NO_HOST_MUTATIONS=TRUE')
    print('R111_F1_P8=NO-GO')
    print('R111_F1_RESULT=REAL_HOST_RECEIPT_REINTERPRETED_REPLAY_VERIFIED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--reconcile', action='store_true')
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--r111-original', type=Path, required=True)
    args = parser.parse_args()
    try:
        need(Path.cwd().resolve() == REPO, 'REPO_REQUIRED')
        if args.reconcile:
            directory, report, manifest = persist(args.r111_original)
        else:
            directory = args.verify
            report, manifest = verify(directory, args.r111_original)
        show(directory, report, manifest)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as e:
        print('R111_F1_STOP=' + type(e).__name__ + ':' + str(e)[:160])
        print('R111_F1_P8=NO-GO')
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
