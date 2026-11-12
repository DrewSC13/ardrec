#!/usr/bin/env python3
"""R32 operator-only: authenticate R31 receipt and create unanswered private review queue.

inspect: read-only. create: write exactly once to private 0700/0600. No original
manual reads, no QCOW2, no client invocation, no shell or network.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

import p8_r32_semantic_triage as model
import p8_r31_manual_windows as r31
import verify_p8_cli_full_sources as r14
import verify_p8_r32_semantic_triage as v32

PATCHES = Path('/home/cicada/Development/GitHub/ardrec-patches')
SOURCE_DIR = PATCHES/'ARDREC_PRIVATE_R31'
SOURCE = SOURCE_DIR/'FTP_SMB_ROFF_WINDOWS_R31_PRIVATE.json'
DEST_DIR = PATCHES/'ARDREC_PRIVATE_R32'
DEST = DEST_DIR/'FTP_SMB_SEMANTIC_REVIEW_QUEUE_R32_PRIVATE.json'


def guarded_file(path, mode, parent_mode):
    model.need(not path.is_symlink() and path.is_file() and
               not path.parent.is_symlink() and path.parent.is_dir(), 'private_path')
    parent_stat = path.parent.lstat()
    info = path.lstat()
    model.need(stat.S_ISDIR(parent_stat.st_mode) and
               stat.S_IMODE(parent_stat.st_mode) == parent_mode and
               stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and
               info.st_nlink == 1 and 0 < info.st_size <= model.MAX_RECEIPT_SIZE,
               'private_mode_or_size')
    return path.read_bytes()


def inspect():
    model.need(os.getuid() == 1000 and os.geteuid() != 0, 'operator_nonroot')
    model.need(PATCHES.is_dir() and not PATCHES.is_symlink(), 'patches_dir')
    model.need(not DEST.exists() and not DEST.is_symlink() and
               not DEST_DIR.exists() and not DEST_DIR.is_symlink(), 'r32_receipt_already_exists')
    model.need(v32.verify()['status'] == 'PASS_P8_R32_39_SOURCE_BOUND_HUMAN_REVIEW_ROWS_DENY_ALL',
               'r32_public_contract')
    raw = guarded_file(SOURCE, 0o600, 0o700)
    model.need(hashlib.sha256(raw).hexdigest() == model.R31_PRIVATE_SHA, 'r31_sha')
    anchors = r31.catalog(r14.safe_read(v32.ROOT, r14.SOURCE, r14.SOURCE_SHA))
    checked = model.audit_r31(raw, anchors)
    queue = model.semantic_queue(checked)
    model.need(len(queue['review_rows']) == 39 and
               queue['unanswered_review_questions'] == 312 and
               queue['dispatch_allowed'] is False and
               queue['semantic_reviews_completed'] == 0, 'queue_invariants')
    print('PASS:r31_private_sha_verified_39_source_windows',flush=True)
    print('PASS:r32_39_human_review_rows_312_unanswered_questions',flush=True)
    print('SOURCE_ROFF_NOT_PRINTED=True',flush=True)
    return queue


def create(queue):
    model.need(not DEST_DIR.exists() and not DEST_DIR.is_symlink() and
               not DEST.exists() and not DEST.is_symlink(), 'already_created')
    raw = (json.dumps(queue, sort_keys=True, indent=2, ensure_ascii=False)+'\n').encode()
    model.need(0 < len(raw) < model.MAX_RECEIPT_SIZE, 'queue_size')
    DEST_DIR.mkdir(mode=0o700)
    model.need(stat.S_IMODE(DEST_DIR.stat().st_mode) == 0o700,'private_dir_mode')
    fd = os.open(DEST, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    fd_dir = os.open(DEST_DIR, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd_dir)
    finally: os.close(fd_dir)
    model.need(stat.S_IMODE(DEST.lstat().st_mode) == 0o600,'private_file_mode')
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','create'))
    args = parser.parse_args()
    print('========== ARDREC / P8-R32 / PRIVATE SEMANTIC REVIEW ==========',flush=True)
    queue = inspect()
    if args.mode == 'inspect':
        print('P8_R32_PRIVATE_INSPECT=PASS_READ_ONLY',flush=True)
    else:
        print('R32_PRIVATE_QUEUE_SHA256='+create(queue),flush=True)
        print('P8_R32_PRIVATE_CREATE=PASS_EXCLUSIVE_PRIVATE_REVIEW_QUEUE',flush=True)
    print('NO_SEMANTIC_APPROVAL=True NO_CLIENT_EXECUTION=True QCOW2_READ=False',flush=True)
    print('P8_OPEN=True P9_STARTED=False A1_TO_A10_STARTED=False',flush=True)
    print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)

if __name__ == '__main__':
    try: main()
    except (model.Denied,KeyError,ValueError,TypeError,OSError) as exc:
        print('P8_R32_PRIVATE=BLOCKED_'+type(exc).__name__,flush=True)
        print('REASON='+str(exc)[:280],flush=True)
        print('DO_NOT_REPEAT_CREATE_IF_REPORT_EXISTS=True',flush=True)
        print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)
        raise SystemExit(1)
