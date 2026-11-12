#!/usr/bin/env python3
"""R35 operator-only review-dossier metadata from PREVIOUS R14 private capture.

inspect: authenticate R14/R31/R32/R33 and recompute candidate metadata without writes.
create: authenticated inspect + one exclusive private metadata-only receipt (no roff).
Neither command executes clients, reads QCOW2, imports new manuals or approves semantics.
The original full roff remains in R14 only; R35 writes no original source bytes.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import p8_r31_manual_windows as r31
import p8_r31_private_manual_windows as private31
import p8_r33_human_adjudication as r33
import p8_r33_private_review_ledger as private33
import p8_r35_source_dossiers as m
import verify_p8_cli_full_sources as v14
import verify_p8_r35_source_dossiers as v35

PATCHES = Path('/home/cicada/Development/GitHub/ardrec-patches')
DEST_DIR = PATCHES/'ARDREC_PRIVATE_R35'
DEST = DEST_DIR/'FTP_SMB_SOURCE_CANDIDATE_DOSSIERS_R35_PRIVATE.json'
SOURCE_R31 = PATCHES/'ARDREC_PRIVATE_R31'/'FTP_SMB_ROFF_WINDOWS_R31_PRIVATE.json'


def need(test,reason):
    m.need(test,'operator_'+reason)


def get_report():
    need(os.getuid()==1000 and os.geteuid()!=0,'nonroot_operator')
    need(PATCHES.is_dir() and not PATCHES.is_symlink(),'patches_directory')
    need(v35.verify()['status']=='PASS_P8_R35_PINNED_MANUAL_CANDIDATE_DOSSIERS_DENY_ALL',
         'public_contract')
    # Authenticate existing R14 capture; no original manual file or QCOW2 is opened.
    raw14=private31.read_source()
    catalog=v14.safe_read(v14.ROOT,v14.SOURCE,v14.SOURCE_SHA)
    full=r31.from_authenticated_report(raw14,catalog,v14.private_reconcile)
    source31=private33.protected_bytes(SOURCE_R31,0o700)
    need(m.sha(source31)==r33.R31_PRIVATE_SHA,'r31_private_receipt_sha')
    previous=r33.parse(source31)
    need(previous==full,'r31_recompute_exactly')
    # Authentic R32 queue, R33 fixed initial ledger and chain; no event is changed.
    ledger,events,old_state=private33.open_session()
    source32=private33.protected_bytes(private33.R32,0o700)
    queue=r33.source_queue(source32)
    need(m.sha(r33.canonical(ledger))==
         '24374563958fa3efde9046aa4286f4ada43da8638b46d8984fca822b177cf93a',
         'original_r33_ledger')
    full14=v14.parse(raw14)
    maps={}
    for row in full14['manuals']:
        if row['manual_path'] in r31.MANUALS:
            maps[row['manual_path']]=base64.b64decode(
                row['full_roff_source_b64'],validate=True)
    matrix=r33.parse(v35.MATRIX.read_bytes())
    report=m.build(maps,catalog,previous,queue,ledger,events,matrix)
    need(report['r33_latest_event_sha256']==old_state['latest_event_sha256'] and
         report['dispatch_allowed'] is False and
         report['full_clauses_certified']==0 and
         report['semantic_reviews_completed']==0 and
         len(report['candidates'])==39,'report_safety')
    need(all('roff' not in ''.join(x.keys()).lower() and
             'source_text' not in x and 'reviewer_note_private' not in x
             for x in report['candidates']),'no_original_source_bytes_exported')
    return report


def write_once(report):
    need(not DEST_DIR.exists() and not DEST_DIR.is_symlink() and
         not DEST.exists() and not DEST.is_symlink(),'r35_already_exists_no_retry')
    data=r33.canonical(report)
    need(0 < len(data) < 100000,'private_metadata_size')
    DEST_DIR.mkdir(mode=0o700)
    need(stat.S_IMODE(DEST_DIR.lstat().st_mode)==0o700,'private_dir_mode')
    fd=os.open(DEST,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
               getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent=os.open(DEST_DIR,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent)
    finally:os.close(parent)
    need(stat.S_IMODE(DEST.lstat().st_mode)==0o600,'private_file_mode')
    return m.sha(data)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','create'))
    args=parser.parse_args()
    print('========== ARDREC / P8-R35 / SOURCE-BOUND REVIEW ==========',flush=True)
    report=get_report()
    print('PASS:r14_3_original_manuals_authenticated_no_qcow2',flush=True)
    print('PASS:r31_windows_r32_queue_r33_ledger_crosschecked',flush=True)
    print('PASS:r35_39_candidates_312_public_desk_questions_denied',flush=True)
    print('R35_CANDIDATE_COUNT=39',flush=True)
    print('R35_DOCUMENTARY_DISPOSITIONS='+str(report['r33_dispositions_recorded']),flush=True)
    print('R35_FULL_CLAUSES_CERTIFIED=0',flush=True)
    if args.mode=='inspect':
        print('P8_R35_INSPECT=PASS_READ_ONLY_NO_NEW_SOURCES',flush=True)
    else:
        print('R35_PRIVATE_DOSSIER_SHA256='+write_once(report),flush=True)
        print('P8_R35_PRIVATE_CREATE=PASS_METADATA_ONLY_EXCLUSIVE',flush=True)
    print('NO_CLIENT_EXECUTION=True QCOW2_READ=False',flush=True)
    print('NO_SEMANTIC_APPROVAL=True P8_OPEN=True AL06_AL07_OPEN=True',flush=True)
    print('P9_STARTED=False A1_TO_A10_STARTED=False',flush=True)
    print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)

if __name__=='__main__':
    try: main()
    except (r33.Denied,r31.Blocked,v14.FullSourceError,ValueError,TypeError,
            KeyError,OSError) as exc:
        print('P8_R35_PRIVATE=BLOCKED_'+type(exc).__name__,flush=True)
        print('REASON='+str(exc)[:300],flush=True)
        print('DO_NOT_REPEAT_CREATE_IF_ALREADY_EXISTS=True',flush=True)
        print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)
        raise SystemExit(1)
