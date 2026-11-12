#!/usr/bin/env python3
"""R33 operator-only, offline documentary human dispositions.

Modes: inspect (read-only before creation), init (create unique private ledger),
status (read-only), record (one new, never overwritten, TTY-human decision).
No roff text is printed; notes are private and never echoed; no network, shell,
subprocess, credential handling, clients or QCOW2 interaction.
"""
from __future__ import annotations
import argparse
import getpass
import hashlib
import os
from pathlib import Path
import stat
import sys

import p8_r33_human_adjudication as m
import verify_p8_r33_human_adjudication as v33

PATCHES=Path('/home/cicada/Development/GitHub/ardrec-patches')
R32_DIR=PATCHES/'ARDREC_PRIVATE_R32'
R32=R32_DIR/'FTP_SMB_SEMANTIC_REVIEW_QUEUE_R32_PRIVATE.json'
DEST_DIR=PATCHES/'ARDREC_PRIVATE_R33'
LEDGER=DEST_DIR/'HUMAN_REVIEW_R33_LEDGER_PRIVATE.json'
EVENT_DIR=DEST_DIR/'events'


def protected_bytes(path:Path, parent_mode:int):
    m.need(path.is_file() and not path.is_symlink() and
           path.parent.is_dir() and not path.parent.is_symlink(),'private_file_path')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        st=os.fstat(fd)
        m.need(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and
               st.st_nlink==1 and 0 < st.st_size<=m.MAX_QUEUE_SIZE and
               stat.S_IMODE(path.parent.lstat().st_mode)==parent_mode,
               'private_mode_or_size')
        with os.fdopen(fd,'rb',closefd=False) as f:
            raw=f.read(m.MAX_QUEUE_SIZE+1)
        m.need(len(raw)==st.st_size,'private_file_size_race')
        return raw
    finally:
        os.close(fd)


def preflight():
    m.need(os.getuid()==1000 and os.geteuid()!=0,'nonroot_operator_required')
    m.need(PATCHES.is_dir() and not PATCHES.is_symlink(),'patches_path_invalid')
    m.need(v33.verify()['status']=='PASS_P8_R33_HUMAN_DOCUMENTARY_ADJUDICATION_DENY_ALL',
           'r33_public_contract')
    raw=protected_bytes(R32,0o700)
    queue=m.source_queue(raw)
    ledger=m.new_ledger(queue)
    m.need(m.sha(raw)==m.R32_PRIVATE_SHA,'r32_original_preserved')
    return ledger


def exclusive_write(path, raw):
    m.need(type(raw) is bytes and 0 < len(raw)<=m.MAX_QUEUE_SIZE,'exclusive_write_size')
    m.need(not path.exists() and not path.is_symlink(),'write_once_only')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False) as file:
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(fd)
    m.need(stat.S_IMODE(path.lstat().st_mode)==0o600,'new_file_private_mode')
    parent_fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(parent_fd)
    finally:os.close(parent_fd)


def init_session(ledger):
    m.need(not DEST_DIR.exists() and not DEST_DIR.is_symlink() and
           not LEDGER.exists() and not EVENT_DIR.exists(),'session_already_exists')
    DEST_DIR.mkdir(mode=0o700)
    m.need(stat.S_IMODE(DEST_DIR.stat().st_mode)==0o700,'session_directory_permissions')
    EVENT_DIR.mkdir(mode=0o700)
    m.need(stat.S_IMODE(EVENT_DIR.stat().st_mode)==0o700,'event_directory_permissions')
    raw=m.canonical(ledger)
    exclusive_write(LEDGER,raw)
    print('R33_PRIVATE_LEDGER_SHA256='+m.sha(raw),flush=True)
    print('P8_R33_PRIVATE_INIT=PASS_EXCLUSIVE_LEDGER_312_UNTRIAGED',flush=True)


def open_session():
    expected=preflight()
    m.need(DEST_DIR.is_dir() and not DEST_DIR.is_symlink() and
           stat.S_IMODE(DEST_DIR.lstat().st_mode)==0o700 and
           EVENT_DIR.is_dir() and not EVENT_DIR.is_symlink() and
           stat.S_IMODE(EVENT_DIR.lstat().st_mode)==0o700,'session_directories')
    ledger_raw=protected_bytes(LEDGER,0o700)
    ledger=m.parse(ledger_raw)
    m.need(ledger==expected and ledger_raw==m.canonical(expected),'ledger_exact_source')
    event_files=sorted(EVENT_DIR.iterdir())
    m.need(len(event_files)<=312,'too_many_events')
    events=[]
    for i,path in enumerate(event_files,1):
        m.need(path.name==f'{i:06d}.json','event_contiguous_names')
        raw=protected_bytes(path,0o700)
        event=m.parse(raw)
        m.need(raw==m.canonical(event),'event_canonical_bytes')
        events.append(event)
    summary=m.validate_journal(ledger,events)
    return ledger,events,summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','init','status','record'))
    parser.add_argument('--term',default=None)
    parser.add_argument('--question',choices=m.QUESTIONS,default=None)
    parser.add_argument('--disposition',choices=m.DISPOSITIONS,default=None)
    args=parser.parse_args()
    print('========== ARDREC / P8-R33 / HUMAN REVIEW LEDGER ==========',flush=True)
    if args.mode in ('inspect','init'):
        m.need(args.term is None and args.question is None and args.disposition is None,
               'unexpected_extra_arguments')
        ledger=preflight()
        m.need(not DEST_DIR.exists() and not DEST_DIR.is_symlink(),
               'r33_session_already_exists_do_not_repeat_init')
        print('PASS:r32_private_receipt_authenticated_39_312',flush=True)
        print('PASS:r33_append_only_human_dispositions_all_unanswered',flush=True)
        if args.mode=='inspect':
            print('P8_R33_PRIVATE_INSPECT=PASS_READ_ONLY',flush=True)
        else:
            init_session(ledger)
    else:
        ledger,events,status=open_session()
        print('R33_DISPOSITIONS_RECORDED='+str(status['dispositions_recorded']),flush=True)
        print('R33_QUESTIONS_STILL_UNTRIAGED='+str(status['questions_still_untriaged']),flush=True)
        print('R33_REVIEW_JOURNAL_SHA256='+status['latest_event_sha256'],flush=True)
        if args.mode=='status':
            m.need(args.term is None and args.question is None and args.disposition is None,
                   'status_unexpected_arguments')
            print('P8_R33_PRIVATE_STATUS=PASS_READ_ONLY',flush=True)
        else:
            m.need(args.term is not None and args.question is not None and
                   args.disposition is not None,'record_requires_exact_triplet')
            m.need(sys.stdin.isatty() and sys.stdout.isatty(),
                   'record_requires_local_interactive_terminal')
            print('AVISO=La nota se conserva solo localmente; no incluir secretos.',flush=True)
            note=getpass.getpass('Nota humana privada (20–512 caracteres; no se mostrará): ')
            event=m.make_event(ledger,events,args.term,args.question,args.disposition,note)
            filename=EVENT_DIR/f'{event["sequence"]:06d}.json'
            exclusive_write(filename,m.canonical(event))
            print('R33_RECORDED_EVENT_SHA256='+m.sha(m.canonical(event)),flush=True)
            print('P8_R33_PRIVATE_RECORD=PASS_ONE_DOCUMENTARY_DISPOSITION_ONLY',flush=True)
    print('NO_SEMANTIC_APPROVAL=True NO_CLIENT_EXECUTION=True QCOW2_READ=False',flush=True)
    print('P8_OPEN=True AL06_AL07_OPEN=True P9_STARTED=False A1_TO_A10_STARTED=False',flush=True)
    print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)

if __name__=='__main__':
    try:main()
    except (m.Denied,ValueError,TypeError,KeyError,OSError) as exc:
        print('P8_R33_PRIVATE=BLOCKED_'+type(exc).__name__,flush=True)
        print('REASON='+str(exc)[:280],flush=True)
        print('NO_AUTOMATIC_RETRY_IF_SESSION_EXISTS=True',flush=True)
        print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)
        raise SystemExit(1)
