#!/usr/bin/env python3
"""R34 private, read-only review navigation. No writer, TTY notes, or clients.

summary: aggregate counts only; list: IDs and counts; focus: one authenticated
term and its eight unanswered/recorded labels. Never prints original roff,
private human notes, dispositions, credentials, argv or full source excerpts.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys

import p8_r33_human_adjudication as r33
import p8_r33_private_review_ledger as operator33
import p8_r34_review_navigation as m
import verify_p8_r34_review_navigation as verifier


def run():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('summary','list','focus'))
    parser.add_argument('--term', default=None)
    parser.add_argument('--offset', type=int, default=0)
    parser.add_argument('--limit', type=int, default=5)
    args=parser.parse_args()
    print('========== ARDREC / P8-R34 / PRIVATE READ-ONLY NAVIGATION ==========', flush=True)
    r33.need(os.getuid()==1000 and os.geteuid()!=0,'r34_operator_nonroot')
    r33.need(verifier.verify()['status']=='PASS_P8_R34_SOURCE_BOUND_READ_ONLY_NAVIGATION_DENY_ALL',
             'r34_public_contract')
    r33.need(args.mode != 'focus' or args.term is not None, 'r34_focus_requires_term')
    r33.need(args.mode == 'focus' or args.term is None, 'r34_unexpected_term')
    r33.need(args.mode == 'list' or (args.offset == 0 and args.limit == 5),
             'r34_unexpected_paging')
    # Use the exact R33 private reader: it authenticates R32, the R33 ledger,
    # 0700/0600 path permissions, contiguous canonical events and SHA chain.
    ledger, events, journal = operator33.open_session()
    raw=operator33.protected_bytes(operator33.R32,0o700)
    queue=r33.source_queue(raw)
    index=m.review_index(queue,ledger,events)
    r33.need(index['latest_r33_event_sha256']==journal['latest_event_sha256'],
             'r34_journal_changed')
    r33.need(r33.sha(r33.canonical(ledger)) == m.R33_LEDGER_INITIAL_SHA,
             'r34_pinned_initial_ledger')
    print('PASS:r32_receipt_and_r33_private_event_chain_authenticated', flush=True)
    print('R34_SOURCE_TERMS=39', flush=True)
    print('R34_DOCUMENTARY_DISPOSITIONS='+str(index['documentary_dispositions_recorded']),flush=True)
    print('R34_QUESTIONS_UNTRIAGED='+str(index['questions_untriaged']), flush=True)
    print('R34_LATEST_R33_EVENT_SHA256='+index['latest_r33_event_sha256'], flush=True)
    if args.mode=='summary':
        for q,count in index['questions_untriaged_by_kind'].items():
            print('UNTRIAGED_'+q+'='+str(count),flush=True)
    elif args.mode=='list':
        for row in m.page(index,args.offset,args.limit):
            print('TERM_ID='+row['term_id']+' UNTRIAGED='+str(row['untriaged_count'])+
                  ' PRIORITY='+row['priority'],flush=True)
    else:
        row=m.one_term(index,args.term)
        print('TERM_ID='+row['term_id'],flush=True)
        print('SOURCE_MANUAL_ID='+row['manual_id'],flush=True)
        print('SOURCE_WINDOW_LINES='+str(row['source_window_start_1based'])+'-'+
              str(row['source_window_end_1based']),flush=True)
        print('SOURCE_WINDOW_SHA256='+row['source_context_sha256'],flush=True)
        print('SOURCE_WINDOW_IS_COMPLETE_CLAUSE=False',flush=True)
        for q,value in row['question_states'].items():
            print('QUESTION='+q+' STATUS='+value,flush=True)
    print('R34_PRIVATE_NAVIGATION=PASS_READ_ONLY_NO_DISPOSITIONS_WRITTEN',flush=True)
    print('NO_SEMANTIC_APPROVAL=True NO_CLIENT_EXECUTION=True QCOW2_READ=False',flush=True)
    print('P8_OPEN=True AL06_AL07_OPEN=True P9_STARTED=False A1_TO_A10_STARTED=False',flush=True)
    print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)


if __name__=='__main__':
    try:run()
    except (r33.Denied,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R34_PRIVATE=BLOCKED_'+type(exc).__name__,flush=True)
        print('REASON='+str(exc)[:280],flush=True)
        print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)
        raise SystemExit(1)
