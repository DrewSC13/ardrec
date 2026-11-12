#!/usr/bin/env python3
"""P8-R34. Pure, conservative review navigation over R33 validated evidence.

Never reads files, invokes clients or network, renders commands, writes decisions,
certifies semantic completeness, or upgrades operational authority.
"""
from __future__ import annotations
from collections import Counter
import hashlib

import p8_r33_human_adjudication as r33

BASE_SHA = 'c9113291d08034934cca86373c8ea5f221323c46'
R33_LEDGER_INITIAL_SHA = '24374563958fa3efde9046aa4286f4ada43da8638b46d8984fca822b177cf93a'
STATES = ('UNTRIAGED', 'DOCUMENTARY_DISPOSITION_RECORDED_NOT_APPROVAL')


def need(value, reason):
    r33.need(value, 'r34_' + reason)


def review_index(queue, ledger, events):
    """Pure validation of authenticated R32->R33 chain, with no note disclosure.

    Queue must be previously authenticated from pinned private R32 bytes. In
    production the private operator adaptor enforces that authentication.
    """
    r33.exact(queue, r33.QUEUE_KEYS, 'r34_source_queue')
    need(queue['schema_version'] == '1.0' and
         queue['scope'] == 'P8_R32_PRIVATE_SEMANTIC_REVIEW_QUEUE_NO_SEMANTIC_VERDICTS' and
         queue['source_main_sha'] == r33.R32_BASE_SHA and
         queue['r31_private_receipt_sha256'] == r33.R31_PRIVATE_SHA and
         queue['source_excerpt_bytes_copied'] is False, 'queue_identity')
    expected = r33.new_ledger(queue)
    need(ledger == expected and r33.canonical(ledger) == r33.canonical(expected),
         'exact_source_ledger')
    state = r33.validate_journal(ledger, events)
    rows = queue['review_rows']
    need(type(rows) is list and len(rows) == 39, 'source_rows_count')
    seen = set()
    decisions = {}
    for event in events:
        key = (event['term_id'], event['question_id'])
        need(key not in decisions, 'duplicate_documentary_question')
        decisions[key] = event['disposition']
    entries=[]
    for row, ledger_item in zip(rows, ledger['review_items']):
        term=row['term_id']
        need(type(term) is str and term not in seen, 'duplicate_or_invalid_term')
        seen.add(term)
        need(ledger_item['term_id'] == term and
             ledger_item['source_context_sha256'] == row['context_sha256'],
             'source_context_binding')
        need(row['context_status'] == 'BOUNDED_ROFF_WINDOW_NOT_COMPLETE_SEMANTIC_CLAUSE' and
             row['attention'] in ('ELEVATED_REVIEW_PRIORITY_ONLY',
                                  'STANDARD_REVIEW_PRIORITY_ONLY'),
             'no_clause_completeness')
        r33.exact(row['review_questions'], r33.QUESTIONS, 'r34_question_set')
        need(all(row['review_questions'][q] == r33.UNANSWERED for q in r33.QUESTIONS),
             'no_r32_answers')
        states = {q: (STATES[1] if (term,q) in decisions else STATES[0])
                  for q in r33.QUESTIONS}
        entries.append({
            'term_id':term,
            'manual_id':term.split(':',1)[0],
            'source_window_start_1based':row['source_line_start_1based'],
            'source_window_end_1based':row['source_line_end_1based'],
            'source_context_sha256':row['context_sha256'],
            'priority':row['attention'],
            'question_states':states,
            'untriaged_count':sum(s == STATES[0] for s in states.values()),
            'recorded_count':sum(s == STATES[1] for s in states.values()),
            'full_clause_certified':False,
            'semantic_review_completed':False,
            'operational_approval':False,
        })
    need(len(entries) == 39 and sum(e['recorded_count'] for e in entries)
         == state['dispositions_recorded'] and
         sum(e['untriaged_count'] for e in entries)
         == state['questions_still_untriaged'], 'count_reconciliation')
    need(state['semantic_reviews_completed'] == 0 and
         state['approved_cli_options'] == 0 and
         state['authorized_cases'] == 0 and
         state['dispatch_allowed'] is False, 'deny_only')
    by_question=Counter()
    for e in entries:
        for q,s in e['question_states'].items():
            if s == STATES[0]: by_question[q]+=1
    result={
        'source_terms':39,
        'questions_total':312,
        'documentary_dispositions_recorded':state['dispositions_recorded'],
        'questions_untriaged':state['questions_still_untriaged'],
        'questions_untriaged_by_kind':{q:by_question[q] for q in r33.QUESTIONS},
        'source_windows_are_complete_clauses':False,
        'semantic_reviews_completed':0,
        'approved_cli_options':0,
        'authorized_cases':0,
        'dispatch_allowed':False,
        'latest_r33_event_sha256':state['latest_event_sha256'],
        'entries':entries,
    }
    need(0 <= result['questions_untriaged'] <= 312 and
         result['questions_untriaged'] + result['documentary_dispositions_recorded'] == 312,
         'total_questions')
    return result


def one_term(index, term):
    """Select an authenticated term, never exposing note/disposition/excerpt."""
    need(type(index) is dict and type(term) is str and
         type(index.get('entries')) is list and len(index['entries'])==39,
         'focus_shape')
    candidates=[e for e in index['entries'] if e['term_id']==term]
    need(len(candidates)==1,'unknown_or_ambiguous_term')
    return candidates[0]


def page(index, offset=0, limit=5):
    """Bounded local navigation; source order unchanged, no assertions of safety."""
    need(type(index) is dict and type(index.get('entries')) is list and
         len(index['entries'])==39, 'page_index')
    need(type(offset) is int and 0 <= offset < 39 and
         type(limit) is int and 1 <= limit <= 10, 'page_bounds')
    return tuple(index['entries'][offset:offset+limit])
