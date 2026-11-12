#!/usr/bin/env python3
"""P8-R33: authenticated human adjudication ledger, never operational approval.

Pure Python; no filesystem, subprocess, network, CLI arguments or shell command
execution. Decisions are private HUMAN documentary dispositions, not verified
semantics, true operational capability, or authority to run test clients.
"""
from __future__ import annotations
import hashlib
import json
import re

R32_PRIVATE_SHA = '1ec74427c6b2f51aece27aeecae4f446a686afa3c73a68ce68c5e89ce36b9532'
R31_PRIVATE_SHA = '8f26fb577e2f744b2f7a67d0aaf8970f427a9f749fdd530996f26cea44d99542'
R32_BASE_SHA = '3a236a74da1b88f1e9485e3a6de82064592a04fa'
R33_BASE_SHA = '43b7d26652a44026d559cc9db7d161bb0374e96e'
MAX_QUEUE_SIZE = 450000
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
TERM = re.compile(r'(?:curl|smbclient|rpcclient)\.1\.gz:(?:--[a-z0-9-]+|[a-z][a-z0-9-]*)\Z', re.ASCII)
QUESTIONS = (
    'SCOPE_AND_OPERATION_SEMANTICS',
    'INPUT_ARGUMENT_SYNTAX_AND_PRECEDENCE',
    'DEFAULTS_ENVIRONMENT_AND_CONFIG_IMPORT',
    'AUTHENTICATION_AND_SECRET_HANDLING',
    'TLS_SIGNING_ENCRYPTION_AND_DOWNGRADE',
    'NETWORK_SIDE_EFFECTS_AND_REMOTE_COMMANDS',
    'DATA_READ_WRITE_DELETE_AND_ROLLBACK',
    'BOUNDS_ERRORS_AND_EXTERNAL_PROOF_NEEDED',
)
DISPOSITIONS = (
    'REQUIRES_COMPLETE_CLAUSE',
    'EXCLUDED_BY_POLICY',
    'DOCUMENTARY_ONLY_UNVERIFIED',
)
UNANSWERED = 'UNANSWERED_NEEDS_HUMAN_REVIEW'
EVENT_KEYS = (
    'schema_version','increment','sequence','previous_event_sha256',
    'source_r32_receipt_sha256','term_id','question_id','disposition',
    'reviewer_note_private','source_context_sha256','semantic_review_completed',
    'approved_cli_option','argv_renderable','capability_proven','dispatch_allowed',
)
LEDGER_KEYS = (
    'schema_version','increment','scope','base_main_sha',
    'source_r32_receipt_sha256','source_r31_receipt_sha256',
    'source_terms','questions_per_term','unanswered_review_questions',
    'review_items','semantic_reviews_completed','approved_cli_options',
    'approved_argv_renderers','authorized_profiles','authorized_cases',
    'material_fields_unbound','runtime_proof_gates_unverified',
    'dispatch_allowed','p8_closed','p9_started','a1_to_a10_started',
)
QUEUE_KEYS = (
    'schema_version','scope','source_main_sha','r31_private_receipt_sha256',
    'source_excerpt_bytes_copied','profiles','source_terms','questions_per_term',
    'unanswered_review_questions','priority_totals',
    'lexical_signal_counts_not_authority','review_rows',
    'semantic_reviews_completed','approved_cli_options','approved_argv_renderers',
    'material_fields_unbound','runtime_proof_gates_unverified',
    'authorized_cases','authorized_profiles','dispatch_allowed',
    'p8_closed','p9_started','a1_to_a10_started',
)
ROW_KEYS = (
    'term_id','manual_path','profile_refs','source_line_start_1based',
    'source_line_end_1based','context_sha256','context_line_count',
    'context_status','lexical_signals_only_not_conclusions','attention',
    'review_questions','semantic_review_completed','approved_cli_option',
    'argv_renderable','capability_proven',
)
class Denied(ValueError):
    pass

def need(value, reason):
    if not value:
        raise Denied('P8_R33_DENY:'+reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(obj):
    return (json.dumps(obj,sort_keys=True,ensure_ascii=False,separators=(',',':'))+'\n').encode('utf-8')

def exact(obj, keys, label):
    need(type(obj) is dict and set(obj) == set(keys),'exact_fields_'+label)

def parse(raw):
    def pairs_unique(pairs):
        d={}
        for k,v in pairs:
            need(k not in d,'duplicate_json_key')
            d[k]=v
        return d
    def invalid_constant(_):
        raise Denied('P8_R33_DENY:invalid_json_constant')
    need(type(raw) is bytes and 0 < len(raw) <= MAX_QUEUE_SIZE,'json_size')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs_unique,
                      parse_constant=invalid_constant)

def source_queue(raw, expected_sha=R32_PRIVATE_SHA):
    """Verify pinned R32 bytes. expected_sha is pinned in operator mode."""
    need(type(expected_sha) is str and expected_sha == R32_PRIVATE_SHA,'expected_queue_pin')
    need(type(raw) is bytes and 0 < len(raw) <= MAX_QUEUE_SIZE and
         sha(raw)==expected_sha,'r32_receipt_sha')
    doc=parse(raw)
    exact(doc,QUEUE_KEYS,'r32_queue')
    need(doc['schema_version']=='1.0' and
         doc['scope']=='P8_R32_PRIVATE_SEMANTIC_REVIEW_QUEUE_NO_SEMANTIC_VERDICTS' and
         doc['source_main_sha']==R32_BASE_SHA and
         doc['r31_private_receipt_sha256']==R31_PRIVATE_SHA and
         doc['source_excerpt_bytes_copied'] is False,'r32_identity')
    for k,n in (('profiles',21),('source_terms',39),('questions_per_term',8),
                ('unanswered_review_questions',312),('semantic_reviews_completed',0),
                ('approved_cli_options',0),('approved_argv_renderers',0),
                ('material_fields_unbound',348),('runtime_proof_gates_unverified',261),
                ('authorized_cases',0),('authorized_profiles',0)):
        need(type(doc[k]) is int and doc[k]==n,'r32_constant_'+k)
    for k in ('dispatch_allowed','p8_closed','p9_started','a1_to_a10_started'):
        need(doc[k] is False,'r32_no_authority_'+k)
    need(type(doc['priority_totals']) is dict and
         type(doc['lexical_signal_counts_not_authority']) is dict,'r32_hints_shape')
    rows=doc['review_rows']
    need(type(rows) is list and len(rows)==39,'r32_rows')
    terms=set()
    for i,row in enumerate(rows):
        exact(row,ROW_KEYS,'r32_row_'+str(i))
        term=row['term_id']
        need(type(term) is str and TERM.fullmatch(term) and term not in terms,'r32_term_id')
        terms.add(term)
        need(type(row['manual_path']) is str and
             row['manual_path'].endswith(term.split(':',1)[0]) and
             type(row['profile_refs']) is list and len(row['profile_refs'])>0 and
             all(type(p) is str and p.startswith(('FTP-','SMB-')) for p in row['profile_refs']),
             'r32_binding')
        need(type(row['context_sha256']) is str and HEX.fullmatch(row['context_sha256']) and
             type(row['context_line_count']) is int and 1 <= row['context_line_count'] <= 24 and
             type(row['source_line_start_1based']) is int and row['source_line_start_1based']>0 and
             type(row['source_line_end_1based']) is int and
             row['source_line_end_1based']==row['source_line_start_1based']+row['context_line_count']-1,
             'r32_context_bounds')
        need(row['context_status']=='BOUNDED_ROFF_WINDOW_NOT_COMPLETE_SEMANTIC_CLAUSE' and
             row['attention'] in ('ELEVATED_REVIEW_PRIORITY_ONLY','STANDARD_REVIEW_PRIORITY_ONLY') and
             type(row['lexical_signals_only_not_conclusions']) is list,
             'r32_no_claim_of_completeness')
        exact(row['review_questions'],QUESTIONS,'r32_questions')
        need(all(row['review_questions'][q]==UNANSWERED for q in QUESTIONS),'r32_questions_unanswered')
        for flag in ('semantic_review_completed','approved_cli_option',
                     'argv_renderable','capability_proven'):
            need(row[flag] is False,'r32_row_denial_'+flag)
    return doc

def new_ledger(queue):
    """Only immutable source IDs and question map; never excerpt bytes or approvals."""
    exact(queue,QUEUE_KEYS,'queue_for_ledger')
    items=[{'term_id':row['term_id'],'source_context_sha256':row['context_sha256']}
           for row in queue['review_rows']]
    need(len(items)==39 and len({x['term_id'] for x in items})==39,'ledger_39_unique')
    out={
        'schema_version':'1.0',
        'increment':'P8-R33',
        'scope':'PRIVATE_APPEND_ONLY_HUMAN_DOCUMENTARY_DISPOSITIONS_DENY_ALL',
        'base_main_sha':R33_BASE_SHA,
        'source_r32_receipt_sha256':R32_PRIVATE_SHA,
        'source_r31_receipt_sha256':R31_PRIVATE_SHA,
        'source_terms':39,
        'questions_per_term':8,
        'unanswered_review_questions':312,
        'review_items':items,
        'semantic_reviews_completed':0,
        'approved_cli_options':0,
        'approved_argv_renderers':0,
        'authorized_profiles':0,
        'authorized_cases':0,
        'material_fields_unbound':348,
        'runtime_proof_gates_unverified':261,
        'dispatch_allowed':False,
        'p8_closed':False,
        'p9_started':False,
        'a1_to_a10_started':False,
    }
    validate_ledger(out)
    return out

def validate_ledger(ledger):
    exact(ledger,LEDGER_KEYS,'ledger')
    need(ledger['schema_version']=='1.0' and ledger['increment']=='P8-R33' and
         ledger['scope']=='PRIVATE_APPEND_ONLY_HUMAN_DOCUMENTARY_DISPOSITIONS_DENY_ALL' and
         ledger['base_main_sha']==R33_BASE_SHA and
         ledger['source_r32_receipt_sha256']==R32_PRIVATE_SHA and
         ledger['source_r31_receipt_sha256']==R31_PRIVATE_SHA,'ledger_identity')
    for k,n in (('source_terms',39),('questions_per_term',8),('unanswered_review_questions',312),
                ('semantic_reviews_completed',0),('approved_cli_options',0),
                ('approved_argv_renderers',0),('authorized_profiles',0),('authorized_cases',0),
                ('material_fields_unbound',348),('runtime_proof_gates_unverified',261)):
        need(type(ledger[k]) is int and ledger[k]==n,'ledger_constant_'+k)
    for k in ('dispatch_allowed','p8_closed','p9_started','a1_to_a10_started'):
        need(ledger[k] is False,'ledger_denial_'+k)
    items=ledger['review_items']
    need(type(items) is list and len(items)==39,'ledger_items_count')
    seen=set()
    for item in items:
        exact(item,('term_id','source_context_sha256'),'ledger_item')
        term=item['term_id']
        need(type(term) is str and TERM.fullmatch(term) and term not in seen,'ledger_item_id')
        seen.add(term)
        need(type(item['source_context_sha256']) is str and HEX.fullmatch(item['source_context_sha256']),
             'ledger_item_context_sha')
    return {x['term_id']:x['source_context_sha256'] for x in items}

def validate_note(note):
    need(type(note) is str and 20 <= len(note) <= 512 and note.strip()==note,
         'private_note_length_or_whitespace')
    need(all(ord(c)>=32 and ord(c)!=127 for c in note),'private_note_control_character')

def validate_journal(ledger, events):
    index=validate_ledger(ledger)
    need(type(events) in (list,tuple) and len(events)<=312,'journal_events_count')
    previous=sha(canonical(ledger))
    used=set()
    for number,event in enumerate(events,1):
        exact(event,EVENT_KEYS,'journal_event')
        need(event['schema_version']=='1.0' and event['increment']=='P8-R33' and
             type(event['sequence']) is int and event['sequence']==number and
             event['previous_event_sha256']==previous and
             event['source_r32_receipt_sha256']==R32_PRIVATE_SHA,
             'journal_sequence_chain')
        term=event['term_id']
        question=event['question_id']
        need(type(term) is str and term in index and
             type(question) is str and question in QUESTIONS and
             (term,question) not in used,'journal_question_identity')
        used.add((term,question))
        need(event['source_context_sha256']==index[term] and
             event['disposition'] in DISPOSITIONS,'journal_source_or_disposition')
        validate_note(event['reviewer_note_private'])
        for flag in ('semantic_review_completed','approved_cli_option','argv_renderable',
                     'capability_proven','dispatch_allowed'):
            need(event[flag] is False,'journal_no_authority_'+flag)
        previous=sha(canonical(event))
    return {'dispositions_recorded':len(events),'questions_still_untriaged':312-len(events),
            'semantic_reviews_completed':0,'approved_cli_options':0,
            'authorized_cases':0,'dispatch_allowed':False,
            'latest_event_sha256':previous}

def make_event(ledger, events, term, question, disposition, note):
    state=validate_journal(ledger,events)
    index=validate_ledger(ledger)
    need(type(term) is str and term in index,'unknown_term')
    need(type(question) is str and question in QUESTIONS,'unknown_question')
    need(type(disposition) is str and disposition in DISPOSITIONS,'unsupported_disposition')
    need(not any(x['term_id']==term and x['question_id']==question for x in events),'already_triaged')
    validate_note(note)
    event={
        'schema_version':'1.0','increment':'P8-R33','sequence':len(events)+1,
        'previous_event_sha256':state['latest_event_sha256'],
        'source_r32_receipt_sha256':R32_PRIVATE_SHA,
        'term_id':term,'question_id':question,'disposition':disposition,
        'reviewer_note_private':note,
        'source_context_sha256':index[term],
        'semantic_review_completed':False,'approved_cli_option':False,
        'argv_renderable':False,'capability_proven':False,'dispatch_allowed':False,
    }
    validate_journal(ledger,[*events,event])
    return event
