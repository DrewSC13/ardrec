#!/usr/bin/env python3
"""R35 pure source-bound documentary candidate dossiers, NEVER semantic approval.

Consumes already-authenticated, previously captured roff; emits ONLY metadata and
public developer desk hypotheses. Structural candidate ranges are NOT full clauses.
No files, sockets, clients, subprocesses or side effects in this model.
"""
from __future__ import annotations
import base64
import hashlib
import re

import p8_r31_manual_windows as r31
import p8_r33_human_adjudication as r33

BASE = 'f0c7ad3feee1315dd9a47ec09763280ce3d564b2'
MATRIX_SHA = 'ad448795cbc01bbdd31644879ce2444c57c13c6c78920a06d803958415d9a453'
MAX_CANDIDATE_LINES = 120
MAX_CANDIDATE_BYTES = 20000
REVIEW_STATUS = 'PENDING_PINNED_SOURCE_AND_PROFILE_EVIDENCE'
SOURCE_STATUS = 'ANCHOR_BOUNDED_CANDIDATE_NOT_COMPLETE_CLAUSE'


def need(test, name):
    r33.need(test, 'r35_' + name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_matrix(matrix, anchors):
    need(type(matrix) is dict and set(matrix) == {
        'allowed_dispatch_count','audit_status','base_main_sha','basis',
        'documentary_semantics_approved','entries','local_runtime_proofs_count',
        'official_sources','question_count','source_term_count','title'
    }, 'matrix_schema')
    need(matrix['audit_status']=='PRELIMINARY_SOURCE_DESK_REVIEW_NOT_R33_HUMAN_RECORD' and
         matrix['base_main_sha']==BASE and
         matrix['allowed_dispatch_count']==0 and
         matrix['documentary_semantics_approved']==0 and
         matrix['local_runtime_proofs_count']==0 and
         matrix['question_count']==312 and matrix['source_term_count']==39,
         'matrix_no_authority')
    need(type(matrix['basis']) is str and len(matrix['basis'])>20 and
         type(matrix['title']) is str and len(matrix['title'])>12 and
         matrix['official_sources']==[
             'https://curl.se/docs/manpage.html',
             'https://www.samba.org/samba/docs/current/man-html/smbclient.1.html',
             'https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html'],
         'matrix_public_context_only')
    expected={x['term_id'] for x in anchors}
    entries=matrix['entries']
    need(type(entries) is list and len(entries)==39,'matrix_39')
    seen=set()
    for entry in entries:
        need(type(entry) is dict and set(entry)=={
            'category','cli_approved','developer_observation_public_docs_only',
            'local_binary_capability_proven','next_evidence_needed',
            'operational_authorization','questions','term_id','term_semantic_certified'
        },'matrix_entry_fields')
        term=entry['term_id']
        need(type(term) is str and term in expected and term not in seen,'matrix_term')
        seen.add(term)
        need(type(entry['category']) is str and
             re.fullmatch('[A-Z_]{4,50}',entry['category']) is not None and
             type(entry['developer_observation_public_docs_only']) is str and
             len(entry['developer_observation_public_docs_only'])>=16 and
             type(entry['next_evidence_needed']) is str and len(entry['next_evidence_needed'])>=16,
             'matrix_descriptions')
        for key in ('cli_approved','local_binary_capability_proven','operational_authorization',
                    'term_semantic_certified'):
            need(entry[key] is False,'matrix_not_approved_'+key)
        questions=entry['questions']
        need(type(questions) is list and len(questions)==8 and
             [x.get('question_id') for x in questions if type(x) is dict]
             ==list(r33.QUESTIONS),'matrix_questions_order')
        for q in questions:
            need(type(q) is dict and set(q)=={
                'question_id','evidence_requirement','review_status'
            } and q['review_status']==REVIEW_STATUS and
                 type(q['evidence_requirement']) is str and len(q['evidence_requirement'])>=12,
                 'question_not_resolved')
    need(seen==expected,'matrix_terms_exact')
    return {x['term_id']:x for x in entries}


def bounded_candidate(source, start_1based, next_anchor_1based=None):
    """A bounded navigational span, NEVER proof of a complete roff clause.

    Stops before next *known* authenticated heading or at strict line/byte
    limits; headings missing from the catalog can exist within the span.
    """
    need(type(source) is bytes and 0 < len(source) <= 300000, 'manual_bytes')
    lines=source.splitlines(keepends=True)
    need(type(start_1based) is int and 1 <= start_1based <= len(lines), 'start')
    need(next_anchor_1based is None or (
        type(next_anchor_1based) is int and
        start_1based < next_anchor_1based <= len(lines)
    ), 'next_anchor')
    n=start_1based-1
    limit=min(len(lines), n+MAX_CANDIDATE_LINES)
    if next_anchor_1based is not None:
        limit=min(limit,next_anchor_1based-1)
    need(limit>n,'empty_span')
    raw=b''
    cursor=n
    while cursor<limit and len(raw)+len(lines[cursor])<=MAX_CANDIDATE_BYTES:
        raw+=lines[cursor]
        cursor+=1
    need(cursor>n,'candidate_first_line_oversize')
    return {
        'candidate_start_line_1based':start_1based,
        'candidate_end_line_1based':cursor,
        'candidate_line_count':cursor-n,
        'candidate_sha256':sha(raw),
        'source_status':SOURCE_STATUS,
        'at_known_next_anchor_boundary':next_anchor_1based is not None and cursor==next_anchor_1based-1,
        'hit_safety_limit':cursor<limit or (limit==n+MAX_CANDIDATE_LINES),
        'full_clause_certified':False,
    }


def build(manuals, catalog, r31_report, queue, ledger, events, matrix):
    """Compute verified candidate locations; no raw roff or private notes returned."""
    anchors=r31.catalog(catalog)
    byterm=validate_matrix(matrix,anchors)
    expected_manuals=r31.MANUALS
    need(type(manuals) is dict and set(manuals)==expected_manuals,'manual_set')
    refs={x['manual_path']:x for x in catalog['source_manifests']}
    for name,content in manuals.items():
        need(type(content) is bytes and 0 < len(content) <=300000 and
             sha(content)==refs[name]['uncompressed_sha256'] and
             len(content)==refs[name]['uncompressed_bytes'], 'manual_source_pin')
    need(type(r31_report) is dict and
         r31_report.get('scope')=='P8_R31_AUTHENTICATED_PRIVATE_MANPAGE_WINDOWS_NOT_SEMANTIC_APPROVAL' and
         len(r31_report.get('source_windows',[]))==39 and
         r31_report.get('complete_semantic_reviews')==0 and
         r31_report.get('dispatch_allowed') is False,'r31_report')
    known={name:sorted({a['source_line_1based'] for a in catalog['term_anchors']
                        if a['manual_path']==name}) for name in expected_manuals}
    state=r33.validate_journal(ledger,events)
    r33.exact(queue,r33.QUEUE_KEYS,'r35_queue')
    need(queue['scope']=='P8_R32_PRIVATE_SEMANTIC_REVIEW_QUEUE_NO_SEMANTIC_VERDICTS' and
         queue['source_main_sha']==r33.R32_BASE_SHA and
         queue['r31_private_receipt_sha256']==r33.R31_PRIVATE_SHA and
         queue['source_excerpt_bytes_copied'] is False and
         all(queue[x] is False for x in
             ('dispatch_allowed','p8_closed','p9_started','a1_to_a10_started')) and
         all(type(queue[x]) is int and queue[x]==0 for x in
             ('semantic_reviews_completed','approved_cli_options','approved_argv_renderers',
              'authorized_profiles','authorized_cases')) and
         queue['unanswered_review_questions']==312 and
         r33.new_ledger(queue)==ledger and len(queue['review_rows'])==39,
         'r32_r33_link')
    index={row['term_id']:row for row in queue['review_rows']}
    need(set(index)==set(byterm),'r32_term_ids')
    r31_index={row['term_id']:row for row in r31_report['source_windows']}
    need(set(r31_index)==set(byterm),'r31_term_ids')
    out=[]
    for a in anchors:
        term=a['term_id']
        original=manuals[a['manual_path']]
        physical=original.splitlines(keepends=True)
        pos=a['source_line_1based']
        need(sha(physical[pos-1])==a['exact_roff_line_sha256'],'anchor_line_sha')
        older=r31_index[term]
        bounded=original.splitlines(keepends=True)[pos-1:pos-1+r31.WINDOW_LINES]
        old_bytes=b''.join(bounded)
        need(base64.b64decode(older['context_b64_private'],validate=True)==old_bytes and
             sha(old_bytes)==older['context_sha256'] and
             older['source_line_start_1based']==pos and
             older['manual_path']==a['manual_path'], 'r31_window_authentication')
        q=index[term]
        need(q['context_sha256']==older['context_sha256'] and
             q['source_line_start_1based']==pos,'r32_window_alignment')
        stop=next((p for p in known[a['manual_path']] if p>pos),None)
        candidate=bounded_candidate(original,pos,stop)
        e=byterm[term]
        out.append({
            'term_id':term,
            'manual_id':a['manual_path'].split('/')[-1],
            'manual_sha256':sha(original),
            'source_anchor_line_1based':pos,
            'source_anchor_sha256':a['exact_roff_line_sha256'],
            'r31_source_window_sha256':older['context_sha256'],
            **candidate,
            'developer_category':e['category'],
            'developer_observation_status':'PRELIMINARY_PUBLIC_DOCS_ONLY',
            'questions_in_scope':list(r33.QUESTIONS),
            'semantic_review_completed':False,
            'client_capability_proven':False,
            'approved_argv_renderers':0,
            'dispatch_allowed':False,
        })
    need(len(out)==39,'count')
    return {
        'schema_version':'1.0','increment':'P8-R35',
        'scope':'PINNED_ORIGINAL_MANUAL_BOUNDED_CANDIDATE_METADATA_NOT_FULL_CLAUSES',
        'base_main_sha':BASE,'source_r14_sha256':r31.R14_FULL_SHA,
        'source_r31_sha256':r33.R31_PRIVATE_SHA,
        'source_r32_sha256':r33.R32_PRIVATE_SHA,
        'source_r33_initial_ledger_sha256':sha(r33.canonical(ledger)),
        'r33_latest_event_sha256':state['latest_event_sha256'],
        'r33_dispositions_recorded':state['dispositions_recorded'],
        'question_count':312,'terms':39,'manuals':3,
        'developer_matrix_sha256':MATRIX_SHA,'candidates':out,
        'full_clauses_certified':0,'semantic_reviews_completed':0,
        'material_fields_unbound':348,'runtime_proof_gates_unverified':261,
        'write_variants_cleanup_unproven':5,
        'approved_cli_options':0,'authorized_cases':0,'dispatch_allowed':False,
        'p8_closed':False,'p9_started':False,'a1_to_a10_started':False,
    }
