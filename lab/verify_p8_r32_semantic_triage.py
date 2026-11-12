#!/usr/bin/env python3
"""R32 source-only CI gate; DOES NOT read R31 private receipt or certify semantics."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r32_semantic_triage as model
import p8_r31_manual_windows as r31
import verify_p8_r31_manual_windows as v31
import verify_p8_cli_full_sources as r14

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT/'lab/p8-r32-semantic-triage-v1/spec.json'
SPEC_SHA = '2ddef15bb9f9f9431d1d389725cf00519bb6cd41a555a56660e26994d272ba07'
MODEL_SHA = 'aa05bd41ff06b2455e8295153eda188bec6d7515dbf703339ccf742ff02a93d6'

def verify():
    model.need(hashlib.sha256(SPEC.read_bytes()).hexdigest()==SPEC_SHA,'spec_sha')
    model.need(hashlib.sha256((ROOT/'lab/p8_r32_semantic_triage.py').read_bytes()).hexdigest()==MODEL_SHA,'model_sha')
    spec=json.loads(SPEC.read_bytes())
    model.exact(spec,(
        'schema_version','roadmap_step','increment','base_main_commit','scope',
        'r31_private_receipt_sha256_operator_report_only', 'r31_public_spec_sha256',
        'r14_anchor_catalog_sha256','model_sha256','profiles','entries','manuals',
        'questions_per_entry','unanswered_review_questions','semantic_reviews_completed',
        'approved_cli_options','approved_argv_renderers','authorized_cases',
        'authorized_profiles','material_fields_unbound','runtime_proof_gates_unverified',
        'ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
        'source_windows_full_semantics_certified','lexical_hints_are_approvals',
        'dispatch_allowed','p8_closed','p9_started','a1_to_a10_started',
    ),'spec')
    model.need(spec['schema_version']=='1.0' and
        type(spec['roadmap_step']) is int and spec['roadmap_step']==8 and
        spec['increment']=='P8-R32' and spec['base_main_commit']==model.R32_BASE_SHA and
        spec['scope']=='PRIVATE_AUTHENTICATED_SOURCE_LINKED_HUMAN_REVIEW_QUEUE_DENY_ALL' and
        spec['r31_private_receipt_sha256_operator_report_only']==model.R31_PRIVATE_SHA and
        spec['r31_public_spec_sha256']=='508f8934fa1629b87a7285c035f032a08ea874442f8a23e4044d32d99cff3d59' and
        spec['r14_anchor_catalog_sha256']==model.R14_ANCHOR_SHA and
        spec['model_sha256']==MODEL_SHA and
        all(type(spec[x]) is int and spec[x]==n for x,n in (
            ('profiles',21),('entries',39),('manuals',3),('questions_per_entry',8),
            ('unanswered_review_questions',312),('semantic_reviews_completed',0),
            ('approved_cli_options',0),('approved_argv_renderers',0),
            ('authorized_cases',0),('authorized_profiles',0),
            ('material_fields_unbound',348),('runtime_proof_gates_unverified',261))),
        'p8_r32_invariants')
    for name in ('ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
                 'source_windows_full_semantics_certified','lexical_hints_are_approvals',
                 'dispatch_allowed','p8_closed','p9_started','a1_to_a10_started'):
        model.need(spec[name] is False,'no_promotion_'+name)
    model.need(v31.verify()['status']=='PASS_P8_R31_39_REAL_SOURCE_ANCHORS_READY_FOR_PRIVATE_EXTRACTION',
               'r31_verified_source_index')
    model.need(r31.R14_FULL_SHA==model.R14_FULL_SHA and
               r31.R14_ANCHOR_SHA==model.R14_ANCHOR_SHA and
               r31.MAIN_SHA==model.R31_BASE_SHA,'r31_identity')
    anchors=r31.catalog(r14.safe_read(ROOT,r14.SOURCE,r14.SOURCE_SHA))
    model.need(len(anchors)==39 and len(set(a['term_id'] for a in anchors))==39,
               'source_39_anchors')
    return {'status':'PASS_P8_R32_39_SOURCE_BOUND_HUMAN_REVIEW_ROWS_DENY_ALL',
            'source_anchors':39,'questions_per_entry':8,'unanswered_questions':312,
            'private_report_read':False,'semantic_reviews_completed':0,
            'approved_cli_options':0,'authorized_cases':0,'dispatch_allowed':False}

if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True))
        print('P8_R32_PUBLIC_VERIFY=PASS_DOCUMENTARY_REVIEW_QUEUE_NO_APPROVAL')
    except (model.Denied,ValueError,TypeError,KeyError,OSError) as exc:
        print('P8_R32_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc)[:280],file=sys.stderr)
        raise SystemExit(1)
