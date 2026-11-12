#!/usr/bin/env python3
"""R33 public CI: source-pinned nonexecutable review ledger contract.

Never reads R31/R32 receipts, local human decisions, QCOW2 or client state.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r33_human_adjudication as m
import verify_p8_r32_semantic_triage as v32
import p8_r32_semantic_triage as r32

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r33-human-adjudication-v1/spec.json'
SPEC_SHA='cd01cc48c881b05681b723ed413ec4f7ffadbb914c248c1f3394dd7fc77826d7'
MODEL_SHA='b91d0cc0573c011c354ffc71c39c51bdb8d4bf5713fdb384dd92aaba99a50ede'
SPEC_KEYS=(
    'schema_version','increment','roadmap_step','base_main_commit','scope',
    'model_sha256','r32_private_receipt_sha256_operator_only',
    'r31_private_receipt_sha256_operator_only','r32_public_spec_sha256',
    'source_terms','profiles','questions_per_term','unanswered_review_questions',
    'semantic_reviews_completed','approved_cli_options','approved_argv_renderers',
    'authorized_cases','authorized_profiles','material_fields_unbound',
    'runtime_proof_gates_unverified','write_variants_cleanup_unproven',
    'ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
    'human_interaction_required','synthetic_tests_only',
    'documentary_dispositions_are_approvals','source_windows_full_semantics_certified',
    'dispatch_allowed','p8_closed','p9_started','a1_to_a10_started',
)

def verify():
    m.need(hashlib.sha256(SPEC.read_bytes()).hexdigest()==SPEC_SHA,'spec_sha')
    m.need(hashlib.sha256((ROOT/'lab/p8_r33_human_adjudication.py').read_bytes()).hexdigest()==MODEL_SHA,
           'model_sha')
    spec=json.loads(SPEC.read_bytes())
    m.exact(spec,SPEC_KEYS,'r33_spec')
    m.need(spec['schema_version']=='1.0' and
           spec['increment']=='P8-R33' and type(spec['roadmap_step']) is int and
           spec['roadmap_step']==8 and spec['base_main_commit']==m.R33_BASE_SHA and
           spec['scope']=='SOURCE_ONLY_PRIVATE_HUMAN_ADJUDICATION_APPEND_ONLY_DENY_ALL' and
           spec['model_sha256']==MODEL_SHA and
           spec['r32_private_receipt_sha256_operator_only']==m.R32_PRIVATE_SHA and
           spec['r31_private_receipt_sha256_operator_only']==m.R31_PRIVATE_SHA and
           spec['r32_public_spec_sha256']=='2ddef15bb9f9f9431d1d389725cf00519bb6cd41a555a56660e26994d272ba07',
           'spec_identity')
    for key,value in (
        ('source_terms',39),('profiles',21),('questions_per_term',8),
        ('unanswered_review_questions',312),('semantic_reviews_completed',0),
        ('approved_cli_options',0),('approved_argv_renderers',0),
        ('authorized_cases',0),('authorized_profiles',0),
        ('material_fields_unbound',348),('runtime_proof_gates_unverified',261),
        ('write_variants_cleanup_unproven',5),
    ):
        m.need(type(spec[key]) is int and spec[key]==value,'spec_constant_'+key)
    for key in ('ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
                'documentary_dispositions_are_approvals',
                'source_windows_full_semantics_certified','dispatch_allowed',
                'p8_closed','p9_started','a1_to_a10_started'):
        m.need(spec[key] is False,'no_authority_'+key)
    m.need(spec['human_interaction_required'] is True and
           spec['synthetic_tests_only'] is True,'human_required_synthetic_only')
    m.need(len(m.QUESTIONS)==8 and len(m.DISPOSITIONS)==3,'fixed_taxonomy')
    m.need(v32.verify()['status']=='PASS_P8_R32_39_SOURCE_BOUND_HUMAN_REVIEW_ROWS_DENY_ALL',
           'upstream_r32_unapproved')
    m.need(r32.R31_PRIVATE_SHA==m.R31_PRIVATE_SHA and
           r32.R32_BASE_SHA==m.R32_BASE_SHA,'r32_source_pins')
    return {
        'status':'PASS_P8_R33_HUMAN_DOCUMENTARY_ADJUDICATION_DENY_ALL',
        'source_terms':39,'questions':312,'human_dispositions_recorded_in_ci':0,
        'semantic_reviews_completed':0,'approved_cli_options':0,
        'authorized_cases':0,'dispatch_allowed':False,'private_evidence_read_in_ci':False,
        'p8_closed':False,'p9_started':False,'a1_to_a10_started':False,
    }

if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True),flush=True)
        print('P8_R33_PUBLIC_VERIFY=PASS_HUMAN_ADJUDICATION_CONTRACT_DENY_ALL',flush=True)
    except (m.Denied,ValueError,TypeError,KeyError,OSError) as exc:
        print('P8_R33_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc)[:280],file=sys.stderr,flush=True)
        raise SystemExit(1)
