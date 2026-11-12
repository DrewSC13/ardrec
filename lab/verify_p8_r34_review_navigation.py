#!/usr/bin/env python3
"""R34 public CI gate: pins source-only read-only navigation, no private reads."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r33_human_adjudication as r33
import p8_r34_review_navigation as m
import verify_p8_r33_human_adjudication as v33

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r34-review-navigation-v1/spec.json'
MODEL=ROOT/'lab/p8_r34_review_navigation.py'
SPEC_SHA='e02896920844f31baa650050163b712c1d946c2d585b5ec04add9fb75cdbc16b'
MODEL_SHA='2700a0c6a5079081950af4de35623f6ab4ad6d3e639b0d3cae705230d2e040f0'
KEYS=(
 'schema_version','roadmap_step','increment','base_main_commit','scope',
 'r32_private_receipt_sha256_operator_only','r33_initial_ledger_sha256_operator_only',
 'r33_model_sha256','r33_public_spec_sha256','r34_model_sha256',
 'source_terms','questions_per_term','initial_questions','profiles',
 'material_fields_unbound','runtime_proof_gates_unverified',
 'write_variants_cleanup_unproven','semantic_reviews_completed',
 'approved_cli_options','approved_argv_renderers','authorized_profiles','authorized_cases',
 'ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
 'private_operator_reads_existing_receipts','private_operator_writes_anything',
 'source_windows_full_clauses_certified','documentary_dispositions_are_semantic_approvals',
 'dispatch_allowed','p8_closed','p9_started','a1_to_a10_started',
)

def verify():
    r33.need(hashlib.sha256(SPEC.read_bytes()).hexdigest()==SPEC_SHA,'r34_spec_sha')
    r33.need(hashlib.sha256(MODEL.read_bytes()).hexdigest()==MODEL_SHA,'r34_model_sha')
    spec=r33.parse(SPEC.read_bytes())
    r33.exact(spec,KEYS,'r34_spec')
    r33.need(spec['schema_version']=='1.0' and
             type(spec['roadmap_step']) is int and spec['roadmap_step']==8 and
             spec['increment']=='P8-R34' and spec['base_main_commit']==m.BASE_SHA and
             spec['scope']=='PRIVATE_READ_ONLY_SOURCE_BOUND_DOCUMENTARY_REVIEW_NAVIGATION_DENY_ALL' and
             spec['r32_private_receipt_sha256_operator_only']==r33.R32_PRIVATE_SHA and
             spec['r33_initial_ledger_sha256_operator_only']==m.R33_LEDGER_INITIAL_SHA and
             spec['r33_model_sha256']=='b91d0cc0573c011c354ffc71c39c51bdb8d4bf5713fdb384dd92aaba99a50ede' and
             spec['r33_public_spec_sha256']=='cd01cc48c881b05681b723ed413ec4f7ffadbb914c248c1f3394dd7fc77826d7' and
             spec['r34_model_sha256']==MODEL_SHA,'r34_identity')
    for field,expected in (('source_terms',39),('questions_per_term',8),
                            ('initial_questions',312),('profiles',21),
                            ('material_fields_unbound',348),('runtime_proof_gates_unverified',261),
                            ('write_variants_cleanup_unproven',5),('semantic_reviews_completed',0),
                            ('approved_cli_options',0),('approved_argv_renderers',0),
                            ('authorized_profiles',0),('authorized_cases',0)):
        r33.need(type(spec[field]) is int and spec[field]==expected,'r34_count_'+field)
    for field in ('ci_reads_private_receipts','ci_reads_qcow2','ci_executes_clients',
                  'private_operator_writes_anything','source_windows_full_clauses_certified',
                  'documentary_dispositions_are_semantic_approvals','dispatch_allowed',
                  'p8_closed','p9_started','a1_to_a10_started'):
        r33.need(spec[field] is False,'r34_denial_'+field)
    r33.need(spec['private_operator_reads_existing_receipts'] is True and
             len(r33.QUESTIONS)==8 and len(m.STATES)==2,
             'r34_read_only_contract')
    r33.need(v33.verify()['status']=='PASS_P8_R33_HUMAN_DOCUMENTARY_ADJUDICATION_DENY_ALL',
             'r33_upstream_source_gate')
    return {
        'status':'PASS_P8_R34_SOURCE_BOUND_READ_ONLY_NAVIGATION_DENY_ALL',
        'source_terms':39,'initial_untriaged_questions':312,
        'real_private_data_read_in_ci':False,'human_decisions_created_in_ci':0,
        'semantic_reviews_completed':0,'authorized_cases':0,'dispatch_allowed':False,
    }

if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True),flush=True)
        print('P8_R34_PUBLIC_VERIFY=PASS_READ_ONLY_NAVIGATION_DENY_ALL',flush=True)
    except (r33.Denied,KeyError,TypeError,ValueError,OSError) as exc:
        print('P8_R34_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc)[:260],file=sys.stderr,flush=True)
        raise SystemExit(1)
