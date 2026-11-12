#!/usr/bin/env python3
"""R35 public CI source-only gate; NO private roff, Qcow2, clients or receipts."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r31_manual_windows as r31
import p8_r33_human_adjudication as r33
import p8_r35_source_dossiers as m
import verify_p8_cli_full_sources as v14
import verify_p8_r34_review_navigation as v34

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r35-source-dossiers-v1/spec.json'
MATRIX=ROOT/'lab/p8-r35-source-dossiers-v1/developer_matrix.json'
MODEL=ROOT/'lab/p8_r35_source_dossiers.py'
OPERATOR=ROOT/'lab/p8_r35_private_source_dossiers.py'
SPEC_SHA='1d2dd9cbe5f2ee2c38b1be864a9a025e990fa5027c27783fd9b9e83dc30e5087'
MODEL_SHA='b1574ac4d2d56621f2e502addfd1c08e07082867c115b599eeafb97d9420dec8'
MATRIX_SHA='ad448795cbc01bbdd31644879ce2444c57c13c6c78920a06d803958415d9a453'
OPERATOR_SHA='1072bd860ae4be65f33e086557c494ac9b3c98f7829eae92494ad0c89b600a88'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify():
    r33.need(sha(SPEC.read_bytes())==SPEC_SHA,'r35_spec_sha')
    r33.need(sha(MODEL.read_bytes())==MODEL_SHA,'r35_model_sha')
    r33.need(sha(MATRIX.read_bytes())==MATRIX_SHA,'r35_matrix_sha')
    r33.need(sha(OPERATOR.read_bytes())==OPERATOR_SHA,'r35_operator_sha')
    spec=r33.parse(SPEC.read_bytes())
    expected_keys={
        'schema_version','roadmap_step','increment','base_main_sha','scope',
        'r14_private_report_sha256','r31_private_receipt_sha256','r32_private_receipt_sha256',
        'r33_initial_ledger_sha256','developer_matrix_sha256','r35_model_sha256',
        'private_operator_code_sha256','source_term_count','original_manual_count',
        'initial_question_count','max_candidate_lines','max_candidate_bytes',
        'material_fields_unbound','runtime_proof_gates_unverified','write_variants_cleanup_unproven',
        'profiles_blocked','full_clauses_certified','semantic_reviews_completed',
        'approved_cli_options','approved_argv_renderers','authorized_cases','authorized_profiles',
        'dispatch_allowed','public_ci_reads_private_receipts','public_ci_reads_qcow2',
        'public_ci_executes_clients','private_operator_reads_preexisting_original_source',
        'private_operator_reads_qcow2','private_operator_writes_existing_receipts',
        'private_operator_may_create_exclusive_metadata_receipt','full_clause_claim_allowed',
        'developer_hypotheses_are_authoritative','p8_closed','p9_started','a1_to_a10_started',
    }
    r33.exact(spec,expected_keys,'r35_spec')
    r33.need(spec['schema_version']=='1.0' and spec['roadmap_step']==8 and
             spec['increment']=='P8-R35' and spec['base_main_sha']==m.BASE and
             spec['scope']=='SOURCE_PINNED_PRIVATE_CLAUSE_CANDIDATE_METADATA_AND_PUBLIC_DEVELOPER_DESK_MATRIX_DENY_ALL' and
             spec['r14_private_report_sha256']==r31.R14_FULL_SHA and
             spec['r31_private_receipt_sha256']==r33.R31_PRIVATE_SHA and
             spec['r32_private_receipt_sha256']==r33.R32_PRIVATE_SHA and
             spec['r33_initial_ledger_sha256']==
                 '24374563958fa3efde9046aa4286f4ada43da8638b46d8984fca822b177cf93a' and
             spec['developer_matrix_sha256']==MATRIX_SHA and
             spec['r35_model_sha256']==MODEL_SHA and
             spec['private_operator_code_sha256']==OPERATOR_SHA,
             'r35_source_identities')
    counts={
        'source_term_count':39,'original_manual_count':3,'initial_question_count':312,
        'max_candidate_lines':120,'max_candidate_bytes':20000,
        'material_fields_unbound':348,'runtime_proof_gates_unverified':261,
        'write_variants_cleanup_unproven':5,'profiles_blocked':29,
        'full_clauses_certified':0,'semantic_reviews_completed':0,
        'approved_cli_options':0,'approved_argv_renderers':0,
        'authorized_cases':0,'authorized_profiles':0,
    }
    for field,value in counts.items():
        r33.need(type(spec[field]) is int and spec[field]==value,'r35_count_'+field)
    for field in (
        'dispatch_allowed','public_ci_reads_private_receipts','public_ci_reads_qcow2',
        'public_ci_executes_clients','private_operator_reads_qcow2',
        'private_operator_writes_existing_receipts','full_clause_claim_allowed',
        'developer_hypotheses_are_authoritative','p8_closed','p9_started','a1_to_a10_started',
    ):
        r33.need(spec[field] is False,'r35_denial_'+field)
    r33.need(spec['private_operator_reads_preexisting_original_source'] is True and
             spec['private_operator_may_create_exclusive_metadata_receipt'] is True,
             'r35_private_operator_scope')
    r33.need(v34.verify()['status']=='PASS_P8_R34_SOURCE_BOUND_READ_ONLY_NAVIGATION_DENY_ALL',
             'r34_upstream_gate')
    anchors=v14.safe_read(v14.ROOT,v14.SOURCE,v14.SOURCE_SHA)
    names=r31.catalog(anchors)
    matrix=r33.parse(MATRIX.read_bytes())
    review=m.validate_matrix(matrix,names)
    r33.need(len(review)==39 and len(r33.QUESTIONS)==8 and
             set(review)=={x['term_id'] for x in names},'r35_312_public_review_items')
    return {
       'status':'PASS_P8_R35_PINNED_MANUAL_CANDIDATE_DOSSIERS_DENY_ALL',
       'source_entries':39,'question_items':312,
       'private_original_sources_read_in_ci':False,
       'developer_observations_carry_authority':False,
       'semantic_reviews_completed':0,'authorized_cases':0,'dispatch_allowed':False,
    }

if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True),flush=True)
        print('P8_R35_PUBLIC_VERIFY=PASS_SOURCE_BOUND_CANDIDATES_DENY_ALL',flush=True)
    except (r33.Denied,r31.Blocked,v14.FullSourceError,
            KeyError,TypeError,ValueError,OSError) as exc:
        print('P8_R35_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc)[:300],file=sys.stderr,flush=True)
        raise SystemExit(1)
