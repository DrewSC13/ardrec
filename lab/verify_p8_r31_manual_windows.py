#!/usr/bin/env python3
"""Public CI R31: verify exact source anchors and deny-only extraction rules.

The seven original manual roff bodies and derived 39 contexts remain ONLY in the
operator's private R14/R31 receipts; this public verifier does not read them.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import p8_r31_manual_windows as model
import verify_p8_cli_full_sources as r14
import verify_p8_r29_typed_declaration as v29
import verify_p8_r30_synthetic_acceptance as v30

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r31-manual-windows-v1/spec.json'
SPEC_SHA='508f8934fa1629b87a7285c035f032a08ea874442f8a23e4044d32d99cff3d59'
MODEL_SHA='2049b311f0af0a36377fe2440c1e6333a8b3fdae2f5dd397454433ebb1f3eb70'


def verify():
    model.require(hashlib.sha256(SPEC.read_bytes()).hexdigest()==SPEC_SHA, 'spec_sha')
    model.require(hashlib.sha256((ROOT/'lab/p8_r31_manual_windows.py').read_bytes()).hexdigest()==MODEL_SHA, 'model_sha')
    spec=json.loads(SPEC.read_bytes())
    model.require(type(spec) is dict and spec['schema_version']=='1.0' and
        spec['scope']=='AUTHENTICATED_PREVIOUSLY_CAPTURED_MANUAL_WINDOWS_PRIVATE_AND_DENY_ONLY' and
        spec['increment']=='P8-R31' and spec['roadmap_step']==8 and
        spec['base_main_commit']==model.MAIN_SHA and spec['model_sha256']==MODEL_SHA and
        spec['r14_private_report_sha256']==model.R14_FULL_SHA and
        spec['r14_anchor_catalog_sha256']==model.R14_ANCHOR_SHA and
        spec['r14_anchor_git_blob']=='db694a770e004e0079829e47066cb86124ffd6c4' and
        spec['profile_count']==21 and spec['unique_documentary_entry_count']==39 and
        spec['manual_count']==3 and spec['context_window_lines']==model.WINDOW_LINES and
        spec['protocol_counts']=={'FTP':10,'SMB':11} and
        spec['material_fields_unbound']==348 and spec['unverified_proof_gates']==261,
        'spec_identity')
    for flag in ('r30_proof_runtime','ci_reads_private_receipts','ci_reads_qcow2',
                 'ci_executes_clients','dispatch_allowed','p8_closed','p9_started',
                 'a1_to_a10_started'):
        model.require(spec[flag] is False,'no_authority:'+flag)
    for flag in ('synthetic_oracles_only','private_context_available_only_after_local_source_authentication'):
        model.require(spec[flag] is True,'no_promotion:'+flag)
    for field in ('semantic_reviews_completed','approved_cli_options','approved_argv_renderers',
                  'authorized_profiles','authorized_cases'):
        model.require(type(spec[field]) is int and spec[field]==0,'no_numeric_promotion:'+field)
    a=r14.safe_read(ROOT,r14.SOURCE,r14.SOURCE_SHA)
    r14_review=r14.verify_repository()
    model.require(r14_review['complete_semantic_reviews']==0 and
                  r14_review['approved_cli_options']==0, 'r14_not_promoted')
    model.require(v29.verify()['dispatch_allowed'] is False and
                  v30.verify()['status']=='PASS_P8_R30_21_SYNTHETIC_ORACLES_DENY_ONLY',
                  'inherited_contracts')
    rows=model.catalog(a)
    model.require(len(rows)==39 and len({x['term_id'] for x in rows})==39, '39_entries')
    return {'status':'PASS_P8_R31_39_REAL_SOURCE_ANCHORS_READY_FOR_PRIVATE_EXTRACTION',
            'profiles':21,'terms':39,'manuals':3,
            'material_proof_of_runtime':False,'private_sources_read_in_ci':False,
            'approved_cli_options':0,'approved_profiles':0,
            'authorized_cases':0,'dispatch_allowed':False,
            'p8_closed':False,'p9_started':False,'a1_to_a10_started':False}


if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True))
        print('P8_R31_PUBLIC_VERIFY=PASS_39_SOURCE_ANCHORS_NOT_APPROVED')
    except (model.Blocked,r14.FullSourceError,ValueError,TypeError,KeyError,OSError) as error:
        print('P8_R31_PUBLIC_VERIFY=FAIL_CLOSED:'+str(error)[:280],file=sys.stderr)
        raise SystemExit(1)
