#!/usr/bin/env python3
"""P8-R22 public CI: pinned static contract, not private sources or guest image."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r22_loader_boundary as r22
import verify_p8_r21_multiarch_reconcile as r21check
import p8_r19_graph as g

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r22-loader-boundary-v1/spec.json'
SPEC_SHA='938d847c92f75a0561953daef579bed6f164bde5884600abe3f219e3062a04af'

def verify():
    earlier=r21check.verify()
    r22.need(earlier['status']=='PASS_P8_R21_STATIC_MULTIARCH_CANDIDATE_INTERFACE_DENY_ONLY',
             'prior_ci_contract')
    raw=SPEC.read_bytes()
    r22.need(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'spec_sha256')
    doc=json.loads(raw)
    expected={'schema_version','roadmap_step','increment','scope','base_main_commit',
              'r18_private_receipt_sha256_operator_only','r19_private_receipt_sha256_operator_only',
              'r20_private_receipt_sha256_operator_only','r21_private_receipt_sha256_operator_only',
              'image_sha256','expected_candidate_dso_nodes','expected_candidate_edges',
              'expected_search_flagged_objects','ci_reads_private_receipts',
              'private_collector_reads_qcow2','effective_loader_resolution_verified',
              'effective_configuration_verified','runtime_binary_identity_verified',
              'authorized_profiles','authorized_cases','dispatch_allowed'}
    r22.need(set(doc)==expected and doc['schema_version']=='1.0' and
             doc['roadmap_step']==8 and doc['increment']=='P8-R22' and
             doc['scope']=='OFFLINE_AUTHENTICATED_RECEIPT_ONLY_ELF_RPATH_RUNPATH_BOUNDARY_DENY_ONLY'
             and doc['base_main_commit']==r22.BASE and
             doc['r18_private_receipt_sha256_operator_only']==r22.R18_SHA and
             doc['r19_private_receipt_sha256_operator_only']==r22.R19_SHA and
             doc['r20_private_receipt_sha256_operator_only']==r22.R20_SHA and
             doc['r21_private_receipt_sha256_operator_only']==r22.R21_SHA and
             doc['image_sha256']==r22.IMAGE_SHA and
             doc['expected_candidate_dso_nodes']==sum(r22.EXPECTED_NODES) and
             doc['expected_candidate_edges']==sum(r22.EXPECTED_EDGES) and
             doc['expected_search_flagged_objects']==sum(r22.EXPECTED_FLAGS),
             'pinned_contract')
    for field in ('ci_reads_private_receipts','private_collector_reads_qcow2',
                  'effective_loader_resolution_verified','effective_configuration_verified',
                  'runtime_binary_identity_verified','dispatch_allowed'):
        r22.need(doc[field] is False,'unsafe_promotion_'+field)
    r22.need(doc['authorized_profiles']==0 and doc['authorized_cases']==0,
             'profile_authority')
    return {'status':'PASS_P8_R22_RECEIPT_ONLY_LOADER_BOUNDARY_INTERFACE_DENY_ONLY',
            'base_main_commit':r22.BASE,'candidate_nodes':sum(r22.EXPECTED_NODES),
            'candidate_edges':sum(r22.EXPECTED_EDGES),
            'search_flagged_objects':sum(r22.EXPECTED_FLAGS),
            'ci_reads_private_receipts':False,'collector_reads_qcow2':False,
            'effective_loader_resolution_verified':False,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False}

if __name__=='__main__':
    try: print(json.dumps(verify(),sort_keys=True))
    except (g.GraphError,OSError,ValueError,KeyError,TypeError) as exc:
        print('P8_R22=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
