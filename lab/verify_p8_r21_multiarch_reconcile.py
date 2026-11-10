#!/usr/bin/env python3
"""Public CI: pinned, deny-only P8-R21 interface; no guest/private receipt access."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r21_multiarch_reconcile as r21
import p8_r21_offline_collect as collector
import verify_p8_r20_samba_candidate as r20_verify
import p8_r19_graph as graph

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r21-multiarch-reconcile-v1/spec.json'
SPEC_SHA='913e84d558473ec10f0319d51a7f2d57f467cd359f1e480fa86d1dd7184d7df7'


def verify():
    old=r20_verify.verify()
    r21.need(old['status']=='PASS_P8_R20_STATIC_SAMBA_CANDIDATE_INTERFACE_DENY_ONLY',
             'r20_source_chain')
    raw=SPEC.read_bytes()
    r21.need(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'spec_sha')
    data=json.loads(raw)
    keys={'schema_version','roadmap_step','increment','scope','base_main_commit',
          'source_r19_receipt_sha256_operator_only','source_r20_receipt_sha256_operator_only',
          'image_sha256','expected_r20_missing','max_layer_names','max_new_nodes',
          'max_new_edges','max_layers','loader_resolution_verified',
          'transitive_dependency_closure_verified','runtime_identity_verified',
          'effective_configuration_verified','approved_profiles','authorized_cases','dispatch_allowed'}
    r21.need(set(data)==keys,'spec_fields')
    r21.need(data['schema_version']=='1.0' and data['roadmap_step']==8 and
             data['increment']=='P8-R21' and
             data['scope']=='OFFLINE_SEVEN_DIRECTORY_ELF_CANDIDATE_RECONCILIATION_DENY_ONLY' and
             data['base_main_commit']==collector.BASE==r21.R21_BASE and
             data['source_r19_receipt_sha256_operator_only']==r21.R19_SHA and
             data['source_r20_receipt_sha256_operator_only']==r21.R20_SHA and
             data['image_sha256']==r21.IMAGE_SHA and
             data['expected_r20_missing']==r21.EXPECTED_MISSING and
             data['max_layer_names']==r21.MAX_NAMES_PER_LAYER and
             data['max_new_nodes']==r21.MAX_NEW_NODES and
             data['max_new_edges']==r21.MAX_NEW_EDGES and
             data['max_layers']==r21.MAX_LAYERS and
             r21.SEARCH_DIRS==tuple(dict.fromkeys((*graph.LIB_DIRS,
                      '/usr/lib/x86_64-linux-gnu/samba'))), 'spec_drift')
    for field in ('loader_resolution_verified','transitive_dependency_closure_verified',
                  'runtime_identity_verified','effective_configuration_verified','dispatch_allowed'):
        r21.need(data[field] is False,'spec_promotion_'+field)
    r21.need(data['approved_profiles']==0 and data['authorized_cases']==0,
             'spec_authority')
    return {'status':'PASS_P8_R21_STATIC_MULTIARCH_CANDIDATE_INTERFACE_DENY_ONLY',
            'base_main_commit':collector.BASE,'seed_edges':8,'seed_sonames':5,
            'candidate_directories':len(r21.SEARCH_DIRS),'ci_reads_private_receipts':False,
            'ci_reads_qcow2':False,'loader_resolution_verified':False,
            'transitive_dependency_closure_verified':False,
            'approved_profiles':0,'authorized_cases':0,'dispatch_allowed':False}

if __name__=='__main__':
    try:print(json.dumps(verify(),sort_keys=True))
    except (graph.GraphError,OSError,ValueError,KeyError,TypeError) as err:
        print('P8_R21=FAIL_CLOSED:'+str(err),file=sys.stderr)
        raise SystemExit(1)
