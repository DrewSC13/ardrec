#!/usr/bin/env python3
"""P8-R19 CI: public, deterministic source pins; never access private QCOW2."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r19_graph as g
import p8_r19_offline_collect as coll
import verify_p8_material_inventory as r9
import verify_p8_r18_elf_metadata as r18

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r19-offline-graph-v1/spec.json'
SPEC_SHA='4eba9d09eec081804e7e18395bf615b3bd6afc0f8e24943af0332d00a5a098e8'

def verify():
    a=r9.verify_repository()
    b=r18.verify()
    g.need(a['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL','r9_baseline')
    g.need(b['status']=='PASS_P8_R18_STATIC_OFFLINE_ELF_INTERFACE_DENY_ONLY','r18_baseline')
    raw=SPEC.read_bytes()
    g.need(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'spec_sha')
    s=json.loads(raw)
    expected_keys={'schema_version','roadmap_step','increment','scope','base_main_commit',
                   'image_sha256','r18_private_receipt_sha256_operator_only',
                   'root_candidates','expected_r18_direct_needed_counts',
                   'max_nodes','max_edges','max_depth','loader_resolution_verified',
                   'transitive_dependency_closure_verified','runtime_identity_verified',
                   'approved_profiles','authorized_cases','dispatch_allowed'}
    g.need(set(s)==expected_keys,'spec_fields')
    g.need(s['schema_version']=='1.0' and s['roadmap_step']==8 and
           s['increment']=='P8-R19' and s['scope']=='READ_ONLY_OFFLINE_ELF_CANDIDATE_GRAPH_NOT_LOADER_PROOF' and
           s['base_main_commit']==coll.BASE and
           s['image_sha256']==r9.IMAGE_SHA and
           s['r18_private_receipt_sha256_operator_only']==coll.R18_SHA and
           s['root_candidates']==list(coll.ROOTS) and
           s['expected_r18_direct_needed_counts']==[5,3,23] and
           s['max_nodes']==g.MAX_GRAPH_NODES and s['max_edges']==g.MAX_GRAPH_EDGES and
           s['max_depth']==g.MAX_GRAPH_DEPTH and
           s['loader_resolution_verified'] is False and
           s['transitive_dependency_closure_verified'] is False and
           s['runtime_identity_verified'] is False and
           s['approved_profiles']==0 and s['authorized_cases']==0 and
           s['dispatch_allowed'] is False,'spec_promotion_or_drift')
    return {'status':'PASS_P8_R19_STATIC_ELF_GRAPH_INTERFACE_DENY_ONLY',
            'base_main_commit':coll.BASE, 'candidate_binaries':3,
            'ci_access_to_private_image':False,'loader_resolution_verified':False,
            'transitive_dependency_closure_verified':False,
            'authorized_cases':0,'approved_profiles':0,'dispatch_allowed':False}

if __name__=='__main__':
    try: print(json.dumps(verify(),sort_keys=True))
    except (g.GraphError,OSError,ValueError,KeyError,TypeError) as err:
        print('P8_R19=FAIL_CLOSED:'+str(err),file=sys.stderr)
        raise SystemExit(1)
