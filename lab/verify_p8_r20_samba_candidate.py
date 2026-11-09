#!/usr/bin/env python3
"""P8-R20 public CI gate: pinned identity, deny-only, no local private material."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r20_samba_candidate as s
import p8_r20_offline_collect as coll
import verify_p8_r19_graph as r19
import verify_p8_material_inventory as r9

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r20-samba-candidate-v1/spec.json'
SPEC_SHA='12c50e6d3e75e7f6458ea003bcda45fd254d2d5d061612e7b29daea169ee0bf4'

def verify():
    upstream=r19.verify()
    s.need(upstream['status']=='PASS_P8_R19_STATIC_ELF_GRAPH_INTERFACE_DENY_ONLY','r19_chain')
    s.need(r9.verify_repository()['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL','r9_chain')
    data=SPEC.read_bytes()
    s.need(hashlib.sha256(data).hexdigest()==SPEC_SHA,'spec_hash')
    obj=json.loads(data)
    s.need(set(obj)=={'schema_version','increment','scope','base_main_commit',
                        'r19_private_receipt_sha256_operator_only','image_sha256',
                        'samba_candidate_directory','expected_r19_observation','bounds',
                        'effective_loader_resolution_verified','runtime_dependency_closure_verified',
                        'authorized_profiles','authorized_cases','dispatch_allowed'},'spec_fields')
    s.need(obj['schema_version']=='1.0' and obj['increment']=='P8-R20' and
           obj['scope']=='SAMBA_MULTIARCH_PRIVATE_DSO_CANDIDATE_SEARCH_ONLY' and
           obj['base_main_commit']==coll.BASE and
           obj['image_sha256']==r9.IMAGE_SHA and
           obj['r19_private_receipt_sha256_operator_only']==coll.R19_SHA and
           obj['samba_candidate_directory']==s.SAMBA_DIR and
           obj['expected_r19_observation']=={'libraries':68,'edges':292,'unresolved':67,'ambiguous':0} and
           obj['bounds']=={'max_probe_names':s.MAX_PROBE_NAMES,'max_new_libraries':s.MAX_NEW_LIBRARIES,
                           'max_added_edges':s.MAX_ADDED_EDGES,'max_layers':s.MAX_LAYERS},'source_drift')
    s.need(obj['effective_loader_resolution_verified'] is False and
           obj['runtime_dependency_closure_verified'] is False and
           obj['authorized_profiles']==0 and obj['authorized_cases']==0 and
           obj['dispatch_allowed'] is False,'authorization_promotion')
    return {'status':'PASS_P8_R20_STATIC_SAMBA_CANDIDATE_INTERFACE_DENY_ONLY',
            'base_main_commit':coll.BASE,'private_image_in_ci':False,
            'allowed_candidate_directory':s.SAMBA_DIR,
            'expected_r19_unresolved_edges':67,'loader_semantics_verified':False,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False}

if __name__=='__main__':
    try:print(json.dumps(verify(),sort_keys=True))
    except (s.g.GraphError,ValueError,OSError,KeyError,TypeError) as exc:
        print('P8_R20=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
