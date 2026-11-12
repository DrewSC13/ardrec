#!/usr/bin/env python3
"""P8-R29: public CI verifier of bounded typed symbolic design, DENY only.

Does not read private receipts, image, SSH configs, passwords or contact services.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r29_typed_declaration as model
import verify_p8_r17_material_closure as v17
import verify_p8_r23_profile_obligations as v23
import verify_p8_r24_capability_proof_boundary as v24
import verify_p8_r26_ssh_include_graph as v26

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r29-typed-intents-v1/spec.json'
SPEC_SHA='c626c080fd772fcf500c54d53b00a05076b81dd16642f4563efd70c0b09d0ed1'
MODEL_SHA='564a5dbedf60cd9d1d9ffb5186a08d09067089d1d034701d5e69cb7d40a921cc'


def verify() -> dict:
    model.must(hashlib.sha256(SPEC.read_bytes()).hexdigest()==SPEC_SHA,'spec_sha256')
    model.must(hashlib.sha256((ROOT/'lab/p8_r29_typed_declaration.py').read_bytes()).hexdigest()==MODEL_SHA,
               'source_module_sha256')
    spec=json.loads(SPEC.read_bytes())
    model.must(type(spec) is dict and set(spec)=={
         'schema_version','roadmap_step','increment','base_main_commit','scope',
         'source_pins','model_module_sha256','profiles','protocol_counts',
         'write_variants','documentary_gate_links','documentary_risk_links',
         'unbound_material_fields','unverified_runtime_gates',
         'r27_private_receipt_sha256_operator_report_only',
         'r28_private_report_sha256_operator_report_only',
         'r27_source_bound_graph_is_not_effective_configuration',
         'ci_reads_private_receipts','ci_reads_qcow2','ci_spawns_clients',
         'argv_renderable','approved_profiles','authorized_cases','dispatch_allowed',
         'p8_closed','p9_started','a1_to_a10_started'},'spec_keys')
    model.must(spec['schema_version']=='1.0' and spec['roadmap_step']==8 and
         spec['increment']=='P8-R29' and spec['base_main_commit']==
         '45203db865f407fef5b57594a4b9ce740783c32d' and
         spec['scope']=='SOURCE_ONLY_TYPED_SYMBOLIC_DECLARATION_VALIDATOR_DENY_ALL' and
         spec['source_pins']==model.PINS and
         spec['model_module_sha256']==MODEL_SHA and
         spec['profiles']==29 and spec['protocol_counts']==model.PROTO_COUNTS and
         spec['write_variants']==5 and spec['documentary_gate_links']==271 and
         spec['documentary_risk_links']==238 and
         spec['unbound_material_fields']==348 and
         spec['unverified_runtime_gates']==261 and
         spec['r27_private_receipt_sha256_operator_report_only']==
         '71fbb3cadcbfb303ad5ce299ef9c2416c7cbec2242d938280ed65c112956ab93' and
         spec['r28_private_report_sha256_operator_report_only']==
         '381f20d35a0bc3863775a41df785bd9ef4a2c66eb851066c3e82de92cca8b22b',
         'spec_identity')
    model.must(spec['r27_source_bound_graph_is_not_effective_configuration'] is True,
               'r27_source_graph_not_effective_configuration')
    for key in ('ci_reads_private_receipts','ci_reads_qcow2','ci_spawns_clients',
                'argv_renderable','dispatch_allowed','p8_closed','p9_started',
                'a1_to_a10_started'):
        model.must(spec[key] is False,'spec_scope_'+key)
    model.must(type(spec['approved_profiles']) is int and spec['approved_profiles']==0 and
         type(spec['authorized_cases']) is int and spec['authorized_cases']==0,
         'spec_authority')
    r17=v17.verify(ROOT,deep=True)
    r23=v23.verify()
    r24=v24.verify()
    r26=v26.verify()
    model.must(r17['status']=='PASS_DENY_ONLY_29_PROFILE_MATERIAL_GAPS' and
         r17['missing_material_bindings']==348 and r17['open_evidence_gate_links']==271 and
         r17['risk_profile_links']==238 and r17['dispatch_allowed'] is False,
         'r17_inherited_contract')
    model.must(r23['status']=='PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY' and
         r23['unbound_material_fields']==348 and r23['authorized_profiles']==0,
         'r23_inherited_contract')
    model.must(r24['status']=='PASS_P8_R24_PROOF_SUFFICIENCY_BOUNDARY_DENY_ONLY' and
         r24['unverified_gate_instances']==261 and r24['dispatch_allowed'] is False,
         'r24_inherited_contract')
    model.must(r26['status']=='PASS_P8_R26_SYNTHETIC_INCLUDE_GRAPH_DENY_ALL' and
         r26['dispatch_allowed'] is False,'r26_inherited_contract')
    rows,summ=model.verify_repository(ROOT)
    for r in rows:
        request={key:r[key] for key in model.REQUEST_KEYS}
        res=model.review_declaration(rows,request)
        model.must(res['decision']=='DENY' and res['argv'] is None and
             res['dispatch_allowed'] is False and res['spawn'] is False,
             'declaration_authorization:'+r['profile_id'])
    model.must(summ['status']=='PASS_P8_R29_29_TYPED_SYMBOLIC_DESIGNS_DENY_ONLY'
         and summ['material_bindings_unbound']==348 and
         summ['runtime_proof_gate_instances_unverified']==261 and
         summ['documentary_gate_links']==271 and summ['documentary_risk_links']==238 and
         summ['approved_profiles']==0 and summ['dispatch_allowed'] is False,
         'derived_summary')
    return {**summ,'scope':'PUBLIC_SOURCE_ONLY_NO_GUEST_ACCESS',
            'r27_receipt_used_as_private_anchor_only':True,
            'r27_private_receipt_read_in_ci':False,
            'r28_private_report_read_in_ci':False}


if __name__=='__main__':
    try:
        print(json.dumps(verify(),sort_keys=True))
        print('P8_R29_PUBLIC_VERIFY=PASS_DESIGN_ONLY_DENY_ALL')
    except (model.Denied,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R29_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
