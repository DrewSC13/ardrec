#!/usr/bin/env python3
"""Public P8-R23 CI contract; public sources only, no runtime, receipts or guest."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r23_profile_obligations as gate
import verify_p8_r22_loader_boundary as r22
import verify_p8_material_inventory as r9

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r23-profile-obligations-v1/spec.json'
SPEC_SHA='4ff8fb35b69ee204f316a56fb40a62fe6c192295f5a33a9626bdceef8d10300b'


def verify():
    upstream=r22.verify()
    gate.need(upstream['status']=='PASS_P8_R22_RECEIPT_ONLY_LOADER_BOUNDARY_INTERFACE_DENY_ONLY',
              'r22_predecessor')
    src=r9.verify_repository()
    gate.need(src['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
              'r9_public_source')
    raw=SPEC.read_bytes()
    gate.need(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'public_spec_sha')
    spec=json.loads(raw)
    exact={'schema_version','roadmap_step','increment','scope','base_main_commit',
           'r22_private_receipt_sha256_operator_only','r9_image_sha256',
           'expected_families','expected_profiles','expected_protocol_distribution',
           'expected_unbound_material_fields','expected_writing_variants',
           'ci_reads_private_receipts','private_audit_reads_qcow2',
           'actual_cli_capability_verified','runtime_binary_identity_verified',
           'effective_configuration_verified','approved_profiles','authorized_cases',
           'dispatch_allowed'}
    gate.need(type(spec) is dict and set(spec)==exact and
              spec['schema_version']=='1.0' and spec['roadmap_step']==8 and
              spec['increment']=='P8-R23' and
              spec['scope']=='PINNED_PUBLIC_PROFILE_MATERIAL_OBLIGATION_LEDGER_DENY_ONLY'
              and spec['base_main_commit']==gate.BASE and
              spec['r22_private_receipt_sha256_operator_only']==gate.R22_SHA and
              spec['r9_image_sha256']==gate.IMAGE_SHA and
              spec['expected_families']==25 and spec['expected_profiles']==29 and
              spec['expected_protocol_distribution']==gate.COUNTS and
              spec['expected_unbound_material_fields']==348 and
              spec['expected_writing_variants']==5,'public_spec_contract')
    for key in ('ci_reads_private_receipts','private_audit_reads_qcow2',
                'actual_cli_capability_verified','runtime_binary_identity_verified',
                'effective_configuration_verified','dispatch_allowed'):
        gate.need(spec[key] is False,'public_spec_unsafe_'+key)
    gate.need(spec['approved_profiles']==0 and spec['authorized_cases']==0,
              'public_spec_authority')
    profiles=r9.read(ROOT,r9.P8_PATH,digest=r9.P8_SHA)
    compat=r9.read(ROOT,r9.CMP_PATH)
    inventory=r9.read(ROOT,r9.INV_PATH)
    catalog=r9.read(ROOT,r9.P7_PATH,digest=r9.P7_SHA)
    rows=gate.profile_rows(profiles,compat,inventory,catalog)
    summary=gate.summarize(rows)
    gate.need(summary['unbound_material_fields']==348 and
              summary['writing_variants_with_independent_cleanup_pending']==5 and
              summary['candidate_profiles']==29 and
              summary['authorized_profiles']==0 and
              summary['dispatch_allowed'] is False,'derived_profile_summary')
    gate.need(gate.deny_request(rows,'SSH-T01-BASE')['decision']=='DENY' and
              gate.deny_request(rows,'NOT-A-PROFILE')['decision']=='DENY',
              'deny_only_invariant')
    return {**summary,'ci_reads_private_receipts':False,
            'private_audit_reads_qcow2':False}


if __name__=='__main__':
    try:print(json.dumps(verify(),sort_keys=True))
    except (gate.GateError,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R23=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
