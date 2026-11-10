#!/usr/bin/env python3
"""Public CI: pinned R23->R24 proof-sufficiency crosswalk; no private receipt read."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r24_capability_proof_boundary as p24
import p8_r23_profile_obligations as r23
import verify_p8_r23_profile_obligations as v23
import verify_p8_material_inventory as r9

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'lab/p8-r24-capability-proof-boundary-v1/spec.json'
SPEC_SHA='e246b87c72522e7206a4640c60238b70dbace010eaa411097a34e1140a3949d5'


def verify():
    old=v23.verify()
    p24.require(old['status']=='PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY' and
                old['profile_obligation_ledger_sha256']==p24.R23_LEDGER_SHA,
                'r23_public_digest_and_state')
    raw=SPEC.read_bytes()
    p24.require(hashlib.sha256(raw).hexdigest()==SPEC_SHA,'spec_sha256')
    spec=json.loads(raw)
    names={'schema_version','roadmap_step','increment','scope','base_main_commit',
           'r23_private_receipt_sha256_operator_only','r23_profile_ledger_sha256',
           'r22_private_receipt_sha256_operator_only','expected_profiles',
           'expected_gate_slots','expected_static_reference_slots',
           'expected_unbound_fields','expected_writing_variants',
           'private_audit_reads_qcow2','ci_reads_private_receipts','executes_guest_binaries',
           'effective_loader_resolution_verified','effective_configuration_verified',
           'operational_capability_verified','authorized_profiles','authorized_cases',
           'dispatch_allowed'}
    p24.require(type(spec) is dict and set(spec)==names and
                spec['schema_version']=='1.0' and spec['roadmap_step']==8 and
                spec['increment']=='P8-R24' and
                spec['scope']=='PINNED_PROOF_SUFFICIENCY_CROSSWALK_STATIC_REFERENCES_DENY_ONLY' and
                spec['base_main_commit']==p24.BASE and
                spec['r23_private_receipt_sha256_operator_only']==p24.R23_RECEIPT_SHA and
                spec['r23_profile_ledger_sha256']==p24.R23_LEDGER_SHA and
                spec['r22_private_receipt_sha256_operator_only']==p24.R22_RECEIPT_SHA and
                spec['expected_profiles']==29 and spec['expected_gate_slots']==261 and
                spec['expected_static_reference_slots']==58 and
                spec['expected_unbound_fields']==348 and
                spec['expected_writing_variants']==5,'spec_contract')
    for k in ('private_audit_reads_qcow2','ci_reads_private_receipts','executes_guest_binaries',
              'effective_loader_resolution_verified','effective_configuration_verified',
              'operational_capability_verified','dispatch_allowed'):
        p24.require(spec[k] is False,'unsafe_spec:'+k)
    p24.require(spec['authorized_profiles']==0 and spec['authorized_cases']==0,
                'public_authority')
    rows=r23.profile_rows(
        r9.read(ROOT,r9.P8_PATH,digest=r9.P8_SHA),
        r9.read(ROOT,r9.CMP_PATH),
        r9.read(ROOT,r9.INV_PATH),
        r9.read(ROOT,r9.P7_PATH,digest=r9.P7_SHA))
    matrix=p24.proof_matrix(rows,p24.R23_LEDGER_SHA)
    summary=p24.summarize(matrix)
    p24.require(summary['profiles']==29 and summary['unverified_gate_instances']==261 and
                summary['offline_candidate_reference_instances']==58 and
                summary['approved_profiles']==0 and
                summary['authorized_cases']==0 and
                summary['dispatch_allowed'] is False,'summary')
    for row in matrix:
        p24.require(p24.deny_profile(matrix,row['profile_id'],{'approval':True})['decision']=='DENY',
                    'authority_spoof')
    return {**summary,'ci_reads_private_receipts':False,
            'private_audit_reads_qcow2':False}


if __name__=='__main__':
    try:print(json.dumps(verify(),sort_keys=True))
    except (r23.GateError,p24.BoundaryError,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R24=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
