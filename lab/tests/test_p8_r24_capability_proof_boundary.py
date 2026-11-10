#!/usr/bin/env python3
"""P8-R24 adversarial synthetic tests; never run SSH/FTP/SMB or read private files."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r23_profile_obligations as p23
import p8_r24_capability_proof_boundary as p24
from test_p8_r23_profile_obligations import fixture


def rows():
    return p23.profile_rows(*fixture())


def matrix():
    r=rows()
    return p24.proof_matrix(r,p23.summarize(r)['profile_obligation_ledger_sha256'])


def claim(m,pid='SSH-T01-BASE',gate='actual_binary_identity'):
    row=next(r for r in m if r['profile_id']==pid)
    return {'profile_id':pid,'gate_id':gate,
            'claim_kind':'PINNED_SOURCE_REFERENCE','origin':p24.ORIGINS[gate],
            'source_sha256':(row['candidate_image_sha256'] if gate=='actual_binary_identity'
                             else p24.R22_RECEIPT_SHA),
            'asserted_status':'CANDIDATE_ONLY'}


def fake_receipt():
    r=rows()
    s=p23.summarize(r)
    return {'schema_version':'1.0',
            'scope':'P8_R23_PUBLISHED_OBLIGATIONS_PRIVATE_NOT_AUTHORITY',
            'base_main_commit':p23.BASE,'image_sha256':p23.IMAGE_SHA,
            'r22_private_receipt_sha256':p24.R22_RECEIPT_SHA,
            'source':'R9_PUBLIC_CANDIDATE_BINARY_P8_UNBOUND_PROFILE_MATRIX',
            'profile_ledger':r,'summary':s,
            'r22_boundary':{'r22_candidate_nodes':138,'r22_candidate_edges':906,
                            'r22_search_flagged_objects':66,
                            'r22_effective_loader_resolution_verified':False},
            'qcow2_accessed':False,'guest_binaries_executed':False,
            'runtime_loader_executed':False,'capability_tested':False,
            'effective_configuration_verified':False,'runtime_binary_identity_verified':False,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False}


class SuccessfulDeniedCases(unittest.TestCase):
    def setUp(self):self.m=matrix()
    def test_matrix_profiles(self):self.assertEqual(len(self.m),29)
    def test_matrix_gates(self):self.assertEqual(sum(len(r['gates']) for r in self.m),261)
    def test_static_reference_count(self):self.assertEqual(p24.summarize(self.m)['offline_candidate_reference_instances'],58)
    def test_sha_stability(self):self.assertEqual(p24.summarize(self.m)['matrix_sha256'],p24.summarize(copy.deepcopy(self.m))['matrix_sha256'])
    def test_sources_are_not_runtime(self):
        for r in self.m:
            for g in r['gates']:
                with self.subTest(r=r['profile_id'],g=g['gate_id']):
                    self.assertFalse(g['gate_closed'])
                    self.assertFalse(g['operational_capability_verified'])
                    self.assertTrue(g['requires_future_material_or_case_evidence'])
    def test_preconditions_unknown(self):
        self.assertEqual(p24.deny_profile(self.m,'UNKNOWN')['reason'],'NO_PROFILE_MATCH')
    def test_per_profile_deny(self):
        for r in self.m:
            with self.subTest(pid=r['profile_id']):
                d=p24.deny_profile(self.m,r['profile_id'],{'approved':True})
                self.assertFalse(d['dispatch_allowed']);self.assertEqual(d['decision'],'DENY')
    def test_valid_offline_primary_candidate(self):
        for row in self.m:
            result=p24.inspect_claim(self.m,claim(self.m,row['profile_id']))
            self.assertEqual(result['decision'],'DENY')
            self.assertFalse(result['evidence_admitted_as_runtime_proof'])
    def test_valid_offline_loader_reference(self):
        for row in self.m:
            result=p24.inspect_claim(self.m,claim(self.m,row['profile_id'],'effective_loader_and_environment'))
            self.assertTrue(result['reference_recognized']);self.assertFalse(result['spawn'])
    def test_write_cleanup_not_assumed(self):
        ids={r['profile_id'] for r in self.m if r['write_cleanup_pending']}
        self.assertEqual(ids,p24.WRITE)
    def test_nonwrite_cleanup_is_not_asserted(self):
        for row in self.m:
            g=row['gates'][-1]
            self.assertTrue(g['conditional_on_mutation']);self.assertFalse(g['gate_closed'])
            self.assertEqual(g['mutation_variant_declared'],row['write_cleanup_pending'])
    def test_expected_gates(self):self.assertEqual(len(p24.EXPECTED_GATES),9)
    def test_no_material_binding(self):
        for row in self.m:self.assertEqual(len(row['pending_binding_fields']),12)
    def test_no_runtime_claim(self):
        for row in self.m:
            self.assertFalse(row['dispatch_allowed']);self.assertFalse(row['approved'])
    def test_summary_deny(self):
        s=p24.summarize(self.m)
        self.assertEqual(s['authorized_cases'],0)
        self.assertFalse(s['effective_loader_resolution_verified'])
    def test_origin_pairing(self):
        for row in self.m:
            a,b=row['gates'][:2]
            self.assertEqual(a['offline_reference_origin'],p24.ORIGINS[a['gate_id']])
            self.assertEqual(b['offline_reference_origin'],p24.ORIGINS[b['gate_id']])
    def test_unknown_proof_requests_denied(self):
        self.assertFalse(p24.deny_profile(self.m,'FTP-T04-BASE',{'isolation':True,'claims':{'auth':True}})['spawn'])


class PoisonedGateCases(unittest.TestCase):
    def setUp(self):self.m=matrix()
    def reject(self,change):
        clone=copy.deepcopy(self.m);change(clone)
        with self.assertRaises(p24.BoundaryError):p24.summarize(clone)


def create_poisoned_test(change):
    def run(self):self.reject(change)
    return run

# 30 independent malformed invariants, all must fail closed.
POISON_CASES={
 'unknown_id':lambda m:m[0].update(profile_id='SSH-T99-BASE'),
 'reordered':lambda m:m.reverse(),
 'duplicate':lambda m:m.__setitem__(1,m[0]),
 'extra_row':lambda m:m.append(copy.deepcopy(m[0])),
 'missing_row':lambda m:m.pop(),
 'candidate_path':lambda m:m[0].update(candidate_binary='/usr/bin/bash'),
 'candidate_sha':lambda m:m[0].update(candidate_image_sha256='notasha'),
 'candidate_protocol':lambda m:m[0].update(protocol='ftp'),
 'candidate_family':lambda m:m[0].update(family_id='SMB-T01'),
 'binding_field_removed':lambda m:m[0]['pending_binding_fields'].pop(),
 'binding_field_added':lambda m:m[0]['pending_binding_fields'].append('secret_key'),
 'writes_undetected':lambda m:m[6].update(write_cleanup_pending=False),
 'reads_pretend_write':lambda m:m[0].update(write_cleanup_pending=True),
 'approved':lambda m:m[0].update(approved=True),
 'authorized_cases':lambda m:m[0].update(authorized_cases=1),
 'dispatch':lambda m:m[0].update(dispatch_allowed=True),
 'status_escalation':lambda m:m[0].update(status='APPROVED'),
 'missing_gates':lambda m:m[0]['gates'].pop(),
 'duplicated_gate':lambda m:m[0]['gates'].__setitem__(1,m[0]['gates'][0]),
 'gate_reorder':lambda m:m[0]['gates'].reverse(),
 'gate_approval':lambda m:m[0]['gates'][0].update(authority_verified=True),
 'gate_verified':lambda m:m[0]['gates'][0].update(proof_verified=True),
 'gate_operational':lambda m:m[0]['gates'][0].update(operational_capability_verified=True),
 'gate_closed':lambda m:m[0]['gates'][0].update(gate_closed=True),
 'gate_status':lambda m:m[0]['gates'][0].update(status='VERIFIED'),
 'static_ref_missing':lambda m:m[0]['gates'][0].update(offline_reference_available=False),
 'static_origin_forged':lambda m:m[0]['gates'][0].update(offline_reference_origin='RUNTIME'),
 'runtime_ref_forged':lambda m:m[0]['gates'][2].update(offline_reference_available=True),
 'future_evidence_false':lambda m:m[0]['gates'][2].update(requires_future_material_or_case_evidence=False),
 'wrong_required_class':lambda m:m[0]['gates'][2].update(required_proof_class='STATIC_PROOF'),
 'conditional_spoof':lambda m:m[0]['gates'][-1].update(conditional_on_mutation=False),
 'cleanup_spoof':lambda m:m[6]['gates'][-1].update(mutation_variant_declared=False),
 'extra_gate_key':lambda m:m[0]['gates'][0].update(approval_token='fake'),
 'extra_row_key':lambda m:m[0].update(runtime_path='/usr/bin/ssh'),
}
for name,fn in POISON_CASES.items():
    setattr(PoisonedGateCases,'test_reject_'+name,create_poisoned_test(fn))


class PoisonedClaims(unittest.TestCase):
    def setUp(self):self.m=matrix()
    def reject(self,change):
        c=claim(self.m);change(c)
        with self.assertRaises(p24.BoundaryError):p24.inspect_claim(self.m,c)


def create_bad_claim(change):
    def run(self):self.reject(change)
    return run

BAD_CLAIMS={
 'missing_id':lambda c:c.pop('profile_id'),
 'unknown_id':lambda c:c.update(profile_id='SSH-T99-BASE'),
 'null_id':lambda c:c.update(profile_id=None),
 'huge_id':lambda c:c.update(profile_id='SSH'*100),
 'wrong_gate':lambda c:c.update(gate_id='client_option_capability'),
 'unknown_gate':lambda c:c.update(gate_id='runtime_shell'),
 'wrong_origin':lambda c:c.update(origin='RUNTIME_VERIFIED'),
 'wrong_kind':lambda c:c.update(claim_kind='AUTHORITY'),
 'forged_sha':lambda c:c.update(source_sha256='0'*64),
 'boolean_sha':lambda c:c.update(source_sha256=True),
 'numeric_sha':lambda c:c.update(source_sha256=1),
 'verified_status':lambda c:c.update(asserted_status='PROOF_VERIFIED'),
 'approved_status':lambda c:c.update(asserted_status='APPROVED'),
 'false_status':lambda c:c.update(asserted_status=False),
 'injected_status':lambda c:c.update(asserted_status='CANDIDATE_ONLY;DISPATCH_ALLOWED'),
 'extra_field':lambda c:c.update(dispatch_allowed=True),
 'missing_origin':lambda c:c.pop('origin'),
 'profile_case_mismatch':lambda c:c.update(profile_id='SMB-T01-BASE'),
 'missing_sha':lambda c:c.pop('source_sha256'),
 'array_claim_kind':lambda c:c.update(claim_kind=['PINNED_SOURCE_REFERENCE']),
}
for name,fn in BAD_CLAIMS.items():
    setattr(PoisonedClaims,'test_reject_'+name,create_bad_claim(fn))


class PoisonedUpstreamAndPrivateReceipt(unittest.TestCase):
    def test_r23_digest_drifts(self):
        with self.assertRaises(p24.BoundaryError):p24.proof_matrix(rows(),'0'*64)
    def test_r23_unauthorized(self):
        r=rows();r[0]['approved']=True
        with self.assertRaises(p23.GateError):p24.proof_matrix(r)
    def test_r23_matrix_count(self):
        r=rows();r.pop()
        with self.assertRaises(p23.GateError):p24.proof_matrix(r)
    def test_request_type(self):
        with self.assertRaises(p24.BoundaryError):p24.deny_profile(matrix(),1)
    def test_request_assertion_type(self):
        with self.assertRaises(p24.BoundaryError):p24.deny_profile(matrix(),'SSH-T01-BASE',True)
    def test_unknown_profile_no_authorization(self):
        self.assertFalse(p24.deny_profile(matrix(),'FAKE')['dispatch_allowed'])
    def test_sha_is_correct_for_synthetic(self):
        self.assertEqual(p24.json_digest(rows()),p23.summarize(rows())['profile_obligation_ledger_sha256'])


class PrivateReceiptBoundary(unittest.TestCase):
    """Synthetic structure validation; SHA of actual R23 receipt remains pinned."""
    def accept(self,r):
        from unittest.mock import patch
        digest=p23.summarize(rows())['profile_obligation_ledger_sha256']
        with patch.object(p24,'R23_LEDGER_SHA',digest):
            return p24.authenticate_r23_receipt(r)

    def test_valid_synthetic_receipt(self):
        self.assertTrue(self.accept(fake_receipt())['r23_ledger_sha256_verified'])
    def test_wrong_scope(self):
        r=fake_receipt();r['scope']='AUTHORIZED'
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_wrong_base(self):
        r=fake_receipt();r['base_main_commit']='0'*40
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_wrong_r22_sha(self):
        r=fake_receipt();r['r22_private_receipt_sha256']='0'*64
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_runtime_loader_claim(self):
        r=fake_receipt();r['runtime_loader_executed']=True
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_guest_executed_claim(self):
        r=fake_receipt();r['guest_binaries_executed']=True
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_capability_claim(self):
        r=fake_receipt();r['capability_tested']=True
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_case_authority_claim(self):
        r=fake_receipt();r['authorized_cases']=1
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_summary_promotion(self):
        r=fake_receipt();r['summary']['dispatch_allowed']=True
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_bridge_promotion(self):
        r=fake_receipt();r['r22_boundary']['r22_effective_loader_resolution_verified']=True
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_tampered_rows_digest(self):
        r=fake_receipt();r['profile_ledger'][0]['profile_id']='SSH-T99-BASE'
        with self.assertRaises(p24.BoundaryError):self.accept(r)
    def test_structure_missing(self):
        r=fake_receipt();r.pop('profile_ledger')
        with self.assertRaises(p24.BoundaryError):self.accept(r)

# Receipt tests use synthesized R23 rows and override published digest only for
# input generator checking: the production receipt sha/digest is pinned and
# cannot be forged by the operator.

if __name__=='__main__':unittest.main()
