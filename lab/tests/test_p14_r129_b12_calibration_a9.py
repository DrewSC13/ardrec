"""R129 B12: signed FTP-T01 calibration + native immutable A9 preflight.

All keys are ephemeral TEST ONLY. No root, VM, packet, A8 state mutation or
DurableStore generation is created. A6 input is a deliberately forgeable copy.
"""
from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
import unittest
from unittest.mock import patch

from ardrec.coordination import r129_b12_calibration_a9 as m
from ardrec.coordination import r129_b11_independent_a6 as a6
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.state import (ConfirmedState,GlobalState,ServiceState,
    ServicePhase,Truth,GuardFact,Transition,TransitionContext,transition_service)
from test_p14_r115_f11_p8_signed_window import keypair,signed

NOW=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)
HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
CATALOG_SHA='a'*64
SESSION='0123456789abcdef'
CASE='FTP_T01_B12_TEST'

class B12(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k=[keypair(f'b12.key.{i}') for i in range(5)]

    def setUp(self):
        self.a6={'schema':a6.SCHEMA+'-physical-admission',
          'head':HEAD,'session':SESSION,'case_id':CASE,'family_id':'FTP-T01',
          'root_b9_original_bytes_replayed':True,
          'root_r127_crash_restoration_verified':True,
          'technical_condition':'FTP_T01_CONTROL_CONNECTION_CONFIRMED',
          'a6':'VERDADERO','a6_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
          'a7_rf_confirmed':None,'a8_transition_applied':None,
          'a9_generation':None,'p8':'NO-GO'}
        self.a6['sha256']=m.sha(self.a6)
        self.trust={'schema':m.TRUST_SCHEMA,'calibration_signer':copy.deepcopy(self.k[0][1]),
                    'revocation_signer':copy.deepcopy(self.k[1][1])}
        self.b11_trust={'schema':a6.TRUST_SCHEMA,'source_signer':copy.deepcopy(self.k[2][1]),
                        'technical_signer':copy.deepcopy(self.k[3][1]),
                        'revocation_signer':copy.deepcopy(self.k[4][1])}
        self.raw={
          'schema':m.CALIBRATION_SCHEMA,'calibration_id':'CAL_B12_001',
          'head':HEAD,'session':SESSION,'case_id':CASE,'family_id':'FTP-T01',
          'service_id':'FTP_DEV','assessment_index':0,
          'a6_sha256':self.a6['sha256'],'catalog_sha256':CATALOG_SHA,
          'measurement_provenance_sha256':'b'*64,
          'initial_risk':'1/2','criticality':'2/3',
          'replacement_risk':'1/4','evidence_contribution':'3/4',
          'weights':['1/3','1/3','1/3'],
          'valid_from':'2026-11-21T21:59:30Z',
          'valid_until':'2026-11-21T22:00:25Z',
          'interpretation_boundary':'CONTROL_CONNECTIVITY_ONLY_NO_VULNERABILITY',
          'a9_publication_authorized':False}
        self.cal=signed(self.raw,self.k[0][0],self.k[0][1],m.CALIBRATION_PREFIX)
        self.rev_raw={'schema':m.REVOCATION_SCHEMA,
          'calibration_sha256':m.sha(self.cal),
          'issued_at':'2026-11-21T21:59:55Z',
          'valid_until':'2026-11-21T22:00:25Z',
          'revoked':False,'reason_code':'CURRENT_CLEAR'}
        self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)

    def call(self,at=NOW):
        return m.preview_signed(admission=self.a6,calibration=self.cal,
          revocation=self.rev,trust=self.trust,b11_trust=self.b11_trust,
          now=at,catalog_sha256=CATALOG_SHA)

    def denial(self,reason):
        with self.assertRaisesRegex(m.Stop,reason):self.call()

    def recalc(self):
        self.cal=signed(self.raw,self.k[0][0],self.k[0][1],m.CALIBRATION_PREFIX)
        self.rev_raw['calibration_sha256']=m.sha(self.cal)
        self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)

    def test_01_two_real_ed25519_signatures(self):
        self.assertTrue(self.call()['calibration_signatures_verified'])
    def test_02_ftp_connectivity_never_publishes(self):
        d=self.call();self.assertEqual(d['a6'],'ND');self.assertIsNone(d['a9_generation'])
    def test_03_untrusted_a6_copy_not_accredited(self):
        self.assertFalse(self.call()['physical_provenance_reverified_here'])
    def test_04_exact_math_candidate_not_confirmed(self):
        d=self.call();self.assertIsNone(d['confirmed_rf']);self.assertIsNotNone(d['a7_math_candidate'])
    def test_05_no_store_opened(self):
        with patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError):self.call()
    def test_06_reproducible_calculation(self):
        self.assertEqual(self.call(),self.call())
    def test_07_candidate_equals_two_oracles(self):
        self.assertEqual(self.call()['a7_math_candidate'],'11/18')
    def test_08_wrong_a6_head(self):
        self.a6['head']='0'*40;self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'});
        self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_09_wrong_a6_session(self):
        self.a6['session']='0'*16;self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'});
        self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_10_wrong_a6_case(self):
        self.a6['case_id']='FORGED';self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'});
        self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_11_forged_a6_digest(self):
        self.a6['sha256']='0'*64;self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_12_no_crash_test(self):
        self.a6['root_r127_crash_restoration_verified']=False
        self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_13_no_b9_readback(self):
        self.a6['root_b9_original_bytes_replayed']=False
        self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_14_vulnerability_claim_rejected(self):
        self.a6['technical_condition']='VULNERABILITY_CONFIRMED'
        self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_15_claimed_a9_rejected(self):
        self.a6['a9_generation']=1
        self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_16_catalog_hash_mismatch(self):
        with self.assertRaisesRegex(m.Stop,'CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH'):
            m.preview_signed(admission=self.a6,calibration=self.cal,revocation=self.rev,
               trust=self.trust,b11_trust=self.b11_trust,now=NOW,catalog_sha256='c'*64)
    def test_17_calibration_other_head(self):
        self.raw['head']='0'*40;self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_18_calibration_other_session(self):
        self.raw['session']='0'*16;self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_19_calibration_other_case(self):
        self.raw['case_id']='FORGED';self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_20_calibration_wrong_sha(self):
        self.raw['a6_sha256']='0'*64;self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_21_calibration_family_changed(self):
        self.raw['family_id']='SSH-T01';self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_22_calibration_service_changed(self):
        self.raw['service_id']='SSH_DEV';self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_23_calibration_a9_permission_forbidden(self):
        self.raw['a9_publication_authorized']=True;self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_24_calibration_unknown_scope(self):
        self.raw['interpretation_boundary']='FULL_VULNERABILITY';self.recalc();self.denial('CALIBRATION_SCOPE_OR_IDENTITY_MISMATCH')
    def test_25_calibration_negative_fraction(self):
        self.raw['evidence_contribution']='-1/2';self.recalc();self.denial('CALIBRATION_MATHEMATICAL_CONTRACT_REJECTED')
    def test_26_calibration_bad_weights(self):
        self.raw['weights']=['1/3','1/3','1/2'];self.recalc();self.denial('CALIBRATION_MATHEMATICAL_CONTRACT_REJECTED')
    def test_27_calibration_reverse_baseline(self):
        self.raw['replacement_risk']='3/4';self.recalc();self.denial('CALIBRATION_MATHEMATICAL_CONTRACT_REJECTED')
    def test_28_calibration_noncanonical_fraction(self):
        self.raw['initial_risk']='2/4';self.recalc();self.denial('CALIBRATION_MATHEMATICAL_CONTRACT_REJECTED')
    def test_29_calibration_signature_tampered(self):
        self.cal['signature_b64']='A'*88;self.denial('REVOCATION_SCOPE_OR_STATUS')
    def test_30_revocation_signature_tampered(self):
        self.rev['signature_b64']='A'*88;self.denial('CALIBRATION_SIGNATURE_REJECTED')
    def test_31_revoked(self):
        self.rev_raw['revoked']=True;self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)
        self.denial('REVOCATION_SCOPE_OR_STATUS')
    def test_32_expired_revocation(self):
        self.rev_raw['issued_at']='2026-11-21T21:59:00Z';self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)
        self.denial('REVOCATION_STALE')
    def test_33_wrong_revocation_target(self):
        self.rev_raw['calibration_sha256']='0'*64;self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)
        self.denial('REVOCATION_SCOPE_OR_STATUS')
    def test_34_signed_window_expired(self):
        with self.assertRaisesRegex(m.Stop,'CALIBRATION_NOT_CURRENT'):
            self.call(NOW+timedelta(seconds=30))
    def test_35_clock_naive(self):
        with self.assertRaisesRegex(m.Stop,'CLOCK_REQUIRED'):self.call(NOW.replace(tzinfo=None))
    def test_36_reuse_b11_source_signer(self):
        self.trust['calibration_signer']=self.b11_trust['source_signer']
        self.denial('SIGNERS_NOT_DISTINCT_FROM_A6')
    def test_37_reuse_b11_technical_signer(self):
        self.trust['calibration_signer']=self.b11_trust['technical_signer']
        self.denial('SIGNERS_NOT_DISTINCT_FROM_A6')
    def test_38_reuse_b11_revocation_signer(self):
        self.trust['revocation_signer']=self.b11_trust['revocation_signer']
        self.denial('SIGNERS_NOT_DISTINCT_FROM_A6')
    def test_39_reuse_b12_signer(self):
        self.trust['revocation_signer']=self.trust['calibration_signer']
        self.denial('SIGNERS_NOT_DISTINCT_FROM_A6')
    def test_40_invalid_a6_type(self):
        self.a6=[];self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_41_extra_calibration_field(self):
        self.raw['secret']='BAD';self.recalc();self.denial('CALIBRATION_FIELDS')
    def test_42_revocation_extra_field(self):
        self.rev_raw['secret']='BAD';self.rev=signed(self.rev_raw,self.k[1][0],self.k[1][1],m.REVOCATION_PREFIX)
        self.denial('REVOCATION_FIELDS')
    def test_43_wrong_new_signer_pem_reused(self):
        self.trust['calibration_signer']['public_key_pem']=self.b11_trust['source_signer']['public_key_pem']
        self.denial('SIGNERS_NOT_DISTINCT_FROM_A6')
    def test_44_unexpected_a6_scope(self):
        self.a6['a6_scope']='VULNERABILITY';self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denial('A6_DOCUMENT_NOT_VALID_SHAPE')
    def test_45_no_network_from_review(self):
        with patch('socket.socket',side_effect=AssertionError('network')):self.call()

class NativePreflight(unittest.TestCase):
    def setUp(self):
        h='f'*64
        service=ServiceState('FTP_DEV',ServicePhase.PREPARADO)
        confirmed=ConfirmedState('RECORD_B12',0,'GEN_0',h,'CONFIG_1',(service,))
        self.state=GlobalState(confirmed,'EXEC_B12',(service,),authority=Truth.VERDADERO)
        self.h=h
    def staged(self):
        ctx=TransitionContext('RECORD_B12','EXEC_B12',0,self.h,
           'EVENT_STOP_B12',(
               GuardFact('cause_verified',Truth.VERDADERO,'REASON_B12'),
               GuardFact('effect_processable',Truth.VERDADERO,'EFFECT_B12')),
           reason_reference='REASON_B12',stop_cause='CONTROL')
        return transition_service(self.state,'FTP_DEV',Transition.DETENER,ctx)
    def test_46_real_native_reducer_in_memory_success(self):
        result=m.native_publish_preflight(state=self.staged(),expected_generation=0,
            reference='GEN_1',event='PUBLICATION_B12')
        self.assertEqual(result['candidate_generation'],1)
        self.assertFalse(result['generation_written'])
    def test_47_no_transition_cannot_publish(self):
        with self.assertRaisesRegex(m.Stop,'NATIVE_A9_PUBLICATION_GUARD_REJECTED'):
            m.native_publish_preflight(state=self.state,expected_generation=0,
                reference='GEN_1',event='PUB_B12')
    def test_48_wrong_cas_generation(self):
        with self.assertRaisesRegex(m.Stop,'NATIVE_A9_PUBLICATION_GUARD_REJECTED'):
            m.native_publish_preflight(state=self.staged(),expected_generation=1,
                reference='GEN_1',event='PUB_B12')
    def test_49_invalid_native_state(self):
        with self.assertRaisesRegex(m.Stop,'NATIVE_STATE_REQUIRED'):
            m.native_publish_preflight(state={},expected_generation=0,
                reference='GEN_1',event='PUB_B12')
    def test_50_reused_event(self):
        with self.assertRaisesRegex(m.Stop,'NATIVE_A9_PUBLICATION_GUARD_REJECTED'):
            m.native_publish_preflight(state=self.staged(),expected_generation=0,
                reference='GEN_1',event='EVENT_STOP_B12')
    def test_51_reused_generation_reference(self):
        with self.assertRaisesRegex(m.Stop,'NATIVE_A9_PUBLICATION_GUARD_REJECTED'):
            m.native_publish_preflight(state=self.staged(),expected_generation=0,
                reference='GEN_0',event='PUB_B12')
    def test_52_no_durable_store_calls(self):
        with patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError):
            m.native_publish_preflight(state=self.staged(),expected_generation=0,
                reference='GEN_1',event='PUB_B12')
    def test_53_reject_bad_generation_type(self):
        with self.assertRaisesRegex(m.Stop,'GENERATION_TYPE'):
            m.native_publish_preflight(state=self.staged(),expected_generation=True,
                reference='GEN_1',event='PUB_B12')
    def test_54_capabilities_are_failclosed(self):
        cap=m.capabilities();self.assertEqual(cap['p8'],'NO-GO')
        self.assertFalse(cap['native_a9_generation_written'])
        self.assertIsNone(cap['risk_without_live_calibration_confirmed'])
    def test_55_native_authority_cannot_be_nd(self):
        from dataclasses import replace
        with self.assertRaisesRegex(m.Stop,'NATIVE_AUTHORITATIVE_STATE_REQUIRED'):
            m.native_publish_preflight(
                state=replace(self.staged(),authority=Truth.ND),
                expected_generation=0,reference='GEN_1',event='PUB_B12')

if __name__=='__main__':unittest.main()
