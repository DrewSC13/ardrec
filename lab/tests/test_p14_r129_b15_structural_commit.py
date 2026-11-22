"""R129 B15: independent Ed25519 publication and actual native private-store replay.

All signed authority and A6 documents are synthetic fixtures in this file.
No root approval, physical network, real experimental risk, or deployed A9.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r129_b15_structural_commit as m
from ardrec.coordination import r129_b11_independent_a6 as b11
from ardrec.persistence import DurableStore
from ardrec.persistence.codec import StorageError
from ardrec.state import (ConfirmedState,GlobalState,ServiceState,
                          ServicePhase,Truth,Transition,GuardFact,TransitionContext)
from test_p14_r115_f11_p8_signed_window import keypair,signed

HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
CASE='FTP-T01-S01-01'
SESSION='0123456789abcdef'
CONFIG='a'*64
WHEN=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)


def native_initial():
    service=ServiceState('FTP_DEV',ServicePhase.PREPARADO)
    confirmed=ConfirmedState('RECORD_B15',0,'G_B15_0',CONFIG,'VERS_B15',(service,))
    return GlobalState(confirmed,'EXEC_B15',(service,),authority=Truth.VERDADERO)


class B15Fixture:
    @classmethod
    def setUpClass(cls):
        cls.keys=[keypair(f'ardrec.b15.external.fixture.{i}') for i in range(3)]

    def setUp(self):
        self.a6={'schema':b11.SCHEMA+'-physical-admission',
          'head':HEAD,'session':SESSION,'case_id':CASE,'family_id':'FTP-T01',
          'root_b9_original_bytes_replayed':True,
          'root_r127_crash_restoration_verified':True,
          'independent_root_witness_sha256':'f'*64,
          'technical_condition':'FTP_T01_CONTROL_CONNECTION_CONFIRMED',
          'a6':'VERDADERO','a6_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
          'a7_rf_confirmed':None,'a8_transition_applied':None,
          'a9_generation':None,'p8':'NO-GO'}
        self.a6['sha256']=m.sha(self.a6)
        self.s={
          'schema':m.SOURCE_SCHEMA,'head':HEAD,'session':SESSION,
          'case_id':CASE,'a6_sha256':self.a6['sha256'],
          'b9_receipt_sha256':'b'*64,
          'r127_witness_sha256':self.a6['independent_root_witness_sha256'],
          'origin':'INDEPENDENT_ORIGINAL_ROOT_B9_AND_B11_READBACK',
          'technical_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY',
          'root_b9_original_bytes_replayed':True,
          'root_r127_crash_restoration_verified':True,
          'observed_at':'2026-11-21T21:59:58Z'}
        self.p={
          'schema':m.GRANT_SCHEMA,'grant_id':'GRANT_B15_ONE','head':HEAD,
          'session':SESSION,'case_id':CASE,'source_sha256':None,
          'a6_sha256':self.a6['sha256'],
          'record_id':'RECORD_B15','configuration_sha256':CONFIG,
          'store_head_sha256':'c'*64,
          'expected_generation':0,'service_id':'FTP_DEV',
          'installed_publisher_sha256':'1'*64,
          'native_persistence_sha256':'2'*64,'native_state_sha256':'3'*64,
          'valid_from':'2026-11-21T21:59:40Z',
          'valid_until':'2026-11-21T22:00:30Z',
          'action':'STOP_AND_PUBLISH_NATIVE_STRUCTURAL_ONLY',
          'publication_class':'ADMINISTRATIVE_CLOSURE_ONLY',
          'confirmed_rf':None,'p8':'NO-GO'}
        self.r={'schema':m.REV_SCHEMA,'grant_sha256':None,
          'issued_at':'2026-11-21T21:59:58Z',
          'valid_until':'2026-11-21T22:00:30Z',
          'revoked':False,'reason_code':'CURRENT_CLEAR'}
        self.trust={'schema':m.TRUST_SCHEMA,
            'source_signer':copy.deepcopy(self.keys[0][1]),
            'publication_signer':copy.deepcopy(self.keys[1][1]),
            'revocation_signer':copy.deepcopy(self.keys[2][1]),
            'excluded_signer_public_sha256':[(hex(i)[2:]*64)[:64] for i in range(10,15)]}
        self.resign_all()

    def resign_all(self):
        self.source=signed(self.s,*self.keys[0],m.SOURCE_PREFIX)
        self.p['source_sha256']=m.sha(self.source)
        self.grant=signed(self.p,*self.keys[1],m.GRANT_PREFIX)
        self.r['grant_sha256']=m.sha(self.grant)
        self.rev=signed(self.r,*self.keys[2],m.REV_PREFIX)

    def review(self,**kwargs):
        return m.review_signed(admission=kwargs.get('admission',self.a6),
            source=kwargs.get('source',self.source),
            grant=kwargs.get('grant',self.grant),
            revocation=kwargs.get('revocation',self.rev),
            trust=kwargs.get('trust',self.trust),now=kwargs.get('now',WHEN))

    def denied(self,where):
        with self.assertRaisesRegex(m.Stop,where):self.review()

class SignedB15(B15Fixture, unittest.TestCase):
    def test_01_real_ed25519_signatures(self):
        self.assertEqual(self.review()['record_id'],'RECORD_B15')
    def test_02_no_claim_of_rf(self):self.assertIsNone(self.review()['confirmed_rf'])
    def test_03_structural_only(self):self.assertFalse(self.review()['experimental_risk_publication'])
    def test_04_no_p8(self):self.assertEqual(self.review()['p8'],'NO-GO')
    def test_05_a6_not_admitted(self):
        self.a6['a6']='ND';self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_06_fake_a6_digest(self):
        self.a6['sha256']='0'*64;self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_07_a6_root_not_replayed(self):
        self.a6['root_b9_original_bytes_replayed']=False;self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_08_a6_crash_not_attested(self):
        self.a6['root_r127_crash_restoration_verified']=False
        self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_09_a6_claimed_rf(self):
        self.a6['a7_rf_confirmed']='1/2';self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_10_a6_claimed_a9(self):
        self.a6['a9_generation']=1;self.a6['sha256']=m.sha({k:v for k,v in self.a6.items() if k!='sha256'})
        self.denied('LIVE_A6_SHAPE_REQUIRED')
    def test_11_source_forged_without_resign(self):
        self.source['statement']['b9_receipt_sha256']='d'*64
        self.p['source_sha256']=m.sha(self.source)
        self.grant=signed(self.p,*self.keys[1],m.GRANT_PREFIX)
        self.r['grant_sha256']=m.sha(self.grant)
        self.rev=signed(self.r,*self.keys[2],m.REV_PREFIX)
        self.denied('INDEPENDENT_SIGNATURE_REJECTED')
    def test_12_source_wrong_session(self):
        self.s['session']='f'*16;self.resign_all();self.denied('SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    def test_13_source_wrong_a6(self):
        self.s['a6_sha256']='f'*64;self.resign_all();self.denied('SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    def test_14_source_wrong_witness(self):
        self.s['r127_witness_sha256']='e'*64;self.resign_all();self.denied('SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    def test_15_source_scope_escalation(self):
        self.s['technical_scope']='FULL_VULNERABILITY';self.resign_all();self.denied('SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    def test_16_source_root_claim_false(self):
        self.s['root_b9_original_bytes_replayed']=False;self.resign_all();self.denied('SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    def test_17_source_stale(self):
        self.s['observed_at']='2026-11-21T21:58:40Z';self.resign_all();self.denied('SOURCE_OBSERVATION_STALE')
    def test_18_grant_wrong_head(self):
        self.p['head']='f'*40;self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_19_grant_wrong_case(self):
        self.p['case_id']='OTHER';self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_20_grant_wrong_service(self):
        self.p['service_id']='SSH_DEV';self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_21_grant_claim_risk(self):
        self.p['confirmed_rf']='1/2';self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_22_grant_p8_go(self):
        self.p['p8']='GO';self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_23_grant_malformed_store_head(self):
        self.p['store_head_sha256']='bad';self.resign_all();self.denied('GRANT_SCOPE_OR_DIGEST_INVALID')
    def test_24_grant_expired(self):
        with self.assertRaisesRegex(m.Stop,'GRANT_NOT_CURRENT'):
            self.review(now=WHEN+timedelta(seconds=45))
    def test_25_grant_excess_duration(self):
        self.p['valid_until']='2026-11-21T23:00:00Z';self.resign_all();self.denied('GRANT_NOT_CURRENT')
    def test_26_revoked(self):
        self.r['revoked']=True;self.resign_all();self.denied('REVOCATION_NOT_BOUND_OR_REVOKED')
    def test_27_revocation_outdated(self):
        self.r['issued_at']='2026-11-21T21:58:00Z';self.resign_all();self.denied('REVOCATION_NOT_FRESH')
    def test_28_revocation_wrong_grant(self):
        self.r['grant_sha256']='0'*64
        self.rev=signed(self.r,*self.keys[2],m.REV_PREFIX)
        self.denied('REVOCATION_NOT_BOUND_OR_REVOKED')
    def test_29_revocation_signature_tamper(self):
        self.rev['signature_b64']='A'*88;self.denied('INDEPENDENT_SIGNATURE_REJECTED')
    def test_30_trust_signer_reused(self):
        self.trust['publication_signer']=self.trust['source_signer'];self.denied('SIGNERS_NOT_INDEPENDENT')
    def test_31_trust_upstream_signer_reused(self):
        self.trust['excluded_signer_public_sha256'][0]=m.signer_pair(self.trust['source_signer'])[1]
        self.denied('UPSTREAM_SIGNER_REUSED')
    def test_32_trust_empty_exclusions(self):
        self.trust['excluded_signer_public_sha256']=[]
        self.denied('UPSTREAM_SIGNER_EXCLUSIONS_REQUIRED')
    def test_33_grant_new_field(self):
        self.p['EXTRA']='x';self.resign_all();self.denied('GRANT_FIELDS')
    def test_34_source_new_field(self):
        self.s['EXTRA']='x';self.resign_all();self.denied('SOURCE_FIELDS')
    def test_35_revocation_new_field(self):
        self.r['EXTRA']='x';self.resign_all();self.denied('REVOCATION_FIELDS')
    def test_36_naive_clock(self):
        with self.assertRaisesRegex(m.Stop,'UTC_CLOCK_REQUIRED'):
            self.review(now=WHEN.replace(tzinfo=None))
    def test_37_capabilities_no_real_install(self):
        c=m.capabilities();self.assertTrue(c['native_structural_commit_path_implemented'])
        self.assertFalse(c['experimental_risk_publication_implemented'])
    def test_38_source_tree_rejects_root_execution(self):
        with self.assertRaisesRegex(m.Stop,'INDEPENDENT_CODE_INSTALL_REQUIRED'):
            self._test_install_reject()
    def _test_install_reject(self):
        with patch.object(m.os,'geteuid',return_value=1000),\
             patch.object(m.pwd,'getpwnam',return_value=type('U',(),{'pw_uid':1000})()):
            m._installed_grant(self.review())
    def test_39_invalid_public_policy(self):
        with self.assertRaisesRegex(m.Stop,'POLICY_PATH_NOT_ALLOWLISTED'):
            m._read_root_public(Path('/etc/passwd'))
    def test_40_document_review_no_storage(self):
        with patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError('store')):
            self.review()


@unittest.skipIf(os.geteuid()==0, 'Private real stores must be tested unprivileged')
class NativeWriterSandbox(B15Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-b15-native-')
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'native-store'
        with DurableStore.create(self.path,native_initial()) as st:
            self.original_head=st.head_sha256
        self.p['store_head_sha256']=self.original_head
        self.resign_all()

    def open(self):
        return DurableStore.open(self.path,record_id='RECORD_B15',configuration_sha256=CONFIG)

    def execute_once(self,refresh=lambda:None):
        v=self.review()
        with self.open() as d:result=m._structural_commit(d,v,refresh)
        return result

    def test_41_native_transition_and_publish(self):
        out=self.execute_once()
        self.assertEqual(out['generation'],1)
        with self.open() as d:
            self.assertEqual(d.state.services[0].phase,ServicePhase.DETENIDO)
            self.assertEqual(d.state.confirmed.generation,1)
            self.assertIsNone(out['confirmed_rf'])
            self.assertFalse(out['recovered_existing_commit'])
    def test_42_reopening_is_replayable(self):
        result=self.execute_once()
        with DurableStore.open(self.path,record_id='RECORD_B15',
             configuration_sha256=CONFIG,expected_head=result['native_store_head_sha256']) as d:
            self.assertEqual(d.state.confirmed.generation_reference,'G_R129_'+SESSION)
    def test_43_idempotent_duplicate_request(self):
        self.execute_once()
        out=self.execute_once()
        self.assertTrue(out['recovered_existing_commit'])
        self.assertEqual(out['generation'],1)
    def test_44_untrusted_preexisting_stage_denied(self):
        with self.open() as d:
            ctx=TransitionContext('RECORD_B15','EXEC_B15',0,CONFIG,'FOREIGN',(
                GuardFact('cause_verified',Truth.VERDADERO,'FOREIGN_REASON'),
                GuardFact('effect_processable',Truth.VERDADERO,'FOREIGN_EFFECT')),
                reason_reference='FOREIGN_REASON',stop_cause='CONTROL')
            d.transition('FTP_DEV',Transition.DETENER,ctx)
        with self.assertRaisesRegex(m.Stop,'STAGED_EVENT_NOT_THIS_GRANT'):self.execute_once()
    def test_45_wrong_store_head_denied(self):
        self.p['store_head_sha256']='0'*64;self.resign_all()
        with self.assertRaisesRegex(m.Stop,'STORE_STAGING_PRECONDITION'):self.execute_once()
    def test_46_revocation_refresh_before_stage(self):
        with self.assertRaisesRegex(m.Stop,'REVOKED_BEFORE_STAGE'):
            self.execute_once(lambda: (_ for _ in ()).throw(m.Stop('REVOKED_BEFORE_STAGE')))
        with self.open() as d:self.assertEqual(d.state.confirmed.generation,0)
    def test_47_revocation_refresh_after_stage(self):
        calls=[]
        def refresh():
            calls.append(1)
            if len(calls)==2:raise m.Stop('REVOKED_BEFORE_COMMIT')
        with self.assertRaisesRegex(m.Stop,'REVOKED_BEFORE_COMMIT'):self.execute_once(refresh)
        with self.open() as d:
            self.assertEqual(d.state.confirmed.generation,0)
            self.assertEqual(d.state.services[0].phase,ServicePhase.DETENIDO)
    def test_48_resume_exact_stage_after_revocation_resolved(self):
        self.test_47_revocation_refresh_after_stage()
        out=self.execute_once()
        self.assertEqual(out['generation'],1)
    def test_49_concurrent_writer_denied(self):
        with self.open():
            with self.assertRaises(StorageError):self.open()
    def _stage_only(self):
        verified=self.review()
        ids=m._ids(verified)
        with self.open() as d:
            s=d.state
            ctx=TransitionContext(s.confirmed.record_id,s.execution_id,0,CONFIG,
               ids['stage_event'],(
               GuardFact('cause_verified',Truth.VERDADERO,ids['reason_reference']),
               GuardFact('effect_processable',Truth.VERDADERO,ids['effect_reference'])),
               reason_reference=ids['reason_reference'],stop_cause='CONTROL')
            d.transition('FTP_DEV',Transition.DETENER,ctx)

    def test_50_simulated_power_loss_before_head(self):
        self._stage_only()
        calls=[]
        def fail(point):
            if point=='head:before_replace' and not calls:
                calls.append(point);raise RuntimeError('POWER_LOSS')
        with DurableStore.open(self.path,record_id='RECORD_B15',configuration_sha256=CONFIG,fault=fail) as st:
            with self.assertRaisesRegex(RuntimeError,'POWER_LOSS'):
                m._structural_commit(st,self.review(),lambda:None)
        with self.open() as st:
            self.assertEqual(st.state.confirmed.generation,0)
            self.assertEqual(st.state.services[0].phase,ServicePhase.DETENIDO)
        out=self.execute_once();self.assertEqual(out['generation'],1)
    def test_51_simulated_power_loss_after_head(self):
        self._stage_only()
        calls=[]
        def fail(point):
            if point=='head:replaced' and not calls:
                calls.append(point);raise RuntimeError('ACK_LOST')
        with DurableStore.open(self.path,record_id='RECORD_B15',configuration_sha256=CONFIG,fault=fail) as st:
            with self.assertRaisesRegex(RuntimeError,'ACK_LOST'):
                m._structural_commit(st,self.review(),lambda:None)
        with self.open() as st:self.assertEqual(st.state.confirmed.generation,1)
        out=self.execute_once();self.assertTrue(out['recovered_existing_commit'])
    def test_52_no_risk_claim_after_commit(self):
        out=self.execute_once()
        self.assertFalse(out['technical_risk_published'])
        self.assertEqual(out['publication_class'],'ADMINISTRATIVE_CLOSURE_ONLY')


if __name__=='__main__':unittest.main()
