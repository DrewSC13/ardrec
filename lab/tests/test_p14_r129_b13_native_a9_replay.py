"""R129-B13: native A8/A9 actual durable test transactions; synthetic only.

No physical A6, P8 or actual risk is created. Actual disk operations are
restricted to temporary private test stores, never the operational store.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import copy
import os
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r129_b13_native_a9_replay as b13
from ardrec.coordination import r129_b12_calibration_a9 as b12
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.persistence import DurableStore
from ardrec.persistence.codec import StorageError
from ardrec.state import (ConfirmedState, GlobalState, ServiceState,
    ServicePhase, Truth, GuardFact, Transition, TransitionContext,
    transition_service)

H = 'f'*64


def initial():
    service=ServiceState('FTP_DEV',ServicePhase.PREPARADO)
    confirmed=ConfirmedState('RECORD_B13',0,'GEN_B13_0',H,'CONFIG_B13',(service,))
    return GlobalState(confirmed,'EXEC_B13',(service,),authority=Truth.VERDADERO)


def context(state, *, event='STOP_B13', cause='CONTROL'):
    return TransitionContext(state.confirmed.record_id,state.execution_id,
      state.confirmed.generation,H,event,(
        GuardFact('cause_verified',Truth.VERDADERO,'REASON_B13'),
        GuardFact('effect_processable',Truth.VERDADERO,'EFFECT_B13')),
      reason_reference='REASON_B13',stop_cause=cause)


def synthetic_review():
    doc={
      'schema':b12.SCHEMA+'-documentary-a7-review',
      'source_kind':'SIGNED_DOCUMENTARY_CALIBRATION_AND_MATH_ONLY',
      'head':'7c1bf90c36b17ace9b670b360b6c183770297bec',
      'session':'0123456789abcdef','case_id':'B13_TEST',
      'service_id':'FTP_DEV',
      'p8':'NO-GO','a6':'ND','confirmed_rf':None,
      'a7_point_candidate_not_proven':True,
      'physical_provenance_reverified_here':False,
      'a8_transition_applied':None,'a9_generation':None,
      'a9_native_transaction_executed':False,
    }
    doc['sha256']=f1.digest(f1.canonical(doc))
    return doc


class DocumentaryBoundary(unittest.TestCase):
    def setUp(self):
        self.doc=synthetic_review()
        self.staged=transition_service(initial(),'FTP_DEV',Transition.DETENER,context(initial()))

    def review(self, **overrides):
        args=dict(documentary=self.doc,staged_state=self.staged,
                  expected_generation=0,reference='GEN_B13_1',event='PUB_B13')
        args.update(overrides)
        return b13.review_untrusted_a7(**args)

    def reject_doc(self, why='DOCUMENTARY_A7_IS_NOT_PHYSICAL_PROOF'):
        self.doc['sha256']=f1.digest(f1.canonical({k:v for k,v in self.doc.items() if k!='sha256'}))
        with self.assertRaisesRegex(b13.Stop,why):self.review()

    def test_01_native_reducer_only(self):
        r=self.review();self.assertTrue(r['native_reducer_checked'])
    def test_02_no_generation(self):
        self.assertFalse(self.review()['store_committed'])
    def test_03_no_rf(self):
        self.assertIsNone(self.review()['confirmed_rf'])
    def test_04_no_a6(self):
        self.assertEqual(self.review()['a6'],'ND')
    def test_05_no_a9(self):
        self.assertIsNone(self.review()['a9'])
    def test_06_no_p8(self):
        self.assertEqual(self.review()['p8'],'NO-GO')
    def test_07_doc_tampered_hash(self):
        self.doc['head']='0'*40
        with self.assertRaisesRegex(b13.Stop,'DOCUMENTARY_A7_IS_NOT_PHYSICAL_PROOF'):self.review()
    def test_08_claim_rf(self):
        self.doc['confirmed_rf']='1/2';self.reject_doc()
    def test_09_claim_a6(self):
        self.doc['a6']='VERDADERO';self.reject_doc()
    def test_10_claim_generation(self):
        self.doc['a9_generation']=1;self.reject_doc()
    def test_11_claim_physical(self):
        self.doc['physical_provenance_reverified_here']=True;self.reject_doc()
    def test_12_claim_a8(self):
        self.doc['a8_transition_applied']=True;self.reject_doc()
    def test_13_claim_durable(self):
        self.doc['a9_native_transaction_executed']=True;self.reject_doc()
    def test_14_claim_point_identified(self):
        self.doc['a7_point_candidate_not_proven']=False;self.reject_doc()
    def test_15_wrong_schema(self):
        self.doc['schema']='OLD';self.reject_doc()
    def test_16_wrong_service(self):
        self.doc['service_id']='SSH_DEV';self.reject_doc('SERVICE_SCOPE_MISMATCH')
    def test_17_bad_state(self):
        with self.assertRaisesRegex(b13.Stop,'NATIVE_STATE_NOT_AUTHORIZED_FOR_PREFLIGHT'):
            self.review(staged_state={})
    def test_18_no_native_authority(self):
        with self.assertRaisesRegex(b13.Stop,'NATIVE_STATE_NOT_AUTHORIZED_FOR_PREFLIGHT'):
            self.review(staged_state=replace(self.staged,authority=Truth.ND))
    def test_19_stale_gen(self):
        with self.assertRaisesRegex(b13.Stop,'EXPECTED_GENERATION_MISMATCH'):
            self.review(expected_generation=1)
    def test_20_no_transition(self):
        with self.assertRaises(b12.Stop):self.review(staged_state=initial())
    def test_21_reused_event(self):
        with self.assertRaises(b12.Stop):self.review(event='STOP_B13')
    def test_22_no_disk_calls(self):
        with patch('ardrec.persistence.DurableStore.create',side_effect=AssertionError),\
             patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError):
            self.review()
    def test_23_capabilities(self):
        d=b13.capabilities()
        self.assertFalse(d['production_a9_commit_exposed'])
        self.assertIsNone(d['a9'])
    def test_24_doc_none(self):
        with self.assertRaisesRegex(b13.Stop,'DOCUMENTARY_A7_IS_NOT_PHYSICAL_PROOF'):
            self.review(documentary=None)


@unittest.skipIf(os.geteuid() == 0, 'Private native persistence tested without root')
class NativeDurableSandbox(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-b13-private-')
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'native-store'

    def start(self, *, fault=None):
        return DurableStore.create(self.path,initial(),fault=fault)

    def open(self):
        return DurableStore.open(self.path,record_id='RECORD_B13',configuration_sha256=H)

    def staged(self,store):
        return store.transition('FTP_DEV',Transition.DETENER,context(store.state))

    def publish(self, store):
        return store.publish(expected_generation=0,reference='GEN_B13_1',event='PUB_B13')

    def test_25_create_real_native_generation_0(self):
        with self.start() as d:self.assertEqual(d.state.confirmed.generation,0)
        with self.open() as d:self.assertEqual(d.state.confirmed.generation,0)
    def test_26_transition_is_durable_not_published(self):
        with self.start() as d:self.staged(d)
        with self.open() as d:
            self.assertEqual(d.state.confirmed.generation,0)
            self.assertEqual(d.state.services[0].phase,ServicePhase.DETENIDO)
    def test_27_publish_native_real_private_generation_1(self):
        with self.start() as d:
            self.staged(d);self.publish(d)
            head=d.head_sha256
        with self.open() as d:
            self.assertEqual(d.state.confirmed.generation,1)
            self.assertEqual(d.head_sha256,head)
            self.assertEqual(d.state.confirmed.incorporated_events,('STOP_B13','PUB_B13'))
    def test_28_idempotent_reopen(self):
        with self.start() as d:
            self.staged(d);self.publish(d);head=d.head_sha256
        for _ in range(3):
            with self.open() as d:self.assertEqual(d.head_sha256,head)
    def test_29_double_publish_rejected(self):
        with self.start() as d:
            self.staged(d);self.publish(d)
            with self.assertRaises(StorageError):self.publish(d)
    def test_30_stale_generation_rejected(self):
        with self.start() as d:
            self.staged(d)
            with self.assertRaises(StorageError):
                d.publish(expected_generation=1,reference='GEN_B13_1',event='PUB_B13')
    def test_31_event_reuse_rejected(self):
        with self.start() as d:
            self.staged(d)
            with self.assertRaises(StorageError):
                d.publish(expected_generation=0,reference='GEN_B13_1',event='STOP_B13')
    def test_32_lock_rejects_second_writer(self):
        with self.start():
            with self.assertRaises(StorageError):self.open()
    def test_33_missing_transition_no_generation(self):
        with self.start() as d:
            with self.assertRaises(StorageError):self.publish(d)
        with self.open() as d:self.assertEqual(d.state.confirmed.generation,0)
    def test_34_duplicate_generation_ref(self):
        with self.start() as d:
            self.staged(d)
            with self.assertRaises(StorageError):
                d.publish(expected_generation=0,reference='GEN_B13_0',event='PUB_B13')

    def _inject(self, point):
        with self.start() as d:
            self.staged(d)
        def fail(stage):
            if stage==point:raise RuntimeError('POWER_LOSS_SIMULATED_'+point)
        with DurableStore.open(self.path,record_id='RECORD_B13',configuration_sha256=H,fault=fail) as d:
            with self.assertRaisesRegex(RuntimeError,'POWER_LOSS_SIMULATED_'):
                self.publish(d)
        with self.open() as d:
            gen=d.state.confirmed.generation
            self.assertIn(gen,(0,1))
            if gen==0:self.assertEqual(d.recovery_action,'PUBLISH_CANDIDATE')
            else:
                self.assertEqual(d.recovery_action,'NONE')
                self.assertEqual(d.state.confirmed.incorporated_events,('STOP_B13','PUB_B13'))
            return gen

    def test_35_head_before_replace(self):
        self.assertEqual(self._inject('head:before_replace'),0)
    def test_36_head_replaced(self):
        self.assertEqual(self._inject('head:replaced'),1)
    def test_37_head_durable(self):
        self.assertEqual(self._inject('head:durable'),1)
    def test_38_acknowledge_loss(self):
        self.assertEqual(self._inject('commit:acknowledge'),1)
    def test_39_journal_created_failure(self):
        self.assertEqual(self._inject('journal:created'),0)
    def test_40_generations_created_failure(self):
        self.assertEqual(self._inject('generations:created'),0)
    def test_41_journal_durable_failure(self):
        self.assertEqual(self._inject('journal:durable'),0)
    def test_42_generations_durable_failure(self):
        self.assertEqual(self._inject('generations:durable'),0)
    def test_43_no_operational_risk_even_with_publish(self):
        with self.start() as d:
            self.staged(d);self.publish(d)
            self.assertEqual(d.state.services[0].phase,ServicePhase.DETENIDO)
            self.assertFalse(hasattr(d.state.confirmed,'final_risk'))
    def test_44_corrupt_head_fails_closed(self):
        with self.start():pass
        p=self.path/'HEAD';p.chmod(0o600);raw=p.read_bytes();p.write_bytes(b'X'+raw[1:]);p.chmod(0o400)
        with self.assertRaises(StorageError):self.open()
    def test_45_missing_head_fails_closed(self):
        with self.start():pass
        (self.path/'HEAD').unlink()
        with self.assertRaises((StorageError,OSError)):self.open()
    def test_46_root_mode_refuses_world_access(self):
        with self.start():pass
        self.path.chmod(0o755)
        with self.assertRaises(StorageError):self.open()
    def test_47_path_symlink_refused(self):
        with self.start():pass
        alias=Path(self.tmp.name)/'alias';alias.symlink_to(self.path,target_is_directory=True)
        with self.assertRaises((StorageError,OSError)):
            DurableStore.open(alias,record_id='RECORD_B13',configuration_sha256=H)

if __name__=='__main__':unittest.main()
