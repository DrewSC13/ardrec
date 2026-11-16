"""R58-N: append-once declared case binding over the existing durable fixture."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO))
from ardrec.coordination import r58n_durable_case_binding as n
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries
import test_p14_r58m_durable_a5 as journal_fixtures
from ardrec.coordination import r58m_durable_a5_audit as m


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.fixture=journal_fixtures.JournalFixture('test_accepted_verified_without_launch')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        self.rid=self.fixture.rid
        self.receipts=self.root.parent/'receipts'
        self.receipts.mkdir(mode=0o700)
        # Fast isolated model of a previously verified R58-L review: durable
        # binding tests do not rely on an independently mounted P7 catalogue.
        # A separate test uses the genuine pinned catalogue when available.
        selected={'service_id':'FTP_DEV','session_id':'DEV_TUTOR_001',
                  'derived_case_id':'FTP-T02-S01-01','assessment_index':0}
        self.review={
            'sha256':'b'*64,'a4':{'sha256':'a'*64},
            'a4_selected_identity':selected,
            'attempt_intent':{**selected,'attempt_id':self.rid,
                              'action':'SYNTHETIC_REVIEW_ONLY'},
            'a5':{'actual_attempts_started':0,'actual_attempt_reservations':0,
                  'real_attempt_budget_attested':False},
            'unit_count':29,'covered_family_count':25,
            'p8_operational':'NO-GO','a6_classification':'ND',
            'technical_truth_accredited':False,'operational_dispatch':False,
            'confirmed_final_risk':None,'published_generation':None,
        }
        p=patch.object(n,'verify_a4_a5_review',return_value=True);p.start()
        self.addCleanup(p.stop)
        q=patch.object(m,'verify_a4_a5_review',return_value=True);q.start()
        self.addCleanup(q.stop)

    def build(self):
        return n.build_binding(self.review,self.root,self.rid)

    def write(self):
        return n.persist_binding(self.receipts,self.review,self.root,self.rid)

    def test_schema_and_identity(self):
        d=self.build()
        self.assertEqual(set(d),n.RECEIPT_FIELDS)
        self.assertEqual(d['a4_selected_identity'],self.review['a4_selected_identity'])
        self.assertEqual(d['declared_request_id'],self.rid)
        self.assertEqual(d['r58l_review_sha256'],self.review['sha256'])
        self.assertEqual(d['a4_selection_sha256'],self.review['a4']['sha256'])
        self.assertTrue(n.verify_binding(d,self.review,self.root,self.rid))

    def test_security_all_false(self):
        d=self.build()
        for field in ('identity_declaration_independently_attested',
                      'physical_case_binding_accredited',
                      'technical_truth_accredited','operational_dispatch'):
            self.assertIs(d[field],False)
        for field in ('confirmed_final_risk','applied_state_transition',
                      'published_generation'):
            self.assertIsNone(d[field])
        self.assertEqual(d['a6_classification'],'ND')
        self.assertEqual(d['p8_operational'],'NO-GO')

    def test_real_25_families_review(self):
        self.assertEqual(self.review['unit_count'],29)
        self.assertEqual(self.review['covered_family_count'],25)
        self.assertEqual(self.review['a5']['actual_attempts_started'],0)

    def test_snapshot_holds_p9_facts(self):
        d=self.build()
        self.assertEqual(d['a5_fixture_state'],'ACCEPTED')
        self.assertEqual(d['a5_fixture_start_intent_count'],0)
        self.assertEqual(d['a5_fixture_event_count'],2)
        self.assertEqual(len(d['a5_fixture_event_head_sha256']),64)
        self.assertEqual(len(d['a5_fixture_journal_sha256']),64)

    def test_created_once_then_idempotent(self):
        first=self.write()
        self.assertEqual(first['persist_status'],'CREATED')
        second=self.write()
        self.assertEqual(second['persist_status'],'REPLAY_IDENTICAL')
        self.assertEqual(first['receipt'],second['receipt'])
        self.assertEqual(len(list(self.receipts.iterdir())),1)
        self.assertFalse(second['case_binding_accredited'])

    def test_verified_persisted(self):
        first=self.write()
        checked=n.verify_persisted(self.receipts,self.review,self.root,self.rid)
        self.assertEqual(checked['receipt_sha256'],first['receipt']['sha256'])
        self.assertEqual(checked['persisted_verification'],
                         'PASS_DECLARED_ONLY_NO_AUTHORITY')
        self.assertFalse(checked['retry_allowed'])

    def test_canonical_file_exact(self):
        d=self.write()
        p=self.receipts/d['receipt_filename']
        self.assertEqual(p.read_bytes(),n.canonical(d['receipt'])+b'\n')
        self.assertEqual(p.stat().st_mode & 0o077,0)
        self.assertEqual(p.stat().st_nlink,1)

    def test_same_inputs_deterministic(self):
        self.assertEqual(self.build(),self.build())

    def test_wrong_request_id(self):
        with self.assertRaises(ValueError):
            n.build_binding(self.review,self.root,'ATT_OTHER')

    def test_wrong_review_attempt_binding(self):
        review=deepcopy(self.review)
        review['attempt_intent']['attempt_id']='ATT_OTHER'
        with self.assertRaises(ValueError):
            n.build_binding(review,self.root,self.rid)

    def test_missing_intent(self):
        report=deepcopy(self.review);report['attempt_intent']=None
        with self.assertRaises(ValueError):
            n.build_binding(report,self.root,self.rid)

    def test_forged_binding_accredited_refused(self):
        d=self.build();d['physical_case_binding_accredited']=True
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_forged_risk_refused(self):
        d=self.build();d['confirmed_final_risk']='0'
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_forged_a6_refused(self):
        d=self.build();d['a6_classification']='VERDADERO'
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_forged_publication_refused(self):
        d=self.build();d['published_generation']=1
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_forged_dispatch_refused(self):
        d=self.build();d['operational_dispatch']=True
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_forged_journal_fingerprint_refused(self):
        d=self.build();d['a5_fixture_request_fingerprint']='0'*64
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_missing_field_refused(self):
        d=self.build();d.pop('p8_operational')
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_extra_field_refused(self):
        d=self.build();d['permit']=True
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_bad_digest_refused(self):
        d=self.build();d['sha256']='z'*64
        with self.assertRaises(n.BindingError):
            n.verify_binding(d,self.review,self.root,self.rid)

    def test_journal_state_change_refused(self):
        self.write()
        self.fixture._build(state='START_INTENT')
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_journal_event_mutation_refused(self):
        self.write()
        self.fixture._mutate('UPDATE events SET entry_sha256=? WHERE seq=2',('a'*64,))
        with self.assertRaises(ValueError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_replay_changed_journal_refused(self):
        self.write()
        self.fixture._build(state='RECOVERY_UNCERTAIN')
        with self.assertRaises(n.BindingError):
            self.write()

    def test_saved_tamper_refused(self):
        first=self.write()
        f=self.receipts/first['receipt_filename']
        f.write_text('{}\n')
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_saved_rehash_refused(self):
        first=self.write();f=self.receipts/first['receipt_filename']
        d=deepcopy(first['receipt']);d['technical_truth_accredited']=True
        d['sha256']=n.digest({k:v for k,v in d.items() if k!='sha256'})
        f.write_bytes(n.canonical(d)+b'\n')
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_saved_missing_refused(self):
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_saved_symlink_refused(self):
        first=self.write();f=self.receipts/first['receipt_filename']
        f.unlink();f.symlink_to(self.root/'attempts.sqlite3')
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_saved_hardlink_refused(self):
        first=self.write();f=self.receipts/first['receipt_filename']
        os.link(f,self.receipts/'extra.json')
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_saved_group_writable_refused(self):
        first=self.write();f=self.receipts/first['receipt_filename']
        f.chmod(0o660)
        with self.assertRaises(n.BindingError):
            n.verify_persisted(self.receipts,self.review,self.root,self.rid)

    def test_root_symlink_refused(self):
        alias=self.root.parent/'alias'
        alias.symlink_to(self.receipts,target_is_directory=True)
        with self.assertRaises(n.BindingError):
            n.persist_binding(alias,self.review,self.root,self.rid)

    def test_root_world_writable_refused(self):
        self.receipts.chmod(0o777)
        with self.assertRaises(n.BindingError):
            self.write()

    def test_root_missing_refused(self):
        with self.assertRaises(n.BindingError):
            n.persist_binding(self.receipts/'missing',self.review,self.root,self.rid)

    def test_relative_root_refused(self):
        with self.assertRaises(n.BindingError):
            n.persist_binding(Path('relative'),self.review,self.root,self.rid)

    def test_read_only_journal_file(self):
        before=(self.root/'attempts.sqlite3').read_bytes()
        self.write()
        self.assertEqual(before,(self.root/'attempts.sqlite3').read_bytes())

    def test_no_wal_shm(self):
        self.write()
        for suffix in ('-wal','-shm'):
            self.assertFalse(Path(str(self.root/'attempts.sqlite3')+suffix).exists())

    def test_reserved_snapshot_replay_blocks_retry(self):
        self.fixture._build(state='RESERVED')
        first=self.write();self.assertEqual(first['receipt']['a5_fixture_start_intent_count'],0)
        self.assertFalse(n.verify_persisted(self.receipts,self.review,self.root,self.rid)['retry_allowed'])

    def test_start_intent_snapshot_does_not_claim_process(self):
        self.fixture._build(state='START_INTENT')
        d=self.write()['receipt']
        self.assertEqual(d['a5_fixture_start_intent_count'],1)
        self.assertFalse(d['technical_truth_accredited'])

    def test_uncertain_snapshot_no_retry(self):
        self.fixture._build(state='RECOVERY_UNCERTAIN')
        self.write()
        self.assertFalse(n.verify_persisted(self.receipts,self.review,self.root,self.rid)['retry_allowed'])

    def test_recorded_limited_no_technical_truth(self):
        self.fixture._build(state='RECORDED_LIMITED')
        d=self.write()['receipt']
        self.assertEqual(d['a5_fixture_state'],'RECORDED_LIMITED')
        self.assertFalse(d['technical_truth_accredited'])

    def test_invalid_request_id_refused(self):
        for rid in ('../escape', 'x/y', '', '\u00f1'):
            with self.subTest(rid=rid),self.assertRaises(ValueError):
                n.build_binding(self.review,self.root,rid)

    def test_unrelated_journal_rejected(self):
        self.fixture._build(state='ACCEPTED')
        with self.assertRaises(ValueError):
            n.build_binding(self.review,self.root,'OTHER')

    def test_separate_receipt_directory_only(self):
        before=list(self.root.iterdir())
        self.write()
        self.assertEqual(before,list(self.root.iterdir()))

    def test_report_in_place_mutation_no_alias(self):
        d=self.build()
        d['a4_selected_identity']['service_id']='HACKED'
        self.assertEqual(self.review['a4_selected_identity']['service_id'],
                         'FTP_DEV')



class RealPinnedIntegration(unittest.TestCase):
    def test_real_r58l_selection_and_binding(self):
        from ardrec.evidence.r58h_ssh_family_logic import CATALOG_PATH, CATALOG_SHA256
        import hashlib
        if not CATALOG_PATH.is_file() or hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest()!=CATALOG_SHA256:
            self.skipTest('ORIGINAL_P7_CATALOG_NOT_IN_TINY_FIXTURE')
        fixture=journal_fixtures.JournalFixture('test_accepted_verified_without_launch')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        entries=synthetic_entries()
        selected=build_a4_a5_review(entries)['a4_selected_identity']
        self.assertIsNotNone(selected)
        review=build_a4_a5_review(entries,attempt_intent={
            **selected,'attempt_id':fixture.rid,'action':'SYNTHETIC_REVIEW_ONLY'})
        receipts=fixture.root.parent/'real_receipts';receipts.mkdir(mode=0o700)
        result=n.persist_binding(receipts,review,fixture.root,fixture.rid)
        self.assertEqual(result['persist_status'],'CREATED')
        self.assertFalse(result['receipt']['physical_case_binding_accredited'])
        self.assertEqual(review['covered_family_count'],25)
        self.assertEqual(review['unit_count'],29)
        self.assertEqual(n.verify_persisted(receipts,review,fixture.root,fixture.rid)['persisted_verification'],
                         'PASS_DECLARED_ONLY_NO_AUTHORITY')

if __name__=='__main__':unittest.main()
