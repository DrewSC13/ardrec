"""R58-M: read-only existing P9 durable journal and conservative R58-L join."""
from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
from ardrec.coordination import r58m_durable_a5_audit as m


def bsha(blob):
    return hashlib.sha256(blob).hexdigest()


def canon(o):
    return json.dumps(o, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


class JournalFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ardrec-r58m-audit-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'journal'
        self.root.mkdir(mode=0o700)
        (self.root/'artifacts').mkdir(mode=0o700)
        self.dbpath=self.root/'attempts.sqlite3'
        self.rid='ATT_R58M_TEST_001'
        self.fixture='ok'
        self.deadline=1000
        self.cap=4096
        self.state='ACCEPTED'
        self._build()

    def _build(self, *, state='ACCEPTED', fixture='ok', starts=None, tamper=None):
        if self.dbpath.exists():self.dbpath.unlink()
        p9={'schema':m.JOURNAL_SCHEMA,'fixture':fixture,'deadline_ms':1000,
            'output_cap':4096,'p8_operational':'NO-GO'}
        fingerprint=bsha(canon(p9))
        events=[('RESERVED',{'fingerprint':fingerprint,**p9})]
        if state!='RESERVED':
            events.append(('ACCEPTED',{'fingerprint':fingerprint,'profile':'FIXTURE_ONLY','p8':'NO-GO'}))
        if state not in ('RESERVED','ACCEPTED'):
            events.append(('START_INTENT',{'prior':'ACCEPTED','start_count':1}))
        result=None
        if state=='RECOVERY_UNCERTAIN':
            events.append(('RECOVERY_UNCERTAIN',{'reason':'unreconciled_start_intent',
                    'no_auto_retry':True,'no_signal_without_owned_identity':True}))
        if state=='RECORDED_LIMITED':
            slug=bsha(self.rid.encode())
            artifacts={}
            for channel,text in (('stdout',b'ARDREC_BENIGN_OK\n'),('stderr',b'ARDREC_TRACE\n')):
                name=f'{slug}.{channel}'
                (self.root/'artifacts'/name).write_bytes(text)
                artifacts[channel]={'name':name,'bytes':len(text),'sha256':bsha(text)}
            result={'schema':m.JOURNAL_SCHEMA, 'p8_operational':'NO-GO',
                    'outcome':'BENIGN_EXIT_ZERO',
                    'global_tree_cleanup_proven':False,
                    'cleanup_scope':'OWNED_LEADER_ONLY_NO_DESCENDANT_CERTIFICATION',
                    'artifacts':artifacts}
            events.append(('RECORDED_LIMITED',{'outcome':'BENIGN_EXIT_ZERO',
                        'result_sha256':bsha(canon(result)),
                        'cleanup_scope':'OWNED_LEADER_ONLY_NO_DESCENDANT_CERTIFICATION'}))
        if starts is None:starts=0 if state in ('RESERVED','ACCEPTED') else 1
        with closing(sqlite3.connect(self.dbpath)) as db:
            db.executescript('''
            CREATE TABLE attempts (id TEXT PRIMARY KEY,fingerprint TEXT,fixture TEXT,
              deadline_ms INTEGER,output_cap INTEGER,state TEXT,start_count INTEGER,
              pid INTEGER,pid_start_ticks INTEGER,result_json TEXT,created_utc TEXT);
            CREATE TABLE events (seq INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT,
              action TEXT,payload_json TEXT,previous_sha256 TEXT,entry_sha256 TEXT);
            ''')
            db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?,?,?,?)',(
               self.rid,fingerprint,fixture,1000,4096,state,starts,None,None,
               None if result is None else canon(result).decode(),'synthetic-time'))
            prev='0'*64
            for action,payload in events:
                event_hash=bsha(canon({'id':self.rid,'action':action,
                                       'payload':payload,'previous':prev}))
                db.execute('INSERT INTO events(request_id,action,payload_json,previous_sha256,entry_sha256) VALUES (?,?,?,?,?)',
                           (self.rid,action,canon(payload).decode(),prev,event_hash))
                prev=event_hash
            db.commit()

    def _mutate(self, sql, args=()):
        with closing(sqlite3.connect(self.dbpath)) as db:
            db.execute(sql,args)
            db.commit()

    def test_accepted_verified_without_launch(self):
        s=m.audit_benign_journal(self.root,self.rid)
        self.assertEqual(s['journal_state'],'ACCEPTED')
        self.assertEqual(s['local_fixture_start_intent_count'],0)
        self.assertEqual(s['event_count'],2)
        self.assertFalse(s['ordinary_retry_allowed'])
        self.assertFalse(s['case_identity_stored_in_journal'])

    def test_reserved_is_not_an_attempt_start(self):
        self._build(state='RESERVED')
        d=m.audit_benign_journal(self.root,self.rid)
        self.assertEqual(d['journal_state'],'RESERVED')
        self.assertEqual(d['local_fixture_start_intent_count'],0)

    def test_start_intent_is_durable_but_not_proof_of_process_launch(self):
        self._build(state='START_INTENT')
        d=m.audit_benign_journal(self.root,self.rid)
        self.assertEqual(d['journal_state'],'START_INTENT')
        self.assertEqual(d['local_fixture_start_intent_count'],1)
        self.assertFalse(d['ordinary_retry_allowed'])

    def test_recovery_uncertain_blocks_retry(self):
        self._build(state='RECOVERY_UNCERTAIN')
        d=m.audit_benign_journal(self.root,self.rid)
        self.assertEqual(d['journal_state'],'RECOVERY_UNCERTAIN')
        self.assertFalse(d['ordinary_retry_allowed'])

    def test_recorded_limited_artifacts_are_checked(self):
        self._build(state='RECORDED_LIMITED')
        d=m.audit_benign_journal(self.root,self.rid)
        self.assertTrue(d['recorded_artifacts_integrity_checked'])
        self.assertEqual(d['result_outcome'],'BENIGN_EXIT_ZERO')

    def test_corrupt_artifact_refused(self):
        self._build(state='RECORDED_LIMITED')
        artifact=next((self.root/'artifacts').iterdir())
        artifact.write_bytes(b'BAD')
        with self.assertRaisesRegex(m.DurableAuditError,'ARTIFACT_INTEGRITY'):
            m.audit_benign_journal(self.root,self.rid)

    def test_symlink_artifact_refused(self):
        self._build(state='RECORDED_LIMITED')
        artifact=next((self.root/'artifacts').iterdir())
        artifact.unlink();artifact.symlink_to(self.dbpath)
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_event_digest_tampering_refused(self):
        self._mutate("UPDATE events SET entry_sha256=? WHERE seq=2",('a'*64,))
        with self.assertRaisesRegex(m.DurableAuditError,'EVENT_CHAIN'):
            m.audit_benign_journal(self.root,self.rid)

    def test_event_payload_tampering_refused(self):
        self._mutate("UPDATE events SET payload_json=? WHERE seq=2",('{}',))
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_previous_hash_tampering_refused(self):
        self._mutate("UPDATE events SET previous_sha256=? WHERE seq=2",('b'*64,))
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_wrong_fingerprint_refused(self):
        self._mutate("UPDATE attempts SET fingerprint=?",('f'*64,))
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_state_laundered_to_recorded_refused(self):
        self._mutate("UPDATE attempts SET state='RECORDED_LIMITED'")
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_state_laundered_to_reserved_refused(self):
        self._mutate("UPDATE attempts SET state='RESERVED'")
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_start_count_forgery_refused(self):
        for val in (1,2,-1):
            with self.subTest(val=val):
                self._mutate('UPDATE attempts SET start_count=?',(val,))
                with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_removed_initial_event_refused(self):
        self._mutate('DELETE FROM events WHERE seq=1')
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_unexpected_request_rejected(self):
        with self.assertRaisesRegex(m.DurableAuditError,'REQUEST_NOT_IN'):
            m.audit_benign_journal(self.root,'ATT_UNKNOWN')

    def test_request_id_unsafe_rejected(self):
        for rid in ('', '../bad', '/tmp/x', 'z'*65, 'x?query'):
            with self.subTest(rid=rid), self.assertRaises(m.DurableAuditError):
                m.audit_benign_journal(self.root,rid)

    def test_readonly_db_remains_byte_identical(self):
        before=self.dbpath.read_bytes()
        m.audit_benign_journal(self.root,self.rid)
        self.assertEqual(self.dbpath.read_bytes(),before)
        self.assertFalse(Path(str(self.dbpath)+'-wal').exists())
        self.assertFalse(Path(str(self.dbpath)+'-shm').exists())

    def test_wal_sidecar_refused(self):
        p=Path(str(self.dbpath)+'-wal')
        p.write_bytes(b'anything')
        with self.assertRaisesRegex(m.DurableAuditError,'LIVE_OR_UNCHECKPOINTED'):
            m.audit_benign_journal(self.root,self.rid)

    def test_shm_sidecar_refused(self):
        p=Path(str(self.dbpath)+'-shm')
        p.write_bytes(b'anything')
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_db_symlink_refused(self):
        backup=self.root/'backup.db'
        self.dbpath.rename(backup)
        self.dbpath.symlink_to(backup)
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_root_symlink_refused(self):
        link=Path(self.temp.name)/'alias'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(link,self.rid)

    def test_group_writable_root_refused(self):
        self.root.chmod(0o770)
        with self.assertRaises(m.DurableAuditError):m.audit_benign_journal(self.root,self.rid)

    def test_systemd_fixture_is_not_benign_audit_scope(self):
        self._build(fixture='r12_systemd')
        with self.assertRaisesRegex(m.DurableAuditError,'SYSTEMD'):
            m.audit_benign_journal(self.root,self.rid)

    def test_actual_benign_pipeline_api_when_present(self):
        try:
            from ardrec.benign_pipeline import BenignPipeline
        except ImportError:
            self.skipTest('LIVE_P9_SOURCE_NOT_IN_TEMPORARY_FIXTURE')
        with tempfile.TemporaryDirectory(prefix='ardrec-r58m-real-p9-') as directory:
            rid='ATT_R58M_REAL_P9'
            journal=BenignPipeline(Path(directory)/'journal')
            journal.submit(rid,'ok',deadline_ms=1000,output_cap=4096)
            journal.accept(rid)
            self.assertEqual(journal.read(rid)['state'],'ACCEPTED')
            self.assertEqual(journal.verify(rid)['p8_operational'],'NO-GO')
            snap=m.audit_benign_journal(journal.root,rid)
            self.assertEqual(snap['journal_state'],'ACCEPTED')
            self.assertEqual(snap['local_fixture_start_intent_count'],0)
            self.assertEqual(snap['event_count'],2)

    def test_actual_recorded_benign_fixture_when_present(self):
        try:
            from ardrec.benign_pipeline import BenignPipeline
        except ImportError:
            self.skipTest('LIVE_P9_SOURCE_NOT_IN_TEMPORARY_FIXTURE')
        with tempfile.TemporaryDirectory(prefix='ardrec-r58m-real-recorded-') as directory:
            rid='ATT_R58M_REAL_RECORDED'
            journal=BenignPipeline(Path(directory)/'journal')
            journal.submit(rid,'ok',deadline_ms=1000,output_cap=4096)
            # Only a local non-network fixture, NOT a VM or technical attempt.
            journal.execute(rid)
            self.assertTrue(journal.verify(rid)['artifacts_verified'])
            snap=m.audit_benign_journal(journal.root,rid)
            self.assertEqual(snap['journal_state'],'RECORDED_LIMITED')
            self.assertEqual(snap['local_fixture_start_intent_count'],1)
            self.assertTrue(snap['recorded_artifacts_integrity_checked'])
            self.assertFalse(snap['case_identity_stored_in_journal'])

    def test_no_binary_or_network_execution_imports(self):
        import ast
        path=REPO/'src/ardrec/coordination/r58m_durable_a5_audit.py'
        tree=ast.parse(path.read_text())
        names=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):names.update(v.name for v in node.names)
            elif isinstance(node,ast.ImportFrom): names.add(node.module or '')
        self.assertFalse(names & {'subprocess','socket','paramiko','asyncssh','fabric'})

    def _review(self):
        identity={'service_id':'SSH_DEV','session_id':'DEV_TUTOR_001',
                  'derived_case_id':'SSH-T01-S01-01','assessment_index':0}
        return {'sha256':'a'*64, 'a4_selected_identity':identity,
                'attempt_intent':{**identity,'attempt_id':self.rid,
                                  'action':'SYNTHETIC_REVIEW_ONLY'},
                'a5':{'actual_attempts_started':0,'actual_attempt_reservations':0,
                      'real_attempt_budget_attested':False},
                'p8_operational':'NO-GO','a6_classification':'ND',
                'technical_truth_accredited':False,'operational_dispatch':False,
                'confirmed_final_risk':None,'published_generation':None}

    def test_readonly_link_is_not_proof_of_case_binding(self):
        review=self._review()
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            d=m.build_durable_a5_link(review,self.root,self.rid)
            self.assertTrue(m.verify_durable_a5_link(d,review,self.root,self.rid))
        self.assertFalse(d['case_identity_binding_accredited'])
        self.assertEqual(d['actual_operational_attempts_started'],0)
        self.assertEqual(d['a6_classification'],'ND')
        self.assertIsNone(d['confirmed_final_risk'])

    def test_link_rejects_wrong_case_identity(self):
        review=self._review()
        review['attempt_intent']['derived_case_id']='SSH-T02-S01-01'
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            with self.assertRaises(m.DurableAuditError):
                m.build_durable_a5_link(review,self.root,self.rid)

    def test_link_rejects_other_request_id(self):
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            with self.assertRaises(m.DurableAuditError):
                m.build_durable_a5_link(self._review(),self.root,'OTHER')

    def test_link_rejects_false_operational_authority(self):
        review=self._review();review['operational_dispatch']=True
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            with self.assertRaises(m.DurableAuditError):
                m.build_durable_a5_link(review,self.root,self.rid)

    def test_link_rejects_real_attempt_claim(self):
        review=self._review();review['a5']['actual_attempts_started']=1
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            with self.assertRaises(m.DurableAuditError):
                m.build_durable_a5_link(review,self.root,self.rid)

    def test_link_rehashed_forged_provenance_refused(self):
        review=self._review()
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            result=m.build_durable_a5_link(review,self.root,self.rid)
            result['case_identity_binding_accredited']=True
            result['sha256']=m.digest({k:v for k,v in result.items() if k!='sha256'})
            with self.assertRaises(m.DurableAuditError):
                m.verify_durable_a5_link(result,review,self.root,self.rid)

    def test_link_report_requires_unchanged_journal(self):
        review=self._review()
        with patch.object(m,'verify_a4_a5_review',return_value=True):
            result=m.build_durable_a5_link(review,self.root,self.rid)
            self._build(state='RESERVED')
            with self.assertRaises(m.DurableAuditError):
                m.verify_durable_a5_link(result,review,self.root,self.rid)


if __name__=='__main__':unittest.main()
