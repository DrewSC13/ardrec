"""R59-A: A5 P9 benigno y SSH histórico verificables, jamás autoridad A6."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r59a_a5_a6_provenance as a
from ardrec.coordination import r58y_observation_register as y
from ardrec.coordination import r58z_verified_workspace as z
from ardrec.coordination import r58m_durable_a5_audit as m


class R59AProvenanceTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = Path(d.name)
        self.db = self.root / 'obs.sqlite3'
        self.p9 = self.root / 'benign'
        self.p9.mkdir()
        self.r422 = self.root / 'r422'
        self.r423 = self.root / 'r423'
        self.r422.mkdir(); self.r423.mkdir()
        self.out = self.root / 'private'
        self.out.mkdir(mode=0o700)
        self.fixture = {
            'physical': {
                'source_kind': 'REAL_READONLY_SSH_SNAPSHOT',
                'r422_report_sha256': y.r424.R422_PIN,
                'r423_report_sha256': y.r424.R423_PIN,
                'route': 'DIRECT_ENS3_EXPECTED', 'arp': 'ABSENT',
                'tx_snapshot': 0, 'rx_snapshot': 15,
                'tap_frames_r422': 0, 'bridge_frames_r422': 0,
                'guest_ping_reported_transmitted_r422': 1,
                'isolation_proven': False, 'p8_operational': 'NO-GO',
            },
            'captured_at_utc': {
                'r422': '2026-11-15T00:46:36Z',
                'r423': '2026-11-15T01:05:07Z',
            },
        }
        self.verifier = patch.object(y, 'verify_sources', return_value=self.fixture)
        self.verifier.start()
        self.addCleanup(self.verifier.stop)
        y.initialize_database(self.db)

    def add_ssh(self):
        return y.import_ssh(self.db, self.r422, self.r423)[1]

    def benign(self):
        return {
            'schema': m.SCHEMA, 'source': 'P9_P12_EXISTING_SQLITE_READ_ONLY',
            'journal_file_sha256': 'a' * 64,
            'request_id': 'R59A_BENIGN_001',
            'request_fingerprint': 'b' * 64,
            'local_fixture_name': 'ok',
            'journal_state': 'RECORDED_LIMITED',
            'local_fixture_start_intent_count': 1,
            'event_count': 4,
            'event_head_sha256': 'c' * 64,
            'result_outcome': 'BENIGN_EXIT_ZERO',
            'recorded_artifacts_integrity_checked': True,
            'local_receipt_chain_self_consistent': True,
            'independent_origin_attested': False,
            'case_identity_stored_in_journal': False,
            'ordinary_retry_allowed': False,
            'operational_dispatch': False,
            'p8_operational': 'NO-GO',
        }

    def report_with_local(self):
        with patch.object(m, 'audit_benign_journal', return_value=self.benign()):
            return a.build_report(self.db,journal_root=self.p9,request_id='R59A_BENIGN_001')

    def rehash(self, doc):
        doc['sha256'] = a.digest(a.canonical({k:v for k,v in doc.items() if k!='sha256'}))

    def test_empty_registry_is_not_positive(self):
        x = a.build_report(self.db)
        self.assertEqual(x['r58y_record_ids'], [])
        self.assertEqual(x['a6_classification'], 'ND')
        self.assertEqual(x['a5_operational_starts'], 0)
        self.assertTrue(a.verify_report(x))

    def test_real_ssh_observation_unbound(self):
        self.add_ssh();x=a.build_report(self.db)
        row=x['a5_reconciliation']['observations_checked'][0]
        self.assertEqual(row['service'],'SSH')
        self.assertEqual(row['a5_binding'],'NO_ATTEMPT_ID_IN_HISTORICAL_SOURCE')
        self.assertEqual(x['a6_reconciliation']['admitted_evidence_count'],0)

    def test_real_r58z_digest_bound(self):
        self.add_ssh();x=a.build_report(self.db)
        self.assertEqual(x['r58z_snapshot_sha256'],z.from_database(self.db)['sha256'])

    def test_benign_p9_journal_is_not_case_join(self):
        self.add_ssh();x=self.report_with_local()
        self.assertEqual(x['r58m_local_benign_a5']['local_fixture_start_intent_count'],1)
        self.assertFalse(x['a5_reconciliation']['operational_attempt_started'])
        self.assertEqual(x['a5_reconciliation']['case_join'],'NOT_ACREDITED')
        self.assertEqual(x['a6_classification'],'ND')

    def test_two_sources_have_different_roles(self):
        self.add_ssh();x=self.report_with_local()
        self.assertEqual(len(x['r58y_record_ids']),1)
        self.assertTrue(x['a5_reconciliation']['local_benign_a5_audited'])
        self.assertIn('P9_BENIGN_JOURNAL_HAS_NO_CASE_IDENTITY',x['a5_reconciliation']['reasons'])

    def test_deterministic_report(self):
        self.add_ssh()
        self.assertEqual(a.build_report(self.db),a.build_report(self.db))

    def test_persist_reopen_idempotent(self):
        self.add_ssh();x=a.build_report(self.db)
        s,p=a.save_report(self.out,x)
        self.assertEqual(s,'CREATED_READONLY_RECONCILIATION')
        self.assertEqual(a.save_report(self.out,x)[0],'REPLAY_IDENTICAL')
        self.assertEqual(a.verify_saved(p,self.db),x)

    def test_p9_persist_reopen_source_validated(self):
        self.add_ssh();x=self.report_with_local()
        _,p=a.save_report(self.out,x)
        with patch.object(m,'audit_benign_journal',return_value=self.benign()):
            self.assertEqual(a.verify_saved(p,self.db,journal_root=self.p9,
                                            request_id='R59A_BENIGN_001'),x)

    def test_modified_physical_source_blocks_reopen(self):
        self.add_ssh();x=a.build_report(self.db);_,p=a.save_report(self.out,x)
        modified=deepcopy(self.fixture)
        modified['physical']['rx_snapshot']=16
        with patch.object(y,'verify_sources',return_value=modified):
            with self.assertRaises(y.ObservationError):a.verify_saved(p,self.db)

    def test_modified_p9_source_blocks_reopen(self):
        self.add_ssh();x=self.report_with_local();_,p=a.save_report(self.out,x)
        changed=self.benign();changed['event_head_sha256']='d'*64
        with patch.object(m,'audit_benign_journal',return_value=changed):
            with self.assertRaisesRegex(a.ReconciliationError,'SOURCE_CHANGED'):
                a.verify_saved(p,self.db,journal_root=self.p9,
                               request_id='R59A_BENIGN_001')

    def test_tampered_file_rejected(self):
        x=a.build_report(self.db);_,p=a.save_report(self.out,x)
        p.write_bytes(p.read_bytes().replace(b'NO-GO',b'GO-GO',1))
        with self.assertRaises(a.ReconciliationError):a.read_report(p)

    def test_world_readable_report_rejected(self):
        x=a.build_report(self.db);_,p=a.save_report(self.out,x)
        p.chmod(0o644)
        with self.assertRaisesRegex(a.ReconciliationError,'UNSAFE'):a.read_report(p)

    def test_symlink_rejected(self):
        x=a.build_report(self.db);_,p=a.save_report(self.out,x)
        sym=self.out/'link.json';sym.symlink_to(p)
        with self.assertRaises(a.ReconciliationError):a.read_report(sym)

    def test_directory_permissions_guard(self):
        x=a.build_report(self.db);self.out.chmod(0o755)
        with self.assertRaisesRegex(a.ReconciliationError,'PERMISSIONS'):
            a.save_report(self.out,x)

    def test_reject_fake_p8_even_with_valid_hash(self):
        x=a.build_report(self.db);x['p8_operational']='GO';self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'FALSE_AUTHORITY'):
            a.verify_report(x)

    def test_reject_fake_a5_start_even_with_valid_hash(self):
        x=a.build_report(self.db);x['a5_operational_starts']=1;self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'FALSE_AUTHORITY'):
            a.verify_report(x)

    def test_reject_fake_a6_positive_even_with_valid_hash(self):
        x=a.build_report(self.db);x['a6_classification']='POSITIVO_VALIDO';self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'FALSE_AUTHORITY'):
            a.verify_report(x)

    def test_reject_fake_final_risk_even_with_valid_hash(self):
        x=a.build_report(self.db);x['confirmed_final_risk']='1/2';self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'FALSE_AUTHORITY'):
            a.verify_report(x)

    def test_reject_fake_publication_even_with_valid_hash(self):
        x=a.build_report(self.db);x['published_generation']='GEN_1';self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'FALSE_AUTHORITY'):
            a.verify_report(x)

    def test_reject_changed_causes_with_rehashed_document(self):
        x=a.build_report(self.db)
        x['a5_reconciliation']['reasons']=[];self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'SEMANTICS'):
            a.verify_report(x)

    def test_reject_invented_ftp_smb_receipt(self):
        x=a.build_report(self.db)
        x['a5_reconciliation']['observations_checked']=[{
            'observation_id':'OBS_SSH_'+'a'*64,'service':'FTPS',
            'a5_binding':'NO_ATTEMPT_ID_IN_HISTORICAL_SOURCE',
            'a6_decision':'ND_UNBOUND_NO_DECLARED_CONDITION',
            'source_kind':'REAL_READONLY_SSH_SNAPSHOT'}]
        x['r58y_record_ids']=['OBS_SSH_'+'a'*64]
        self.rehash(x)
        with self.assertRaisesRegex(a.ReconciliationError,'OBSERVATION_INJECTION'):
            a.verify_report(x)

    def test_duplicate_json_key_rejected(self):
        x=a.build_report(self.db);_,p=a.save_report(self.out,x)
        raw=p.read_text()
        p.write_text(raw.replace('"schema":','"schema":"fake","schema":',1))
        with self.assertRaisesRegex(a.ReconciliationError,'DUPLICATE_JSON_KEY'):
            a.read_report(p)

    def test_no_source_pairing_refused(self):
        with self.assertRaisesRegex(a.ReconciliationError,'REQUIRED_TOGETHER'):
            a.build_report(self.db,journal_root=self.p9)
        with self.assertRaisesRegex(a.ReconciliationError,'REQUIRED_TOGETHER'):
            a.build_report(self.db,request_id='R59A_BENIGN_001')

    def test_invalid_p9_summary_refused(self):
        bad=self.benign();bad['case_identity_stored_in_journal']=True
        with patch.object(m,'audit_benign_journal',return_value=bad):
            with self.assertRaisesRegex(a.ReconciliationError,'AUTHORITY_INVALID'):
                a.build_report(self.db,journal_root=self.p9,request_id='R59A_BENIGN_001')

    def test_bad_p9_result_refused(self):
        bad=self.benign();bad['result_outcome']='FULL_SSH_EXPL0IT'
        with patch.object(m,'audit_benign_journal',return_value=bad):
            with self.assertRaisesRegex(a.ReconciliationError,'RESULT_NOT_VERIFIED'):
                a.build_report(self.db,journal_root=self.p9,request_id='R59A_BENIGN_001')

    def test_report_missing_field_refused(self):
        x=a.build_report(self.db);x.pop('technical_truth_accredited')
        with self.assertRaises(a.ReconciliationError):a.verify_report(x)

    def test_format_has_provenance_without_vulnerability_claim(self):
        self.add_ssh();x=a.build_report(self.db)
        printed=a.format_text(x)
        self.assertIn('OBS_SSH_',printed)
        self.assertIn('A6: ND',printed)
        self.assertIn('P8: NO-GO',printed)
        self.assertNotIn('POSITIVO_VALIDO',printed)


if __name__ == '__main__': unittest.main()
