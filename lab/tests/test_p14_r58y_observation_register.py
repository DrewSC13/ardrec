"""R58-Y: pruebas offline de durabilidad, integridad y frontera A5/A6/A9."""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r58y_observation_register as m


class TestR58Y(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.db=self.root/'obs.sqlite3'
        self.s422=self.root/'r422'
        self.s423=self.root/'r423'
        self.s422.mkdir();self.s423.mkdir()
        self.physical={
            'source_kind':'REAL_READONLY_SSH_SNAPSHOT',
            'r422_report_sha256':m.r424.R422_PIN,
            'r423_report_sha256':m.r424.R423_PIN,
            'route':'DIRECT_ENS3_EXPECTED','arp':'ABSENT',
            'tx_snapshot':0,'rx_snapshot':15,
            'tap_frames_r422':0,'bridge_frames_r422':0,
            'guest_ping_reported_transmitted_r422':1,
            'isolation_proven':False,'p8_operational':'NO-GO',
        }
        self.source={'physical':self.physical,
                     'captured_at_utc':{'r422':'2026-11-15T00:46:14Z',
                                        'r423':'2026-11-15T01:04:51Z'}}
        self.patcher=patch.object(m,'verify_sources',return_value=self.source)
        self.mock_source=self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def import_one(self):
        return m.import_ssh(self.db,self.s422,self.s423)

    def test_stable_record_identity(self):
        a=m.build_ssh_record(self.s422,self.s423)
        b=m.build_ssh_record(self.s422,self.s423)
        self.assertEqual(a,b)
        self.assertTrue(a['record_id'].startswith('OBS_SSH_'))
        self.assertEqual(len(a['record_id']),72)

    def test_initialize_empty_without_forged_observations(self):
        self.assertEqual(m.initialize_database(self.db),0)
        self.assertEqual(m.load_records(self.db),[])
        self.assertEqual(m.initialize_database(self.db),0)

    def test_import_and_reopen(self):
        state,record=self.import_one()
        self.assertEqual(state,'IMPORTED')
        rows=m.load_records(self.db)
        self.assertEqual(rows,[record])
        self.assertEqual(self.db.stat().st_mode & 0o777,0o600)

    def test_replay_idempotent(self):
        first=self.import_one()[1]
        self.assertEqual(self.import_one(),('REPLAY_IDENTICAL',first))
        self.assertEqual(len(m.load_records(self.db)),1)

    def test_reject_source_drift(self):
        self.import_one()
        changed=deepcopy(self.source)
        changed['physical']['rx_snapshot']=16
        with patch.object(m,'verify_sources',return_value=changed):
            with self.assertRaisesRegex(m.ObservationError,'source_no_longer_matches'):
                m.load_records(self.db)

    def test_reject_tampered_database_payload(self):
        self.import_one()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('UPDATE observations SET payload=?',('tampered',))
        with self.assertRaises(m.ObservationError):
            m.load_records(self.db,revalidate_sources=False)

    def test_reject_hash_recomputed_for_false_claim(self):
        self.import_one()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            row=conn.execute('SELECT payload FROM observations').fetchone()
            import json
            payload=json.loads(row[0])
            payload['a6_classification']='VERDADERO'
            raw=m.canon(payload).decode('ascii')
            conn.execute('UPDATE observations SET payload=?,sha256=?',(raw,m.digest(raw.encode())))
        with self.assertRaisesRegex(m.ObservationError,'record_authority_escalation'):
            m.load_records(self.db,revalidate_sources=False)

    def test_reject_world_readable_database(self):
        self.import_one()
        self.db.chmod(0o644)
        with self.assertRaisesRegex(m.ObservationError,'database_file_unsafe'):
            m.load_records(self.db)

    def test_reject_database_symlink(self):
        self.import_one()
        link=self.root/'shortcut.sqlite3'
        link.symlink_to(self.db)
        with self.assertRaisesRegex(m.ObservationError,'symlink_path_denied'):
            m.load_records(link)

    def test_no_fake_ftp_smb_records(self):
        _,rec=self.import_one()
        for service in ('FTPS','SMB'):
            lines='\n'.join(m.service_rows([rec],service))
            self.assertIn('SIN RECIBO FISICO',lines)
            self.assertIn('A6: ND',lines)
            self.assertIn('A9: GENERACION NO PUBLICADA',lines)

    def test_ssh_not_counted_as_a6_or_a5(self):
        _,rec=self.import_one()
        self.assertIsNone(rec['a5_attempt_id'])
        self.assertEqual(rec['a6_classification'],'ND')
        self.assertIsNone(rec['a7_confirmed_rf'])
        self.assertIsNone(rec['a9_published_generation'])
        self.assertFalse(rec['technical_truth_accredited'])
        self.assertIn('ENS3 TX: 0', '\n'.join(m.service_rows([rec],'SSH')))

    def test_layout_deterministic(self):
        _,rec=self.import_one()
        for selected in range(3):
            frame=m.render_frame([rec],selected,112,33)
            self.assertEqual(len(frame),33)
            self.assertTrue(all(len(line)==112 for line in frame))
            self.assertIn(m.SERVICES[selected],''.join(frame))
            self.assertEqual(frame,m.render_frame([rec],selected,112,33))

    def test_invalid_layout_fails(self):
        with self.assertRaises(m.ObservationError):
            m.render_frame([],width=30)

    def test_empty_records_not_fake_success(self):
        lines='\n'.join(m.service_rows([],'SSH'))
        self.assertIn('SIN RECIBO FISICO',lines)
        self.assertIn('A6: ND',lines)

    def test_reject_invented_claim_with_valid_digest(self):
        rec=m.build_ssh_record(self.s422,self.s423)
        rec['p8_operational']='GO'
        with self.assertRaisesRegex(m.ObservationError,'record_authority_escalation'):
            m.validate_record(rec)

    def test_reject_extra_physical_data(self):
        rec=m.build_ssh_record(self.s422,self.s423)
        rec['physical']['r422_report_sha256']='0'*64
        with self.assertRaises(m.ObservationError):
            m.validate_record(rec)

    def test_source_verifier_double_read_and_timestamps(self):
        self.patcher.stop()
        self.addCleanup(lambda: None)
        witness={'captured_at_utc':'2026-11-15T00:46:14Z'}
        route={'captured_at_utc':'2026-11-15T01:04:51Z'}
        with patch.object(m.r424,'read_physical',side_effect=[self.physical,self.physical]) as read, \
             patch.object(m.r424.r422,'verify_private_receipt',return_value=witness), \
             patch.object(m.r424,'verified_directory',return_value={m.r424.r423.RESULT:self.s423/'r.json'}), \
             patch.object(m.r424.r365,'read_json',return_value=route), \
             patch.object(m.r424.r423,'verify_report'):
            out=m.verify_sources(self.s422,self.s423)
        self.assertEqual(read.call_count,2)
        self.assertEqual(out['captured_at_utc']['r422'],witness['captured_at_utc'])

    def test_source_drift_between_reads_denied(self):
        self.patcher.stop()
        changed=dict(self.physical);changed['rx_snapshot']=16
        with patch.object(m.r424,'read_physical',side_effect=[self.physical,changed]), \
             patch.object(m.r424.r422,'verify_private_receipt',return_value={'captured_at_utc':'2026-11-15T00:46:14Z'}), \
             patch.object(m.r424,'verified_directory',return_value={m.r424.r423.RESULT:self.s423/'r.json'}), \
             patch.object(m.r424.r365,'read_json',return_value={'captured_at_utc':'2026-11-15T01:04:51Z'}), \
             patch.object(m.r424.r423,'verify_report'):
            with self.assertRaisesRegex(m.ObservationError,'source_changed_during_read'):
                m.verify_sources(self.s422,self.s423)


if __name__=='__main__':
    unittest.main()
