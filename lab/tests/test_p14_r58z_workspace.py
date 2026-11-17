"""R58-Z: pruebas de sesión documental desde SQLite R58-Y, A6 ND y A9 bloqueado."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r58y_observation_register as y
from ardrec.coordination import r58z_verified_workspace as z


class R58ZTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.db=self.root/'obs.sqlite3'
        self.r422=self.root/'r422'; self.r423=self.root/'r423'
        self.r422.mkdir();self.r423.mkdir()
        self.store=self.root/'private'
        self.store.mkdir(mode=0o700)
        self.fixture={'physical': {
            'source_kind':'REAL_READONLY_SSH_SNAPSHOT',
            'r422_report_sha256':y.r424.R422_PIN,
            'r423_report_sha256':y.r424.R423_PIN,
            'route':'DIRECT_ENS3_EXPECTED','arp':'ABSENT',
            'tx_snapshot':0,'rx_snapshot':15,
            'tap_frames_r422':0,'bridge_frames_r422':0,
            'guest_ping_reported_transmitted_r422':1,
            'isolation_proven':False,'p8_operational':'NO-GO'},
            'captured_at_utc':{'r422':'2026-11-15T00:46:36Z',
                               'r423':'2026-11-15T01:05:07Z'}}
        self.patch=patch.object(y,'verify_sources',return_value=self.fixture)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        y.initialize_database(self.db)

    def imported(self):
        outcome, record = y.import_ssh(self.db,self.r422,self.r423)
        self.assertEqual(outcome,'IMPORTED')
        return record

    def test_empty_is_observation_none(self):
        d=z.from_database(self.db)
        self.assertEqual(d['total_observations'],0)
        self.assertEqual(d['services'][0]['stages'][9]['status'],'SIN_OBSERVACION')

    def test_real_observation_derived_from_r58y(self):
        rec=self.imported();d=z.from_database(self.db)
        self.assertEqual(d['services'][0]['observations'][0]['record_id'],rec['record_id'])
        self.assertEqual([g['observation_count'] for g in d['services']],[1,0,0])

    def test_a5_a6_a7_a9_never_promoted(self):
        self.imported();d=z.from_database(self.db)
        self.assertEqual(d['a5_operational_starts'],0)
        self.assertEqual(d['a6_accredited_conditions'],0)
        self.assertEqual(d['services'][0]['stages'][5]['status'],'ND')
        self.assertIsNone(d['a7_confirmed_rf'])
        self.assertIsNone(d['a9_published_generation'])

    def test_persist_reopen_and_idempotence(self):
        self.imported();d=z.from_database(self.db)
        first,path=z.persist_snapshot(self.store,d)
        second,path2=z.persist_snapshot(self.store,z.from_database(self.db))
        self.assertEqual((first,second),('CREATED_DOCUMENTARY_ONLY','REPLAY_IDENTICAL'))
        self.assertEqual(path,path2)
        self.assertEqual(z.verify_saved_against_sources(path,self.db),d)

    def test_source_changed_blocks_reopen(self):
        self.imported();d=z.from_database(self.db)
        _,path=z.persist_snapshot(self.store,d)
        changed=deepcopy(self.fixture)
        changed['physical']['rx_snapshot']=16
        with patch.object(y,'verify_sources',return_value=changed):
            with self.assertRaises(y.ObservationError):
                z.verify_saved_against_sources(path,self.db)

    def test_reject_false_risk_with_recomputed_hash(self):
        self.imported();d=z.from_database(self.db)
        bad=deepcopy(d);bad['a7_confirmed_rf']='1/2'
        bad['sha256']=z.sha(z.canon({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaisesRegex(z.WorkspaceError,'authority_escalation'):
            z.verify_workspace(bad)

    def test_reject_false_generation_with_recomputed_hash(self):
        d=z.from_database(self.db);d['a9_published_generation']='GEN_1'
        d['sha256']=z.sha(z.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(z.WorkspaceError):z.verify_workspace(d)

    def test_reject_fake_ftps_even_with_valid_hash(self):
        d=z.from_database(self.db);d['services'][1]['observations'].append({'fake':True})
        d['services'][1]['observation_count']=1
        d['services'][1]['stages']=z._stage_rows('FTPS',1)
        d['total_observations']=1
        d['sha256']=z.sha(z.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(z.WorkspaceError,'invented_ftp_smb'):
            z.verify_workspace(d)

    def test_tampered_snapshot_rejected(self):
        self.imported();_,p=z.persist_snapshot(self.store,z.from_database(self.db))
        p.write_bytes(p.read_bytes().replace(b'NO-GO',b'GO-GO',1))
        with self.assertRaises(z.WorkspaceError):z.read_snapshot(p)

    def test_missing_snapshot_rejected(self):
        with self.assertRaises(z.WorkspaceError):z.read_snapshot(self.store/'absent.json')

    def test_symlink_snapshot_rejected(self):
        _,p=z.persist_snapshot(self.store,z.from_database(self.db))
        sym=self.store/'alias.json';sym.symlink_to(p)
        with self.assertRaises(z.WorkspaceError):z.read_snapshot(sym)

    def test_world_readable_snapshot_rejected(self):
        _,p=z.persist_snapshot(self.store,z.from_database(self.db))
        p.chmod(0o644)
        with self.assertRaises(z.WorkspaceError):z.read_snapshot(p)

    def test_directory_permission_guard(self):
        self.store.chmod(0o755)
        with self.assertRaisesRegex(z.WorkspaceError,'directory_permissions'):
            z.persist_snapshot(self.store,z.from_database(self.db))

    def test_printed_stages_and_provenance(self):
        self.imported();doc=z.from_database(self.db)
        s='\n'.join(z.view_lines(doc,0,9))
        self.assertIn('CAPTURA SSH R42.2',s)
        self.assertIn('A6:ND',s)
        self.assertIn('NO es evidencia A6 ni generacion A9',s)

    def test_frame_geometry_and_determinism(self):
        self.imported();doc=z.from_database(self.db)
        for service in range(3):
            f=z.frame(doc,service,9,110,31)
            self.assertEqual(len(f),31)
            self.assertTrue(all(len(s)==110 for s in f))
            self.assertEqual(f,z.frame(doc,service,9,110,31))

    def test_reject_duplicate_record(self):
        rec=self.imported()
        with self.assertRaises(z.WorkspaceError):z.build_workspace([rec,rec])

    def test_reject_synthetic_a6_claim(self):
        self.imported();d=z.from_database(self.db)
        bad=deepcopy(d)
        bad['services'][0]['stages'][5]['status']='VERDADERO'
        bad['sha256']=z.sha(z.canon({k:v for k,v in bad.items() if k!='sha256'}))
        with self.assertRaises(z.WorkspaceError):z.verify_workspace(bad)

    def test_sha_reproducible_from_same_sqlite(self):
        self.imported()
        self.assertEqual(z.from_database(self.db)['sha256'],z.from_database(self.db)['sha256'])

    def test_empty_snapshot_no_fake_results(self):
        d=z.from_database(self.db)
        self.assertEqual(z.persist_snapshot(self.store,d)[0],'CREATED_DOCUMENTARY_ONLY')
        self.assertTrue(z.verify_workspace(d))


if __name__=='__main__':
    unittest.main()
