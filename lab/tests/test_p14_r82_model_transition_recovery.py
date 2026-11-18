"""R82: real SQLite transaction/replay and reject tampering, NO operational changes."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO/'scripts'))
import ardrec_p14_r81_functional_smoke as r81
import ardrec_p14_r82_model_transition_recovery as r82
from ardrec.persistence.codec import canonical,digest

@unittest.skipIf(os.geteuid()==0,'R82 tests require nonroot')
class ModelTransitionAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='ardrec-r82-')
        cls.r81=Path(cls.tmp.name)/'r81'
        cls.root=Path(cls.tmp.name)/'r82'
        cls.source=r81.create(cls.r81)
        cls.doc=r82.create(cls.root,cls.r81)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_01_replay_exact(self):
        self.assertEqual(r82.verify(self.root,self.r81),self.doc)

    def test_02_source_is_fresh_dev(self):
        self.assertEqual(r81.verify(self.r81),self.source)
        self.assertEqual(self.doc['r81_software_smoke_sha256'],self.source['sha256'])
        self.assertEqual(self.doc['r81_synthetic_units'],54)
        self.assertEqual(self.doc['r81_family_count'],25)
        self.assertEqual(self.doc['r58_model_cases'],29)
        self.assertTrue(self.doc['populations_are_distinct'])

    def test_03_model_transitions_and_phase_counts(self):
        self.assertEqual(self.doc['model_t1_count'],2)
        self.assertEqual(self.doc['model_t8_pause_count'],1)
        self.assertEqual(self.doc['model_t9_resume_count'],1)
        self.assertEqual(self.doc['model_t10_stop_count'],1)
        self.assertEqual(self.doc['model_phase_counts'],
                         {'PREPARADO':27,'PENDIENTE':1,'PAUSADO':0,'DETENIDO':1})

    def test_04_atomic_rollback_and_replay(self):
        self.assertEqual(self.doc['atomic_rollback_checks'],2)
        self.assertEqual(self.doc['idempotent_replay_checks'],2)
        self.assertTrue(self.doc['terminal_reentry_rejected'])
        self.assertEqual(len(self.doc['model_cases']),2)

    def test_05_no_operational_authority(self):
        self.assertEqual(self.doc['a6'],'ND')
        self.assertIsNone(self.doc['confirmed_rf'])
        self.assertFalse(self.doc['technical_truth_accredited'])
        self.assertFalse(self.doc['operational_state_mutated'])
        self.assertEqual(self.doc['operational_transitions_applied'],0)
        self.assertEqual(self.doc['physical_executions'],0)
        self.assertFalse(self.doc['operational_dispatch'])
        self.assertEqual(self.doc['p8_operational'],'NO-GO')
        self.assertEqual(self.doc['system_functional_acceptance'],'PENDING')
        self.assertEqual(self.doc['experimental_validation'],'NOT_RUN')

    def test_06_not_able_to_recreate(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_SECOND_PROCESS')):
            with self.assertRaises(ValueError):
                r82.create(self.root,self.r81)

    def test_07_verify_no_subprocess(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_CHILD_PROCESS')):
            self.assertEqual(r82.verify(self.root,self.r81),self.doc)

    def test_08_reject_forged_go_and_risk_even_rehashed(self):
        p=self.root/'MANIFEST.json'; old=p.read_bytes()
        try:
            for field,value in (('p8_operational','GO'),('confirmed_rf','5/12'),
                                ('operational_transitions_applied',1),
                                ('physical_executions',1)):
                with self.subTest(field=field):
                    forged=copy.deepcopy(self.doc)
                    forged[field]=value
                    forged['sha256']=digest(canonical({k:v for k,v in forged.items() if k!='sha256'}))
                    p.write_bytes(canonical(forged)+b'\n')
                    with self.assertRaisesRegex(r82.R82Error,'MANIFEST_REPLAY_DRIFT'):
                        r82.verify(self.root,self.r81)
        finally:p.write_bytes(old)

    def test_09_reject_modified_source_r81(self):
        p=self.r81/'MANIFEST.json';before=p.read_bytes()
        try:
            p.write_bytes(before+b'\n')
            with self.assertRaises(ValueError):r82.verify(self.root,self.r81)
        finally:p.write_bytes(before)

    def test_10_reject_injected_sqlite_event(self):
        path=next((self.root/'overlay').iterdir())
        before=path.read_bytes()
        try:
            with sqlite3.connect(path) as conn:
                conn.execute("UPDATE events SET sha=? WHERE seq=1",('f'*64,))
            with self.assertRaises(ValueError):r82.verify(self.root,self.r81)
        finally:path.write_bytes(before)
        self.assertEqual(r82.verify(self.root,self.r81)['sha256'],self.doc['sha256'])

    def test_11_reject_untrusted_extra_artifact(self):
        p=self.root/'BAD.txt'
        try:
            p.write_text('NO')
            with self.assertRaisesRegex(r82.R82Error,'UNEXPECTED_TOP_LEVEL_ARTIFACT'):
                r82.verify(self.root,self.r81)
        finally:p.unlink()

    def test_12_reject_extra_model_database(self):
        p=self.root/'overlay'/'extra.sqlite3'
        try:
            p.write_bytes(b'forged')
            with self.assertRaisesRegex(r82.R82Error,'MODEL_FILE_SET_DRIFT'):
                r82.verify(self.root,self.r81)
        finally:p.unlink()

    def test_13_reject_nonprivate_folder(self):
        p=self.root/'overlay'
        p.chmod(0o755)
        try:
            with self.assertRaisesRegex(r82.R82Error,'MODEL_DIRECTORY_UNSAFE'):
                r82.verify(self.root,self.r81)
        finally:p.chmod(0o700)

    def test_14_reject_symlink(self):
        link=Path(self.tmp.name)/'link_r82'
        link.symlink_to(self.root)
        try:
            with self.assertRaises(ValueError):r82.verify(link,self.r81)
        finally:link.unlink()

    def test_15_cli_verify(self):
        cmd=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r82_model_transition_recovery.py'),
             '--verify','--work-dir',str(self.root),'--r81-receipt',str(self.r81),
             '--expected-r81-sha256',self.source['sha256']]
        result=subprocess.run(cmd,cwd=REPO,capture_output=True,timeout=120)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'R82=PASS_REPLAY_NO_EXECUTION',result.stdout)
        self.assertIn(b'R82_P8=NO-GO',result.stdout)

    def test_16_cli_wrong_source_pin(self):
        cmd=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r82_model_transition_recovery.py'),
             '--verify','--work-dir',str(self.root),'--r81-receipt',str(self.r81),
             '--expected-r81-sha256','0'*64]
        result=subprocess.run(cmd,cwd=REPO,capture_output=True,timeout=120)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'EXPECTED_R81_SHA_MISMATCH',result.stderr)

    def test_17_source_absence_operational_commands(self):
        text=(REPO/'scripts/ardrec_p14_r82_model_transition_recovery.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'shell=True',
                          'virsh ', 'sudo ', 'systemctl ', 'nft ',
                          'gh pr merge', 'socket.connect('):
            self.assertNotIn(forbidden,text)

if __name__=='__main__':unittest.main()
