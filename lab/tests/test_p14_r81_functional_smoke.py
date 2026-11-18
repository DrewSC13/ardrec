"""R81: aceptación funcional sintética de software desde una sesión fresca."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
sys.path.insert(0, str(REPO/'scripts'))

import ardrec_p14_r81_functional_smoke as r81
from ardrec.persistence.codec import canonical

@unittest.skipIf(os.geteuid() == 0, 'R81 no admite root')
class FreshSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ardrec-r81-')
        cls.addpath = Path(cls.temp.name)
        cls.root = cls.addpath / 'session'
        cls.document = r81.create(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_01_verify_exact_manifest(self):
        self.assertEqual(r81.verify(self.root), self.document)

    def test_02_fresh_lifecycle(self):
        self.assertEqual(self.document['stage_count'],10)
        self.assertEqual(self.document['synthetic_units'],54)
        self.assertEqual(self.document['family_count'],25)
        self.assertEqual(self.document['local_benign_starts'],1)
        self.assertEqual(self.document['presentation_count'],8)

    def test_03_no_authority(self):
        self.assertEqual(self.document['a6'],'ND')
        self.assertIsNone(self.document['confirmed_rf'])
        self.assertEqual(self.document['a8_applied_transitions'],0)
        self.assertEqual(self.document['a9_new_generations'],0)
        self.assertEqual(self.document['physical_executions'],0)
        self.assertFalse(self.document['operational_dispatch'])
        self.assertEqual(self.document['p8_operational'],'NO-GO')
        self.assertEqual(self.document['system_functional_acceptance'],'PENDING')
        self.assertEqual(self.document['experimental_validation'],'NOT_RUN')

    def test_04_verify_never_executes_child(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('EXECUTION_FORBIDDEN')):
            self.assertEqual(r81.verify(self.root), self.document)

    def test_05_second_create_rejected_without_second_start(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('RECREATION_FORBIDDEN')):
            with self.assertRaisesRegex(ValueError,'already_exists'):
                r81.create(self.root)

    def test_06_presentations_match_rederivation(self):
        docs=r81.recompute(self.root)
        self.assertEqual(docs,self.document)
        names={p.name for p in (self.root/'views').iterdir()}
        self.assertEqual(names,{n for n,_,_ in r81.VIEWS})
        for p in (self.root/'views').iterdir():
            self.assertIn(b'R80=PASS_VERIFIED_READONLY',p.read_bytes())
            self.assertIn(b'P8=NO-GO',p.read_bytes())

    def test_07_negative_fake_GO_rejected_even_rehashed(self):
        m=self.root/'MANIFEST.json'
        old=m.read_bytes()
        try:
            forged=copy.deepcopy(self.document)
            forged['p8_operational']='GO'
            forged['sha256']=r81.digest(canonical({k:v for k,v in forged.items() if k!='sha256'}))
            m.write_bytes(canonical(forged)+b'\n')
            with self.assertRaisesRegex(r81.R81Error,'MANIFEST_REPLAY_DRIFT'):
                r81.verify(self.root)
        finally:
            m.write_bytes(old)

    def test_08_negative_fake_rf_rejected(self):
        p=self.root/'MANIFEST.json'
        old=p.read_bytes()
        try:
            forged=copy.deepcopy(self.document)
            forged['confirmed_rf']='5/12'
            p.write_bytes(canonical(forged)+b'\n')
            with self.assertRaisesRegex(r81.R81Error,'MANIFEST_REPLAY_DRIFT'):
                r81.verify(self.root)
        finally:
            p.write_bytes(old)

    def test_09_negative_tampered_presentation_rejected(self):
        p=self.root/'views'/'algoritmo_A7.txt'
        old=p.read_bytes()
        try:
            p.write_bytes(old+b'FORGED')
            with self.assertRaisesRegex(r81.R81Error,'VIEW_REPLAY_DRIFT'):
                r81.verify(self.root)
        finally:
            p.write_bytes(old)

    def test_10_negative_tampered_source_rejected(self):
        p=self.root/'sources'/'r76.json'
        old=p.read_bytes()
        try:
            p.write_bytes(old+b'\n')
            with self.assertRaises(ValueError):
                r81.verify(self.root)
        finally:
            p.write_bytes(old)

    def test_11_negative_extra_view_rejected(self):
        p=self.root/'views'/'EXTRA.txt'
        try:
            r81.write(self.root,'views/EXTRA.txt',b'EXTRA')
            with self.assertRaisesRegex(r81.R81Error,'EXTRA_OR_MISSING_VIEW'):
                r81.verify(self.root)
        finally:
            p.unlink()

    def test_12_negative_symlink_rejected(self):
        p=self.addpath/'ln'
        p.symlink_to(self.root)
        try:
            with self.assertRaises(ValueError):
                r81.verify(p)
        finally:
            p.unlink()

    def test_13_reject_parent_world_readable(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)
            parent.chmod(0o755)
            with self.assertRaisesRegex(ValueError,'private_parent_0700'):
                r81.create(parent/'new')

    def test_14_cli_verify(self):
        command=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r81_functional_smoke.py'),
                 '--verify','--work-dir',str(self.root)]
        result=subprocess.run(command,cwd=REPO,capture_output=True,timeout=40)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'PASS_VERIFIED_NO_EXECUTION',result.stdout)
        self.assertIn(b'SYSTEM_ACCEPTANCE=PENDING',result.stdout)

    def test_15_source_no_network_or_host_tools(self):
        source=(REPO/'scripts/ardrec_p14_r81_functional_smoke.py').read_text()
        for forbidden in ('os.system(', 'subprocess.run(', 'shell=True',
                          'systemctl ', 'virsh ', 'sudo ', 'nft ',
                          'gh pr merge'):
            self.assertNotIn(forbidden,source)

class Shape(unittest.TestCase):
    def test_16_requires_mode(self):
        result=subprocess.run([sys.executable,'-B',
            str(REPO/'scripts/ardrec_p14_r81_functional_smoke.py'),
            '--work-dir','/tmp/xx'],cwd=REPO,capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)

    def test_17_security_labels(self):
        self.assertIn('SYNTHETIC_DEV',r81.SOURCE)
        self.assertEqual(len(r81.VIEWS),8)

if __name__=='__main__':
    unittest.main()
