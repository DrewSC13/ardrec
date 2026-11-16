"""R58-J: check minimal, safe CI insertion and source retention."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/ci.yml'
TEST_CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58j_*.py' -v"
DEMO_CMD="PYTHONPATH=src python3 -B scripts/ardrec_p14_r58j_smb_family_demo.py --synthetic-offline"
OLD='Demostrar R58-I FTP CONTROL DATA READ WRITE / Check pinned FTP preview'
NEW='Evaluar A6 R58-J familias SMB en modo sintetico / Test SMB family variants'

class SMBFamilyCITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=WORKFLOW.read_text()

    def test_workflow_exists(self):self.assertTrue(WORKFLOW.is_file())
    def test_test_step_once(self):self.assertEqual(self.text.count(NEW),1)
    def test_test_command_once(self):self.assertEqual(self.text.count(TEST_CMD),1)
    def test_demo_command_once(self):self.assertEqual(self.text.count(DEMO_CMD),1)
    def test_after_ftp(self):self.assertLess(self.text.index(OLD),self.text.index(NEW))
    def test_before_traceability(self):self.assertLess(self.text.index(NEW),self.text.index('Verificar trazabilidad vigente'))
    def test_python_job(self):self.assertIn('Python - empaquetado / packaging',self.text)
    def test_rust_job(self):self.assertIn('Rust - compilación / build',self.text)
    def test_prior_ssh(self):self.assertIn('Evaluar A6 R58-H familias SSH',self.text)
    def test_prior_ftp(self):self.assertIn('Evaluar A6 R58-I familias FTP',self.text)
    def test_prior_r58g(self):self.assertIn('Probar registro R58-G',self.text)
    def test_no_root_new_step(self):
        start=self.text.index(NEW)
        end=self.text.index('Verificar trazabilidad vigente',start)
        piece=self.text[start:end]
        for banned in ('sudo ','virsh ','nft -f','systemctl','apt install','curl ', 'wget ', 'ssh ', 'smbclient '):
            self.assertNotIn(banned,piece)
    def test_source_exists(self):
        for file in ('src/ardrec/evidence/r58j_smb_family_logic.py',
                     'scripts/ardrec_p14_r58j_smb_family_demo.py',
                     'docs/development/p14-r58j-a6-smb-family-trivalent-preview.md'):
            self.assertTrue((ROOT/file).is_file())

if __name__=='__main__':unittest.main()
