"""R58-I CI contract: offline, unprivileged FTP evaluation after SSH R58-H."""
from __future__ import annotations
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
CI=ROOT/'.github/workflows/ci.yml'
NAME='Evaluar A6 R58-I familias FTP en modo sintetico / Test FTP family variants'
DEMO='Demostrar R58-I FTP CONTROL DATA READ WRITE / Check pinned FTP preview'
PRIOR='Demostrar R58-H sobre catalogo fijado / Check pinned SSH demo'
AFTER='Verificar trazabilidad vigente / Verify current traceability'
CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58i_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58i_ftp_family_demo.py --synthetic-offline'

class FTPFamilyCITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.data=CI.read_text()
    def test_workflow_exists(self):self.assertTrue(CI.is_file())
    def test_prior_ssh_present(self):self.assertIn(PRIOR,self.data)
    def test_step_once(self):self.assertEqual(self.data.count('name: '+NAME),1)
    def test_demo_once(self):self.assertEqual(self.data.count('name: '+DEMO),1)
    def test_command_once(self):self.assertEqual(self.data.count(CMD),1)
    def test_demo_command_once(self):self.assertEqual(self.data.count(DEMO_CMD),1)
    def test_steps_after_ssh_before_traceability(self):
        self.assertLess(self.data.index(PRIOR),self.data.index(NAME))
        self.assertLess(self.data.index(NAME),self.data.index(DEMO))
        self.assertLess(self.data.index(DEMO),self.data.index(AFTER))
    def test_python_job_preserved(self):self.assertIn('Python - empaquetado / packaging',self.data)
    def test_rust_job_preserved(self):self.assertIn('Rust - compilación / build',self.data)
    def test_no_privileged_actions(self):
        section=self.data[self.data.index(NAME):self.data.index(AFTER)]
        for token in ('sudo ','virsh ','nft ','systemctl ','pip install','apt install'):
            self.assertNotIn(token,section)
    def test_sources_created(self):
        self.assertTrue((ROOT/'src/ardrec/evidence/r58i_ftp_family_logic.py').is_file())
        self.assertTrue((ROOT/'scripts/ardrec_p14_r58i_ftp_family_demo.py').is_file())
    def test_pinned_catalog(self):
        code=(ROOT/'src/ardrec/evidence/r58i_ftp_family_logic.py').read_text()
        self.assertIn('CATALOG_PIN_MISMATCH',code)
        self.assertIn('CATALOG_SHA256',code)
    def test_no_execution_from_cli(self):
        code=(ROOT/'scripts/ardrec_p14_r58i_ftp_family_demo.py').read_text()
        self.assertNotIn('subprocess.',code)
        self.assertIn('--synthetic-offline',code)

if __name__=='__main__':unittest.main()
