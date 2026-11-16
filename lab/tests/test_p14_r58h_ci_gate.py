"""R58-H CI regression: no privileged actions, pin check, old steps preserved."""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
CI=ROOT/'.github/workflows/ci.yml'
NAME='Evaluar A6 R58-H familias SSH en modo sintetico / Test eight SSH family classifications'
DEMO='Demostrar R58-H sobre catalogo fijado / Check pinned SSH demo'
OLD='Probar registro R58-G A6 de confianza y vigencia offline / Test pinned registry trust policy'
CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58h_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58h_ssh_family_demo.py --synthetic-offline'

class SSHFamilyCITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=CI.read_text()
    def test_previous_r58g_still_present(self):self.assertIn(OLD,self.data)
    def test_ssh_step_once(self):self.assertEqual(self.data.count('name: '+NAME),1)
    def test_cli_step_once(self):self.assertEqual(self.data.count('name: '+DEMO),1)
    def test_ssh_test_command_once(self):self.assertEqual(self.data.count(CMD),1)
    def test_ssh_demo_command_once(self):self.assertEqual(self.data.count(DEMO_CMD),1)
    def test_new_steps_order(self):
        self.assertLess(self.data.index(OLD),self.data.index(NAME))
        self.assertLess(self.data.index(NAME),self.data.index(DEMO))
        self.assertLess(self.data.index(DEMO),self.data.index('Verificar trazabilidad vigente'))
    def test_existing_development_python_job(self):self.assertIn('Python - empaquetado / packaging',self.data)
    def test_existing_development_rust_job(self):self.assertIn('Rust - compilación / build',self.data)
    def test_no_privileged_new_actions(self):
        frag=self.data[self.data.index(NAME):self.data.index('Verificar trazabilidad vigente')]
        self.assertNotIn('sudo ',frag)
        for token in ('virsh ','nft ','systemctl ','start ','nmap ','ssh '):
            self.assertNotIn('run: '+token,frag)
    def test_source_exists(self):
        self.assertTrue((ROOT/'src/ardrec/evidence/r58h_ssh_family_logic.py').is_file())
        self.assertTrue((ROOT/'scripts/ardrec_p14_r58h_ssh_family_demo.py').is_file())
    def test_catalog_sha_pinned_by_source(self):
        text=(ROOT/'src/ardrec/evidence/r58h_ssh_family_logic.py').read_text()
        self.assertIn('5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e',text)
        self.assertIn('CATALOG_PIN_MISMATCH',text)

if __name__=='__main__':unittest.main()
