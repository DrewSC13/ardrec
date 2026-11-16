"""R58-G gate: one new offline, non-privileged workflow step."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/ci.yml'
STEP='Probar registro R58-G A6 de confianza y vigencia offline / Test pinned registry trust policy'
CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58g_*.py' -v"
OLD='Probar A6 R58-F testigos Ed25519 offline / Test signed witness evidence bindings'

class TestR58GCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content=WORKFLOW.read_text(encoding='utf-8')
    def test_workflow_present(self):self.assertTrue(WORKFLOW.is_file())
    def test_once_step(self):self.assertEqual(self.content.count(STEP),1)
    def test_once_run(self):self.assertEqual(self.content.count(CMD),1)
    def test_after_r58f(self):
        self.assertTrue(self.content.index(STEP)>self.content.index(OLD))
    def test_before_traceability(self):
        self.assertTrue(self.content.index(STEP)<self.content.index('Verificar trazabilidad vigente'))
    def test_new_step_not_root(self):
        start=self.content.index(STEP)
        snippet=self.content[start:start+250]
        self.assertNotIn('sudo ',snippet)
        self.assertNotIn('virsh ',snippet)
        self.assertNotIn('systemctl ',snippet)
    def test_python_job_preserved(self):self.assertIn('Python - empaquetado / packaging',self.content)
    def test_rust_job_preserved(self):self.assertIn('Rust - compilación / build',self.content)
    def test_old_r58f_preserved(self):self.assertEqual(self.content.count(OLD),1)
    def test_old_r58e_preserved(self):self.assertIn('Probar vinculacion R58-E A6 A7 A8',self.content)
    def test_old_r58d_preserved(self):self.assertIn('Probar A7 R58-D intervalos exactos',self.content)
    def test_old_r58c_preserved(self):self.assertIn('Probar integracion R58-C F11 y A6-A9 offline',self.content)
    def test_triggers_preserved(self):
        self.assertIn('  pull_request:',self.content)
        self.assertIn('  push:',self.content)
