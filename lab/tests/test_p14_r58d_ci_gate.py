"""R58-D workflow contract: pure offline testing and existing gates preserved."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT/'.github/workflows/ci.yml'
STEP = 'Probar A7 R58-D intervalos exactos / Test exact risk intervals'
COMMAND = "PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58d_*.py' -v"
PRIOR = 'Probar integracion R58-C F11 y A6-A9 offline / Test F11 plan and documentary chain'


class TestR58DCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()

    def test_workflow_exists(self): self.assertTrue(WORKFLOW.is_file())
    def test_new_step_exactly_once(self): self.assertEqual(self.source.count(STEP),1)
    def test_run_command_exactly_once(self): self.assertEqual(self.source.count(COMMAND),1)
    def test_after_r58c(self):
        self.assertLess(self.source.index(PRIOR),self.source.index(STEP))
    def test_prior_gate_preserved(self):
        self.assertIn("test_p14_r58c_*.py",self.source)
    def test_python_rust_preserved(self):
        self.assertIn('Python - empaquetado / packaging',self.source)
        self.assertIn('Rust - compilación / build',self.source)
    def test_triggers_preserved(self):
        self.assertIn('pull_request:',self.source)
        self.assertIn('push:',self.source)
    def test_new_step_not_privileged(self):
        tail=self.source.split('- name: '+STEP,1)[1].split('\n      - name:',1)[0]
        self.assertIn(COMMAND,tail)
        for forbidden in ('sudo ', 'nft ', 'virsh ', 'systemctl ', 'curl ', 'wget ', 'bash -c', 'git push'):
            self.assertNotIn(forbidden,tail)


if __name__=='__main__': unittest.main()
