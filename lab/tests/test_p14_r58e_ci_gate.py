"""R58-E offline CI contract: no host mutation and no removal of prior gates."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT/'.github/workflows/ci.yml'
STEP = 'Probar vinculacion R58-E A6 A7 A8 / Test conservative unit evidence binding'
RUN = "PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58e_*.py' -v"
PARENT = 'Probar A7 R58-D intervalos exactos / Test exact risk intervals'

class TestR58ECI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text=WORKFLOW.read_text('utf-8')
    def test_step_once(self):
        self.assertEqual(self.text.count('- name: '+STEP),1)
    def test_run_once(self):
        self.assertEqual(self.text.count('run: '+RUN),1)
    def test_after_r58d(self):
        self.assertLess(self.text.index(PARENT),self.text.index(STEP))
    def test_existing_r58c_still_present(self):
        self.assertIn('Probar integracion R58-C F11 y A6-A9 offline',self.text)
    def test_r58d_still_present(self):
        self.assertIn(PARENT,self.text)
    def test_python_rust_jobs(self):
        self.assertIn('python:',self.text.lower())
        self.assertIn('rust:',self.text.lower())
    def test_no_privileged_actions_in_step(self):
        chunk=self.text.split('- name: '+STEP,1)[1].split('\n      - name:',1)[0]
        for forbidden in ('sudo ', 'virsh ', 'systemctl ', 'nft ', 'apt install', 'curl ', 'wget '):
            self.assertNotIn(forbidden,chunk)
    def test_sources_available(self):
        for path in ('src/ardrec/coordination/r58e_evidence_risk_bridge.py',
                     'scripts/ardrec_p14_r58e_unit_bridge.py',
                     'lab/tests/test_p14_r58e_unit_bridge.py'):
            self.assertTrue((ROOT/path).is_file())

if __name__=='__main__':unittest.main()
