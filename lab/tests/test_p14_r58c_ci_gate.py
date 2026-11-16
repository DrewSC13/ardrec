"""R58-C CI integration: host operations forbidden in GitHub runner."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
CI=ROOT/'.github/workflows/ci.yml'
OLD=("      - name: Probar F11 R58-B barreras de arranque offline / Test source-only boot guard candidates\n"
     "        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58b_f11_*.py' -v\n\n")
NEW=("      - name: Probar integracion R58-C F11 y A6-A9 offline / Test F11 plan and documentary chain\n"
     "        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58c_*.py' -v\n\n")

class TestR58CCiGate(unittest.TestCase):
    def test_workflow_exists(self):self.assertTrue(CI.is_file())
    def test_prior_step_present(self):self.assertEqual(CI.read_text().count(OLD),1)
    def test_exactly_one_new_step(self):self.assertEqual(CI.read_text().count(NEW),1)
    def test_inserted_after_r58b(self):
        s=CI.read_text()
        self.assertEqual(s.index(NEW),s.index(OLD)+len(OLD))
    def test_python_rust_preserved(self):
        s=CI.read_text()
        self.assertIn('  python:\n',s)
        self.assertIn('  rust:\n',s)
    def test_pr_and_push_preserved(self):
        s=CI.read_text()
        self.assertIn('  pull_request:\n',s)
        self.assertIn('  push:\n',s)
    def test_no_physical_actions(self):
        for verb in ('--host-readonly','sudo ','virsh ','nft ','systemctl ','--write-development-receipt'):
            self.assertNotIn(verb,NEW)
    def test_test_files_present(self):
        for name in ('test_p14_r58c_f11_plan.py','test_p14_r58c_documentary_chain.py'):
            self.assertTrue((ROOT/'lab/tests'/name).is_file())
