"""R58-F CI integration must stay source-only, runner-portable and additive."""
from pathlib import Path
import unittest

REPO=Path(__file__).resolve().parents[2]
CI=(REPO/'.github/workflows/ci.yml').read_text()
OLD='Probar vinculacion R58-E A6 A7 A8 / Test conservative unit evidence binding'
NEW='Probar A6 R58-F testigos Ed25519 offline / Test signed witness evidence bindings'
CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58f_*.py' -v"

class TestR58FCI(unittest.TestCase):
    def test_ci_exists(self):self.assertTrue((REPO/'.github/workflows/ci.yml').is_file())
    def test_new_step_once(self):self.assertEqual(CI.count(NEW),1)
    def test_new_command_once(self):self.assertEqual(CI.count(CMD),1)
    def test_old_r58e_preserved(self):self.assertEqual(CI.count(OLD),1)
    def test_new_after_old(self):self.assertLess(CI.index(OLD),CI.index(NEW))
    def test_r58d_preserved(self):self.assertIn('test_p14_r58d_*.py',CI)
    def test_r58c_preserved(self):self.assertIn('test_p14_r58c_*.py',CI)
    def test_python_rust(self):
        self.assertIn('Python - empaquetado / packaging',CI)
        self.assertIn('Rust - compilación / build',CI)
    def test_ci_read_only(self):
        line=next(x for x in CI.splitlines() if CMD in x)
        self.assertNotIn('sudo',line)
        self.assertNotIn('virsh',line)
        self.assertNotIn('nft',line)
        self.assertNotIn('systemctl',line)
    def test_correct_sources(self):
        for item in ('src/ardrec/evidence/r58f_signed_witness.py',
                     'src/ardrec/coordination/r58f_signed_bridge.py',
                     'scripts/ardrec_p14_r58f_signed_witness_demo.py'):
            self.assertTrue((REPO/item).is_file(),item)

if __name__=='__main__':unittest.main()
