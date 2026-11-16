"""R58-K CI traceability and no-privilege integration guards."""
from pathlib import Path
import unittest

REPO=Path(__file__).resolve().parents[2]
CI=REPO/'.github/workflows/ci.yml'
SOURCE=REPO/'src/ardrec/coordination/r58k_unified_family_bridge.py'
DEMO=REPO/'scripts/ardrec_p14_r58k_unified_family_demo.py'
DOC=REPO/'docs/development/p14-r58k-a6-unified-25-family-coordinator.md'
TEST=REPO/'lab/tests/test_p14_r58k_unified_bridge.py'
STEP='Probar coordinador R58-K A6 A7 A8 de 25 familias / Test unified family coordination'
DEMO_STEP='Demostrar R58-K 29 casos SSH FTP SMB sin ejecucion / Test unified synthetic preview'
CMD="PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58k_*.py' -v"
DEMO_CMD='PYTHONPATH=src python3 -B scripts/ardrec_p14_r58k_unified_family_demo.py --synthetic-offline'
PREV='Demostrar R58-J SMB SIGNING ENCRYPTION READ WRITE / Check pinned SMB preview'
NEXT='Verificar trazabilidad vigente / Verify current traceability'


class UnifiedCITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci=CI.read_text()
    def test_ci_file_exists(self):self.assertTrue(CI.is_file())
    def test_files_exist(self):
        for p in (SOURCE,DEMO,DOC,TEST):self.assertTrue(p.is_file(),str(p))
    def test_step_once(self):self.assertEqual(self.ci.count(STEP),1)
    def test_demo_step_once(self):self.assertEqual(self.ci.count(DEMO_STEP),1)
    def test_command_once(self):self.assertEqual(self.ci.count(CMD),1)
    def test_demo_command_once(self):self.assertEqual(self.ci.count(DEMO_CMD),1)
    def test_correct_order(self):
        self.assertLess(self.ci.index(PREV),self.ci.index(STEP))
        self.assertLess(self.ci.index(STEP),self.ci.index(DEMO_STEP))
        self.assertLess(self.ci.index(DEMO_STEP),self.ci.index(NEXT))
    def test_python_job(self):self.assertIn('Python - empaquetado / packaging',self.ci)
    def test_rust_job(self):self.assertIn('Rust - compilación / build',self.ci)
    def test_prior_ssh_ftp_smb(self):
        for x in ('R58-H familias SSH','R58-I familias FTP','R58-J familias SMB'):
            self.assertIn(x,self.ci)
    def test_prior_f11_is_present(self):
        self.assertIn('F11 R58-B barreras de arranque offline',self.ci)
    def test_privileges_not_added(self):
        section=self.ci[self.ci.index(STEP):self.ci.index(NEXT)]
        for word in ('sudo ', 'systemctl ', 'virsh ', 'nft ', 'privileged:', 'libvirt'):
            self.assertNotIn(word,section)
    def test_only_synthetic_commands(self):
        section=self.ci[self.ci.index(STEP):self.ci.index(NEXT)]
        self.assertEqual(section.count('run:'),2)
        self.assertIn('--synthetic-offline',section)
    def test_source_catalog_pin(self):
        self.assertIn('CATALOG_SHA256',SOURCE.read_text())
        self.assertIn('THESIS_SHA256',SOURCE.read_text())
    def test_source_integrates_r58e(self):
        self.assertIn('build_unit_bridge',SOURCE.read_text())
        self.assertIn('verify_unit_bridge',SOURCE.read_text())
    def test_source_prohibits_evidence_injection(self):
        self.assertIn("'evidence': []",SOURCE.read_text())
    def test_demo_requires_flag(self):
        self.assertIn('--synthetic-offline',DEMO.read_text())
    def test_ci_uses_unprivileged_python(self):
        self.assertNotIn('sudo',self.ci[self.ci.index(STEP):self.ci.index(NEXT)])

if __name__=='__main__':unittest.main()
