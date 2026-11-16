"""Source-only CI gate for R58-A/F11-P: explicit discovery and no host writes."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / '.github/workflows/ci.yml'
FTP_GATE = "      - name: Probar interfaz y candidata FTP R58-A / Test read-only FTP NIC and candidate\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_ftp_*.py' -v\n\n"
F11_GATE = "      - name: Probar auditoria F11-P R58-A / Test read-only boot readiness\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_f11p_*.py' -v\n\n"

class TestF11PCIGate(unittest.TestCase):
    def content(self):
        return CI.read_text(encoding='utf-8')

    def test_workflow_exists(self):
        self.assertTrue(CI.is_file())

    def test_single_new_gate(self):
        self.assertEqual(self.content().count(F11_GATE), 1)

    def test_after_ftp_gate(self):
        raw=self.content()
        self.assertEqual(raw.count(FTP_GATE),1)
        self.assertEqual(raw.index(F11_GATE),raw.index(FTP_GATE)+len(FTP_GATE))

    def test_python_rust_jobs_preserved(self):
        raw=self.content()
        self.assertIn('  python:\n',raw)
        self.assertIn('  rust:\n',raw)

    def test_ci_uses_offline_unittest_discovery_only(self):
        gate=F11_GATE
        self.assertIn("-m unittest discover -s lab/tests",gate)
        self.assertIn("'test_p14_r58a_f11p_*.py'",gate)
        self.assertNotIn(' --host-readonly',gate)
        self.assertNotIn('boot-guard.py',gate)

    def test_new_step_has_no_privileged_command(self):
        gate=F11_GATE
        for forbidden in ('sudo ','virsh ','nft ','systemctl ','gh ','git push',' -f ',' --host-readonly',' --live'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden,gate)

    def test_f11p_sources_present(self):
        for name in ('lab/tests/test_p14_r58a_f11p_boot_readiness.py',
                     'scripts/ardrec_p14_r58a_f11p_boot_readiness.py',
                     'docs/development/p14-r58a-f11p-boot-readiness-readonly.md',
                     'docs/development/p14-r58a-f11p-boot-readiness-manifest.json'):
            with self.subTest(name=name):
                self.assertTrue((ROOT/name).is_file())

    def test_ci_gate_does_not_invoke_host_script(self):
        raw=self.content()
        self.assertNotIn('run: python3 -B scripts/ardrec_p14_r58a_f11p_boot_readiness.py',raw)

    def test_git_actions_pr_and_push_preserved(self):
        raw=self.content()
        self.assertIn('  pull_request:\n',raw)
        self.assertIn('  push:\n',raw)
        self.assertIn('    branches: [main]\n',raw)

    def test_ftp_gate_is_still_present(self):
        self.assertEqual(self.content().count(FTP_GATE),1)
