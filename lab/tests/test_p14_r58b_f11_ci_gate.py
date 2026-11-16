"""Verify the R58-B F11 runtime-source-only CI gate and no host actions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT/'.github/workflows/ci.yml'
OLD = "      - name: Probar auditoria F11-P R58-A / Test read-only boot readiness\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_f11p_*.py' -v\n\n"
NEW = "      - name: Probar F11 R58-B barreras de arranque offline / Test source-only boot guard candidates\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58b_f11_*.py' -v\n\n"


class TestF11Bci(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=CI.read_text(encoding='utf-8')

    def test_new_step_exactly_once(self):
        self.assertEqual(self.raw.count(NEW),1)

    def test_previous_step_preserved(self):
        self.assertEqual(self.raw.count(OLD),1)

    def test_inserted_after_predecessor(self):
        self.assertEqual(self.raw.index(NEW),self.raw.index(OLD)+len(OLD))

    def test_other_jobs_remain(self):
        self.assertIn('  python:\n',self.raw)
        self.assertIn('  rust:\n',self.raw)

    def test_pr_push_triggers_remain(self):
        self.assertIn('  pull_request:\n',self.raw)
        self.assertIn('  push:\n',self.raw)

    def test_no_host_actions_in_step(self):
        for forbidden in ('sudo ', 'virsh ', 'nft ', 'systemctl ',
                          '--host-readonly', '--install', '--activate'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,NEW)

    def test_discovery_pattern_only(self):
        self.assertIn("-p 'test_p14_r58b_f11_*.py'", NEW)

    def test_source_guard_exists(self):
        self.assertTrue((ROOT/'lab/f11-runtime-v1/00-ardrec-r33-deny').is_file())


if __name__=='__main__':
    unittest.main()
