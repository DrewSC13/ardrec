"""CI contract for ARDREC R58-A FTP: no host operations."""
from __future__ import annotations
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / '.github/workflows/ci.yml'
GATE = "      - name: Probar interfaz y candidata FTP R58-A / Test read-only FTP NIC and candidate\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r58a_ftp_*.py' -v\n\n"
OLD = "      - name: Probar programa conjunto SSH FTPS SMB R56.0 / Test R56.0 three-service closure contract\n        run: PYTHONPATH=src python3 -B -m unittest discover -s lab/tests -p 'test_p14_r560*.py' -v\n\n"

class TestFtpCiGate(unittest.TestCase):
    def test_ci_file_exists(self):
        self.assertTrue(CI.is_file())
    def test_gate_exactly_once(self):
        self.assertEqual(CI.read_text(encoding='utf-8').count(GATE),1)
    def test_after_r56(self):
        raw=CI.read_text(encoding='utf-8')
        self.assertEqual(raw.count(OLD),1)
        self.assertEqual(raw.index(GATE),raw.index(OLD)+len(OLD))
    def test_existing_jobs_preserved(self):
        raw=CI.read_text(encoding='utf-8')
        self.assertIn('  python:\n',raw)
        self.assertIn('  rust:\n',raw)
        self.assertIn('  pull_request:\n',raw)
    def test_test_files_present(self):
        for name in ('test_p14_r58a_ftp_runner_candidate.py','test_p14_r58a_ftp_runner_readiness.py'):
            with self.subTest(name=name):self.assertTrue((ROOT/'lab/tests'/name).is_file())
    def test_no_host_side_effects_in_gate(self):
        raw=CI.read_text(encoding='utf-8')
        gate=raw[raw.index(GATE):raw.index(GATE)+len(GATE)]
        for forbidden in ('sudo ', 'virsh ', 'nft ', 'systemctl ', 'enable ', 'start ', ' --host-readonly'):
            with self.subTest(forbidden=forbidden):self.assertNotIn(forbidden,gate)
