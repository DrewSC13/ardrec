"""Regresión R26-H1: pathlib.PosixPath se acepta; enlaces y ausencias no."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.coordination.demo_session import (
    SCENARIO_FORMAT, SessionError, read_fixed_scenario,
)

FIXTURE = ROOT / 'lab' / 'p14-r26-session-v1' / 'scenario.json'


class PathGuardRegressionTests(unittest.TestCase):
    def test_real_regular_path_reads_scenario(self):
        self.assertTrue(FIXTURE.is_file(), 'fixture R26 ausente')
        self.assertFalse(FIXTURE.is_symlink())
        self.assertIsInstance(FIXTURE, Path)
        fixture = read_fixed_scenario(FIXTURE)
        self.assertEqual(fixture['format'], SCENARIO_FORMAT)
        self.assertEqual({u['id'] for u in fixture['services']},
                         {'SSH_DEV', 'FTP_DEV', 'SMB_DEV'})

    def test_symlink_rejected_even_if_target_exists(self):
        with tempfile.TemporaryDirectory() as td:
            linked = Path(td) / 'scenario_link.json'
            linked.symlink_to(FIXTURE)
            self.assertTrue(linked.is_file())
            self.assertTrue(linked.is_symlink())
            with self.assertRaises(SessionError) as raised:
                read_fixed_scenario(linked)
            self.assertEqual(raised.exception.code, 'scenario_missing_or_symlink')

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SessionError) as raised:
                read_fixed_scenario(Path(td) / 'missing.json')
            self.assertEqual(raised.exception.code, 'scenario_missing_or_symlink')

    def test_non_path_argument_rejected(self):
        with self.assertRaises(SessionError) as raised:
            read_fixed_scenario(str(FIXTURE))  # type: ignore[arg-type]
        self.assertEqual(raised.exception.code, 'scenario_missing_or_symlink')


if __name__ == '__main__':
    unittest.main()
