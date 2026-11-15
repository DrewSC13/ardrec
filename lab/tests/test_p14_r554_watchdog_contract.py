"""R55.4 user timer contract test suite; offline only, no user systemd needed."""
from __future__ import annotations

from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r554_watchdog_contract as g

UNIT = 'ardrec-r554-probe-20261115T160000Z-4321'

class TestR554Contract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.parent.chmod(0o700)
        self.root = self.parent / UNIT
        self.state = self.root / 'state.txt'
        self.restore = self.root / 'restore-pending.txt'

    def test_source_merge_pin(self):
        self.assertEqual(g.SOURCE_MAIN, 'ce3b9e9f30751f99d2915cef8041c82eeb3c2aec')

    def test_initial_marker_is_deny(self):
        self.assertEqual(g.PREPARED, b'DENY_SIMULATED\n')

    def test_allowed_marker_distinct(self):
        self.assertNotEqual(g.PREPARED, g.OPENED)

    def test_no_privileged_binary(self):
        self.assertEqual(g.EXPECTED_BIN, '/usr/bin/mv')

    def test_timer_command_bounded(self):
        argv = g.timer_command(UNIT, self.restore, self.state)
        g.verify_timer_command(argv, UNIT, self.restore, self.state)
        self.assertEqual(argv[:2], ['/usr/bin/systemd-run', '--user'])

    def test_timer_delay_minimum(self):
        g.timer_command(UNIT, self.restore, self.state, delay_s=5)

    def test_timer_delay_maximum(self):
        g.timer_command(UNIT, self.restore, self.state, delay_s=15)

    def test_timer_delay_too_short(self):
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, self.restore, self.state, delay_s=4)

    def test_timer_delay_too_long(self):
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, self.restore, self.state, delay_s=16)

    def test_bad_unit_rejected(self):
        with self.assertRaises(g.R554Error):
            g.timer_command('other.timer', self.restore, self.state)

    def test_bad_restore_path_rejected(self):
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, self.root/'other', self.state)

    def test_bad_state_path_rejected(self):
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, self.restore, self.root/'notstate')

    def test_cross_parent_rejected(self):
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, self.restore, self.parent/'state.txt')

    def test_command_tamper_rejected(self):
        argv = g.timer_command(UNIT, self.restore, self.state)
        argv[-3] = '/usr/sbin/nft'
        with self.assertRaises(g.R554Error):
            g.verify_timer_command(argv, UNIT, self.restore, self.state)

    def test_shell_tamper_rejected(self):
        argv = g.timer_command(UNIT, self.restore, self.state)
        argv[-3] = '/bin/sh'
        with self.assertRaises(g.R554Error):
            g.verify_timer_command(argv, UNIT, self.restore, self.state)

    def test_sudo_tamper_rejected(self):
        argv = g.timer_command(UNIT, self.restore, self.state)
        argv[0] = '/usr/bin/sudo'
        with self.assertRaises(g.R554Error):
            g.verify_timer_command(argv, UNIT, self.restore, self.state)

    def test_symlink_component_rejected(self):
        self.root.mkdir(mode=0o700)
        bad = self.root/'link'
        bad.symlink_to(self.parent)
        with self.assertRaises(g.R554Error):
            g.timer_command(UNIT, bad/'restore-pending.txt', bad/'state.txt')

    def test_private_parent_mode_rejected(self):
        self.parent.chmod(0o755)
        with self.assertRaises(g.R554Error):
            g.safe_directory(self.root, existing=False)

    def test_private_parent_valid(self):
        g.safe_directory(self.root, existing=False)

    def test_root_existing_wrong_mode(self):
        self.root.mkdir(mode=0o755)
        with self.assertRaises(g.R554Error):
            g.safe_directory(self.root, existing=True)

    def test_root_existing_secure(self):
        self.root.mkdir(mode=0o700)
        g.safe_directory(self.root, existing=True)

    def test_success_report_still_no_go(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=True, seconds=8.4, timer_state='FIRED')
        g.verify_report(doc)
        self.assertEqual(doc['p8_operational'], 'NO-GO')
        self.assertFalse(doc['physical_restore_tested'])
        self.assertEqual(doc['status'], 'SYNTHETIC_USER_TIMER_RESTORED_NO_GO')

    def test_failure_report_no_go(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=False, seconds=20, timer_state='UNCONFIRMED')
        g.verify_report(doc)
        self.assertEqual(doc['status'], 'REVIEW_REQUIRED_NO_GO')

    def test_false_p8_go_rejected(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=True, seconds=8, timer_state='FIRED')
        doc['p8_operational'] = 'GO'
        with self.assertRaises(g.R554Error):
            g.verify_report(doc)

    def test_false_physical_rollback_rejected(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=True, seconds=8, timer_state='FIRED')
        doc['physical_restore_tested'] = True
        with self.assertRaises(g.R554Error):
            g.verify_report(doc)

    def test_fake_success_when_worker_alive_rejected(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=True, seconds=8, timer_state='FIRED')
        doc['worker_killed'] = False
        with self.assertRaises(g.R554Error):
            g.verify_report(doc)

    def test_bad_timer_state_rejected(self):
        with self.assertRaises(g.R554Error):
            g.synthetic_report(unit=UNIT, started=False, worker_killed=False,
                               restored=False, seconds=0, timer_state='FAKE')

    def test_bad_duration_rejected(self):
        with self.assertRaises(g.R554Error):
            g.synthetic_report(unit=UNIT, started=False, worker_killed=False,
                               restored=False, seconds=1000, timer_state='UNCONFIRMED')

    def test_json_is_canonical(self):
        self.assertEqual(g.canon({'z':1,'a':2}), b'{"a":2,"z":1}\n')

    def test_invalid_user_path_rejected(self):
        with self.assertRaises(g.R554Error):
            g.safe_directory(Path('relative'), existing=False)

    def test_report_injection_rejected(self):
        doc = g.synthetic_report(unit=UNIT, started=True, worker_killed=True,
                                 restored=True, seconds=8, timer_state='FIRED')
        doc['extra'] = True
        with self.assertRaises(g.R554Error):
            g.verify_report(doc)

if __name__ == '__main__':
    unittest.main()
