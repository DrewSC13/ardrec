"""R135/B: read-only VM inventory observations never accredit physical 5/1."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / 'scripts/ardrec_p14_r135_lab_readiness.py'
spec = importlib.util.spec_from_file_location('r135_lab', SRC)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fake(argv):
    assert argv[1:3] == ['--connect', 'qemu:///system']
    if argv[3] == 'domstate':
        return {'exit_code': 0,
                'stdout': 'shut off\n' if argv[4].endswith('-smb') else 'running\n',
                'stderr': ''}
    if argv[3] == 'net-info':
        return {'exit_code': 0, 'stdout': 'Active: yes\n', 'stderr': ''}
    raise AssertionError('unexpected command')


class PhysicalReadinessTests(unittest.TestCase):
    def good(self):
        with patch.object(m.shutil, 'which', return_value='/usr/bin/virsh'):
            return m.collect(fake)

    def test_01_inventory(self):
        r = self.good()
        self.assertEqual(len(r['domains']), 4)
        self.assertEqual(len(r['networks']), 3)

    def test_02_expected_pilot_states(self):
        self.assertTrue(self.good()['vm_pilot_alignment'])

    def test_03_not_5_1_proven(self):
        self.assertFalse(self.good()['physical_5_1_proved'])

    def test_04_no_deny_restoration_claim(self):
        self.assertFalse(self.good()['autonomous_deny_restore_proved'])

    def test_05_no_traffic(self):
        self.assertFalse(self.good()['network_enable_performed'])

    def test_06_no_root_install(self):
        self.assertFalse(self.good()['root_install_accredited'])

    def test_07_p8_no_go(self):
        self.assertEqual(self.good()['p8'], 'NO-GO')

    def test_08_a6_nd(self):
        self.assertEqual(self.good()['a6'], 'ND')

    def test_09_virsh_missing(self):
        with patch.object(m.shutil, 'which', return_value=None):
            r = m.collect(fake)
        self.assertEqual(r['blocker'], 'VIRSH_UNAVAILABLE')
        self.assertEqual(r['readiness'], 'NOT_ACCREDITED')

    def test_10_failed_domain_query(self):
        def broken(argv):
            if argv[3] == 'domstate' and argv[4].endswith('-ftp'):
                return {'exit_code': 1, 'stdout': '', 'stderr': 'denied'}
            return fake(argv)
        with patch.object(m.shutil, 'which', return_value='/usr/bin/virsh'):
            r = m.collect(broken)
        self.assertEqual(r['domains']['ftp']['observed_state'], 'ND')
        self.assertFalse(r['vm_pilot_alignment'])

    def test_11_no_smb_start(self):
        def bad(argv):
            if argv[3] == 'domstate' and argv[4].endswith('-smb'):
                return {'exit_code': 0, 'stdout': 'running\n', 'stderr': ''}
            return fake(argv)
        with patch.object(m.shutil, 'which', return_value='/usr/bin/virsh'):
            r = m.collect(bad)
        self.assertFalse(r['domains']['smb']['matches_pilot'])

    def test_12_readonly_commands_only(self):
        calls=[]
        def recorded(argv):
            calls.append(argv[:])
            return fake(argv)
        with patch.object(m.shutil, 'which', return_value='/usr/bin/virsh'):
            m.collect(recorded)
        self.assertTrue(all(v[3] in ('domstate','net-info') for v in calls))
        self.assertEqual(len(calls), 7)

if __name__ == '__main__':
    unittest.main()
