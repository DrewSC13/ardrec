"""R136: read-only interpretation of R135 host inventory snapshots."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / 'scripts/ardrec_p14_r136_lab_diagnosis.py'
sys.path.insert(0, str(SCRIPT.parent))
import ardrec_p14_r136_lab_diagnosis as m


def fixture():
    expected = m.EXPECTED_DOMAINS
    return {
        'schema': 'ARDREC-R135-READONLY-PHYSICAL-READINESS-v1',
        'virsh_available': True,
        'domains': {
            svc: {'name': 'ardrec-r33-dev-'+svc, 'observed_state': state,
                  'query_exit_code': 0, 'pilot_expected_running': state == 'running',
                  'matches_pilot': True}
            for svc, state in expected.items()
        },
        'networks': {
            svc: {'name': 'ardrec-r33-dev-net-'+svc, 'query_exit_code': 0,
                  'query_succeeded': True}
            for svc in m.EXPECTED_NETWORKS
        },
        'vm_pilot_alignment': True,
        'readiness': 'NOT_ACCREDITED', 'a6': 'ND', 'p8': 'NO-GO',
    }


class LabDiagnosis(unittest.TestCase):
    def setUp(self):
        self.doc = fixture()

    def run_case(self):
        return m.diagnose(self.doc)

    def test_01_aligned_never_proves_physical(self):
        result = self.run_case()
        self.assertTrue(result['vm_alignment_deduced'])
        self.assertEqual(result['findings'], [])
        self.assertFalse(result['physical_5_1_proved'])
        self.assertFalse(result['safe_to_autostart'])

    def test_02_ssh_down(self):
        self.doc['domains']['ssh']['observed_state'] = 'shut off'
        self.assertEqual(self.run_case()['findings'][0]['service'], 'ssh')

    def test_03_ftp_down(self):
        self.doc['domains']['ftp']['observed_state'] = 'shut off'
        self.assertEqual(self.run_case()['findings'][0]['service'], 'ftp')

    def test_04_runner_down(self):
        self.doc['domains']['runner']['observed_state'] = 'shut off'
        self.assertEqual(self.run_case()['findings'][0]['service'], 'runner')

    def test_05_smb_running(self):
        self.doc['domains']['smb']['observed_state'] = 'running'
        self.assertEqual(self.run_case()['findings'][0]['service'], 'smb')

    def test_06_vm_query_failed(self):
        self.doc['domains']['ftp']['query_exit_code'] = 1
        self.assertFalse(self.run_case()['vm_alignment_deduced'])

    def test_07_missing_domain(self):
        del self.doc['domains']['ftp']
        self.assertEqual(self.run_case()['findings'][0]['status'], 'NOT_QUERIED')

    def test_08_network_query_failed(self):
        self.doc['networks']['smb']['query_exit_code'] = 2
        out = self.run_case()
        self.assertTrue(out['vm_alignment_deduced'])
        self.assertEqual(out['findings'][0]['kind'], 'network')

    def test_09_virsh_unavailable(self):
        self.doc['virsh_available'] = False
        self.doc['domains'] = {}
        self.doc['networks'] = {}
        result = self.run_case()
        self.assertFalse(result['vm_alignment_deduced'])
        self.assertEqual(result['findings'][0]['status'], 'UNAVAILABLE')

    def test_10_invalid_schema(self):
        self.doc['schema'] = 'UNTRUSTED'
        with self.assertRaisesRegex(ValueError, 'R135_REPORT_SCHEMA_INVALID'):
            self.run_case()

    def test_11_cli_json(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'report.json'
            f.write_text(json.dumps(self.doc), encoding='utf-8')
            p = subprocess.run([sys.executable, '-B', str(SCRIPT), '--report', str(f)],
                               capture_output=True, check=False, timeout=6)
            self.assertEqual(p.returncode, 0)
            result = json.loads(p.stdout)
            self.assertFalse(result['root_install_authorized'])

    def test_12_cli_invalid_report_denied(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / 'bad.json'
            f.write_bytes(b'not-json')
            p = subprocess.run([sys.executable, '-B', str(SCRIPT), '--report', str(f)],
                               capture_output=True, check=False, timeout=6)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(b'STOP:', p.stderr)


if __name__ == '__main__':
    unittest.main()
