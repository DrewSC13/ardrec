"""R166-F2: verificacion de lectura estrictamente pasiva (fixtures no fisicos)."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from ardrec.coordination import r119_live_inspection as r119
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r113_f6_six_binding_guard as six


def synthetic_capture():
    clock = '2026-11-23T12:00:00Z'
    probe = {'rc': 1, 'timeout': False, 'truncated': False,
             'start': clock, 'end': clock, 'stdout': '', 'stderr': ''}
    return {'schema': f5.SCHEMA, 'start': clock, 'end': clock,
            'probes': {name: dict(probe) for name in f5.READS},
            'source': 'LOCAL_ROOT_READONLY_NOT_AUTHORITY',
            'traffic_authorized': False}


def synthetic_ftp_host():
    # Solamente documento de prueba de proyeccion: no permite trafico.
    return {'nft': 'MATCH', 'helper': 'MATCH', 'f11_hook': 'MATCH',
            'states': {'runner': 'RUNNING', 'ssh': 'RUNNING',
                       'ftp': 'RUNNING', 'smb': 'OFF'},
            'vm_definitions': {k: 'MATCH' for k in f5.VMS},
            'bindings': {k: ('ABSENT_WHILE_OFF' if k == 'smb' else 'DENY_MATCH')
                         for k in six.ROLES},
            'p8': 'NO-GO', 'a6': 'ND', 'authority_attested': False}


class PhysicalReadbackDiagnostics(unittest.TestCase):
    def test_01_failed_probes_visible_without_promoting_state(self):
        capture = synthetic_capture()
        host = f5.report(capture)
        rows = r119.diagnostic_lines(capture, host, mode='F5_LIVE_CAPTURE')
        self.assertIn('R166_F2_FTP_PHASE=NOT_ESTABLISHED', rows)
        self.assertIn('R166_F2_PROBE_STATE_FTP=RC_1', rows)
        self.assertIn('R166_F2_P8=NO-GO', rows)
        self.assertIn('R166_F2_HOST_MUTATIONS=0', rows)
        self.assertIn('R166_F2_FAILED_PROBES=' + str(len(f5.READS)), rows)

    def test_02_refuses_forged_report(self):
        capture = synthetic_capture()
        host = f5.report(capture)
        host['states']['ftp'] = 'RUNNING'
        with self.assertRaisesRegex(r119.Stop, 'DIAGNOSTIC_SOURCE_REPORT_MISMATCH'):
            r119.diagnostic_lines(capture, host, mode='F5_LIVE_CAPTURE')

    def test_03_ftp_5_to_1_is_readback_only(self):
        host = synthetic_ftp_host()
        self.assertEqual(r119.ftp_phase_deny_readback(host),
                         'FIVE_DENY_ONE_ABSENT_READBACK_ONLY')
        self.assertEqual(host['p8'], 'NO-GO')
        self.assertFalse(host['authority_attested'])

    def test_04_sixth_smb_binding_present_rejects_5_1(self):
        host = synthetic_ftp_host()
        host['bindings']['smb'] = 'DENY_MATCH'
        self.assertEqual(r119.ftp_phase_deny_readback(host), 'NOT_ESTABLISHED')

    def test_05_missing_runner_binding_rejects_5_1(self):
        host = synthetic_ftp_host()
        host['bindings']['runner_smb'] = 'MISSING_OR_TRANSITION'
        self.assertEqual(r119.ftp_phase_deny_readback(host), 'NOT_ESTABLISHED')

    def test_06_missing_nft_or_hook_rejects_5_1(self):
        host = synthetic_ftp_host()
        for field in ('nft', 'helper', 'f11_hook'):
            altered = copy.deepcopy(host)
            altered[field] = 'ND'
            self.assertEqual(r119.ftp_phase_deny_readback(altered),
                             'NOT_ESTABLISHED')

    def test_07_smb_running_rejects_5_1(self):
        host = synthetic_ftp_host()
        host['states']['smb'] = 'RUNNING'
        self.assertEqual(r119.ftp_phase_deny_readback(host), 'NOT_ESTABLISHED')

    def test_08_replay_must_say_historical(self):
        capture = synthetic_capture()
        host = f5.report(capture)
        rows = r119.diagnostic_lines(capture, host,
                                     mode='F5_PRIVATE_RECEIPT_REPLAY')
        self.assertIn('R166_F2_CAPTURE_CLASS=HISTORICAL_REPLAY', rows)
        self.assertIn('R166_F2_P8=NO-GO', rows)

    def test_09_diagnostic_never_invokes_subprocess(self):
        capture = synthetic_capture()
        host = f5.report(capture)
        with patch('subprocess.run', side_effect=AssertionError('NO EXECUTION')):
            rows = r119.diagnostic_lines(capture, host, mode='F5_LIVE_CAPTURE')
        self.assertIn('R166_F2_A6_PHYSICAL_ADMITTED=NO', rows)
        self.assertIn('R166_F2_A9_PUBLISHED=NO', rows)

    def test_10_invalid_mode_fails_closed(self):
        capture = synthetic_capture()
        with self.assertRaisesRegex(r119.Stop, 'DIAGNOSTIC_MODE_INVALID'):
            r119.diagnostic_lines(capture, f5.report(capture), mode='OPERATIONAL')


if __name__ == '__main__':
    unittest.main()
