"""R166-F3: pruebas de clasificación causal sin sudo, libvirt ni tráfico."""
from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch
import unittest

from ardrec.coordination import r119_live_inspection as r119
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from test_p14_r166_f2_physical_readback import synthetic_capture


def probe(msg, *, rc=1, timeout=False, truncated=False):
    return {'rc': rc, 'timeout': timeout, 'truncated': truncated,
            'start': '2026-11-23T12:00:00Z',
            'end': '2026-11-23T12:00:00Z', 'stdout': '',
            'stderr': base64.b64encode(msg.encode('utf-8')).decode('ascii')}


class R166F3Causes(unittest.TestCase):
    def test_01_sudo_auth_required(self):
        p = probe('sudo: a password is required')
        self.assertEqual(r119.probe_cause('state_ftp', p), 'SUDO_AUTH_REQUIRED')

    def test_02_sudo_policy_denied(self):
        p = probe('sudo: user is not allowed to execute /usr/bin/virsh')
        self.assertEqual(r119.probe_cause('xml_smb', p), 'SUDO_POLICY_DENIED')

    def test_03_libvirt_missing(self):
        self.assertEqual(r119.probe_cause('state_ftp', probe('error: failed to get domain foo')),
                         'LIBVIRT_OBJECT_NOT_FOUND')

    def test_04_libvirt_connect(self):
        self.assertEqual(r119.probe_cause('bindings_list', probe('error: failed to connect to the hypervisor')),
                         'LIBVIRT_CONNECT_FAILED')

    def test_05_nft_missing(self):
        self.assertEqual(r119.probe_cause('nft', probe('Error: No such file or directory')),
                         'NFT_TABLE_NOT_FOUND')

    def test_06_sha_missing(self):
        self.assertEqual(r119.probe_cause('hook_sha', probe('sha256sum: No such file or directory')),
                         'SOURCE_FILE_NOT_FOUND')

    def test_07_timeout_is_not_sudo(self):
        self.assertEqual(r119.probe_cause('nft', probe('sudo: a password is required', timeout=True)),
                         'TIMEOUT')

    def test_08_nonzero_unknown_does_not_invent_cause(self):
        self.assertEqual(r119.probe_cause('state_ftp', probe('unexpected failure')),
                         'UNCLASSIFIED_NONZERO')

    def test_09_no_error_text_is_unknown(self):
        self.assertEqual(r119.probe_cause('state_ftp', probe('')),
                         'NONZERO_WITHOUT_STDERR')

    def test_10_sanitization_no_raw_data(self):
        doc = synthetic_capture()
        secret = 'SECRET_NEVER_LEAK_001'
        doc['probes']['state_ftp'] = probe('sudo: a password is required '+secret)
        host = f5.report(doc)
        with patch('subprocess.run', side_effect=AssertionError('NO EXECUTION')):
            rows = r119.cause_lines(doc, host)
        output = '\n'.join(rows)
        self.assertIn('R166_F3_PROBE_STATE_FTP_CAUSE=SUDO_AUTH_REQUIRED', rows)
        self.assertNotIn(secret, output)
        self.assertIn('R166_F3_P8=NO-GO', rows)
        self.assertIn('R166_F3_HOST_MUTATIONS=0', rows)

    def test_11_forged_host_rejected(self):
        doc = synthetic_capture()
        host = f5.report(doc)
        host['states']['ftp'] = 'RUNNING'
        with self.assertRaisesRegex(r119.Stop, 'F3_SOURCE_REPORT_MISMATCH'):
            r119.cause_lines(doc, host)

    def test_12_metadata_root_private(self):
        class S:
            st_mode = 0o100600
            st_uid = 0
            st_nlink = 1
        with patch.object(Path, 'lstat', return_value=S()):
            self.assertEqual(r119._root_path_metadata(Path('/etc/ardrec/test')),
                             'ROOT_0600_METADATA_ONLY')

    def test_13_metadata_absence_not_root_approval(self):
        with patch.object(Path, 'lstat', side_effect=PermissionError('deny')):
            text = '\n'.join(r119.r163_presence_lines())
        self.assertIn('R166_F3_R163_METADATA_ALL_VISIBLE=NO', text)
        self.assertIn('R166_F3_R163_SIGNED_AUTHORITY=NOT_ATTESTED', text)
        self.assertIn('R166_F3_P8=NO-GO', text)

    def test_14_reject_symlink_root(self):
        class S:
            st_mode = 0o120777
            st_uid = 0
            st_nlink = 1
        with patch.object(Path, 'lstat', return_value=S()):
            self.assertEqual(r119._root_path_metadata(Path('/etc/ardrec/test')),
                             'SYMLINK_REJECTED')

    def test_15_no_extra_shell(self):
        doc = synthetic_capture()
        host = f5.report(doc)
        with patch('subprocess.run', side_effect=AssertionError('NO EXECUTION')):
            rows = r119.cause_lines(doc, host)
            with patch.object(Path, 'lstat', side_effect=FileNotFoundError()):
                root = r119.r163_presence_lines()
        self.assertEqual(len([x for x in rows if x.startswith('R166_F3_PROBE_')]),
                         len(f5.READS))
        self.assertIn('R166_F3_R163_SOURCE_AUTHENTICITY=NOT_ATTESTED', root)

    def test_16_cli_flags_require_diagnostic(self):
        with patch('os.geteuid', return_value=1000):
            self.assertEqual(r119.main(['--capturar', '--texto', '--causas']), 2)


if __name__ == '__main__':
    unittest.main()
