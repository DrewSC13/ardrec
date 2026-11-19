"""R112-F12R: PosixPath/Path acceptance in actual runner predecessor CLI.

Unit-level, offline: no guest start, no host/network mutation or sudo.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]
import ardrec_p14_r112_f12_postreboot_boot as cli


class RunnerPredecessorPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='f12r-path-')
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.plan = self.directory / 'plan-test'
        self.plan.mkdir()
        self.receipt = self.directory / 'receipt.json'
        self.receipt.write_bytes(b'{"unit":"only"}\n')
        self.valid_result = {
            'role': 'ssh',
            'guest_states': cli.core.expected('ssh', True),
            'traffic_authorized': False,
            'p8_operational': 'NO-GO',
        }

    def test_concrete_posixpath_accepted_without_real_host_calls(self):
        self.assertIsInstance(self.plan, Path)
        self.assertIsNot(type(self.plan), Path)
        with patch.object(cli, 'private') as check_private, \
             patch.object(cli, 'replay', return_value=self.valid_result) as replay:
            result = cli.previous_ssh(self.plan, self.receipt)
        self.assertEqual(result['type'], 'F12_SSH')
        self.assertEqual(result['plan'], str(self.plan))
        self.assertEqual(result['receipt'], str(self.receipt))
        self.assertEqual(result['sha256'], hashlib.sha256(self.receipt.read_bytes()).hexdigest())
        self.assertEqual(check_private.call_count, 2)
        replay.assert_called_once_with(self.plan, self.directory, expected_role='ssh')

    def test_runner_predecessor_dispatch_accepts_concrete_paths(self):
        with patch.object(cli, 'private'), \
             patch.object(cli, 'replay', return_value=self.valid_result):
            result = cli.previous('runner', self.plan, self.receipt)
        self.assertEqual(result['type'], 'F12_SSH')

    def test_rejects_string_paths_without_implicit_cast(self):
        for plan, receipt in [(str(self.plan), self.receipt),
                              (self.plan, str(self.receipt))]:
            with self.subTest(plan=type(plan).__name__, receipt=type(receipt).__name__):
                with patch.object(cli, 'private') as validate, \
                     patch.object(cli, 'replay') as replay:
                    with self.assertRaisesRegex(ValueError, 'SSH_PREDECESSOR_REQUIRED'):
                        cli.previous_ssh(plan, receipt)
                    validate.assert_not_called()
                    replay.assert_not_called()

    def test_bad_receipt_name_denied(self):
        wrong = self.directory / 'not-a-receipt.json'
        with patch.object(cli, 'private') as validate:
            with self.assertRaisesRegex(ValueError, 'SSH_RECEIPT_FILE_NAME'):
                cli.previous_ssh(self.plan, wrong)
            validate.assert_not_called()

    def test_cannot_accept_unattested_ssh(self):
        bad = dict(self.valid_result)
        bad['traffic_authorized'] = True
        with patch.object(cli, 'private'), patch.object(cli, 'replay', return_value=bad):
            with self.assertRaisesRegex(ValueError, 'SSH_PREDECESSOR_REPLAY_FAILED'):
                cli.previous_ssh(self.plan, self.receipt)

    def test_ssh_role_rejects_previous_runner_args(self):
        with self.assertRaisesRegex(ValueError, 'SSH_PREDECESSOR_SCOPE'):
            cli.previous('ssh', self.plan, self.receipt)


if __name__ == '__main__':
    unittest.main()
