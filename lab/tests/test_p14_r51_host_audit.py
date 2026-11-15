"""R51: asegurar que la inspección no pueda mutar libvirt ni nftables."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import ardrec_p14_r51_host_audit as h

class R51HostAuditTests(unittest.TestCase):
    def test_four_commands_are_readonly_allowlisted(self):
        self.assertEqual(set(h.FIXED), {'nft_tables','r34_table','domains','networks'})
        for cmd in h.FIXED.values():
            self.assertEqual(cmd[:3], ['/usr/bin/sudo','-n','--'])
            self.assertFalse(any(x in cmd for x in (
                'start','stop','define','undefine','destroy','delete','add','flush',
                'replace','insert','reset','net-start','net-define','qemu-agent-command')))

    def test_forbidden_command_is_rejected(self):
        with self.assertRaisesRegex(h.AuditError, 'command_not_allowlisted'):
            h.run_readonly('start_vm')

    def test_missing_r34_never_authorizes(self):
        data = {key: {'command':key, 'rc':0, 'stdout':b'', 'stderr':b''}
                for key in h.FIXED}
        data['r34_table']['rc'] = 1
        out = h.analyze(data)
        self.assertEqual(out['classification'], 'R34_NOT_VERIFIED_OR_UNAVAILABLE_NO_GO')
        self.assertFalse(out['activation_allowed'])

    def test_present_table_is_not_isolation_proof(self):
        data = {key: {'command':key, 'rc':0, 'stdout':b'', 'stderr':b''}
                for key in h.FIXED}
        data['r34_table']['stdout'] = b'table bridge ardrec_r34_guard { chain x { type filter hook forward priority 0; } }'
        out = h.analyze(data)
        self.assertEqual(out['classification'], 'R34_TABLE_OBSERVED_UNREVIEWED_NO_GO')
        self.assertFalse(out['isolation_proven'])

    def test_false_positive_stdout_cannot_grant_go(self):
        data = {key: {'command':key, 'rc':0, 'stdout':b'', 'stderr':b''}
                for key in h.FIXED}
        data['r34_table']['stdout'] = b'ERROR'
        self.assertEqual(h.analyze(data)['classification'],'R34_RESPONSE_INCONSISTENT_NO_GO')

    def test_runner_contract_does_not_use_shell_or_stdin(self):
        calls = []
        def runner(argv, **kw):
            calls.append((argv, kw))
            return SimpleNamespace(returncode=1,stdout=b'',stderr=b'not found')
        value = h.run_readonly('r34_table', runner)
        self.assertEqual(value['rc'], 1)
        self.assertEqual(calls[0][0], h.FIXED['r34_table'])
        opts = calls[0][1]
        self.assertNotIn('shell', opts)
        self.assertEqual(opts['check'], False)
        self.assertEqual(opts['timeout'], 15)
        self.assertTrue(opts['close_fds'])

    def test_capture_private_receipt_and_no_go(self):
        with tempfile.TemporaryDirectory() as td:
            parent = Path(td) / 'private'
            parent.mkdir(mode=0o700)
            calls = []
            def runner(argv, **kw):
                calls.append(argv)
                return SimpleNamespace(returncode=1 if 'r34' in argv else 0,
                                       stdout=b'',stderr=b'not found')
            outdir, conclusion, receipt_sha = h.capture(parent, runner)
            self.assertEqual(len(calls), 4)
            self.assertEqual(conclusion['p8_operational'],'NO-GO')
            self.assertEqual(len(receipt_sha),64)
            self.assertEqual(stat.S_IMODE(outdir.stat().st_mode),0o700)
            files = list(outdir.iterdir())
            self.assertEqual(len(files),10)
            self.assertTrue(all(stat.S_IMODE(f.stat().st_mode)==0o600 for f in files))
            with open(outdir/'receipt.json',encoding='ascii') as f:
                parsed=json.load(f)
            self.assertEqual(parsed['assessment']['activation_allowed'],False)
            self.assertFalse(parsed['assessment']['guest_qga_called'])
            self.assertEqual(len(parsed['raw_files_sha256']),8)

    def test_private_parent_requires_0700(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td)/'unsafe'
            parent.mkdir(mode=0o755)
            with self.assertRaisesRegex(h.AuditError,'private_parent_owner_mode'):
                h.private_parent(parent)

    def test_summary_always_preserves_previous_receipts(self):
        data={key:{'command':key,'rc':0,'stdout':b'', 'stderr':b''} for key in h.FIXED}
        summary=h.analyze(data)
        self.assertFalse(summary['historical_receipts_replaced'])
        self.assertFalse(summary['host_change_performed'])
        self.assertFalse(summary['activation_allowed'])

if __name__ == '__main__':
    unittest.main()
