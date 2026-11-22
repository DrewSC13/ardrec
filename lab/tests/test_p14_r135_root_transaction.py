"""R135: deterministic source-only publication and recovery tests.

Every test is sandboxed in a private temporary directory. No root installation,
external trust provisioning, traffic enablement, or laboratory hosts are touched.
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'src/ardrec/coordination/r135_root_transaction.py'
SPEC = importlib.util.spec_from_file_location('r135_core_test', SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
HEAD = '118906392855a240342365373485c92670516194'


class RootTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b4 = (REPO / 'scripts/ardrec_p14_r130_b4_root_guard_v2.py').read_bytes()
        cls.b9 = (REPO / 'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py').read_bytes()
        assert hashlib.sha256(cls.b4).hexdigest() == m.B4_SHA
        assert hashlib.sha256(cls.b9).hexdigest() == m.B9_SHA

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='r135-private-')
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.parent.chmod(0o700)
        self.calls = []
        b4manifest = {
            'schema': 'ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle',
            'script_sha256': m.B4_SHA, 'guard_sha256': m.GUARD_SHA,
            'approved_head': HEAD, 'deny_only': True,
            'root_install_independent': True,
        }
        b9manifest = {
            'schema': 'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle',
            'approved_head': HEAD, 'script_sha256': m.B9_SHA,
            'r126_deny_controller_sha256': m.B4_SHA,
            'legacy_f3_sha256': m.F3_SHA, 'guard_sha256': m.GUARD_SHA,
            'root_staged_independently': True, 'automatic_network': False,
            'p8': 'NO-GO',
        }
        self.payload = {}
        for group, names in [('B4', m.B4), ('B9', m.B9)]:
            for name in names:
                if name.endswith('.json'):
                    self.payload[group + '/' + name] = m.canonical({'schema': 'TEST-ONLY', 'name': name})
        self.payload.update({
            'B4/root-controller.py': self.b4,
            'B9/root-executor.py': self.b9,
            'B4/manifest.json': m.canonical(b4manifest),
            'B9/manifest.json': m.canonical(b9manifest),
            'B9/lock': b'ARDREC-R128-B9-ROOT-LOCK\n',
        })

    def authority(self, phase, plan):
        self.calls.append(phase)
        return True   # ONLY a test stub. Never operational approval.

    def run_case(self, fault=None, authorize=None):
        return m.publish_pair(parent=self.parent, payload=self.payload, head=HEAD,
                              authorize=authorize or self.authority, fault=fault)

    def test_01_valid_inventory(self):
        self.assertEqual(m.validate_payload(self.payload, HEAD)['head'], HEAD)

    def test_02_source_b4_tampered(self):
        self.payload['B4/root-controller.py'] += b'x'
        with self.assertRaisesRegex(m.Refusal, 'B4_PIN_INVALID'):
            self.run_case()

    def test_03_source_b9_tampered(self):
        self.payload['B9/root-executor.py'] += b'x'
        with self.assertRaisesRegex(m.Refusal, 'B9_PIN_INVALID'):
            self.run_case()

    def test_04_missing_operational_file(self):
        del self.payload['B9/release.json']
        with self.assertRaisesRegex(m.Refusal, 'FILE_SET_INVALID'):
            self.run_case()

    def test_05_wrong_manifest(self):
        self.payload['B4/manifest.json'] = m.canonical({'bad': 1})
        with self.assertRaisesRegex(m.Refusal, 'B4_MANIFEST_INVALID'):
            self.run_case()

    def test_06_noncanonical_json(self):
        self.payload['B9/release.json'] = b'{}'
        with self.assertRaisesRegex(m.Refusal, 'JSON_NONCANONICAL'):
            self.run_case()

    def test_07_complete(self):
        out = self.run_case()
        self.assertEqual(out['status'], 'PRIVATE_PAIR_PUBLISHED')
        self.assertFalse(out['root_install_authorized'])
        self.assertEqual(self.calls, ['before_journal', 'before_b4', 'before_b9', 'before_receipt'])

    def test_08_replay_readback(self):
        self.run_case()
        self.calls.clear()
        out = self.run_case()
        self.assertEqual(out['status'], 'ALREADY_PUBLISHED_VERIFIED')
        self.assertEqual(self.calls, [])

    def assert_resume(self, phase):
        with self.assertRaisesRegex(m.Refusal, 'INJECTED'):
            self.run_case(fault=phase)
        out = self.run_case()
        self.assertEqual(out['status'], 'PRIVATE_PAIR_PUBLISHED')

    def test_09_after_stage(self):
        self.assert_resume('after_stage')

    def test_10_before_b4(self):
        self.assert_resume('before_b4')

    def test_11_only_b4(self):
        self.assert_resume('after_b4')

    def test_12_both_no_receipt(self):
        self.assert_resume('after_b9')

    def test_13_before_receipt(self):
        self.assert_resume('before_receipt')

    def test_14_revoked_between_publications(self):
        with self.assertRaisesRegex(m.Refusal, 'INJECTED_AFTER_B4'):
            self.run_case('after_b4')
        def deny_b9(phase, plan):
            return phase != 'before_b9'
        with self.assertRaisesRegex(m.Refusal, 'FRESH_AUTHORIZATION_REQUIRED:before_b9'):
            self.run_case(authorize=deny_b9)
        self.assertTrue((self.parent / 'published-b4').is_dir())
        self.assertFalse((self.parent / 'published-b9').exists())

    def test_15_preexisting_target_denied(self):
        (self.parent / 'published-b4').mkdir(mode=0o700)
        with self.assertRaisesRegex(m.Refusal, 'PREEXISTING_DESTINATION'):
            self.run_case()

    def test_16_missing_file_after_publication(self):
        self.run_case()
        (self.parent / 'published-b4/root-controller.py').unlink()
        with self.assertRaisesRegex(m.Refusal, 'PUBLISHED_FILE_SET_CHANGED'):
            self.run_case()

    def test_17_changed_bytes_after_publication(self):
        self.run_case()
        (self.parent / 'published-b9/root-executor.py').write_bytes(b'bad')
        with self.assertRaisesRegex(m.Refusal, 'FILE_METADATA_INVALID'):
            self.run_case()

    def test_18_corrupt_journal(self):
        self.run_case()
        (self.parent / 'journal.json').write_bytes(b'bad')
        with self.assertRaises(m.Refusal):
            self.run_case()

    def test_19_symlink_parent(self):
        link = self.parent / 'link'
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaisesRegex(m.Refusal, 'SYMLINK_DIRECTORY'):
            m.publish_pair(parent=link, payload=self.payload, head=HEAD, authorize=self.authority)

    def test_20_concurrent_lock(self):
        lock_path = self.parent / '.r135.lock'
        lock_path.touch(mode=0o600)
        lock_path.chmod(0o600)
        with lock_path.open('rb+') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.Refusal, 'CONCURRENT_TRANSACTION_DENIED'):
                self.run_case()

    def test_21_enospc_preserves_journal(self):
        old = m.exclusive_file
        def full(path, raw):
            if path.name == 'root-executor.py':
                raise OSError(28, 'No space left on device')
            return old(path, raw)
        with patch.object(m, 'exclusive_file', side_effect=full):
            with self.assertRaises(OSError):
                self.run_case()
        self.assertTrue((self.parent / 'journal.json').is_file())
        self.assertFalse((self.parent / 'published-b4').exists())
        self.assertFalse((self.parent / 'published-b9').exists())

    def test_22_unexpected_file(self):
        (self.parent / 'foreign').write_text('x')
        with self.assertRaisesRegex(m.Refusal, 'UNEXPECTED_TRANSACTION_ENTRY'):
            self.run_case()

    def test_23_missing_b4_with_b9(self):
        with self.assertRaisesRegex(m.Refusal, 'INJECTED_AFTER_B9'):
            self.run_case('after_b9')
        (self.parent / 'published-b4').rename(self.parent / 'saved-b4')
        with self.assertRaisesRegex(m.Refusal, 'UNEXPECTED_TRANSACTION_ENTRY'):
            self.run_case()

    def test_24_no_authorizer(self):
        with self.assertRaisesRegex(m.Refusal, 'INDEPENDENT_AUTHORIZER_MISSING'):
            m.publish_pair(parent=self.parent, payload=self.payload, head=HEAD,
                           authorize=None)

    def test_25_rejected_authorizer_before_first_mutation(self):
        with self.assertRaisesRegex(m.Refusal, 'FRESH_AUTHORIZATION_REQUIRED:before_journal'):
            self.run_case(authorize=lambda phase, plan: False)
        self.assertFalse((self.parent / 'journal.json').exists())

    def test_26_receipt_mode(self):
        self.run_case()
        (self.parent / 'receipt.json').chmod(0o644)
        with self.assertRaisesRegex(m.Refusal, 'FILE_METADATA_INVALID'):
            self.run_case()

    def test_27_hardlink_detected(self):
        self.run_case()
        original = self.parent / 'published-b4/root-controller.py'
        twin = self.parent / 'shadow-hardlink'
        twin.hardlink_to(original)
        with self.assertRaises(m.Refusal):
            self.run_case()

    def test_28_unexpected_fault(self):
        with self.assertRaisesRegex(m.Refusal, 'UNKNOWN_FAULT'):
            self.run_case('outside')

    def test_29_capabilities(self):
        c = m.capabilities()
        self.assertFalse(c['root_trust_anchored'])
        self.assertFalse(c['root_install_executed'])
        self.assertFalse(c['network_traffic'])

    def test_31_partial_receipt_fail_closed(self):
        with self.assertRaisesRegex(m.Refusal, 'INJECTED_AFTER_B9'):
            self.run_case('after_b9')
        (self.parent / 'receipt.json').write_bytes(b'partial')
        with self.assertRaises(m.Refusal):
            self.run_case()
        self.assertEqual((self.parent / 'receipt.json').read_bytes(), b'partial')

    def test_32_partial_pending_file_denied(self):
        with self.assertRaisesRegex(m.Refusal, 'INJECTED_AFTER_STAGE'):
            self.run_case('after_stage')
        p = self.parent / '.pending-b9/root-executor.py'
        p.write_bytes(b'partial')
        with self.assertRaises(m.Refusal):
            self.run_case()
        self.assertEqual(p.read_bytes(), b'partial')

    def test_30_bad_head(self):
        with self.assertRaisesRegex(m.Refusal, 'HEAD_INVALID'):
            m.publish_pair(parent=self.parent, payload=self.payload,
                           head='bad', authorize=self.authority)


if __name__ == '__main__':
    unittest.main()
