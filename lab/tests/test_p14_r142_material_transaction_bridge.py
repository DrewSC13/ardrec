"""R142 protected acquisition -> signed semantics -> sandbox recovery.

All authorities are ephemeral and all files are owned by an unprivileged test
account. These tests intentionally do not establish independent root trust.
"""
from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_p14_r139_independent_release_review as test139
from ardrec.coordination import r141_root_material_reader as reader141
from ardrec.coordination import r142_material_transaction_bridge as bridge
from ardrec.coordination import r140_release_transaction_sandbox as sandbox140
from ardrec.coordination import r135_root_transaction as txn


class R142Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test139.R139ReleaseTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        test139.R139ReleaseTests.tearDownClass()

    def setUp(self):
        self.fixture = test139.R139ReleaseTests('test_01_positive_full_signed_review')
        self.fixture.setUp()
        self.root_temp = tempfile.TemporaryDirectory(prefix='ardrec-r142-root-')
        self.root = Path(self.root_temp.name)
        self.root.chmod(0o700)
        self.temp = tempfile.TemporaryDirectory(prefix=sandbox140.PREFIX)
        self.parent = Path(self.temp.name)
        self.clock = lambda: test139.NOW
        self.input = {
            **self.fixture.fix.external,
            'release_trust': self.fixture.b9.canon(self.fixture.release_trust),
            'release_revocation': self.fixture.b9.canon(self.fixture.revocation),
            'f8_reference': self.fixture.f8_reference,
        }
        for folder in ('var', 'var/lib', 'var/lib/ardrec',
                       reader141.DROP, reader141.DROP + '/B4',
                       reader141.DROP + '/B9', 'etc', 'etc/ardrec',
                       str(Path(reader141.BOOT_REFERENCE).parent.parent),
                       str(Path(reader141.BOOT_REFERENCE).parent)):
            path = self.root / folder
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)
        for name, body in self.fixture.fix.payload.items():
            self.put(reader141.DROP + '/' + name, body)
        self.put(reader141.DROP + '/approval.json',
                 txn.canonical({'schema': 'ARDREC-R142-UNTRUSTED-TEST-DOCUMENT'}))
        for name, relative in reader141.POLICY.items():
            self.put(relative, self.input[name])
        self.put(reader141.BOOT_REFERENCE, self.input['f8_reference'])

    def tearDown(self):
        self.root_temp.cleanup()
        self.temp.cleanup()

    def put(self, relative, body):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o600)
        return path

    def path(self, label):
        if label in reader141.POLICY:
            return self.root / reader141.POLICY[label]
        if label == 'f8_reference':
            return self.root / reader141.BOOT_REFERENCE
        if label == 'approval':
            return self.root / reader141.DROP / 'approval.json'
        return self.root / reader141.DROP / label

    def run_bridge(self, **override):
        values = dict(parent=self.parent, head=test139.HEAD,
                      boot_id=test139.BOOT, clock=self.clock)
        values.update(override)
        with reader141.LockedTree(self.root, owner=os.geteuid()) as tree:
            return bridge.exercise_from_reader(reader=tree, **values)

    def run_review(self, **override):
        values = dict(head=test139.HEAD,
                      boot_id=test139.BOOT, clock=self.clock)
        values.update(override)
        with reader141.LockedTree(self.root, owner=os.geteuid()) as tree:
            return bridge.review_from_reader(reader=tree, **values)

    def denied(self, substring=None, **kwargs):
        with self.assertRaises((ValueError, OSError)) as ctx:
            self.run_bridge(**kwargs)
        if substring:
            self.assertIn(substring, str(ctx.exception))
        return str(ctx.exception)

    def test_01_complete_signed_capture_to_receipt(self):
        result = self.run_bridge()
        self.assertEqual(result['status'], 'PRIVATE_PAIR_PUBLISHED')
        self.assertTrue((self.parent / 'receipt.json').is_file())
        self.assertFalse(result['root_install_authorized'])

    def test_02_four_live_input_rechecks(self):
        result = self.run_bridge()
        self.assertEqual(result['phases_rechecked'], list(sandbox140.STAGES))
        self.assertEqual(result['phase_readbacks'], 4)
        self.assertEqual(result['protected_files_checked_per_read'], 27)

    def test_03_readonly_review(self):
        result = self.run_review()
        self.assertEqual(result['operational_signed_semantics'], 'PASS')
        self.assertEqual(result['release_signed_semantics'], 'PASS')
        self.assertFalse(result['root_install_authorized'])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_04_idempotent_rechecked(self):
        first = self.run_bridge()
        second = self.run_bridge()
        self.assertEqual(second['status'], 'ALREADY_PUBLISHED_VERIFIED')
        self.assertEqual(first['receipt_sha256'], second['receipt_sha256'])

    def test_05_resume_after_b4(self):
        self.denied('INJECTED_AFTER_B4', fault='after_b4')
        self.assertTrue((self.parent / 'published-b4').is_dir())
        self.assertFalse((self.parent / 'published-b9').exists())
        self.assertEqual(self.run_bridge()['status'], 'PRIVATE_PAIR_PUBLISHED')

    def test_06_resume_after_b9(self):
        self.denied('INJECTED_AFTER_B9', fault='after_b9')
        self.assertTrue((self.parent / 'published-b9').is_dir())
        self.assertEqual(self.run_bridge()['status'], 'PRIVATE_PAIR_PUBLISHED')

    def test_07_resume_before_b4(self):
        self.denied('INJECTED_BEFORE_B4', fault='before_b4')
        self.assertEqual(self.run_bridge()['status'], 'PRIVATE_PAIR_PUBLISHED')

    def test_08_resume_before_receipt(self):
        self.denied('INJECTED_BEFORE_RECEIPT', fault='before_receipt')
        self.assertEqual(self.run_bridge()['status'], 'PRIVATE_PAIR_PUBLISHED')

    def test_09_reject_tampered_b4_source(self):
        self.put(reader141.DROP + '/B4/root-controller.py', b'tampered')
        self.denied('B4_SOURCE_PIN_MISMATCH')

    def test_10_reject_tampered_b9_source(self):
        self.put(reader141.DROP + '/B9/root-executor.py', b'tampered')
        self.denied('B9_SOURCE_PIN_MISMATCH')

    def test_11_reject_forged_grant(self):
        self.put(reader141.DROP + '/B4/grant.json', txn.canonical({'schema': 'FAKE'}))
        self.denied()
        self.assertFalse((self.parent / 'published-b4').exists())

    def test_12_reject_release_revocation_corruption(self):
        self.put(reader141.POLICY['release_revocation'], txn.canonical({'schema':'FAKE'}))
        self.denied()

    def test_13_reject_release_trust_corruption(self):
        self.put(reader141.POLICY['release_trust'], txn.canonical({'schema':'FAKE'}))
        self.denied()

    def test_14_reject_f8_reference_mutation(self):
        self.put(reader141.BOOT_REFERENCE, txn.canonical({'schema':'FAKE'}))
        self.denied()

    def test_15_reject_wrong_boot(self):
        self.denied(boot_id='11111111-1111-4111-8111-111111111111')

    def test_16_reject_wrong_head(self):
        self.denied(head='0' * 40)

    def test_17_reject_expired_window(self):
        self.denied(clock=lambda: test139.NOW + timedelta(minutes=10))

    def test_18_reject_missing_policy(self):
        self.path('pilot_trust').unlink()
        self.denied()

    def test_19_reject_missing_approval_document(self):
        self.path('approval').unlink()
        self.denied('DROP_ENTRIES_UNEXPECTED')

    def test_20_reject_symlinked_policy(self):
        target = self.path('root_trust')
        content = target.read_bytes()
        target.unlink()
        sibling = self.put('etc/ardrec/other.json', content)
        target.symlink_to(sibling)
        self.denied()

    def test_21_reject_hardlinked_policy(self):
        target = self.path('root_trust')
        other = target.with_name('other.json')
        os.link(target, other)
        self.denied('FILE_METADATA_INVALID')

    def test_22_reject_permissive_mode(self):
        self.path('root_trust').chmod(0o644)
        self.denied('FILE_METADATA_INVALID')

    def test_23_reject_unexpected_drop_entry(self):
        self.put(reader141.DROP + '/unapproved.json', b'{}\n')
        self.denied('DROP_ENTRIES_UNEXPECTED')

    def test_24_reject_change_before_b9(self):
        def edit(phase):
            if phase == 'before_b9':
                self.put(reader141.POLICY['window_revocation'], txn.canonical({'schema':'FAKE'}))
        self.denied('ROOT_INPUT_CHANGED_BETWEEN_PHASES', test_phase_hook=edit)
        self.assertTrue((self.parent / 'published-b4').is_dir())
        self.assertFalse((self.parent / 'published-b9').exists())

    def test_25_reject_changed_approval_during_transaction(self):
        def edit(phase):
            if phase == 'before_b4':
                self.put(reader141.DROP + '/approval.json',
                         txn.canonical({'schema': 'CHANGED_UNTRUSTED'}))
        self.denied('ROOT_INPUT_CHANGED_BETWEEN_PHASES', test_phase_hook=edit)
        self.assertFalse((self.parent / 'published-b4').exists())

    def test_26_reject_root_process(self):
        with reader141.LockedTree(self.root, owner=os.geteuid()) as tree:
            with mock.patch.object(bridge.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(bridge.Refusal, 'ROOT_FORBIDDEN'):
                    bridge.exercise_from_reader(
                        reader=tree, parent=self.parent, head=test139.HEAD,
                        boot_id=test139.BOOT, clock=self.clock)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_27_reject_nested_sandbox(self):
        nested = self.parent / 'nested'
        nested.mkdir(mode=0o700)
        self.denied('SANDBOX_SCOPE_REQUIRED', parent=nested)

    def test_28_reject_unexpected_fault(self):
        self.denied('UNKNOWN_FAULT', fault='root-install')

    def test_29_no_privileged_claims(self):
        out = self.run_bridge()
        for key in ('root_install_authorized', 'root_install_executed',
                    'operational_destinations_written', 'traffic_enabled',
                    'root_provenance_verified', 'independent_git_signature_verified',
                    'physical_f8_chain_attested'):
            self.assertFalse(out[key])
        self.assertEqual((out['a6'],out['a9'],out['p8']), ('ND',None,'NO-GO'))

    def test_30_capabilities(self):
        c = bridge.capabilities()
        self.assertFalse(c['root_installer'])
        self.assertFalse(c['root_provenance_verified'])
        self.assertFalse(c['traffic_enabled'])
        self.assertTrue(c['snapshot_and_phase_recheck'])


if __name__ == '__main__':
    unittest.main()
