"""R140 integration tests: ephemeral Ed25519 + strictly nonroot sandbox writes."""
from __future__ import annotations

from datetime import timedelta
import fcntl
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_p14_r139_independent_release_review as source
from ardrec.coordination import r135_root_transaction as txn
from ardrec.coordination import r140_release_transaction_sandbox as bridge


class R140SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source.R139ReleaseTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        source.R139ReleaseTests.tearDownClass()

    def setUp(self):
        self.source = source.R139ReleaseTests('test_01_positive_full_signed_review')
        self.source.setUp()
        self.temp = tempfile.TemporaryDirectory(prefix=bridge.PREFIX)
        self.parent = Path(self.temp.name)
        self.data = dict(
            parent=self.parent,
            payload=self.source.fix.payload,
            external=self.source.fix.external,
            release_trust=self.source.b9.canon(self.source.release_trust),
            release_revocation=self.source.b9.canon(self.source.revocation),
            f8_reference=self.source.f8_reference,
            b4_source=self.source.fix.b4raw,
            b9_source=self.source.fix.b9raw,
            head=source.HEAD,
            boot_id=source.BOOT,
            clock=lambda: source.NOW,
        )

    def tearDown(self):
        self.temp.cleanup()

    def exercise(self, **changes):
        return bridge.exercise_sandbox(**(self.data | changes))

    def fail(self, reason=None, **changes):
        with self.assertRaises((ValueError, OSError)) as captured:
            self.exercise(**changes)
        if reason:
            self.assertIn(reason, str(captured.exception))
        return str(captured.exception)

    def test_01_complete(self):
        result = self.exercise()
        self.assertEqual(result['status'], 'PRIVATE_PAIR_PUBLISHED')
        self.assertTrue((self.parent/'receipt.json').is_file())

    def test_02_idempotent(self):
        first=self.exercise()
        second=self.exercise()
        self.assertEqual(second['status'],'ALREADY_PUBLISHED_VERIFIED')
        self.assertEqual(first['receipt_sha256'],second['receipt_sha256'])

    def test_03_all_phases_revalidated(self):
        result=self.exercise()
        self.assertEqual(result['reviewed_phases'],
                         ['before_journal','before_b4','before_b9','before_receipt'])
        self.assertEqual(result['reviewed_phase_count'],4)

    def test_04_before_b4_resume(self):
        self.fail('INJECTED_BEFORE_B4',fault='before_b4')
        self.assertFalse((self.parent/'published-b4').exists())
        self.assertEqual(self.exercise()['status'],'PRIVATE_PAIR_PUBLISHED')

    def test_05_after_b4_resume(self):
        self.fail('INJECTED_AFTER_B4',fault='after_b4')
        self.assertTrue((self.parent/'published-b4').is_dir())
        self.assertFalse((self.parent/'published-b9').exists())
        self.assertEqual(self.exercise()['status'],'PRIVATE_PAIR_PUBLISHED')

    def test_06_after_b9_resume(self):
        self.fail('INJECTED_AFTER_B9',fault='after_b9')
        self.assertTrue((self.parent/'published-b9').is_dir())
        self.assertFalse((self.parent/'receipt.json').exists())
        self.assertEqual(self.exercise()['status'],'PRIVATE_PAIR_PUBLISHED')

    def test_07_before_receipt_resume(self):
        self.fail('INJECTED_BEFORE_RECEIPT',fault='before_receipt')
        self.assertEqual(self.exercise()['status'],'PRIVATE_PAIR_PUBLISHED')

    def test_08_after_stage_resume(self):
        self.fail('INJECTED_AFTER_STAGE',fault='after_stage')
        self.assertTrue((self.parent/'.pending-b4').exists())
        self.assertEqual(self.exercise()['status'],'PRIVATE_PAIR_PUBLISHED')

    def test_09_forbidden_operational_claims(self):
        result=self.exercise()
        for key in ('installation_permission','root_install_executed',
                    'traffic_enabled','operational_destinations_written',
                    'root_trust_provenance_verified'):
            self.assertFalse(result[key])
        self.assertEqual((result['a6'],result['a9'],result['p8']),('ND',None,'NO-GO'))

    def test_10_idempotent_still_checks_signed_release(self):
        self.exercise()
        self.data['release_trust']=b'{}\n'
        self.fail()

    def test_11_mutation_before_journal_rejected(self):
        def mutate(phase):
            if phase=='before_journal':
                self.data['payload']['B4/contract.json']+=b' '
        self.fail('INPUT_MUTATED_BETWEEN_PHASES',test_phase_hook=mutate)
        self.assertFalse((self.parent/'journal.json').exists())

    def test_12_mutation_after_b4_rejected(self):
        def mutate(phase):
            if phase=='before_b9':
                self.data['external']['pilot_trust']+=b' '
        self.fail('INPUT_MUTATED_BETWEEN_PHASES',test_phase_hook=mutate)
        self.assertTrue((self.parent/'published-b4').exists())
        self.assertFalse((self.parent/'published-b9').exists())

    def test_13_b4_tamper(self):
        self.data['payload']['B4/root-controller.py']+=b'x'
        self.fail('B4_PIN_INVALID')

    def test_14_b9_tamper(self):
        self.data['payload']['B9/root-executor.py']+=b'x'
        self.fail('B9_PIN_INVALID')

    def test_15_release_trust_invalid(self):
        self.fail(release_trust=b'{}\n')

    def test_16_release_revocation_invalid(self):
        self.fail(release_revocation=b'{}\n')

    def test_17_f8_reference_mismatch(self):
        altered=txn.canonical({'schema':source.r139.REFERENCE_SCHEMA,
                               'plan':'another','boot':'another'})
        self.fail(f8_reference=altered)

    def test_18_wrong_head(self):
        self.fail(head='0'*40)

    def test_19_wrong_boot(self):
        self.fail(boot_id='00000000-0000-4000-8000-000000000001')

    def test_20_expired_phase_denied(self):
        ticks=[0]
        def clock():
            ticks[0]+=1
            return source.NOW if ticks[0]<=3 else source.NOW+timedelta(minutes=10)
        self.fail(clock=clock)
        self.assertFalse((self.parent/'published-b9').exists())

    def test_21_missing_payload_file(self):
        del self.data['payload']['B9/lock']
        self.fail()

    def test_22_wrong_parent_name(self):
        with tempfile.TemporaryDirectory(prefix='r140-unrelated-') as folder:
            self.fail('SANDBOX_SCOPE_REQUIRED',parent=Path(folder))

    def test_23_nested_parent_denied(self):
        child=self.parent/'nested'
        child.mkdir(mode=0o700)
        self.fail('SANDBOX_SCOPE_REQUIRED',parent=child)

    def test_24_symlink_parent_denied(self):
        link=self.parent.parent/(self.parent.name+'-link')
        try:
            link.symlink_to(self.parent)
            self.fail('SANDBOX_SYMLINK_DENIED',parent=link)
        finally:
            if link.is_symlink():link.unlink()

    def test_25_insecure_parent_denied(self):
        os.chmod(self.parent,0o755)
        self.fail('SANDBOX_METADATA_INVALID')
        os.chmod(self.parent,0o700)

    def test_26_root_rejected_without_write(self):
        with mock.patch.object(bridge.os,'geteuid',return_value=0):
            self.fail('ROOT_FORBIDDEN')
        self.assertEqual(list(self.parent.iterdir()),[])

    def test_27_altered_published_file_denied(self):
        self.exercise()
        path=self.parent/'published-b4'/'contract.json'
        path.write_bytes(b'drift')
        self.fail()

    def test_28_missing_published_directory_denied(self):
        self.exercise()
        (self.parent/'published-b9').rename(self.parent/'moved-b9')
        self.fail()

    def test_29_wrong_transaction_fault(self):
        self.fail('UNKNOWN_FAULT',fault='root_install')

    def test_30_capabilities(self):
        cap=bridge.capabilities()
        self.assertFalse(cap['root_installer'])
        self.assertFalse(cap['root_trust_provenance_verified'])
        self.assertFalse(cap['traffic_enabled'])
        self.assertEqual(cap['p8'],'NO-GO')

if __name__=='__main__':unittest.main()
