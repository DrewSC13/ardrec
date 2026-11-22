"""R139 exact offline release signatures; all keys are ephemeral test keys."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from ardrec.coordination import r139_independent_release_review as r139
from ardrec.coordination import r135_root_transaction as txn
import test_p14_r136_operational_semantics as fixture
HEAD, BOOT, NOW, START = fixture.HEAD, fixture.BOOT, fixture.NOW, fixture.START


class R139ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.OperationalSemantics.setUpClass()
        cls.shared = fixture.OperationalSemantics
        for name in ('release_auth', 'release_rev'):
            secret = cls.shared.root / (name + '.key')
            public = cls.shared.root / (name + '.pub')
            fixture.openssl('genpkey', '-algorithm', 'ED25519', '-out', secret)
            fixture.openssl('pkey', '-in', secret, '-pubout', '-out', public)
            cls.shared.keys[name] = (secret, public.read_text('ascii'))

    @classmethod
    def tearDownClass(cls):
        cls.shared.tearDownClass()

    def setUp(self):
        self.fix = fixture.OperationalSemantics('test_01_complete_signed_b4_b9')
        self.fix.setUp()
        self.b9 = self.fix.b9
        self.f8_reference = txn.canonical({
            'schema': r139.REFERENCE_SCHEMA,
            'plan': '/home/cicada/ardrec-lab/f8/plan-existing',
            'boot': '/home/cicada/ardrec-lab/f8/receipt-existing',
        })
        manifest = self.b9.parse(self.fix.payload['B9/manifest.json'])
        self.release_statement = {
            'schema': self.b9.RELEASE_SCHEMA,
            'release_id': 'r139_release_test',
            'approved_head': HEAD,
            'boot_id': BOOT,
            'manifest_sha256': self.b9.digest(manifest),
            'script_sha256': txn.B9_SHA,
            'r126_deny_controller_sha256': txn.B4_SHA,
            'legacy_f3_sha256': txn.F3_SHA,
            'guard_sha256': txn.GUARD_SHA,
            'f8_reference_sha256': hashlib.sha256(self.f8_reference).hexdigest(),
            'source_commit_signature_verified': True,
            'independent_review': True,
            'valid_from': START,
            'valid_until': '2026-11-22T03:03:00Z',
            'action': 'RELEASE_EXACT_ROOT_BUNDLE_FOR_SINGLE_FTP_T01',
            'p8': 'NO-GO',
        }
        self.release_trust = {
            'schema': self.b9.RELEASE_TRUST_SCHEMA,
            'release_signer': self.fix.key('release_auth'),
            'revocation_signer': self.fix.key('release_rev'),
        }
        self.resign_release()
        self.resign_revocation()

    def resign_release(self):
        self.release = self.fix.sign('release_auth', self.b9.RELEASE_PREFIX,
                                     self.release_statement)
        self.fix.payload['B9/release.json'] = self.b9.canon(self.release)

    def resign_revocation(self):
        self.revocation = self.fix.rev(
            'release_rev', self.b9.RELEASE_REV_PREFIX, self.b9.RELEASE_REV_SCHEMA,
            'release_id', self.release_statement['release_id'],
            'release_sha256', self.b9.digest(self.release),
        )

    def run_review(self, **replace):
        arguments = dict(
            payload=self.fix.payload,
            external=self.fix.external,
            b4_source=self.fix.b4raw,
            b9_source=self.fix.b9raw,
            release_trust=self.b9.canon(self.release_trust),
            release_revocation=self.b9.canon(self.revocation),
            f8_reference=self.f8_reference,
            head=HEAD, boot_id=BOOT, now=NOW,
        )
        arguments.update(replace)
        return r139.review(**arguments)

    def deny(self, code=None, **kw):
        with self.assertRaises(ValueError) as caught:
            self.run_review(**kw)
        if code:
            self.assertIn(code, str(caught.exception))

    def test_01_positive_full_signed_review(self):
        review = self.run_review()
        self.assertEqual(review['operational_signed_semantics'], 'PASS')
        self.assertEqual(review['release_signed_semantics'], 'PASS')
        self.assertFalse(review['installation_permission'])
        self.assertFalse(review['root_trust_provenance_verified'])
        self.assertFalse(review['f8_physical_boot_chain_attested'])
        self.assertEqual(review['p8'], 'NO-GO')

    def test_02_b4_source_tampered(self):
        self.deny('B4_PIN_INVALID', payload={**self.fix.payload,
             'B4/root-controller.py': self.fix.b4raw + b'x'})

    def test_03_b9_source_tampered(self):
        self.deny('B9_PIN_INVALID', payload={**self.fix.payload,
             'B9/root-executor.py': self.fix.b9raw + b'x'})

    def test_04_forged_release_signature(self):
        self.release['signature_b64'] = base64.b64encode(bytes(64)).decode()
        self.fix.payload['B9/release.json'] = self.b9.canon(self.release)
        self.deny('SIGNATURE_INVALID')

    def test_05_release_revoked(self):
        self.revocation['statement']['revoked'] = True
        self.revocation = self.fix.sign('release_rev', self.b9.RELEASE_REV_PREFIX,
                                        self.revocation['statement'])
        self.deny('REVOCATION_NOT_BOUND_OR_REVOKED')

    def test_06_release_expired(self):
        self.release_statement['valid_until'] = '2026-11-22T03:00:04Z'
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_NOT_CURRENT')

    def test_07_release_revocation_stale(self):
        self.revocation['statement']['issued_at'] = '2026-11-22T02:58:00Z'
        self.revocation = self.fix.sign('release_rev', self.b9.RELEASE_REV_PREFIX,
                                        self.revocation['statement'])
        self.deny('REVOCATION_NOT_FRESH')

    def test_08_signer_reused_from_operational_role(self):
        self.release_trust['release_signer'] = self.fix.key('root_grant')
        self.deny('ROOT_RELEASE_SIGNERS_NOT_DISTINCT')

    def test_09_release_revoker_reuses_operational_key(self):
        self.release_trust['revocation_signer'] = self.fix.key('traffic_rev')
        self.deny('ROOT_RELEASE_SIGNERS_NOT_DISTINCT')

    def test_10_release_signer_and_revoker_same(self):
        self.release_trust['revocation_signer'] = self.fix.key('release_auth')
        self.deny('ROOT_RELEASE_SIGNERS_NOT_DISTINCT')

    def test_11_reused_key_with_new_identifier(self):
        self.release_trust['release_signer']['key_id'] = 'unused.reused.id'
        self.release_trust['release_signer']['public_key_pem'] = self.fix.key('root_grant')['public_key_pem']
        self.deny('ROOT_RELEASE_SIGNERS_NOT_DISTINCT')

    def test_12_wrong_head(self):
        self.release_statement['approved_head'] = '0' * 40
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_13_wrong_boot_id(self):
        self.release_statement['boot_id'] = 'f' * 36
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_14_wrong_manifest_sha(self):
        self.release_statement['manifest_sha256'] = '0' * 64
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_15_wrong_f8_reference_sha(self):
        self.release_statement['f8_reference_sha256'] = '0' * 64
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_16_invalid_f8_schema(self):
        self.deny('F8_REFERENCE_SCHEMA', f8_reference=txn.canonical({'schema':'fake', 'plan':'p','boot':'b'}))

    def test_17_f8_noncanonical(self):
        self.deny('JSON_NONCANONICAL', f8_reference=b'{}')

    def test_18_missing_upstream_trust(self):
        e = dict(self.fix.external); del e['pilot_trust']
        self.deny('EXTERNAL_DOCUMENT_SCOPE', external=e)

    def test_19_missing_traffic_revocation(self):
        e = dict(self.fix.external); del e['traffic_revocation']
        self.deny('EXTERNAL_DOCUMENT_SCOPE', external=e)

    def test_20_malformed_release_trust(self):
        self.deny('RELEASE_TRUST_FIELDS', release_trust=txn.canonical({'schema':'fake'}))

    def test_21_wrong_release_revocation_id(self):
        self.revocation['statement']['release_id'] = 'another-release'
        self.revocation = self.fix.sign('release_rev', self.b9.RELEASE_REV_PREFIX,
                                        self.revocation['statement'])
        self.deny('REVOCATION_NOT_BOUND_OR_REVOKED')

    def test_22_wrong_release_revocation_sha(self):
        self.revocation['statement']['release_sha256'] = '0' * 64
        self.revocation = self.fix.sign('release_rev', self.b9.RELEASE_REV_PREFIX,
                                        self.revocation['statement'])
        self.deny('REVOCATION_NOT_BOUND_OR_REVOKED')

    def test_23_wrong_release_revocation_signature(self):
        self.revocation['signature_b64'] = base64.b64encode(bytes(64)).decode()
        self.deny('SIGNATURE_INVALID')

    def test_24_release_git_signature_claim_false(self):
        self.release_statement['source_commit_signature_verified'] = False
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_25_release_independent_review_claim_false(self):
        self.release_statement['independent_review'] = False
        self.resign_release(); self.resign_revocation()
        self.deny('ROOT_RELEASE_SCOPE_INVALID')

    def test_26_forged_operational_grant(self):
        entry = self.fix.b4.parse(self.fix.payload['B4/grant.json'])
        entry['signature_b64'] = base64.b64encode(bytes(64)).decode()
        self.fix.payload['B4/grant.json'] = self.b9.canon(entry)
        self.deny('SIGNATURE_INVALID')

    def test_27_changed_handoff(self):
        self.fix.payload['B9/f13-handoff.json'] = txn.canonical({'schema':'TEST_ONLY'})
        self.deny()

    def test_28_noncanonical_release(self):
        self.fix.payload['B9/release.json'] = b'{}'
        self.deny('JSON_NONCANONICAL')

    def test_29_expired_time(self):
        self.deny(now=datetime(2026, 11, 23, tzinfo=timezone.utc))

    def test_30_capabilities(self):
        caps = r139.capabilities()
        self.assertFalse(caps['root_installer'])
        self.assertFalse(caps['root_provenance_verified'])
        self.assertFalse(caps['traffic_enabled'])
        self.assertEqual(caps['p8'], 'NO-GO')


if __name__ == '__main__':
    unittest.main()
