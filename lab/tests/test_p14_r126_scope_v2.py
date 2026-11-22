"""R126 V2: real Ed25519 scope + independent revocation; not P8."""
from __future__ import annotations

from datetime import timedelta
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as legacy
from ardrec.coordination import r115_f15_p7_independent_pilot as pilot
from ardrec.coordination import r126_operational_controller as controller
from ardrec.coordination import r126_scope_v2 as m
from test_p14_r115_f11_p8_signed_window import (
    CATALOG, NOW, HEAD, contract, keypair, signed,
)


def fixture():
    contract_doc=contract()
    scope_key,scope_pub=keypair('r126.scope.signer')
    revoke_key,revoke_pub=keypair('r126.revocation.signer')
    scope_statement={
        'schema':f3.AUTH_SCHEMA,'authorization_id':'FTP-T01-R126-AUTH',
        'case_id':contract_doc['case_id'],'family_id':'FTP-T01','stage':'DEV',
        'valid_from':contract_doc['valid_from'],
        'valid_until':contract_doc['valid_until'],
        'target':copy.deepcopy(contract_doc['target']),
        'client_sha256':contract_doc['client']['sha256'],
        'profile_sha256':contract_doc['profile']['sha256'],
        'catalog_sha256':contract_doc['catalog_sha256'],
        'limits':copy.deepcopy(contract_doc['limits']),
    }
    auth=signed(scope_statement,scope_key,scope_pub,f3.PREFIX_AUTH)
    contract_doc['authority']['sha256']=f1.digest(f1.canonical(auth))
    revoke_stmt={
        'schema':f3.REVOCATION_SCHEMA,
        'authorization_sha256':f1.digest(f1.canonical(auth)),
        'authorization_id':scope_statement['authorization_id'],
        'issued_at':'2026-11-20T16:59:50Z',
        'valid_until':'2026-11-20T17:01:00Z',
        'revoked':False,'reason_code':'CURRENT_CLEAR',
    }
    revoke=signed(revoke_stmt,revoke_key,revoke_pub,f3.PREFIX_REVOKE)
    trust={'schema':f3.TRUST_SCHEMA,'scope_signer':scope_pub,
           'revocation_signer':revoke_pub}
    root={m.TRUST:f1.canonical(trust),m.REVOCATION:f1.canonical(revoke)}
    return f1.canonical(contract_doc),f1.canonical(auth),root


def review(c,a,root,*,head=HEAD,now=NOW):
    return m.review_scope(contract_raw=c,authorization_raw=a,
                          catalog_raw=CATALOG,expected_head=head,now=now,
                          root_loader=lambda path:(root[path] if path in root else (_ for _ in ()).throw(FileNotFoundError(path))))


class ScopeV2Tests(unittest.TestCase):
    def test_01_distinct_v2_root_paths(self):
        self.assertNotEqual(m.TRUST,legacy.TRUST)
        self.assertNotEqual(m.REVOCATION,legacy.REVOCATION)
        self.assertTrue(str(m.TRUST).startswith('/etc/ardrec/'))

    def test_02_cryptographic_signature_and_current_revocation(self):
        c,a,root=fixture()
        v=review(c,a,root)
        self.assertEqual(v[0],'VERDADERO')
        self.assertIn('DOCUMENT_ONLY_NOT_P8',v[1])
        self.assertEqual(v[2],f1.digest(a))

    def test_03_wrong_head(self):
        c,a,root=fixture()
        with self.assertRaisesRegex(m.Stop,'SOURCE_COMMIT_MISMATCH'):
            review(c,a,root,head='f'*40)

    def test_04_legacy_head_refused(self):
        c,a,root=fixture()
        d=f1.load(c);d['source_commit']=legacy.BASE
        with self.assertRaisesRegex(m.Stop,'LEGACY_F6_BASE_NOT_ACCEPTED'):
            review(f1.canonical(d),a,root,head=legacy.BASE)

    def test_05_revoked(self):
        c,a,root=fixture()
        original=f1.load(root[m.REVOCATION]);original['statement']['revoked']=True
        # To verify the signed-revocation branch, mock only the crypto function.
        root[m.REVOCATION]=f1.canonical(original)
        with patch.object(m.f3,'auth_review',return_value={
                'status':'FALSO','crypto_verified':True,
                'authorization_sha256':f1.digest(a)}):
            self.assertEqual(review(c,a,root)[0],'FALSO')

    def test_06_no_provisioned_root(self):
        c,a,root=fixture()
        del root[m.TRUST]
        self.assertEqual(review(c,a,root)[0],'ND')

    def test_07_revocation_stale(self):
        c,a,root=fixture()
        # A valid signed revocation can still be too old at the review instant.
        self.assertEqual(review(c,a,root,now=NOW+timedelta(seconds=35))[0],'ND')

    def test_08_revocation_expired(self):
        c,a,root=fixture()
        self.assertEqual(review(c,a,root,now=NOW+timedelta(seconds=61))[0],'ND')

    def test_09_unsafe_injected_trust(self):
        c,a,root=fixture();raw=root[m.TRUST]
        root[m.TRUST]=raw+b' '
        self.assertEqual(review(c,a,root)[0],'FALSO')

    def test_10_modified_signed_authorization(self):
        c,a,root=fixture()
        signed_auth=f1.load(a)
        signed_auth['statement']['limits']['timeout_seconds']=9
        self.assertEqual(review(c,f1.canonical(signed_auth),root)[0],'FALSO')

    def test_11_distinct_signer_enforced(self):
        c,a,root=fixture()
        trust=f1.load(root[m.TRUST]);trust['revocation_signer']=trust['scope_signer']
        root[m.TRUST]=f1.canonical(trust)
        self.assertEqual(review(c,a,root)[0],'FALSO')

    def test_12_malformed_contract_rejected(self):
        c,a,root=fixture()
        with self.assertRaisesRegex(m.Stop,'SCOPE_CONTRACT_INVALID'):
            review(b'{}',a,root)

    def test_13_clock_naive(self):
        c,a,root=fixture()
        with self.assertRaisesRegex(m.Stop,'CURRENT_CLOCK_REQUIRED'):
            review(c,a,root,now=NOW.replace(tzinfo=None))

    def test_14_nongit_head(self):
        c,a,root=fixture()
        with self.assertRaisesRegex(m.Stop,'EXPECTED_SOURCE_HEAD_INVALID'):
            review(c,a,root,head='incomplete')

    def test_15_enrollment_never_authorizes(self):
        info=m.enrollment_plan(expected_head=HEAD)
        self.assertEqual(info['p8'],'NO-GO')
        self.assertFalse(info['private_keys_generated_here'])
        self.assertFalse(info['signature_issued_here'])
        self.assertFalse(info['network_traffic_authorized'])
        self.assertNotIn('private_key_pem',str(info))

    def test_16_for_head_bound(self):
        c,a,root=fixture()
        with patch.object(m,'review_scope',return_value=('ND','NOT_PROVISIONED',None)) as validator:
            # Live callback closes over the HEAD and does not accept root_loader.
            reviewer=m.for_head(HEAD)
            self.assertEqual(reviewer(c,a,catalog_raw=CATALOG,now=NOW)[0],'ND')
            self.assertEqual(validator.call_args.kwargs['expected_head'],HEAD)
            self.assertNotIn('root_loader',validator.call_args.kwargs)

    def test_17_scope_status_never_p8(self):
        c,a,root=fixture()
        self.assertEqual(review(c,a,root)[0],'VERDADERO')
        self.assertNotIn('GO',review(c,a,root)[1])

    def test_18_no_root_legacy_authority_auto_fallback(self):
        c,a,root=fixture()
        del root[m.REVOCATION]
        self.assertEqual(review(c,a,root)[0],'ND')

    def test_19_timestamp_microseconds_refused(self):
        c,a,root=fixture()
        with self.assertRaises(m.Stop):
            review(c,a,root,now=NOW+timedelta(microseconds=1))

    def test_20_live_controller_uses_v2_reviewer(self):
        with patch.object(controller.scope_v2,'root_role_separation',return_value=True),\
             patch.object(controller.f15,'signed_pilot_review',return_value={'document_status':'ND'}) as verify:
            controller.signed_documents(contract_raw=b'{}',authorization_raw=b'{}',
                                        pilot_raw=b'{}',catalog_raw=CATALOG,head=HEAD,now=NOW)
            self.assertIn('scope_reviewer',verify.call_args.kwargs)
            self.assertTrue(callable(verify.call_args.kwargs['scope_reviewer']))

    def test_21_deny_loader_default_not_editable_from_cli(self):
        from inspect import signature
        self.assertIs(signature(m.for_head(HEAD)).parameters['now'].default,
                      signature(m.for_head(HEAD)).empty)


    def test_22_reject_scope_pilot_reused_public_key(self):
        c,a,root=fixture()
        trust=f1.load(root[m.TRUST])
        pilot_trust={'schema':pilot.TRUST_SCHEMA,
            'pilot_signer':trust['scope_signer'],
            'revocation_signer':trust['revocation_signer']}
        with self.assertRaisesRegex(m.Stop,'SCOPE_AND_PILOT_SIGNERS_NOT_INDEPENDENT'):
            m.verify_signer_separation(trust,pilot_trust)

    def test_23_distinct_four_roles(self):
        c,a,root=fixture()
        trust=f1.load(root[m.TRUST])
        _,p1=keypair('r126.pilot.signer')
        _,p2=keypair('r126.pilot.revocation.signer')
        pilot_trust={'schema':pilot.TRUST_SCHEMA,
            'pilot_signer':p1,'revocation_signer':p2}
        self.assertTrue(m.verify_signer_separation(trust,pilot_trust))

    def test_24_reject_same_id_different_key(self):
        c,a,root=fixture()
        trust=f1.load(root[m.TRUST])
        _,p1=keypair(trust['scope_signer']['key_id'])
        _,p2=keypair('r126.pilot.revocation.signer')
        pilot_trust={'schema':pilot.TRUST_SCHEMA,
            'pilot_signer':p1,'revocation_signer':p2}
        with self.assertRaisesRegex(m.Stop,'SCOPE_AND_PILOT_SIGNERS_NOT_INDEPENDENT'):
            m.verify_signer_separation(trust,pilot_trust)

    def test_25_signed_documents_checks_real_pinned_roles(self):
        with patch.object(controller.scope_v2,'root_role_separation',return_value=True) as check,             patch.object(controller.f15,'signed_pilot_review',return_value={'document_status':'ND'}) as verify:
            controller.signed_documents(contract_raw=b'{}',authorization_raw=b'{}',
                                        pilot_raw=b'{}',catalog_raw=CATALOG,head=HEAD,now=NOW)
            check.assert_called_once()
            self.assertIn('scope_reviewer',verify.call_args.kwargs)

    def test_26_no_injected_root_role_evidence(self):
        with patch.object(controller.scope_v2,'root_role_separation',side_effect=m.Stop('MISSING_TRUST')):
            with self.assertRaisesRegex(controller.Stop,'CURRENT_SIGNED_PILOT_REJECTED'):
                controller.signed_documents(contract_raw=b'{}',authorization_raw=b'{}',
                                            pilot_raw=b'{}',catalog_raw=CATALOG,head=HEAD,now=NOW)

    def test_27_provisioning_plan_includes_all_operational_roles(self):
        x=m.enrollment_plan(expected_head=HEAD)
        self.assertEqual(len(x['additional_independent_root_policies']),7)
        self.assertEqual(x['source_commit'],HEAD)
        self.assertFalse(x['root_install_performed_here'])
        self.assertFalse(x['guest_boot_authorized'])


if __name__=='__main__':
    unittest.main()
