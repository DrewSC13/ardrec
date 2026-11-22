"""B3: real Ed25519 scope + F15 pilot + F11 traffic-window documentary review."""
from __future__ import annotations

import copy
from datetime import timedelta
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r126_scope_v2 as scope
from ardrec.coordination import r126_window_v2 as mod
from test_p14_r115_f11_p8_signed_window import CATALOG, NOW, HEAD, budget, keypair, signed
from test_p14_r126_scope_v2 import fixture as scope_fixture


def fixture():
    contract, auth, root = scope_fixture()
    pilot_key, pilot_public = keypair('r126.b3.pilot.signer.real')
    pilot_rev_key, pilot_rev_pub = keypair('r126.b3.pilot.revocation')
    pilot_trust = {'schema':f15.TRUST_SCHEMA, 'pilot_signer':pilot_public,
                   'revocation_signer':pilot_rev_pub}
    c=f1.load(contract)
    pilot_stmt={'schema':f15.PERMIT_SCHEMA,'pilot_id':'R126B3FTP-PILOT',
        'case_id':c['case_id'],'stage':'DEV','family_id':'FTP-T01',
        'head':HEAD,'contract_sha256':f1.digest(contract),
        'scope_authorization_sha256':f1.digest(auth),
        'catalog_sha256':f1.digest(CATALOG),'target':copy.deepcopy(c['target']),
        'budget':budget(),'valid_from':'2026-11-20T16:59:50Z',
        'valid_until':'2026-11-20T17:00:30Z',
        'action':'ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
        'pilot_only_no_production_p8':True}
    permit=signed(pilot_stmt,pilot_key,pilot_public,f15.PERMIT_PREFIX)
    rev_stmt={'schema':f15.REV_SCHEMA,'pilot_sha256':f1.digest(f1.canonical(permit)),
              'pilot_id':pilot_stmt['pilot_id'],
              'issued_at':'2026-11-20T16:59:55Z',
              'valid_until':'2026-11-20T17:00:30Z',
              'revoked':False,'reason_code':'CURRENT_CLEAR'}
    pilot_rev=signed(rev_stmt,pilot_rev_key,pilot_rev_pub,f15.REV_PREFIX)
    root[f15.TRUST]=f1.canonical(pilot_trust)
    root[f15.REVOCATION]=f1.canonical(pilot_rev)
    window_key,window_pub=keypair('r126.b3.window.signer')
    window_rev_key,window_rev_pub=keypair('r126.b3.window.revocation')
    window_trust={'schema':f11.TRUST_SCHEMA,
                  'window_signer':window_pub, 'revocation_signer':window_rev_pub}
    window_stmt={'schema':f11.WINDOW_SCHEMA,'window_id':'R126B3FTP-WINDOW',
                 'case_id':c['case_id'],'family_id':'FTP-T01','stage':'DEV',
                 'head':HEAD,'catalog_sha256':f1.digest(CATALOG),
                 'contract_sha256':f1.digest(contract),
                 'scope_authorization_sha256':f1.digest(auth),
                 'target':copy.deepcopy(c['target']),
                 'valid_from':'2026-11-20T16:59:55Z',
                 'valid_until':'2026-11-20T17:00:25Z',
                 'action':'ONE_FTP_CONTROL_GREETING_READ_ONLY',
                 'budget':budget(),'network_traffic_requested':True}
    window=signed(window_stmt,window_key,window_pub,f11.WINDOW_PREFIX)
    window_rev_stmt={'schema':f11.REV_SCHEMA,
                     'window_sha256':f1.digest(f1.canonical(window)),
                     'window_id':window_stmt['window_id'],
                     'issued_at':'2026-11-20T16:59:55Z',
                     'valid_until':'2026-11-20T17:00:25Z',
                     'revoked':False,'reason_code':'CURRENT_CLEAR'}
    window_rev=signed(window_rev_stmt,window_rev_key,window_rev_pub,f11.REV_PREFIX)
    root[f11.TRUST]=f1.canonical(window_trust)
    root[f11.REVOCATION]=f1.canonical(window_rev)
    return {'contract':contract,'auth':auth,'pilot':f1.canonical(permit),
            'window':f1.canonical(window),'root':root,
            'window_private':window_key,'window_public':window_pub,
            'window_rev_private':window_rev_key,'window_rev_public':window_rev_pub}


def perform(f, *, now=NOW, head=HEAD, scope_verifier=None, pilot_verifier=None):
    root=f['root']
    def s(c,a,*,catalog_raw,now):
        return scope.review_scope(contract_raw=c,authorization_raw=a,
            catalog_raw=catalog_raw,expected_head=head,now=now,
            root_loader=lambda p:root[p])
    def p(c,a,raw,*,catalog_raw,now,head,scope_reviewer):
        return f15.signed_pilot_review(c,a,raw,now=now,head=head,
            catalog_raw=catalog_raw,loader=lambda path:root[path],
            scope_reviewer=scope_reviewer)
    return mod.review_documents(contract_raw=f['contract'],
        authorization_raw=f['auth'],pilot_raw=f['pilot'],window_raw=f['window'],
        catalog_raw=CATALOG,expected_head=head,now=now,
        scope_reviewer=scope_verifier or s,pilot_reviewer=pilot_verifier or p,
        trust_loader=lambda path:root[path])


class WindowV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean=fixture()

    def setUp(self):
        self.f=copy.deepcopy(self.clean)

    def resign_window(self):
        data=f1.load(self.f['window'])['statement']
        self.f['window']=f1.canonical(signed(data,self.f['window_private'],
                                     self.f['window_public'],f11.WINDOW_PREFIX))
        self.resign_revocation()

    def resign_revocation(self):
        original=f1.load(self.f['root'][f11.REVOCATION])['statement']
        original['window_sha256']=f1.digest(self.f['window'])
        self.f['root'][f11.REVOCATION]=f1.canonical(signed(original,
            self.f['window_rev_private'],self.f['window_rev_public'],f11.REV_PREFIX))

    def test_01_valid_all_three_independent_documents(self):
        x=perform(self.f)
        self.assertEqual(x['document_status'],'DOCUMENT_SIGNED')
        self.assertFalse(x['dispatch'])
        self.assertEqual(x['p8'],'NO-GO')
        self.assertFalse(x['root_controller_grant_attested'])

    def test_02_valid_signature_still_no_root_grant(self):
        x=perform(self.f)
        self.assertFalse(x['session_specific_permit_bound'])
        self.assertFalse(x['independent_60s_watchdog_attested'])
        self.assertIsNone(x['a9'])

    def test_03_window_is_same_head(self):
        w=f1.load(self.f['window']);w['statement']['head']='f'*40
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_WRONG_CASE_HEAD_OR_TARGET'):perform(self.f)

    def test_04_wrong_contract_head(self):
        with self.assertRaisesRegex(mod.Stop,'CONTRACT_HEAD_MISMATCH'):
            perform(self.f,head='f'*40)

    def test_05_changed_window_target_rejected(self):
        w=f1.load(self.f['window']);w['statement']['target']['ip']='10.203.31.3'
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_WRONG_CASE_HEAD_OR_TARGET'):perform(self.f)

    def test_06_window_signature_modified(self):
        w=f1.load(self.f['window']);w['signature_b64']='AA=='
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_SIGNATURE_OR_REVOCATION_INVALID'):perform(self.f)

    def test_07_window_signature_from_wrong_domain(self):
        w=f1.load(self.f['window']);w=signed(w['statement'],self.f['window_private'],
            self.f['window_public'],f15.PERMIT_PREFIX)
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_SIGNATURE_OR_REVOCATION_INVALID'):perform(self.f)

    def test_08_revoked_window(self):
        r=f1.load(self.f['root'][f11.REVOCATION]);r['statement']['revoked']=True
        self.f['root'][f11.REVOCATION]=f1.canonical(signed(r['statement'],
             self.f['window_rev_private'],self.f['window_rev_public'],f11.REV_PREFIX))
        self.assertEqual(perform(self.f)['document_status'],'REVOKED')

    def test_09_revocation_wrong_hash(self):
        r=f1.load(self.f['root'][f11.REVOCATION]);r['statement']['window_sha256']='a'*64
        self.f['root'][f11.REVOCATION]=f1.canonical(signed(r['statement'],
             self.f['window_rev_private'],self.f['window_rev_public'],f11.REV_PREFIX))
        with self.assertRaisesRegex(mod.Stop,'WINDOW_REVOCATION_NOT_BOUND'):perform(self.f)

    def test_10_revocation_stale(self):
        r=f1.load(self.f['root'][f11.REVOCATION]);r['statement']['issued_at']='2026-11-20T16:59:00Z'
        self.f['root'][f11.REVOCATION]=f1.canonical(signed(r['statement'],
             self.f['window_rev_private'],self.f['window_rev_public'],f11.REV_PREFIX))
        with self.assertRaisesRegex(mod.Stop,'WINDOW_REVOCATION_NOT_FRESH'):perform(self.f)

    def test_11_window_longer_than_60s(self):
        w=f1.load(self.f['window']);w['statement']['valid_from']='2026-11-20T16:58:00Z'
        self.f['window']=f1.canonical(w)
        self.resign_window()
        with self.assertRaisesRegex(mod.Stop,'WINDOW_EXPIRED_OR_TOO_LONG'):perform(self.f)

    def test_12_window_too_late(self):
        current=lambda c,a,**kw:('VERDADERO','SIGNED',f1.digest(a))
        pilot=lambda *a,**kw:{'document_status':'DOCUMENT_SIGNED','head':HEAD,
            'scope_authorization_sha256':f1.digest(self.f['auth']),
            'pilot_sha256':f1.digest(self.f['pilot']),'budget':budget()}
        with self.assertRaisesRegex(mod.Stop,'WINDOW_EXPIRED_OR_TOO_LONG'):
            perform(self.f,now=NOW+timedelta(seconds=27),
                    scope_verifier=current,pilot_verifier=pilot)

    def test_13_budget_additional_attempts(self):
        w=f1.load(self.f['window']);w['statement']['budget']['additional_attempts']=1
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_BUDGET_INVALID'):perform(self.f)

    def test_14_window_expands_pilot_budget(self):
        w=f1.load(self.f['window']);w['statement']['budget']['max_recv_bytes']=2048
        w['statement']['budget']['max_recv_calls']=8
        self.f['window']=f1.canonical(w)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_EXPANDS_PILOT_BUDGET'):perform(self.f)

    def test_15_scope_missing(self):
        def scope_false(*a,**kw):return ('ND','NOT_PROVISIONED',None)
        with self.assertRaisesRegex(mod.Stop,'CURRENT_SCOPE_NOT_SIGNED_AND_FRESH'):
            perform(self.f,scope_verifier=scope_false)

    def test_16_pilot_revoked(self):
        r=f1.load(self.f['root'][f15.REVOCATION]);r['statement']['revoked']=True
        # Stored signature becomes invalid. Either invalid or revoked is a hard stop.
        self.f['root'][f15.REVOCATION]=f1.canonical(r)
        with self.assertRaisesRegex(mod.Stop,'INDEPENDENT_PILOT_DOCUMENT_REJECTED'):
            perform(self.f)

    def test_17_pilot_false_review(self):
        def fail(*a,**kw):return {'document_status':'REVOKED'}
        with self.assertRaisesRegex(mod.Stop,'PILOT_NOT_CURRENTLY_SIGNED'):
            perform(self.f,pilot_verifier=fail)

    def test_18_trust_bad_schema(self):
        bad=f1.load(self.f['root'][f11.TRUST]);bad['schema']='OTHER'
        self.f['root'][f11.TRUST]=f1.canonical(bad)
        with self.assertRaisesRegex(mod.Stop,'WINDOW_ROOT_TRUST_OR_STRUCTURE_INVALID'):
            perform(self.f)

    def test_19_missing_root_file(self):
        del self.f['root'][f11.TRUST]
        with self.assertRaisesRegex(mod.Stop,'WINDOW_ROOT_TRUST_OR_STRUCTURE_INVALID'):
            perform(self.f)

    def test_20_noncanonical_root_revocation(self):
        self.f['root'][f11.REVOCATION]+=b' '
        with self.assertRaisesRegex(mod.Stop,'WINDOW_ROOT_TRUST_OR_STRUCTURE_INVALID'):
            perform(self.f)

    def test_21_six_distinct_roles(self):
        keys=f1.load(self.f['root'][scope.TRUST]);p=f1.load(self.f['root'][f15.TRUST]);w=f1.load(self.f['root'][f11.TRUST])
        mod._separate(keys,p,w)

    def test_22_same_signer_public_key(self):
        s=f1.load(self.f['root'][scope.TRUST]);p=f1.load(self.f['root'][f15.TRUST]);w=f1.load(self.f['root'][f11.TRUST]);w['window_signer']=p['pilot_signer']
        with self.assertRaisesRegex(mod.Stop,'SIGNERS_NOT_INDEPENDENT'):
            mod._separate(s,p,w)

    def test_23_same_role_id_new_key(self):
        s=f1.load(self.f['root'][scope.TRUST]);p=f1.load(self.f['root'][f15.TRUST]);w=f1.load(self.f['root'][f11.TRUST]);w['window_signer']['key_id']=s['scope_signer']['key_id']
        with self.assertRaisesRegex(mod.Stop,'SIGNERS_NOT_INDEPENDENT'):
            mod._separate(s,p,w)

    def test_24_missing_authority_review_inputs(self):
        with self.assertRaises(mod.Stop):mod.review_documents(
            contract_raw=self.f['contract'],authorization_raw=b'{}',pilot_raw=self.f['pilot'],
            window_raw=self.f['window'],catalog_raw=CATALOG,expected_head=HEAD,now=NOW)

    def test_25_forged_window_return_no_go(self):
        with patch.object(mod,'review_documents',return_value={'dispatch':True}) as injected:
            # The interface must not advertise any executor/authorization path.
            self.assertFalse(mod.capabilities()['physical_window_opened'])
            self.assertFalse(mod.capabilities()['independent_root_controller_grant'])

    def test_26_current_api_has_no_loader(self):
        import inspect
        self.assertNotIn('trust_loader', inspect.signature(mod.review_current).parameters)

    def test_27_revocation_expired(self):
        r=f1.load(self.f['root'][f11.REVOCATION])
        r['statement']['valid_until']='2026-11-20T17:00:00Z'
        self.f['root'][f11.REVOCATION]=f1.canonical(signed(r['statement'],
             self.f['window_rev_private'],self.f['window_rev_public'],f11.REV_PREFIX))
        with self.assertRaisesRegex(mod.Stop,'WINDOW_REVOCATION_NOT_FRESH'):
            perform(self.f)

    def test_28_scope_changed_raw(self):
        self.f['auth']+=b' '
        with self.assertRaisesRegex(mod.Stop,'CONTRACT_OR_DOCUMENT_INVALID'):
            perform(self.f)

    def test_29_noncanonical_window(self):
        self.f['window']+=b' '
        with self.assertRaisesRegex(mod.Stop,'CONTRACT_OR_DOCUMENT_INVALID'):
            perform(self.f)

    def test_30_malformed_clock(self):
        with self.assertRaisesRegex(mod.Stop,'CLOCK_NOT_TRUSTED'):
            perform(self.f,now=NOW+timedelta(microseconds=1))


if __name__=='__main__':unittest.main()
