"""B14: genuine independent Ed25519 release + fresh revocation; no privileged IO."""
from __future__ import annotations
import copy
from datetime import datetime,timezone,timedelta
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from test_p14_r128_root_v2_executor import signed_fixture, BOOT, NOW, x, b4
from test_p14_r115_f11_p8_signed_window import keypair, signed

HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
F8='a'*64


def fixture():
    original=signed_fixture()
    rpriv,rpub=keypair('ardrec.r128.release.signer.test')
    vpriv,vpub=keypair('ardrec.r128.release.revocation.test')
    manifest={'schema':x.SCHEMA+'-root-bundle','approved_head':HEAD,
       'script_sha256':'1'*64,'r126_deny_controller_sha256':x.B4_PIN,
       'legacy_f3_sha256':x.F3_PIN,'guard_sha256':x.GUARD_PIN,
       'root_staged_independently':True,'automatic_network':False,'p8':'NO-GO'}
    st={'schema':x.RELEASE_SCHEMA,'release_id':'R128_B14_SIGNED_RELEASE_TEST',
      'approved_head':HEAD,'boot_id':BOOT,
      'manifest_sha256':x.digest(manifest),'script_sha256':manifest['script_sha256'],
      'r126_deny_controller_sha256':x.B4_PIN,'legacy_f3_sha256':x.F3_PIN,
      'guard_sha256':x.GUARD_PIN,'f8_reference_sha256':F8,
      'source_commit_signature_verified':True,'independent_review':True,
      'valid_from':'2026-11-20T16:59:55Z',
      'valid_until':'2026-11-20T17:00:55Z',
      'action':'RELEASE_EXACT_ROOT_BUNDLE_FOR_SINGLE_FTP_T01','p8':'NO-GO'}
    release=signed(st,rpriv,rpub,x.RELEASE_PREFIX)
    rs={'schema':x.RELEASE_REV_SCHEMA,'release_id':st['release_id'],
        'release_sha256':x.digest(release),
        'issued_at':'2026-11-20T16:59:59Z',
        'valid_until':'2026-11-20T17:00:55Z',
        'revoked':False,'reason_code':'CURRENT_CLEAR'}
    rev=signed(rs,vpriv,vpub,x.RELEASE_REV_PREFIX)
    trust={'schema':x.RELEASE_TRUST_SCHEMA,
           'release_signer':rpub,'revocation_signer':vpub}
    return {'original':original,'manifest':manifest,'release':release,
            'revocation':rev,'trust':trust,'rpriv':rpriv,'rpub':rpub,
            'vpriv':vpriv,'vpub':vpub}

class SignedRelease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.sample=fixture()
    def setUp(self):self.f=copy.deepcopy(self.sample)
    def review(self,**kwargs):
        f=self.f
        return x.signed_release(auth=b4,
          manifest=kwargs.get('manifest',f['manifest']),
          release=f['release'], trust=f['trust'], revocation=f['revocation'],
          b4docs=f['original']['d'],boot_id=kwargs.get('boot_id',BOOT),
          f8_reference_sha256=kwargs.get('f8',F8),
          traffic_trust=f['original']['trust'],now=kwargs.get('now',NOW))
    def resign(self):
        f=self.f
        f['release']=signed(f['release']['statement'],f['rpriv'],f['rpub'],x.RELEASE_PREFIX)
        self.resign_rev()
    def resign_rev(self):
        f=self.f
        f['revocation']['statement']['release_sha256']=x.digest(f['release'])
        f['revocation']=signed(f['revocation']['statement'],f['vpriv'],f['vpub'],x.RELEASE_REV_PREFIX)

    def test_01_actual_ed25519_signature_positive(self):
        v=self.review();self.assertTrue(v['root_release_signed']);self.assertFalse(v['operational_traffic_granted'])
    def test_02_no_general_p8(self):self.assertEqual(self.review()['p8'],'NO-GO')
    def test_03_release_signature_tampered(self):
        self.f['release']['statement']['approved_head']='f'*40
        with self.assertRaises(Exception):self.review()
    def test_04_release_head_not_pinned(self):
        self.f['release']['statement']['approved_head']='f'*40;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_05_unmatched_script(self):
        self.f['release']['statement']['script_sha256']='e'*64;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_06_unmatched_b4(self):
        self.f['release']['statement']['r126_deny_controller_sha256']='e'*64;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_07_unmatched_f3(self):
        self.f['release']['statement']['legacy_f3_sha256']='e'*64;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_08_unmatched_guard(self):
        self.f['release']['statement']['guard_sha256']='e'*64;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_09_unmatched_boot_id(self):
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):
            self.review(boot_id='00000000-0000-0000-0000-000000000000')
    def test_10_unmatched_f8_reference(self):
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review(f8='f'*64)
    def test_11_no_signature_verified_attestation(self):
        self.f['release']['statement']['source_commit_signature_verified']=False;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_12_no_external_review(self):
        self.f['release']['statement']['independent_review']=False;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_13_global_p8_claim_refused(self):
        self.f['release']['statement']['p8']='GO';self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_14_revoked(self):
        self.f['revocation']['statement']['revoked']=True;self.resign_rev()
        with self.assertRaisesRegex(b4.Stop,'REVOCATION'):self.review()
    def test_15_revocation_signature_tampered(self):
        self.f['revocation']['statement']['revoked']=True
        with self.assertRaises(Exception):self.review()
    def test_16_stale_revocation(self):
        self.f['revocation']['statement']['issued_at']='2026-11-20T16:58:00Z';self.resign_rev()
        with self.assertRaisesRegex(b4.Stop,'REVOCATION_NOT_FRESH'):self.review()
    def test_17_future_release(self):
        self.f['release']['statement']['valid_from']='2026-11-20T18:00:00Z';self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_NOT_CURRENT'):self.review()
    def test_18_expired_release(self):
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_NOT_CURRENT'):
            self.review(now=NOW+timedelta(seconds=60))
    def test_19_excessive_duration(self):
        self.f['release']['statement']['valid_until']='2026-11-21T18:00:00Z';self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_NOT_CURRENT'):self.review()
    def test_20_reused_traffic_signer(self):
        self.f['trust']['release_signer']=self.f['original']['trust']['traffic_signer']
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SIGNERS'):self.review()
    def test_21_reused_deny_signer(self):
        self.f['trust']['revocation_signer']=self.f['original']['d']['root_trust']['grant_signer']
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SIGNERS'):self.review()
    def test_22_same_release_and_revocation_signer(self):
        self.f['trust']['revocation_signer']=self.f['trust']['release_signer']
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SIGNERS'):self.review()
    def test_23_wrong_revocation_target(self):
        self.f['revocation']['statement']['release_sha256']='f'*64;self.resign_rev()
        # Re-signing restores current link, so alter again and re-sign directly.
        self.f['revocation']['statement']['release_sha256']='f'*64
        self.f['revocation']=signed(self.f['revocation']['statement'],self.f['vpriv'],self.f['vpub'],x.RELEASE_REV_PREFIX)
        with self.assertRaisesRegex(b4.Stop,'REVOCATION'):self.review()
    def test_24_manifest_altered_after_sign(self):
        bad=dict(self.f['manifest']);bad['script_sha256']='f'*64
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review(manifest=bad)
    def test_25_no_mutable_f8_replay_call_in_source(self):
        source=Path(x.__file__).read_text()
        self.assertNotIn('legacy.review_boot_provenance(',source)
        self.assertNotIn('from ardrec.coordination import r116_f12_runner_ftp_boot',source)
    def test_26_actual_root_staging_blocked(self):
        with self.assertRaisesRegex(x.Stop,'INDEPENDENT_ROOT_STAGING_REQUIRED'):x.stage()
    def test_27_claim_bound_to_release_domain(self):
        self.assertTrue(x.RELEASE_PREFIX.endswith(b'\x00'))
        self.assertNotEqual(x.RELEASE_PREFIX,x.GRANT_PREFIX)
    def test_28_release_id_changed(self):
        self.f['release']['statement']['release_id']='../../BAD';self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_29_manifest_digest_bound(self):
        self.f['release']['statement']['manifest_sha256']='0'*64;self.resign()
        with self.assertRaisesRegex(x.Stop,'ROOT_RELEASE_SCOPE'):self.review()
    def test_30_revocation_reviewer_not_privilege(self):
        self.assertFalse(self.review()['operational_traffic_granted'])

if __name__=='__main__':unittest.main()
