"""R59-G: offline two-signature A5-v2 declaration, no A5/A6 authority."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59e_a5_a6_family_bridge as e
from ardrec.coordination import r59f_variant_origin as f
from ardrec.coordination import r59g_signed_a5_review as g
from ardrec.evidence import r58g_trust_registry as reg
from test_p14_r59f_variant_origin import family_sources
from scripts import ardrec_p14_r59g_signed_review as cli

ZERO = '0'*64
START='2026-11-16T18:00:00Z'
FINISH='2026-11-16T18:01:00Z'
REVIEW='2026-11-16T18:02:00Z'


def openssl(*args):
    out=subprocess.run(['/usr/bin/openssl',*args],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
    if out.returncode:
        raise RuntimeError('OPENSSL_FIXTURE_FAILED:'+out.stderr.decode('utf-8','replace')[:100])
    return out.stdout


class R59GSignedReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys=tempfile.TemporaryDirectory()
        cls.signer={}
        for role in ('observer','reviewer'):
            private=Path(cls.keys.name)/(role+'-private.pem')
            public=Path(cls.keys.name)/(role+'-public.pem')
            openssl('genpkey','-algorithm','ED25519','-out',str(private))
            public.write_bytes(openssl('pkey','-in',str(private),'-pubout'))
            cls.signer[role]=(private,public.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.v2,self.a5,self.a6,self.signed=[root/x for x in ('v2','a5','a6','signed')]
        for p in (self.v2,self.a5,self.a6,self.signed):
            p.mkdir(mode=0o700);p.chmod(0o700)
        self.rule_patch=patch.object(e,'_sources',side_effect=family_sources)
        self.rule_patch.start();self.addCleanup(self.rule_patch.stop)
        self.attempt='ATT_R59G_FTP_T02_DATA'
        self.intent=f.build_intent(service_id='FTP_DEV',session_id='DEV_TUTOR_001',
            family_id='FTP-T02',derived_case_id='FTP-T02-S01-01',assessment_index=0,
            attempt_id=self.attempt,configuration_sha256=ZERO,
            method_id='FTP_EFFECTIVE_CONFIG_READONLY',variant='DATA')
        self.support=b'OFFLINE_UNTRUSTED_FIXTURE_SUPPORT_R59G'
        self.receipt=f.make_receipt(self.intent,outcome='OBSERVADO_POSITIVO',
            source_kind='EXTERNAL_UNVERIFIED',support=self.support,
            start_utc=START,finish_utc=FINISH)
        f.persist(self.v2,self.a5,self.a6,self.intent,self.receipt,self.support)
        self.statement=g.statement_for(f.verify_stored(self.v2,self.a5,self.a6,self.attempt))
        self.registry=self.make_registry()
        self.pin=reg.registry_digest(self.registry)
        self.registry_path=root/'registry.json'
        self.registry_path.write_bytes(d.canonical(self.registry)+b'\n')
        self.registry_path.chmod(0o600)
        self.signatures=self.sign(self.statement)

    def make_registry(self):
        authorities=[]
        for role in ('observer','reviewer'):
            authorities.append({'role':role,'key_id':role.upper()+'_KEY1',
                'owner_id':role.upper()+'_OWNER',
                'organization_id':role.upper()+'_ORG',
                'public_key_pem':self.signer[role][1],
                'enrolled_at_utc':'2026-11-15T00:00:00Z',
                'valid_from_utc':'2026-11-16T00:00:00Z',
                'valid_until_utc':'2026-11-18T00:00:00Z',
                'revoked_at_utc':None})
        return {'schema':reg.SCHEMA,'campaign_id':'CAMPAIGN_R59G_OFFLINE',
            'session_id':'DEV_TUTOR_001','review_status':'DOCUMENTARY_ONLY_NO_TECHNICAL_AUTHORITY',
            'window_start_utc':'2026-11-16T17:00:00Z',
            'window_end_utc':'2026-11-17T21:00:00Z',
            'scope':[{'service_id':'FTP_DEV','case_id':'FTP-T02-S01-01','assessment_index':0,
                      'configuration_sha256':ZERO,
                      'method_id':'FTP_EFFECTIVE_CONFIG_READONLY'}],
            'authorities':authorities}

    def sign(self,statement):
        msg=g.signing_bytes(statement)
        message=Path(self.tmp.name)/'message.bin'
        message.write_bytes(msg);message.chmod(0o600)
        signatures={}
        for role in ('observer','reviewer'):
            raw=openssl('pkeyutl','-sign','-inkey',str(self.signer[role][0]),
                        '-rawin','-in',str(message))
            signatures[role]={'key_id':role.upper()+'_KEY1',
                              'signature_b64':base64.b64encode(raw).decode('ascii')}
        return signatures

    def review(self,*,signatures=None,registry=None,pin=None,review=REVIEW):
        return g.build_review(self.v2,self.a5,self.a6,self.attempt,
              signatures=self.signatures if signatures is None else signatures,
              registry_document=self.registry if registry is None else registry,
              registry_pin_sha256=self.pin if pin is None else pin,
              review_at_utc=review)

    def save(self,*,signatures=None,regpath=None,pin=None,review=REVIEW):
        return g.persist(self.signed,self.v2,self.a5,self.a6,self.attempt,
            signatures=self.signatures if signatures is None else signatures,
            registry_path=self.registry_path if regpath is None else regpath,
            registry_pin_sha256=self.pin if pin is None else pin,review_at_utc=review)

    def test_statement_all_identity_and_variant(self):
        s=self.statement
        self.assertEqual(set(s),g.STATEMENT_FIELDS)
        for key in f.IDENTITY:
            self.assertEqual(s[key],self.intent[key])
        self.assertEqual(s['variant'],'DATA')
        self.assertEqual(s['support_sha256'],d.sha(self.support))
        self.assertEqual(s['v2_intent_sha256'],self.intent['sha256'])

    def test_cryptographic_two_role_valid(self):
        r=self.review()
        self.assertTrue(r['cryptographic_attribution_verified'])
        self.assertEqual(len(r['verified_roles']),2)
        self.assertEqual(r['a6_classification'],'ND')
        self.assertFalse(r['a5_physical_start_accredited'])
        self.assertFalse(r['independent_physical_origin_attested'])
        self.assertIsNone(r['published_generation'])
        self.assertEqual(r['p8_operational'],'NO-GO')

    def test_signed_domain_separator(self):
        self.assertTrue(g.signing_bytes(self.statement).startswith(g.PREFIX))
        self.assertNotEqual(g.signing_bytes(self.statement),d.canonical(self.statement))

    def test_signed_statement_deterministic(self):
        self.assertEqual(self.review(),self.review())

    def test_private_store_and_reopen(self):
        result=self.save()
        self.assertEqual(result['status'],'CREATED')
        doc=g.verify_stored(self.signed,self.v2,self.a5,self.a6,self.attempt,
                           registry_path=self.registry_path,registry_pin_sha256=self.pin)
        self.assertEqual(doc['sha256'],result['signed_review_sha256'])

    def test_identical_replay(self):
        a=self.save();b=self.save()
        self.assertEqual(b['status'],'REPLAY_IDENTICAL')
        self.assertEqual(a['signed_review_sha256'],b['signed_review_sha256'])

    def test_signatures_are_over_v2_not_legacy(self):
        altered=deepcopy(self.statement)
        altered['v2_report_sha256']='f'*64
        with self.assertRaises(Exception):
            self.review(signatures=self.sign(altered))

    def test_signatures_wrong_variant_denied(self):
        altered=deepcopy(self.statement);altered['variant']='CONTROL'
        with self.assertRaises(Exception):self.review(signatures=self.sign(altered))

    def test_signatures_wrong_attempt_denied(self):
        altered=deepcopy(self.statement);altered['attempt_id']='ATT_OTHER'
        with self.assertRaises(Exception):self.review(signatures=self.sign(altered))

    def test_signatures_wrong_support_denied(self):
        altered=deepcopy(self.statement);altered['support_sha256']='f'*64
        with self.assertRaises(Exception):self.review(signatures=self.sign(altered))

    def test_signature_data_tampering(self):
        bad=deepcopy(self.signatures)
        bad['observer']['signature_b64']=bad['observer']['signature_b64'][:-2]+'AA'
        with self.assertRaises(Exception):self.review(signatures=bad)

    def test_signature_swapped_between_roles(self):
        bad=deepcopy(self.signatures)
        bad['observer']['signature_b64'],bad['reviewer']['signature_b64']=(
            bad['reviewer']['signature_b64'],bad['observer']['signature_b64'])
        with self.assertRaises(Exception):self.review(signatures=bad)

    def test_signature_one_missing_denied(self):
        with self.assertRaises(Exception):self.review(signatures={'observer':self.signatures['observer']})

    def test_signature_duplicate_key_ids_denied(self):
        bad=deepcopy(self.signatures);bad['reviewer']['key_id']=bad['observer']['key_id']
        with self.assertRaises(Exception):self.review(signatures=bad)

    def test_external_registry_wrong_pin_denied(self):
        with self.assertRaises(Exception):self.review(pin='f'*64)

    def test_registry_scope_other_case_denied(self):
        x=deepcopy(self.registry);x['scope'][0]['case_id']='FTP-T02-S02-02'
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_registry_scope_other_config_denied(self):
        x=deepcopy(self.registry);x['scope'][0]['configuration_sha256']='f'*64
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_registry_session_mismatch_denied(self):
        x=deepcopy(self.registry);x['session_id']='OTHER_SESSION'
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_registry_revocation_denied(self):
        x=deepcopy(self.registry);x['authorities'][0]['revoked_at_utc']='2026-11-16T18:01:30Z'
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_registry_wrong_key_denied(self):
        x=deepcopy(self.registry)
        x['authorities'][0]['public_key_pem']=self.signer['reviewer'][1]
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_future_review_invalid(self):
        with self.assertRaises(Exception):self.review(review='2026-11-18T18:02:00Z')

    def test_before_finish_invalid(self):
        with self.assertRaises(Exception):self.review(review='2026-11-16T17:00:00Z')

    def test_campaign_start_after_attempt_denied(self):
        x=deepcopy(self.registry);x['window_start_utc']='2026-11-16T18:00:30Z'
        with self.assertRaises(Exception):self.review(registry=x,pin=reg.registry_digest(x))

    def test_changed_review_time_creates_conflict(self):
        self.save()
        with self.assertRaises(Exception):self.save(review='2026-11-16T18:03:00Z')

    def test_tampered_signed_file_refused(self):
        self.save();p=self.signed/g._file(self.attempt)
        p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_rehashed_false_a6_denied(self):
        self.save();p=self.signed/g._file(self.attempt)
        doc=json.loads(p.read_bytes());doc['a6_classification']='POSITIVO_VALIDO'
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        p.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_rehashed_false_a5_denied(self):
        self.save();p=self.signed/g._file(self.attempt)
        doc=json.loads(p.read_bytes());doc['a5_physical_start_accredited']=True
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        p.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_tampered_v2_source_refused(self):
        self.save();p=self.v2/f._name(self.attempt)
        p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_tampered_support_source_refused(self):
        self.save()
        p=next(self.a5.glob('r59d-support-*.bin'))
        p.write_bytes(b'altered')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_registry_file_changed_after_persist_denied(self):
        self.save();self.registry_path.write_bytes(b'{}\n')
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256=self.pin)

    def test_registry_pin_changed_on_reopen_denied(self):
        self.save()
        with self.assertRaises(Exception):g.verify_stored(self.signed,self.v2,self.a5,self.a6,
              self.attempt,registry_path=self.registry_path,registry_pin_sha256='f'*64)

    def test_signatures_no_start_refused(self):
        intent=f.build_intent(service_id='SSH_DEV',session_id='DEV_TUTOR_001',
            family_id='SSH-T01',derived_case_id='SSH-T01-S01-01',assessment_index=0,
            attempt_id='ATT_R59G_NO_START',configuration_sha256=ZERO,
            method_id='SSH_EFFECTIVE_CONFIG_READONLY',variant=None)
        f.persist(self.v2,self.a5,self.a6,intent,f.make_receipt(intent),b'')
        no_start=f.verify_stored(self.v2,self.a5,self.a6,intent['attempt_id'])
        with self.assertRaises(Exception):g.statement_for(no_start)

    def test_output_dir_public_denied(self):
        self.signed.chmod(0o755)
        with self.assertRaises(Exception):self.save()

    def test_output_same_as_source_denied(self):
        with self.assertRaises(Exception):g.persist(self.v2,self.v2,self.a5,self.a6,
           self.attempt,signatures=self.signatures,registry_path=self.registry_path,
           registry_pin_sha256=self.pin,review_at_utc=REVIEW)

    def test_output_symlink_denied(self):
        link=Path(self.tmp.name)/'link'
        link.symlink_to(self.signed,target_is_directory=True)
        with self.assertRaises(Exception):g.persist(link,self.v2,self.a5,self.a6,self.attempt,
           signatures=self.signatures,registry_path=self.registry_path,
           registry_pin_sha256=self.pin,review_at_utc=REVIEW)

    def test_source_kind_local_fixture_denied(self):
        i=f.build_intent(service_id='SSH_DEV',session_id='DEV_TUTOR_001',
            family_id='SSH-T02',derived_case_id='SSH-T02-S01-01',assessment_index=0,
            attempt_id='ATT_R59G_LOCAL',configuration_sha256=ZERO,
            method_id='SSH_EFFECTIVE_CONFIG_READONLY',variant=None)
        r=f.make_receipt(i,outcome='INCONCLUSO',source_kind='LOCAL_BENIGN_FIXTURE',
                support=b'local',start_utc=START,finish_utc=FINISH)
        f.persist(self.v2,self.a5,self.a6,i,r,b'local')
        with self.assertRaises(Exception):
            g.statement_for(f.verify_stored(self.v2,self.a5,self.a6,i['attempt_id']))

    def test_statement_extra_fields_denied(self):
        wrong=deepcopy(self.statement);wrong['surplus']='FORGED'
        with self.assertRaises(Exception):g.signing_bytes(wrong)

    def test_statement_false_p8_denied(self):
        wrong=deepcopy(self.statement);wrong['p8_operational']='GO'
        with self.assertRaises(Exception):g.signing_bytes(wrong)

    def test_cli_submit_and_reopen_signed(self):
        bundle=Path(self.tmp.name)/'signatures.json'
        bundle.write_bytes(d.canonical({'schema':cli.BUNDLE_SCHEMA,
                                        'signatures':self.signatures})+b'\n')
        bundle.chmod(0o600)
        base=['app','--v2-root',str(self.v2),'--a5-root',str(self.a5),
              '--a6-root',str(self.a6),'--attempt-id',self.attempt,
              '--output-root',str(self.signed),
              '--registry-path',str(self.registry_path),
              '--registry-pin-sha256',self.pin]
        stdout=io.StringIO()
        with patch.object(sys,'argv',base+['--submit-signed',
                    '--signatures-path',str(bundle),'--review-at-utc',REVIEW]),redirect_stdout(stdout):
            self.assertEqual(cli.main(),0)
        first=json.loads(stdout.getvalue())
        self.assertEqual(first['mode'],'CREATED')
        stdout=io.StringIO()
        with patch.object(sys,'argv',base+['--verify-signed']),redirect_stdout(stdout):
            self.assertEqual(cli.main(),0)
        second=json.loads(stdout.getvalue())
        self.assertEqual(second['mode'],'VERIFIED_REOPENED')
        self.assertEqual(first['signed_review_sha256'],second['signed_review_sha256'])
        self.assertEqual(second['a6_classification'],'ND')

    def test_cli_inspection_does_not_forge_signature(self):
        argv=['app','--inspect-v2','--v2-root',str(self.v2),
              '--a5-root',str(self.a5),'--a6-root',str(self.a6),
              '--attempt-id',self.attempt]
        out=io.StringIO()
        with patch.object(sys,'argv',argv),redirect_stdout(out):
            self.assertEqual(cli.main(),0)
        doc=json.loads(out.getvalue())
        self.assertFalse(doc['signed_review_present'])
        self.assertFalse(doc['a5_physical_start_accredited'])

    def test_cli_requires_external_registry_and_pin(self):
        argv=['app','--verify-signed','--v2-root',str(self.v2),
              '--a5-root',str(self.a5),'--a6-root',str(self.a6),
              '--attempt-id',self.attempt]
        out=io.StringIO()
        with patch.object(sys,'argv',argv),redirect_stdout(out):
            self.assertEqual(cli.main(),23)
        self.assertIn('SIGNATURE_MODE_REQUIRES_PINNED_EXTERNAL_REGISTRY',out.getvalue())

    def test_cli_public_signature_bundle_denied(self):
        bundle=Path(self.tmp.name)/'public-signatures.json'
        bundle.write_bytes(d.canonical({'schema':cli.BUNDLE_SCHEMA,
                                        'signatures':self.signatures})+b'\n')
        bundle.chmod(0o644)
        argv=['app','--submit-signed','--v2-root',str(self.v2),
              '--a5-root',str(self.a5),'--a6-root',str(self.a6),
              '--attempt-id',self.attempt,'--output-root',str(self.signed),
              '--registry-path',str(self.registry_path),
              '--registry-pin-sha256',self.pin,
              '--signatures-path',str(bundle),'--review-at-utc',REVIEW]
        out=io.StringIO()
        with patch.object(sys,'argv',argv),redirect_stdout(out):
            self.assertEqual(cli.main(),23)
        self.assertIn('PRIVATE_FILE_MODE_SIZE_OR_OWNER',out.getvalue())

    def test_source_no_network_dispatch(self):
        source=Path(g.__file__).read_text()
        for forbidden in ('virsh start','nft -f','systemctl start','P8=GO'):
            self.assertNotIn(forbidden,source)


if __name__=='__main__':
    unittest.main()
