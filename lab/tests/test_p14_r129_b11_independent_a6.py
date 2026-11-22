"""B11: independent Ed25519 physical + technical FTP-T01 attestations.

All positive scenarios use *injected test fixtures* for root-owned files and
R127. They are NOT live field evidence, and never publish a generation.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r129_b11_independent_a6 as m
from test_p14_r115_f11_p8_signed_window import keypair,signed
import test_p14_r129_b10_receipt_gate as b10_fixture

NOW=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)


@unittest.skipIf(os.geteuid()==0,'Filesystem F13 fixtures must be nonroot')
class IndependentA6B11(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spriv,cls.spub=keypair('r129.b11.source.test')
        cls.tpriv,cls.tpub=keypair('r129.b11.technical.test')
        cls.rpriv,cls.rpub=keypair('r129.b11.revocation.test')

    def setUp(self):
        x=b10_fixture.ReceiptB10('test_01_f13_prespent');x.setUp();self.addCleanup(x.doCleanups)
        self.x=x
        self.candidate=x.run_review()
        self.witness={'statement':{'schema':m.r127.SCHEMA,
            'boot_id':x.intent['boot_id']},'signer_key_id':'r127-test',
            'signature_b64':'TEST_ONLY_NOT_VALID'}
        self.trust={'schema':m.TRUST_SCHEMA,'source_signer':copy.deepcopy(self.spub),
                    'technical_signer':copy.deepcopy(self.tpub),
                    'revocation_signer':copy.deepcopy(self.rpub)}
        cs=self.candidate
        sw={'schema':m.SOURCE_SCHEMA,'head':cs['head'],'session':cs['session'],
            'case_id':cs['case_id'],'family_id':'FTP-T01',
            'root_readback_method':'INDEPENDENT_ROOT_OWNED_B9_READBACK',
            'b9_intent_sha256':cs['root_intent_candidate_sha256'],
            'b9_receipt_sha256':cs['root_receipt_candidate_sha256'],
            'guest_sha256':cs['guest_result_candidate_sha256'],
            'qga_sha256':cs['qga_candidate_sha256'],
            'r127_witness_sha256':m.sha(self.witness),
            'observed_at':'2026-11-21T21:59:55Z'}
        self.source=signed(sw,self.spriv,self.spub,m.SOURCE_PREFIX)
        tw={'schema':m.TECH_SCHEMA,'head':cs['head'],'session':cs['session'],
            'case_id':cs['case_id'],'source_attestation_sha256':m.sha(self.source),
            'r127_witness_sha256':m.sha(self.witness),
            'condition_id':'FTP-T01_CONTROL_CONNECTION',
            'required_supports':['TARGET_ATTESTATION','INTEGRITY_PROVENANCE',
                'CONTROL_CHANNEL_RESPONSE'],
            'decision':'CONTROL_CONNECTION_CONFIRMED',
            'interpretation_boundary':'NOT_AUTHENTICATION_NOT_FILE_ACCESS_NOT_VULNERABILITY',
            'issued_at':'2026-11-21T21:59:59Z',
            'valid_until':'2026-11-21T22:00:50Z'}
        self.technical=signed(tw,self.tpriv,self.tpub,m.TECH_PREFIX)
        rw={'schema':m.REV_SCHEMA,
            'source_attestation_sha256':m.sha(self.source),
            'technical_verdict_sha256':m.sha(self.technical),
            'issued_at':'2026-11-21T21:59:59Z',
            'valid_until':'2026-11-21T22:00:50Z',
            'revoked':False,'reason_code':'CURRENT_CLEAR'}
        self.revocation=signed(rw,self.rpriv,self.rpub,m.REV_PREFIX)

    def review(self,now=NOW):
        return m.signed_review(candidate=self.candidate,source=self.source,
            technical=self.technical,revocation=self.revocation,
            witness=self.witness,trust=self.trust,now=now)

    def denial(self,reason):
        with self.assertRaisesRegex(m.Stop,reason):self.review()

    def resign_source(self):
        self.source=signed(self.source['statement'],self.spriv,self.spub,m.SOURCE_PREFIX)

    def resign_technical(self):
        self.technical['statement']['source_attestation_sha256']=m.sha(self.source)
        self.technical=signed(self.technical['statement'],self.tpriv,self.tpub,m.TECH_PREFIX)

    def resign_revocation(self):
        self.revocation['statement']['source_attestation_sha256']=m.sha(self.source)
        self.revocation['statement']['technical_verdict_sha256']=m.sha(self.technical)
        self.revocation=signed(self.revocation['statement'],self.rpriv,self.rpub,m.REV_PREFIX)

    def test_01_real_ed25519_three_roles(self):
        self.assertTrue(self.review()['signatures_verified'])
    def test_02_documentary_does_not_accredit_a6(self):
        self.assertEqual(self.review()['a6'],'ND')
    def test_03_never_publish_a9(self):
        self.assertIsNone(self.review()['a9'])
    def test_04_never_claim_confirmed_rf(self):
        self.assertIsNone(self.review()['confirmed_rf'])
    def test_05_never_open_store(self):
        with patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError):
            self.review()
    def test_06_source_signature_modified(self):
        self.source['signature_b64']='A'*88
        self.resign_technical();self.resign_revocation()
        self.denial('A6_INDEPENDENT_SIGNATURE_REJECTED')
    def test_07_technical_signature_modified(self):
        self.technical['signature_b64']='A'*88
        self.resign_revocation()
        self.denial('A6_INDEPENDENT_SIGNATURE_REJECTED')
    def test_08_revocation_signature_modified(self):
        self.revocation['signature_b64']='A'*88;self.denial('A6_INDEPENDENT_SIGNATURE_REJECTED')
    def test_09_key_reuse_id(self):
        self.trust['technical_signer']=self.trust['source_signer'];self.denial('A6_SIGNERS_NOT_INDEPENDENT')
    def test_10_key_reuse_pem(self):
        self.trust['technical_signer']['public_key_pem']=self.trust['source_signer']['public_key_pem'];self.denial('A6_SIGNERS_NOT_INDEPENDENT')
    def test_11_wrong_head(self):
        self.source['statement']['head']='0'*40;self.denial('A6_SOURCE_NOT_BOUND')
    def test_12_wrong_session(self):
        self.source['statement']['session']='0'*16;self.denial('A6_SOURCE_NOT_BOUND')
    def test_13_wrong_case(self):
        self.source['statement']['case_id']='FORGED';self.denial('A6_SOURCE_NOT_BOUND')
    def test_14_wrong_intent_digest(self):
        self.source['statement']['b9_intent_sha256']='0'*64;self.denial('A6_SOURCE_NOT_BOUND')
    def test_15_wrong_receipt_digest(self):
        self.source['statement']['b9_receipt_sha256']='0'*64;self.denial('A6_SOURCE_NOT_BOUND')
    def test_16_wrong_qga_digest(self):
        self.source['statement']['qga_sha256']='0'*64;self.denial('A6_SOURCE_NOT_BOUND')
    def test_17_wrong_guest_digest(self):
        self.source['statement']['guest_sha256']='0'*64;self.denial('A6_SOURCE_NOT_BOUND')
    def test_18_wrong_witness_digest(self):
        self.source['statement']['r127_witness_sha256']='0'*64;self.denial('A6_SOURCE_NOT_BOUND')
    def test_19_forged_support_set(self):
        self.technical['statement']['required_supports']=['CONTROL_CHANNEL_RESPONSE'];self.denial('A6_TECH_DECISION_NOT_FTP_T01')
    def test_20_claim_login_from_greeting(self):
        self.technical['statement']['decision']='AUTHENTICATED';self.denial('A6_TECH_DECISION_NOT_FTP_T01')
    def test_21_claim_vulnerability_from_greeting(self):
        self.technical['statement']['interpretation_boundary']='VULNERABILITY';self.denial('A6_TECH_DECISION_NOT_FTP_T01')
    def test_22_missing_revocation(self):
        self.revocation['statement']['revoked']=True;self.denial('A6_REVOKED_OR_REVOCATION_STALE')
    def test_23_revocation_stale(self):
        self.denial_at('A6_REVOKED_OR_REVOCATION_STALE',NOW+timedelta(seconds=35))
    def denial_at(self,reason,at):
        with self.assertRaisesRegex(m.Stop,reason):self.review(at)
    def test_24_revocation_wrong_target(self):
        self.revocation['statement']['source_attestation_sha256']='0'*64;self.denial('A6_REVOCATION_NOT_BOUND')
    def test_25_technical_source_sha_mismatch(self):
        self.technical['statement']['source_attestation_sha256']='0'*64;self.denial('A6_TECH_DECISION_NOT_FTP_T01')
    def test_26_source_stale(self):
        self.denial_at('A6_SOURCE_STALE',NOW+timedelta(seconds=61))
    def test_27_clock_naive(self):
        self.denial_at('CLOCK_REQUIRED',NOW.replace(tzinfo=None))
    def test_28_a5_candidate_forged(self):
        self.candidate['sha256']='0'*64;self.denial('A5_CANDIDATE_NOT_POSITIVE_OR_UNTRUSTED')
    def test_29_a5_greeting_not_complete(self):
        self.candidate['banner_is_complete_220']=False
        self.candidate['sha256']=m.sha({k:v for k,v in self.candidate.items() if k!='sha256'})
        self.denial('A5_CANDIDATE_NOT_POSITIVE_OR_UNTRUSTED')
    def test_30_a5_claimed_root_origin_forged(self):
        self.candidate['independent_root_origin_verified']=True
        self.candidate['sha256']=m.sha({k:v for k,v in self.candidate.items() if k!='sha256'})
        self.denial('A5_CANDIDATE_NOT_POSITIVE_OR_UNTRUSTED')
    def test_31_root_only_live(self):
        with patch.object(m.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(m.Stop,'INDEPENDENT_ROOT_A6_REVIEW_REQUIRED'):
                self.live()
    def live(self):
        return m.admit_live(candidate=self.candidate,
            source=self.source,technical=self.technical,
            revocation=self.revocation,witness=self.witness,
            pre={},post={},now=NOW)
    def root_test(self,*,r127_result=None,root_sources=None):
        x=self.x
        result={'schema':m.r127.SCHEMA+'-verification','head':self.candidate['head'],
                'session':self.candidate['session'],'case_id':self.candidate['case_id'],
                'signed_witness_sha256':m.sha(self.witness),
                'external_root_trust_anchored':True,
                'physical_closure_claim_accepted':True,
                'crash_test_executed':True,'max_60s_met':True}
        if r127_result is not None:result.update(r127_result)
        originals=(x.handoff,x.intent,x.receipt,x.guest,x.qga)
        sources=root_sources if root_sources is not None else originals
        with patch.object(m.os,'geteuid',return_value=0),\
             patch.object(m,'_trusted_install',return_value=None),\
             patch.object(m,'_root_bytes',return_value=f1.canonical(self.trust)),\
             patch.object(m,'_root_sources',return_value=sources),\
             patch.object(m.r127,'verify_root_anchored',return_value=result):
            return self.live()
    def test_32_live_test_fixture_positive_only_ftp_connection(self):
        r=self.root_test()
        self.assertEqual(r['a6'],'VERDADERO')
        self.assertEqual(r['technical_condition'],'FTP_T01_CONTROL_CONNECTION_CONFIRMED')
        self.assertIsNone(r['a7_rf_confirmed'])
        self.assertIsNone(r['a9_generation'])
    def test_33_live_wrong_root_receipt(self):
        copied=copy.deepcopy(self.x.receipt);copied['case_id']='BAD'
        with self.assertRaisesRegex(m.Stop,'ROOT_B9_BYTES_AND_EXPORTED_EVIDENCE_DIVERGE'):
            self.root_test(root_sources=(self.x.handoff,self.x.intent,copied,self.x.guest,self.x.qga))
    def test_34_live_r127_not_anchored(self):
        with self.assertRaisesRegex(m.Stop,'ROOT_R127_WITNESS_NOT_ACCEPTED'):
            self.root_test(r127_result={'external_root_trust_anchored':False})
    def test_35_live_wrong_root_boot(self):
        self.witness['statement']['boot_id']='WRONG_BOOT'
        # Retarget signed source + tech + revocation to the modified witness.
        self.source['statement']['r127_witness_sha256']=m.sha(self.witness)
        self.resign_source()
        self.technical['statement']['r127_witness_sha256']=m.sha(self.witness)
        self.resign_technical();self.resign_revocation()
        with self.assertRaisesRegex(m.Stop,'ROOT_B9_BYTES_AND_EXPORTED_EVIDENCE_DIVERGE'):
            self.root_test()
    def test_36_live_wrong_head_witness(self):
        with self.assertRaisesRegex(m.Stop,'ROOT_R127_WITNESS_NOT_ACCEPTED'):
            self.root_test(r127_result={'head':'0'*40})
    def test_41_root_guest_result_not_complete(self):
        bad=copy.deepcopy(self.x.guest);bad['response_hex']=b'331 password required\r\n'.hex()
        with self.assertRaisesRegex(m.Stop,'ROOT_B9_BYTES_AND_EXPORTED_EVIDENCE_DIVERGE'):
            self.root_test(root_sources=(self.x.handoff,self.x.intent,self.x.receipt,
                                         bad,self.x.qga))
    def test_42_signed_review_no_implicit_network(self):
        with patch('socket.socket',side_effect=AssertionError('socket not authorized')):
            self.review()
    def test_43_root_provision_required(self):
        with patch.object(m.os,'geteuid',return_value=0),\
             patch.object(m,'_trusted_install',return_value=None),\
             patch.object(m,'_root_bytes',side_effect=FileNotFoundError('root trust absent')):
            with self.assertRaises(FileNotFoundError):
                self.live()
    def test_44_mutable_git_source_cannot_accredit_live_a6(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaisesRegex(m.Stop,'INDEPENDENT_A6_ROOT_INSTALL_REQUIRED'):
                self.live()
    def test_45_installer_pins_exact_path(self):
        self.assertEqual(m.INSTALLED_CODE.name,'root-admission.py')
        self.assertTrue(str(m.INSTALLED_CODE).startswith('/var/lib/ardrec/'))
    def test_37_root_trust_allowlisted(self):
        with self.assertRaisesRegex(m.Stop,'ROOT_PATH_NOT_ALLOWLISTED'):
            m._root_bytes(Path('/tmp/not-a-trust.json'),policy=True)
    def test_38_root_session_allowlisted(self):
        with self.assertRaisesRegex(m.Stop,'ROOT_PATH_NOT_ALLOWLISTED'):
            m._root_bytes(m.ROOT/'pilot-invalid'/'receipt.json')
    def test_39_capabilities_do_not_claim_a9(self):
        self.assertFalse(m.capabilities()['a9_global_generation_written'])
    def test_40_capabilities_require_real_root(self):
        self.assertTrue(m.capabilities()['b9_live_root_owned_sources_required'])

if __name__=='__main__':unittest.main()
