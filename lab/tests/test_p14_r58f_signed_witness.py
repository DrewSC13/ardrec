"""R58-F signed witness proof gates: real Ed25519, no physical-truth promotion."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.evidence.r58f_signed_witness import (
    SCHEMA, REPORT, WitnessError, admit_signed_witness, verify_signed_witness,
    signing_bytes,
)
from ardrec.coordination.r58f_signed_bridge import (
    SignedBridgeError, build_signed_bridge, verify_signed_bridge,
)
from scripts.ardrec_p14_r58e_unit_bridge import synthetic_units
from scripts.ardrec_p14_r58f_signed_witness_demo import AS_OF

OPENSSL='/usr/bin/openssl'

class SignedWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='ardrec-r58f-tests-')
        cls.root=Path(cls.temp.name)
        cls.support=b'R58F purely synthetic support\n'
        cls.statement={
            'schema':SCHEMA,'record_id':'R58F_SIGNED_001',
            'session_id':'DEV_TUTOR_001','service_id':'SSH_DEV',
            'case_id':'CASE_REFERENCE','assessment_index':0,
            'configuration_sha256':'a'*64,
            'captured_at_utc':'2026-11-16T11:59:00Z',
            'method_id':'SSH_EFFECTIVE_CONFIG_READONLY',
            'observed_claim':'INCONCLUSIVE',
            'support_sha256':hashlib.sha256(cls.support).hexdigest(),
            'support_bytes':len(cls.support),
        }
        cls.keys={};cls.trust={}
        for role in ('observer','reviewer'):
            private=cls.root/(role+'.private.pem')
            public=cls.root/(role+'.public.pem')
            p=subprocess.run([OPENSSL,'genpkey','-algorithm','ED25519',
                               '-out',str(private)],check=False,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if p.returncode:raise AssertionError(p.stderr)
            private.chmod(0o600)
            subprocess.run([OPENSSL,'pkey','-in',str(private),'-pubout','-out',str(public)],
                           check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            cls.keys[role]=private
            cls.trust[role]={'key_id':'TEST_'+role.upper(),
                             'public_key_pem':public.read_bytes()}
        cls.expected={'session_id':'DEV_TUTOR_001','service_id':'SSH_DEV',
                      'case_id':'CASE_REFERENCE','assessment_index':0,
                      'configuration_sha256':'a'*64}
        cls.signatures=cls.signed(cls.statement)
        cls.report=admit_signed_witness(cls.statement,cls.signatures,cls.trust,
                                        cls.support,expected=cls.expected,as_of_utc=AS_OF)
        cls.units=synthetic_units()
        cls.bindings={(u['service_id'],u['case_id'],u['assessment_index']):'a'*64
                      for u in cls.units}
        cls.bundle={'statement':cls.statement,'signatures':cls.signatures,'support':cls.support}
        cls.bridge=build_signed_bridge(cls.units,[cls.bundle],
                                       configuration_hashes=cls.bindings,
                                       trusted_authorities=cls.trust,as_of_utc=AS_OF)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    @classmethod
    def signed(cls,statement):
        data=cls.root/'message.bin'
        data.write_bytes(signing_bytes(statement))
        signs={}
        for role,private in cls.keys.items():
            sig=cls.root/(role+'.sig')
            r=subprocess.run([OPENSSL,'pkeyutl','-sign','-inkey',str(private),
                              '-rawin','-in',str(data),'-out',str(sig)],
                             check=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            if r.returncode:raise AssertionError(r.stderr)
            signs[role]={'key_id':cls.trust[role]['key_id'],
                         'signature_b64':base64.b64encode(sig.read_bytes()).decode('ascii')}
        return signs

    def admit(self,statement=None,signatures=None,trust=None,support=None,
              expected=None,as_of=None):
        return admit_signed_witness(
            self.statement if statement is None else statement,
            self.signatures if signatures is None else signatures,
            self.trust if trust is None else trust,
            self.support if support is None else support,
            expected=self.expected if expected is None else expected,
            as_of_utc=AS_OF if as_of is None else as_of)

    def test_real_signature_verified(self):self.assertTrue(self.report['cryptographic_attribution_verified'])
    def test_dual_distinct_roles(self):self.assertEqual(len({r['public_key_sha256'] for r in self.report['roles']}),2)
    def test_signed_report_roundtrip(self):
        self.assertTrue(verify_signed_witness(self.report,self.signatures,self.trust,
                                               self.support,expected=self.expected))
    def test_report_no_truth(self):
        self.assertFalse(self.report['technical_truth_accredited'])
        self.assertFalse(self.report['signer_independence_physically_attested'])
        self.assertEqual(self.report['a6_classification'],'ND')
        self.assertIsNone(self.report['confirmed_rf'])
    def test_signed_ftp_attribution_but_no_accreditation(self):
        stmt={**self.statement,'record_id':'R58F_FTP_SIGNED',
              'service_id':'FTP_DEV','method_id':'FTP_EFFECTIVE_CONFIG_READONLY'}
        expected={**self.expected,'service_id':'FTP_DEV'}
        doc=self.admit(statement=stmt,signatures=self.signed(stmt),expected=expected)
        self.assertTrue(doc['cryptographic_attribution_verified'])
        self.assertFalse(doc['technical_truth_accredited'])
        self.assertEqual(doc['a6_classification'],'ND')
    def test_signed_smb_attribution_but_no_accreditation(self):
        stmt={**self.statement,'record_id':'R58F_SMB_SIGNED',
              'service_id':'SMB_DEV','method_id':'SMB_EFFECTIVE_CONFIG_READONLY'}
        expected={**self.expected,'service_id':'SMB_DEV'}
        doc=self.admit(statement=stmt,signatures=self.signed(stmt),expected=expected)
        self.assertTrue(doc['cryptographic_attribution_verified'])
        self.assertIsNone(doc['confirmed_rf'])
    def test_multiservice_signed_bridge(self):
        stmt={**self.statement,'record_id':'R58F_FTP_SIGNED',
              'service_id':'FTP_DEV','method_id':'FTP_EFFECTIVE_CONFIG_READONLY'}
        bundle={'statement':stmt,'signatures':self.signed(stmt),'support':self.support}
        report=build_signed_bridge(self.units,[self.bundle,bundle],
                   configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
        self.assertEqual(report['signed_witness_count'],2)
        self.assertTrue(all(x['confirmed_rf'] is None for x in report['decisions']))
        self.assertFalse(report['technical_truth_accredited'])
    def test_no_generation_or_dispatch(self):
        self.assertIsNone(self.report['published_generation'])
        self.assertFalse(self.report['operational_dispatch'])
        self.assertEqual(self.report['p8'],'NO-GO')
    def test_invalid_claim_signature(self):
        stmt={**self.statement,'observed_claim':'MATCH'}
        with self.assertRaisesRegex(WitnessError,'SIGNATURE_INVALID'):self.admit(statement=stmt)
    def test_valid_signed_match_still_nd(self):
        stmt={**self.statement,'observed_claim':'MATCH'}
        doc=self.admit(statement=stmt,signatures=self.signed(stmt))
        self.assertEqual(doc['a6_classification'],'ND')
    def test_valid_signed_diff_still_nd(self):
        stmt={**self.statement,'observed_claim':'DIFF'}
        doc=self.admit(statement=stmt,signatures=self.signed(stmt))
        self.assertIsNone(doc['evidence_contribution'])
    def test_unknown_claim(self):
        with self.assertRaises(WitnessError):self.admit(statement={**self.statement,'observed_claim':'VERDADERO'})
    def test_missing_signature_role(self):
        with self.assertRaisesRegex(WitnessError,'SIGNATURE_ROLES'):
            self.admit(signatures={'observer':self.signatures['observer']})
    def test_extra_signature_role(self):
        with self.assertRaises(WitnessError):
            self.admit(signatures={**self.signatures,'operator':self.signatures['observer']})
    def test_swapped_signers(self):
        sig=deepcopy(self.signatures)
        sig['observer'],sig['reviewer']=sig['reviewer'],sig['observer']
        with self.assertRaises(WitnessError):self.admit(signatures=sig)
    def test_one_key_reused_for_two_roles(self):
        trust=deepcopy(self.trust)
        trust['reviewer']['public_key_pem']=trust['observer']['public_key_pem']
        with self.assertRaisesRegex(WitnessError,'PUBLIC_KEY_REUSED'):
            self.admit(trust=trust)
    def test_key_id_reused_for_two_roles(self):
        trust=deepcopy(self.trust);sig=deepcopy(self.signatures)
        trust['reviewer']['key_id']=trust['observer']['key_id']
        sig['reviewer']['key_id']=trust['observer']['key_id']
        with self.assertRaises(WitnessError):self.admit(signatures=sig,trust=trust)
    def test_signature_bytes_tampered(self):
        sig=deepcopy(self.signatures)
        raw=bytearray(base64.b64decode(sig['observer']['signature_b64']))
        raw[-1]^=1
        sig['observer']['signature_b64']=base64.b64encode(raw).decode('ascii')
        with self.assertRaisesRegex(WitnessError,'SIGNATURE_INVALID'):self.admit(signatures=sig)
    def test_bad_base64(self):
        sig=deepcopy(self.signatures);sig['observer']['signature_b64']='!'*88
        with self.assertRaises(WitnessError):self.admit(signatures=sig)
    def test_bad_signature_length(self):
        sig=deepcopy(self.signatures)
        sig['observer']['signature_b64']=base64.b64encode(b'x'*63).decode('ascii')
        with self.assertRaises(WitnessError):self.admit(signatures=sig)
    def test_support_tamper(self):
        with self.assertRaisesRegex(WitnessError,'SUPPORT_DIGEST_OR_SIZE'):
            self.admit(support=b'R58F purely synthetic supportX')
    def test_support_size_forged(self):
        with self.assertRaises(WitnessError):
            self.admit(statement={**self.statement,'support_bytes':0})
    def test_configuration_wrong(self):
        with self.assertRaisesRegex(WitnessError,'SCOPE_MISMATCH_configuration_sha256'):
            self.admit(expected={**self.expected,'configuration_sha256':'b'*64})
    def test_service_wrong(self):
        with self.assertRaisesRegex(WitnessError,'SCOPE_MISMATCH_service_id'):
            self.admit(expected={**self.expected,'service_id':'FTP_DEV'})
    def test_case_wrong(self):
        with self.assertRaisesRegex(WitnessError,'SCOPE_MISMATCH_case_id'):
            self.admit(expected={**self.expected,'case_id':'CASE_POLICY'})
    def test_window_wrong(self):
        with self.assertRaisesRegex(WitnessError,'SCOPE_MISMATCH_assessment_index'):
            self.admit(expected={**self.expected,'assessment_index':1})
    def test_session_wrong(self):
        with self.assertRaisesRegex(WitnessError,'SCOPE_MISMATCH_session_id'):
            self.admit(expected={**self.expected,'session_id':'OTHER'})
    def test_stale_capture(self):
        with self.assertRaisesRegex(WitnessError,'CAPTURE_OUTSIDE_REVIEW_WINDOW'):
            self.admit(as_of='2026-11-20T12:00:00Z')
    def test_future_capture(self):
        with self.assertRaisesRegex(WitnessError,'CAPTURE_OUTSIDE_REVIEW_WINDOW'):
            self.admit(as_of='2026-11-16T11:00:00Z')
    def test_bad_calendar(self):
        with self.assertRaises(WitnessError):
            self.admit(statement={**self.statement,'captured_at_utc':'2026-02-30T00:00:00Z'})
    def test_boolean_window(self):
        with self.assertRaises(WitnessError):
            self.admit(statement={**self.statement,'assessment_index':True})
    def test_case_method_mismatch(self):
        with self.assertRaises(WitnessError):
            self.admit(statement={**self.statement,'service_id':'FTP_DEV'})
    def test_extra_field(self):
        with self.assertRaises(WitnessError):
            self.admit(statement={**self.statement,'physical_truth':True})
    def test_bad_report_rehashed(self):
        doc=deepcopy(self.report)
        doc['technical_truth_accredited']=True
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaisesRegex(WitnessError,'REPORT_RECONSTRUCTION_MISMATCH'):
            verify_signed_witness(doc,self.signatures,self.trust,self.support,expected=self.expected)
    def test_bad_report_wrong_source(self):
        doc=deepcopy(self.report)
        doc['statement']['observed_claim']='MATCH'
        with self.assertRaises(WitnessError):
            verify_signed_witness(doc,self.signatures,self.trust,self.support,expected=self.expected)
    def test_bridge(self):self.assertTrue(verify_signed_bridge(self.bridge,self.units,[self.bundle],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF))
    def test_bridge_provenance_not_proof(self):
        self.assertFalse(self.bridge['technical_truth_accredited'])
        self.assertTrue(self.bridge['all_a6_nd'])
        self.assertEqual(self.bridge['signed_witness_count'],1)
    def test_bridge_unit_specific(self):
        self.assertEqual([d['signed_witness_review_sha256'] is not None for d in self.bridge['decisions']],[False,False,True])
    def test_bridge_full_intervals(self):
        for d in self.bridge['decisions']:
            self.assertEqual((d['a7_rf_lower'],d['a7_rf_upper']),('1/4','7/12'))
            self.assertIsNone(d['confirmed_rf'])
    def test_bridge_a8_only_advisory(self):
        for d in self.bridge['decisions']:
            self.assertEqual(d['a8_recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
            self.assertIsNone(d['a8_applied_transition'])
    def test_bridge_no_publication(self):
        self.assertIsNone(self.bridge['published_generation'])
        self.assertFalse(self.bridge['operational_dispatch'])
    def test_bridge_no_signed(self):
        d=build_signed_bridge(self.units,[],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
        self.assertEqual(d['signed_witness_count'],0)
    def test_duplicate_unit_witness(self):
        with self.assertRaisesRegex(SignedBridgeError,'DUPLICATE_UNIT_WITNESS'):
            build_signed_bridge(self.units,[self.bundle,self.bundle],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_unbound_witness(self):
        with self.assertRaisesRegex(SignedBridgeError,'UNBOUND_SIGNED_STATEMENT'):
            build_signed_bridge(self.units[1:2],[self.bundle],
                                configuration_hashes={('FTP_DEV','CASE_REFERENCE',0):'a'*64},
                                trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_missing_config_binding(self):
        with self.assertRaisesRegex(SignedBridgeError,'CONFIGURATION_SCOPE_INCOMPLETE'):
            build_signed_bridge(self.units,[self.bundle],configuration_hashes={},trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_wrong_config_binding(self):
        d=dict(self.bindings)
        d[('SSH_DEV','CASE_REFERENCE',0)]='b'*64
        with self.assertRaises(WitnessError):
            build_signed_bridge(self.units,[self.bundle],configuration_hashes=d,trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_bridge_wrong_report_sha(self):
        doc=deepcopy(self.bridge);doc['decisions'][2]['confirmed_rf']='1/2'
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaisesRegex(SignedBridgeError,'REPORT_NOT_REPRODUCIBLE'):
            verify_signed_bridge(doc,self.units,[self.bundle],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_bridge_forbid_user_supplied_evidence(self):
        units=deepcopy(self.units)
        units[2]['evidence']=[{'evidence_id':'E_FAKED','kind':'SYNTHETIC_FIXED','lower':'1','upper':'1'}]
        with self.assertRaises(ValueError):
            build_signed_bridge(units,[self.bundle],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_untrusted_bundle_cannot_supply_its_own_trust(self):
        injected={**self.bundle,'trust':self.trust}
        with self.assertRaisesRegex(SignedBridgeError,'BUNDLE_SCHEMA'):
            build_signed_bridge(self.units,[injected],configuration_hashes=self.bindings,
                                trusted_authorities=self.trust,as_of_utc=AS_OF)
    def test_bridge_permutation(self):
        d=build_signed_bridge(list(reversed(self.units)),[self.bundle],configuration_hashes=self.bindings,trusted_authorities=self.trust,as_of_utc=AS_OF)
        self.assertEqual(d,self.bridge)
    def test_cli_synthetic_ephemeral_keys(self):
        repo=Path(__file__).resolve().parents[2]
        env=dict(os.environ);env['PYTHONPATH']=str(repo/'src')
        proc=subprocess.run([sys.executable,'-B',str(repo/'scripts/ardrec_p14_r58f_signed_witness_demo.py'),
                             '--synthetic-offline'],cwd=repo,env=env,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            timeout=30,check=False)
        self.assertEqual(proc.returncode,0,proc.stderr.decode('utf-8','replace'))
        d=json.loads(proc.stdout)
        self.assertEqual(d['signed_witness_count'],1)
        self.assertEqual(d['p8_operational'],'NO-GO')
    def test_rsa_is_rejected(self):
        private=self.root/'rsa.pem';public=self.root/'rsa_pub.pem'
        subprocess.run([OPENSSL,'genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048',
                        '-out',str(private)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        subprocess.run([OPENSSL,'pkey','-in',str(private),'-pubout','-out',str(public)],
                       check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        trust=deepcopy(self.trust);trust['reviewer']['public_key_pem']=public.read_bytes()
        with self.assertRaises(WitnessError):self.admit(trust=trust)

if __name__=='__main__':unittest.main()
