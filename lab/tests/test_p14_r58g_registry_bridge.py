"""R58-G adversarial campaign key registration and documentary no-GO gates."""
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

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.coordination.r58g_registry_bridge import (
    RegistryBridgeError, build_registry_bridge, verify_registry_bridge,
)
from ardrec.evidence.r58g_trust_registry import (
    RegistryError, SCHEMA, read_pinned_registry, registry_digest,
    validate_registry, trusted_for_capture,
)
from ardrec.evidence.r58f_signed_witness import (
    SCHEMA as WITNESS_SCHEMA, SERVICES, signing_bytes,
)
from scripts.ardrec_p14_r58e_unit_bridge import synthetic_units

AS_OF='2026-11-16T12:00:00Z'
CAPTURE='2026-11-16T11:59:00Z'
OPENSSL='/usr/bin/openssl'


class TestR58GRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='ardrec-r58g-tests-')
        cls.root=Path(cls.temp.name)
        cls.units=synthetic_units()
        cls.support=b'R58-G synthetic text; no VM acquisition\n'
        cls.statement={
            'schema':WITNESS_SCHEMA,'record_id':'R58G_SYNTH_001',
            'session_id':'DEV_TUTOR_001','service_id':'SSH_DEV',
            'case_id':'CASE_REFERENCE','assessment_index':0,
            'configuration_sha256':'a'*64,'captured_at_utc':CAPTURE,
            'method_id':'SSH_EFFECTIVE_CONFIG_READONLY','observed_claim':'INCONCLUSIVE',
            'support_sha256':hashlib.sha256(cls.support).hexdigest(),
            'support_bytes':len(cls.support),
        }
        cls.private={};cls.authority=[]
        for role,owner,org in (('observer','OWNER_ALPHA','GROUP_ALPHA'),
                               ('reviewer','OWNER_BRAVO','GROUP_BRAVO')):
            private=cls.root/(role+'.private.pem')
            public=cls.root/(role+'.public.pem')
            cp=subprocess.run([OPENSSL,'genpkey','-algorithm','ED25519','-out',str(private)],
                              check=False,capture_output=True,timeout=10)
            if cp.returncode:raise AssertionError(cp.stderr)
            private.chmod(0o600)
            subprocess.run([OPENSSL,'pkey','-in',str(private),'-pubout','-out',str(public)],
                           check=True,capture_output=True,timeout=10)
            cls.private[role]=private
            cls.authority.append({
                'role':role,'key_id':'KEY_'+role.upper(),'owner_id':owner,
                'organization_id':org,'public_key_pem':public.read_text('ascii'),
                'enrolled_at_utc':'2026-11-14T00:00:00Z',
                'valid_from_utc':'2026-11-15T00:00:00Z',
                'valid_until_utc':'2026-11-17T23:00:00Z',
                'revoked_at_utc':None,
            })
        cls.registry={
            'schema':SCHEMA,'campaign_id':'DEV_TUTOR_001','session_id':'DEV_TUTOR_001',
            'review_status':'DOCUMENTARY_ONLY_NO_TECHNICAL_AUTHORITY',
            'window_start_utc':'2026-11-16T00:00:00Z',
            'window_end_utc':'2026-11-17T00:00:00Z',
            'scope': sorted([{
                'service_id':u['service_id'],'case_id':u['case_id'],
                'assessment_index':u['assessment_index'],
                'configuration_sha256':'a'*64,'method_id':SERVICES[u['service_id']],
            } for u in cls.units],key=lambda x:(x['service_id'],x['case_id'],x['assessment_index'])),
            'authorities':cls.authority,
        }
        cls.pin=registry_digest(cls.registry)
        cls.bundle={'statement':cls.statement,'signatures':cls.sign(cls.statement),
                    'support':cls.support}
        cls.report=cls.build()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def sign(cls,statement):
        msg=cls.root/'data.bin'
        msg.write_bytes(signing_bytes(statement))
        signatures={}
        for item in cls.authority:
            role=item['role']
            dest=cls.root/(role+'.sig')
            proc=subprocess.run([OPENSSL,'pkeyutl','-sign','-inkey',str(cls.private[role]),
                                 '-rawin','-in',str(msg),'-out',str(dest)],
                                check=False,capture_output=True,timeout=10)
            if proc.returncode:raise AssertionError(proc.stderr)
            signatures[role]={'key_id':item['key_id'],
                              'signature_b64':base64.b64encode(dest.read_bytes()).decode('ascii')}
        return signatures

    @classmethod
    def build(cls,registry=None,bundles=None,units=None,prior=(),pin=None,asof=AS_OF):
        return build_registry_bridge(
            cls.units if units is None else units,
            [cls.bundle] if bundles is None else bundles,
            registry=cls.registry if registry is None else registry,
            pinned_registry_sha256=cls.pin if pin is None else pin,
            as_of_utc=asof,prior_record_ids=prior)

    def altered(self,callback):
        reg=deepcopy(self.registry)
        callback(reg)
        return reg,registry_digest(reg)

    def test_registry_valid(self):
        self.assertIs(validate_registry(self.registry,pinned_sha256=self.pin),self.registry)
    def test_registry_pin_deterministic(self):
        self.assertEqual(self.pin,registry_digest(deepcopy(self.registry)))
    def test_wrong_external_pin(self):
        with self.assertRaisesRegex(RegistryError,'REGISTRY_PIN_MISMATCH'):
            self.build(pin='0'*64)
    def test_pin_not_optional(self):
        with self.assertRaises(RegistryError):self.build(pin='not-valid')
    def test_registry_not_a_dict(self):
        with self.assertRaises(RegistryError):validate_registry([],pinned_sha256=self.pin)
    def test_extra_registry_field_rehashed(self):
        reg,pin=self.altered(lambda r:r.update({'technical_authority':True}))
        with self.assertRaisesRegex(RegistryError,'REGISTRY_SCHEMA'):self.build(registry=reg,pin=pin)
    def test_status_cannot_be_go(self):
        reg,pin=self.altered(lambda r:r.update({'review_status':'GO'}))
        with self.assertRaisesRegex(RegistryError,'REGISTRY_MUST_BE_NON_OPERATIONAL'):
            self.build(registry=reg,pin=pin)
    def test_fixed_dev_session_required(self):
        reg,pin=self.altered(lambda r:r.update(
            {'session_id':'OTHER_SESSION','campaign_id':'OTHER_SESSION'}))
        with self.assertRaisesRegex(RegistryBridgeError,'R58F_ONLY_DEV_TUTOR_001_SUPPORTED'):
            self.build(registry=reg,pin=pin)
    def test_rsa_public_key_not_ed25519(self):
        private=self.root/'rsa.key'
        public=self.root/'rsa.pub'
        subprocess.run([OPENSSL,'genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048',
                        '-out',str(private)],check=True,capture_output=True,timeout=15)
        subprocess.run([OPENSSL,'pkey','-in',str(private),'-pubout','-out',str(public)],
                       check=True,capture_output=True,timeout=15)
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'public_key_pem':public.read_text('ascii')}))
        with self.assertRaisesRegex(RegistryError,'REGISTRY_ED25519_KEY_REQUIRED'):
            self.build(registry=reg,pin=pin)
    def test_forged_pem_body_not_accepted(self):
        bogus='-----BEGIN PUBLIC KEY-----\n'+('A'*80)+'\n-----END PUBLIC KEY-----\n'
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'public_key_pem':bogus}))
        with self.assertRaisesRegex(RegistryError,'REGISTRY_ED25519_KEY_REQUIRED'):
            self.build(registry=reg,pin=pin)
    def test_campaign_requires_signed_session(self):
        reg,pin=self.altered(lambda r:r.update({'campaign_id':'OTHER_CAMPAIGN'}))
        with self.assertRaisesRegex(RegistryBridgeError,'CAMPAIGN_MUST_BE_SIGNED_SESSION'):
            self.build(registry=reg,pin=pin)
    def test_bad_campaign_identifier(self):
        reg,pin=self.altered(lambda r:r.update({'campaign_id':'IN VALID'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_end_before_start(self):
        reg,pin=self.altered(lambda r:r.update({'window_end_utc':'2026-11-15T00:00:00Z'}))
        with self.assertRaisesRegex(RegistryError,'CAMPAIGN_WINDOW_INVALID'):
            self.build(registry=reg,pin=pin)
    def test_campaign_bad_calendar(self):
        reg,pin=self.altered(lambda r:r.update({'window_start_utc':'2026-02-30T00:00:00Z'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_scope_extra_field(self):
        reg,pin=self.altered(lambda r:r['scope'][0].update({'foo':True}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_scope_index_boolean(self):
        reg,pin=self.altered(lambda r:r['scope'][0].update({'assessment_index':True}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_scope_duplicate(self):
        reg,pin=self.altered(lambda r:r['scope'].append(deepcopy(r['scope'][-1])))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_scope_unsorted(self):
        reg,pin=self.altered(lambda r:r['scope'].reverse())
        with self.assertRaisesRegex(RegistryError,'CAMPAIGN_SCOPE_NOT_CANONICAL'):
            self.build(registry=reg,pin=pin)
    def test_campaign_bad_method(self):
        reg,pin=self.altered(lambda r:r['scope'][0].update({'method_id':'SSH_EFFECTIVE_CONFIG_READONLY'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_bad_config(self):
        reg,pin=self.altered(lambda r:r['scope'][0].update({'configuration_sha256':'z'*64}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_bad_service(self):
        reg,pin=self.altered(lambda r:r['scope'][0].update({'service_id':'HTTP_DEV'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_campaign_55_units(self):
        def add(r):
            r['scope']=[{**r['scope'][0],'case_id':f'CASE_{i}'} for i in range(55)]
        reg,pin=self.altered(add)
        with self.assertRaisesRegex(RegistryError,'CAMPAIGN_SCOPE_COUNT'):
            self.build(registry=reg,pin=pin)
    def test_register_both_roles_exactly(self):
        reg,pin=self.altered(lambda r:r['authorities'].pop())
        with self.assertRaisesRegex(RegistryError,'REGISTRY_TWO_ROLES_REQUIRED'):
            self.build(registry=reg,pin=pin)
    def test_register_roles_cannot_swap(self):
        reg,pin=self.altered(lambda r:r['authorities'].reverse())
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_roles_cannot_reuse_key(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'public_key_pem':r['authorities'][0]['public_key_pem']}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_same_key_with_different_pem_wrapping_rejected(self):
        key=self.authority[0]['public_key_pem']
        lines=key.splitlines()
        b64=''.join(lines[1:-1])
        wrapped=('-----BEGIN PUBLIC KEY-----\n'+
                 '\n'.join(b64[i:i+16] for i in range(0,len(b64),16))+
                 '\n-----END PUBLIC KEY-----\n')
        self.assertNotEqual(key,wrapped)
        reg,pin=self.altered(lambda r:r['authorities'][1].update({'public_key_pem':wrapped}))
        with self.assertRaisesRegex(RegistryError,'REGISTRY_PUBLIC_KEY_DUPLICATE'):
            self.build(registry=reg,pin=pin)
    def test_register_roles_cannot_reuse_owner(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'owner_id':r['authorities'][0]['owner_id']}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_roles_cannot_reuse_organization(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'organization_id':r['authorities'][0]['organization_id']}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_roles_cannot_reuse_key_id(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'key_id':r['authorities'][0]['key_id']}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_invalid_pem(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update({'public_key_pem':'NO KEY'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_invalid_lifetime(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'valid_until_utc':'2026-11-14T00:00:00Z'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_register_revoked_before_enrollment(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'revoked_at_utc':'2026-11-13T00:00:00Z'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_revoked_before_capture(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'revoked_at_utc':'2026-11-15T10:00:00Z'}))
        with self.assertRaisesRegex(RegistryError,'SIGNER_REVOKED_BY_REVIEW'):
            self.build(registry=reg,pin=pin)
    def test_revoked_at_review(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'revoked_at_utc':AS_OF}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_revoked_after_review_allowed_for_that_review(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'revoked_at_utc':'2026-11-16T13:00:00Z'}))
        doc=self.build(registry=reg,pin=pin)
        self.assertEqual(doc['a6_classification'],'ND')
    def test_key_not_valid_at_capture(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'valid_from_utc':'2026-11-16T11:59:30Z'}))
        with self.assertRaisesRegex(RegistryError,'SIGNER_NOT_VALID_AT_CAPTURE_AND_REVIEW'):
            self.build(registry=reg,pin=pin)
    def test_key_expired_before_review(self):
        reg,pin=self.altered(lambda r:r['authorities'][1].update(
            {'valid_until_utc':'2026-11-16T11:59:30Z'}))
        with self.assertRaises(RegistryError):self.build(registry=reg,pin=pin)
    def test_capture_outside_campaign(self):
        stmt=deepcopy(self.statement);stmt['captured_at_utc']='2026-11-15T23:59:00Z'
        bundle={**self.bundle,'statement':stmt,'signatures':self.sign(stmt)}
        with self.assertRaises(RegistryError):self.build(bundles=[bundle])
    def test_review_outside_campaign(self):
        with self.assertRaises(RegistryError):self.build(asof='2026-11-18T00:00:00Z')
    def test_valid_signed_document_still_nd(self):
        self.assertTrue(self.report['registered_owner_separation_claim_checked'])
        self.assertIs(self.report['physical_safety_and_signer_independence_attested'],False)
        self.assertEqual(self.report['a6_classification'],'ND')
        self.assertIsNone(self.report['confirmed_final_risk'])
        self.assertEqual(self.report['signed_witness_count'],1)
    def test_ssh_ftp_smb_remain_unknown(self):
        self.assertEqual(self.report['unit_count'],3)
        self.assertEqual({d['service_id'] for d in self.report['decisions']},
                         {'SSH_DEV','FTP_DEV','SMB_DEV'})
        self.assertTrue(all(d['a7_rf_lower']=='1/4' and d['a7_rf_upper']=='7/12'
                            and d['a8_applied_transition'] is None
                            and d['confirmed_rf'] is None for d in self.report['decisions']))
    def test_registry_pin_is_not_independent_provenance(self):
        self.assertIs(self.report['registry_pin_matched_caller_parameter'],True)
        self.assertIs(self.report['registry_pin_provenance_independently_attested'],False)
    def test_campaign_digest_bound_to_report(self):
        self.assertEqual(self.report['campaign_id'],'DEV_TUTOR_001')
        self.assertEqual(self.report['registry_sha256'],self.pin)
    def test_no_host_or_state_mutation(self):
        self.assertIs(self.report['operational_dispatch'],False)
        self.assertIs(self.report['vm_checks_executed'],False)
        self.assertEqual(self.report['p8_operational'],'NO-GO')
        self.assertIsNone(self.report['published_generation'])
    def test_report_reproduces(self):
        self.assertTrue(verify_registry_bridge(self.report,self.units,[self.bundle],
                          registry=self.registry,pinned_registry_sha256=self.pin,
                          as_of_utc=AS_OF,prior_record_ids=()))
    def test_report_permutation_independent(self):
        self.assertEqual(self.report,self.build(units=list(reversed(self.units))))
    def test_registry_scope_unit_missing(self):
        with self.assertRaises(RegistryBridgeError):self.build(units=self.units[1:])
    def test_registry_scope_unit_foreign(self):
        units=deepcopy(self.units);units[0]['case_id']='FOREIGN'
        with self.assertRaises(RegistryBridgeError):self.build(units=units)
    def test_bundle_wrong_configuration(self):
        statement=deepcopy(self.statement);statement['configuration_sha256']='b'*64
        bundle={**self.bundle,'statement':statement,'signatures':self.sign(statement)}
        with self.assertRaises(ValueError):self.build(bundles=[bundle])
    def test_bundle_wrong_method(self):
        statement=deepcopy(self.statement);statement['method_id']='FTP_EFFECTIVE_CONFIG_READONLY'
        with self.assertRaises(RegistryBridgeError):self.build(bundles=[{**self.bundle,'statement':statement}])
    def test_bundle_wrong_session(self):
        statement=deepcopy(self.statement);statement['session_id']='OTHER_SESSION'
        with self.assertRaises(RegistryBridgeError):self.build(bundles=[{**self.bundle,'statement':statement}])
    def test_bundle_with_own_trust_rejected(self):
        with self.assertRaises(RegistryBridgeError):
            self.build(bundles=[{**self.bundle,'trusted_authorities':self.authority}])
    def test_invalid_signature(self):
        bundle=deepcopy(self.bundle)
        bundle['signatures']['observer']['signature_b64']='A'*88
        with self.assertRaises(ValueError):self.build(bundles=[bundle])
    def test_replay_in_prior_ids_rejected(self):
        with self.assertRaisesRegex(RegistryBridgeError,'REPLAY_OR_DUPLICATE_RECORD'):
            self.build(prior=('R58G_SYNTH_001',))
    def test_prior_duplicate_not_canonical(self):
        with self.assertRaisesRegex(RegistryBridgeError,'PRIOR_RECORDS_NOT_CANONICAL'):
            self.build(prior=('R58G_SYNTH_001','R58G_SYNTH_001'))
    def test_prior_unsorted_not_canonical(self):
        with self.assertRaises(RegistryBridgeError):self.build(prior=('B','A'))
    def test_prior_history_can_be_empty(self):
        self.assertEqual(self.report['historical_record_ids_sha256'],digest([]))
    def test_invalid_prior_type(self):
        with self.assertRaises(RegistryBridgeError):self.build(prior=['A'])
    def test_wrong_registry_key_after_repin_rejects_signature(self):
        reg,pin=self.altered(lambda r:r['authorities'][0].update(
            {'key_id':'REPLACED_KEY'}))
        with self.assertRaises(ValueError):self.build(registry=reg,pin=pin)
    def test_rehashed_report_false_accreditation(self):
        doc=deepcopy(self.report);doc['technical_truth_accredited']=True
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(RegistryBridgeError):verify_registry_bridge(
            doc,self.units,[self.bundle],registry=self.registry,
            pinned_registry_sha256=self.pin,as_of_utc=AS_OF,prior_record_ids=())
    def test_rehashed_report_false_transition(self):
        doc=deepcopy(self.report);doc['applied_state_transition']='T8'
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(RegistryBridgeError):verify_registry_bridge(
            doc,self.units,[self.bundle],registry=self.registry,
            pinned_registry_sha256=self.pin,as_of_utc=AS_OF,prior_record_ids=())
    def test_rehashed_report_false_generation(self):
        doc=deepcopy(self.report);doc['published_generation']='GEN_1'
        doc['sha256']=digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(RegistryBridgeError):verify_registry_bridge(
            doc,self.units,[self.bundle],registry=self.registry,
            pinned_registry_sha256=self.pin,as_of_utc=AS_OF,prior_record_ids=())
    def test_no_signed_witness_allowed(self):
        doc=self.build(bundles=[])
        self.assertEqual(doc['signed_witness_count'],0)
        self.assertTrue(all(d['a6_classification']=='ND' for d in doc['decisions']))
    def test_registry_file_read_exact_canonical(self):
        p=self.root/'external-registry.json'
        p.write_bytes(canonical(self.registry)+b'\n')
        self.assertEqual(read_pinned_registry(p,pinned_sha256=self.pin),self.registry)
    def test_registry_file_noncanonical_rejected(self):
        p=self.root/'external-registry.json'
        p.write_bytes(json.dumps(self.registry,indent=2).encode('ascii'))
        with self.assertRaises(RegistryError):read_pinned_registry(p,pinned_sha256=self.pin)
    def test_registry_file_duplicate_key_rejected(self):
        p=self.root/'external-registry.json'
        p.write_text('{"schema":"x","schema":"y"}',encoding='utf-8')
        with self.assertRaises(RegistryError):read_pinned_registry(p,pinned_sha256=self.pin)
    def test_registry_file_symlink_rejected(self):
        p=self.root/'external-registry.json';p.write_bytes(canonical(self.registry)+b'\n')
        symlink=self.root/'external-registry.link';symlink.unlink(missing_ok=True)
        symlink.symlink_to(p)
        with self.assertRaises(RegistryError):read_pinned_registry(symlink,pinned_sha256=self.pin)
    def test_registry_file_pin_rejects_mutation(self):
        p=self.root/'external-registry.json'
        new=deepcopy(self.registry);new['window_end_utc']='2026-11-17T00:00:01Z'
        p.write_bytes(canonical(new)+b'\n')
        with self.assertRaisesRegex(RegistryError,'REGISTRY_PIN_MISMATCH'):
            read_pinned_registry(p,pinned_sha256=self.pin)
    def test_cli_offline(self):
        repo=Path(__file__).resolve().parents[2]
        env=os.environ.copy();env['PYTHONPATH']=str(repo/'src')
        proc=subprocess.run([sys.executable,'-B',str(repo/'scripts/ardrec_p14_r58g_trust_registry_demo.py'),
                             '--synthetic-offline'],cwd=repo,env=env,
                             stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,timeout=25,check=False)
        self.assertEqual(proc.returncode,0,proc.stderr.decode('utf-8','replace'))
        doc=json.loads(proc.stdout)
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertEqual(doc['signed_witness_count'],1)
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertIsNone(doc['published_generation'])


if __name__=='__main__':unittest.main()
