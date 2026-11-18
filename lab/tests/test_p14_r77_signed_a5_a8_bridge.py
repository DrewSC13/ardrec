"""R77 adversarial signed-documentary intake bound to R76, never A6 truth."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts'))
import ardrec_p14_r77_signed_a5_a8_bridge as r77
from ardrec.analytics.exact_preview import canonical
from ardrec.evidence.r58f_signed_witness import SCHEMA as SIGN_SCHEMA, signing_bytes
from ardrec.evidence.r58g_trust_registry import SCHEMA as REG_SCHEMA, registry_digest

CAPTURE='2026-11-18T11:59:00Z'
REVIEW='2026-11-18T12:00:00Z'
OPENSSL='/usr/bin/openssl'

@unittest.skipIf(os.geteuid()==0,'R75/R76/R77 require nonroot')
class SignedR76Boundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='ardrec-r77-')
        cls.parent=Path(cls.temp.name)
        cls.root=cls.parent/'r75'
        cls.r75=r77.r76.r75.create(cls.root)
        cls.r76=r77.r76.build(cls.root)
        candidate=next(c for c in cls.r76['candidates'] if c['declared_outcome']=='OBSERVADO_POSITIVO')
        cls.candidate=candidate
        intent=candidate['a5_intent']
        cls.support=b'R77 SYNTHETIC DOCUMENTARY CLAIM: NOT A GUEST OBSERVATION\n'
        cls.statement={
            'schema':SIGN_SCHEMA, 'record_id':'R77_SYNTH_RECORD_001',
            'session_id':'DEV_TUTOR_001', 'service_id':candidate['service_id'],
            'case_id':candidate['a7_case_id'],'assessment_index':0,
            'configuration_sha256':intent['configuration_sha256'],
            'captured_at_utc':CAPTURE,'method_id':intent['method_id'],
            'observed_claim':'MATCH',
            'support_sha256':hashlib.sha256(cls.support).hexdigest(),
            'support_bytes':len(cls.support),
        }
        cls.keys={};cls.authorities=[]
        for role,owner,org in (('observer','R77_OWNER_1','R77_ORG_1'),
                               ('reviewer','R77_OWNER_2','R77_ORG_2')):
            private=cls.parent/(role+'.priv')
            public=cls.parent/(role+'.pub')
            subprocess.run([OPENSSL,'genpkey','-algorithm','ED25519','-out',str(private)],
                           check=True,capture_output=True,timeout=15)
            private.chmod(0o600)
            subprocess.run([OPENSSL,'pkey','-in',str(private),'-pubout','-out',str(public)],
                           check=True,capture_output=True,timeout=15)
            cls.keys[role]=private
            cls.authorities.append({
                'role':role,'key_id':'R77_'+role.upper(),
                'owner_id':owner,'organization_id':org,
                'public_key_pem':public.read_text('ascii'),
                'enrolled_at_utc':'2026-11-17T00:00:00Z',
                'valid_from_utc':'2026-11-18T00:00:00Z',
                'valid_until_utc':'2026-11-20T00:00:00Z',
                'revoked_at_utc':None,
            })
        cls.registry={
            'schema':REG_SCHEMA,'campaign_id':'DEV_TUTOR_001','session_id':'DEV_TUTOR_001',
            'review_status':'DOCUMENTARY_ONLY_NO_TECHNICAL_AUTHORITY',
            'window_start_utc':'2026-11-18T00:00:00Z',
            'window_end_utc':'2026-11-19T00:00:00Z',
            'scope':sorted([{
                'service_id':row['service_id'], 'case_id':row['a7_case_id'],
                'assessment_index':row['a5_intent']['assessment_index'],
                'configuration_sha256':row['a5_intent']['configuration_sha256'],
                'method_id':row['a5_intent']['method_id'],
            } for row in cls.r76['candidates']],
            key=lambda x:(x['service_id'],x['case_id'],x['assessment_index'])),
            'authorities':cls.authorities,
        }
        cls.pin=registry_digest(cls.registry)
        cls.bundle={'statement':cls.statement,
                    'signatures':cls.sign(cls.statement), 'support':cls.support}
        cls.report=cls.build()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def sign(cls,statement):
        message=cls.parent/'msg.bin'; message.write_bytes(signing_bytes(statement))
        result={}
        for auth in cls.authorities:
            role=auth['role']; file=cls.parent/(role+'.sig')
            subprocess.run([OPENSSL,'pkeyutl','-sign','-inkey',str(cls.keys[role]),
                            '-rawin','-in',str(message),'-out',str(file)],
                           check=True,capture_output=True,timeout=15)
            result[role]={'key_id':auth['key_id'],
                          'signature_b64':base64.b64encode(file.read_bytes()).decode('ascii')}
        return result

    @classmethod
    def build(cls,*,doc=None,reg=None,pin=None,bundles=None,prior=(),asof=REVIEW,root=None):
        return r77.build(cls.root if root is None else root,
                         cls.r76 if doc is None else doc,
                         cls.registry if reg is None else reg,
                         pinned_registry_sha256=cls.pin if pin is None else pin,
                         signed_bundles=[cls.bundle] if bundles is None else bundles,
                         prior_record_ids=prior,as_of_utc=asof)

    def test_01_signed_documentary_link(self):
        d=self.report
        self.assertEqual(d['signed_documentary_witness_count'],1)
        self.assertEqual(d['remaining_unaccredited_units'],25)
        self.assertEqual(d['r76_sha256'],self.r76['sha256'])
        self.assertEqual(d['r75_manifest_sha256'],self.r76['r75_manifest_sha256'])
        self.assertFalse(d['independent_pin_origin_verified'])
        self.assertFalse(d['signer_physical_independence_attested'])

    def test_02_no_technical_claim(self):
        d=self.report
        self.assertEqual(d['a6_classification'],'ND')
        self.assertIsNone(d['a7_confirmed_rf'])
        self.assertFalse(d['technical_truth_accredited'])
        self.assertEqual(d['a8_applied_transitions'],0)
        self.assertEqual(d['a9_new_generations'],0)
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertFalse(d['operational_dispatch'])
        self.assertEqual(len(d['signed_documentary_review']['decisions']),25)

    def test_03_report_round_trip(self):
        self.assertTrue(r77.verify(self.report,self.root,self.r76,self.registry,
             pinned_registry_sha256=self.pin,signed_bundles=[self.bundle],
             prior_record_ids=(),as_of_utc=REVIEW))

    def test_04_repeat_deterministic(self):
        self.assertEqual(canonical(self.build()),canonical(self.report))

    def test_05_wrong_pin_refused(self):
        with self.assertRaises(ValueError):self.build(pin='0'*64)

    def test_06_foreign_case_refused(self):
        b=copy.deepcopy(self.bundle);b['statement']['case_id']='CASE_FORGED'
        with self.assertRaises(ValueError):self.build(bundles=[b])

    def test_07_positive_claim_mismatch_refused(self):
        b=copy.deepcopy(self.bundle);b['statement']['observed_claim']='DIFF'
        b['signatures']=self.sign(b['statement'])
        with self.assertRaisesRegex(r77.R77Error,'SIGNED_ASSERTION_NOT_BOUND'):
            self.build(bundles=[b])

    def test_08_tampered_support_refused(self):
        b=copy.deepcopy(self.bundle);b['support']=b'FAKE SUPPORT'
        with self.assertRaises(ValueError):self.build(bundles=[b])

    def test_09_tampered_signature_refused(self):
        b=copy.deepcopy(self.bundle)
        sig=b['signatures']['observer']['signature_b64']
        b['signatures']['observer']['signature_b64']=('A' if sig[0]!='A' else 'B')+sig[1:]
        with self.assertRaises(ValueError):self.build(bundles=[b])

    def test_10_replayed_record_refused(self):
        with self.assertRaises(ValueError):
            self.build(prior=('R77_SYNTH_RECORD_001',))

    def test_11_revoke_registration_refused(self):
        reg=copy.deepcopy(self.registry)
        reg['authorities'][0]['revoked_at_utc']='2026-11-18T11:59:59Z'
        with self.assertRaises(ValueError):
            self.build(reg=reg,pin=registry_digest(reg))

    def test_12_registry_scope_change_refused(self):
        reg=copy.deepcopy(self.registry);reg['scope'].pop()
        with self.assertRaisesRegex(r77.R77Error,'REGISTRY_SCOPE_DOES_NOT_MATCH_R76'):
            self.build(reg=reg,pin=registry_digest(reg))

    def test_13_r76_forged_go_refused(self):
        d=copy.deepcopy(self.r76);d['p8_operational']='GO'
        with self.assertRaises(ValueError):self.build(doc=d)

    def test_14_r75_source_tampering_refused(self):
        path=self.root/'reports'/'54_units.json';old=path.read_bytes()
        try:
            path.write_bytes(old+b'\n')
            with self.assertRaises(ValueError):self.build()
        finally:path.write_bytes(old)

    def test_15_signed_no_start_refused(self):
        row=next(x for x in self.r76['candidates'] if x['declared_outcome']=='NO_START')
        b=copy.deepcopy(self.bundle)
        b['statement']['service_id']=row['service_id']
        b['statement']['case_id']=row['a7_case_id']
        b['statement']['method_id']=row['a5_intent']['method_id']
        b['signatures']=self.sign(b['statement'])
        with self.assertRaises(ValueError):self.build(bundles=[b])

    def test_16_forged_report_risk_refused(self):
        report=copy.deepcopy(self.report)
        report['a7_confirmed_rf']='1/2'
        report['sha256']=hashlib.sha256(canonical({k:v for k,v in report.items() if k!='sha256'})).hexdigest()
        with self.assertRaisesRegex(r77.R77Error,'REPORT_RECONSTRUCTION'):
            r77.verify(report,self.root,self.r76,self.registry,
              pinned_registry_sha256=self.pin,signed_bundles=[self.bundle],
              prior_record_ids=(),as_of_utc=REVIEW)

    def test_17_duplicate_bundle_refused(self):
        with self.assertRaises(ValueError):self.build(bundles=[self.bundle,self.bundle])

    def test_18_cli_private_files_and_verify(self):
        p=self.parent/'inputs';p.mkdir(mode=0o700)
        data={
            'r76.json':self.r76,
            'registry.json':self.registry,
            'bundles.json':[{'statement':self.statement,
              'signatures':self.bundle['signatures'],
              'support_b64':base64.b64encode(self.support).decode('ascii')}],
            'prior.json':[],
            'result.json':self.report,
        }
        for name,value in data.items():
            (p/name).write_bytes(canonical(value)+b'\n')
            (p/name).chmod(0o600)
        args=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r77_signed_a5_a8_bridge.py'),
           '--receipt-dir',str(self.root),'--r76-report',str(p/'r76.json'),
           '--registry-json',str(p/'registry.json'),'--registry-pin-sha256',self.pin,
           '--bundles-json',str(p/'bundles.json'),'--prior-ids-json',str(p/'prior.json'),
           '--as-of-utc',REVIEW]
        cp=subprocess.run(args+['--json'],cwd=REPO,capture_output=True,timeout=35)
        self.assertEqual(cp.returncode,0,cp.stderr.decode())
        self.assertEqual(cp.stdout,canonical(self.report)+b'\n')
        cp=subprocess.run(args+['--verify-json',str(p/'result.json')],cwd=REPO,
                          capture_output=True,timeout=35)
        self.assertEqual(cp.returncode,0,cp.stderr.decode())
        self.assertIn(b'PASS_VERIFIED_DOCUMENTARY_NO_EXECUTION',cp.stdout)

    def test_19_world_readable_private_input_refused(self):
        p=self.parent/'public.json';p.write_bytes(b'{}\n');p.chmod(0o644)
        with self.assertRaises(r77.R77Error):r77.read_canonical(p)

    def test_20_symlink_input_refused(self):
        p=self.parent/'data.json';p.write_bytes(b'{}\n');p.chmod(0o600)
        link=self.parent/'symlink.json';link.symlink_to(p)
        with self.assertRaises(r77.R77Error):r77.read_canonical(link)

    def test_21_unsupported_bundle_json_rejected(self):
        with self.assertRaises(r77.R77Error):
            r77.bundles_from_json([{'statement':self.statement,'signatures':self.bundle['signatures'],
                                    'support_b64':'ABC'}])

    def test_22_bad_historical_order_rejected(self):
        with self.assertRaises(ValueError):self.build(prior=('Z','A'))

    def test_23_no_physical_operations_in_bridge(self):
        source=(REPO/'scripts/ardrec_p14_r77_signed_a5_a8_bridge.py').read_text()
        for forbidden in ('subprocess.run(', 'os.system(', 'shell=True','systemctl ',
                          'virsh ', 'sudo ', 'nft ', 'gh pr merge','--host-readonly'):
            self.assertNotIn(forbidden,source)

if __name__=='__main__':unittest.main()
