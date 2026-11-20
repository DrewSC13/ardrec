"""R115-F6 regression: signed admission handoff and verified F5 evidence, no host calls."""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
import test_p14_r115_f5_lifecycle_readiness as fx
from test_p14_r115_f3_f11_authority import signed_set
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f6_signed_scope_and_activation as f

NOW=datetime(2026,11,20,14,30,tzinfo=timezone.utc)

def signed_receipt(doc):
    report=f5.report(doc)
    files={'capture.json':f1.canonical(doc),'report.json':f1.canonical(report)}
    files['manifest.json']=f1.canonical({
        'schema':'ARDREC-R115-F5-RECEIPT-v1',
        'files_sha256':{n:f1.digest(raw) for n,raw in files.items()},
        'scope':'READ_ONLY_NO_DISPATCH_NO_AUTHORITY'})
    return files

class F6(unittest.TestCase):
    def readback(self,files,now=NOW):
        def reader(path):
            return files[path.name]
        with patch.object(f.f2,'private_read',side_effect=reader):
            return f.verify_f5_receipt(Path('/unused'),now=now)

    def test_offline_handoff_never_grants(self):
        _,report,age=self.readback(signed_receipt(fx.fixture()))
        out=f.decision(report,age,('ND','NOT_PROVISIONED',None))
        self.assertEqual(out['f5_lifecycle_stage'],'OFFLINE_DENY_BASELINE_MATCH')
        self.assertEqual(out['a3']['SERVICE_READY'],'FALSO')
        self.assertEqual(out['a5_dispatch'],'NO-GO')
        self.assertFalse(out['boot_lease_issued'])
        self.assertFalse(out['traffic_authorized'])
        self.assertEqual(out['next_authorized_workflow'],
            'SEPARATE_BOOT_AUTHORIZATION_R112_F12_THEN_R112_F10')
    def test_five_gates_remain_blocked_even_scope_verified(self):
        r=f5.report(fx.fixture())
        out=f.decision(r,0,('VERDADERO','SIGNED_SCOPE_ROOT_ANCHORED_AT_REVIEW_ONLY','a'*64))
        self.assertEqual(out['a3']['SCOPE_APPROVED'],'VERDADERO')
        self.assertEqual(len(out['blocking_gates']),4)
        self.assertEqual(out['a5_dispatch'],'NO-GO')
    def test_running_six_deny_not_a_traffic_approval(self):
        doc=fx.fixture(states={r:'RUNNING' for r in f5.VMS},active=f5.six.ROLES)
        _,report,_=self.readback(signed_receipt(doc))
        out=f.decision(report,0,('VERDADERO','SIGNED_SCOPE','b'*64))
        self.assertEqual(out['f5_lifecycle_stage'],'RUNNING_SIX_DENY_BINDINGS_MATCH')
        self.assertEqual(out['a3']['LAB_ISOLATION_CONFIRMED'],'ND')
        self.assertEqual(out['a3']['CLIENT_COMPATIBLE'],'ND')
        self.assertEqual(out['a3']['SERVICE_READY'],'ND')
        self.assertEqual(out['p8'],'NO-GO')
    def test_drift_is_false(self):
        d=fx.fixture();d['probes']['nft']['stdout']='YWJj'
        _,report,_=self.readback(signed_receipt(d))
        self.assertEqual(f.decision(report,0,('ND','X',None))['a3']['LAB_ISOLATION_CONFIRMED'],'FALSO')
    def test_stale_f5_is_rejected(self):
        with self.assertRaisesRegex(f.Stop,'STALE'):
            self.readback(signed_receipt(fx.fixture()),now=NOW+timedelta(minutes=3))
    def test_future_f5_rejected(self):
        with self.assertRaisesRegex(f.Stop,'STALE'):
            self.readback(signed_receipt(fx.fixture()),now=NOW-timedelta(seconds=6))
    def test_tampered_report_bytes(self):
        files=signed_receipt(fx.fixture())
        files['report.json']+=b' '
        with self.assertRaisesRegex(f.Stop,'SHA'):
            self.readback(files)
    def test_fake_recomputed_report_rejected(self):
        files=signed_receipt(fx.fixture())
        bogus=f1.load(files['report.json']);bogus['a5_dispatch']='GO'
        files['report.json']=f1.canonical(bogus)
        m=f1.load(files['manifest.json']);m['files_sha256']['report.json']=f1.digest(files['report.json'])
        files['manifest.json']=f1.canonical(m)
        with self.assertRaisesRegex(f.Stop,'NOT_REPRODUCIBLE'):
            self.readback(files)
    def test_wrong_manifest_schema(self):
        files=signed_receipt(fx.fixture());m=f1.load(files['manifest.json']);m['scope']='AUTHORIZE'
        files['manifest.json']=f1.canonical(m)
        with self.assertRaisesRegex(f.Stop,'MANIFEST'):
            self.readback(files)
    def test_missing_signed_material_remains_nd(self):
        status=f.scope(None,None,catalog_raw=b'{}',now=NOW)
        self.assertEqual(status[0],'ND')
        with self.assertRaisesRegex(f.Stop,'PARTIAL_SCOPE_INPUT'):
            f.scope(None,b'{}',catalog_raw=b'{}',now=NOW)
    def test_no_arbitrary_trust_path(self):
        with self.assertRaisesRegex(f.Stop,'NOT_ALLOWLISTED'):
            f.secure_root_file(Path('/tmp/untrusted.json'))
    def test_report_input_schema_required(self):
        with self.assertRaises(f.Stop):f.decision({},0,('ND','X',None))
    def test_state_cannot_be_invented(self):
        r=f5.report(fx.fixture());r['lifecycle_stage']='GO_NOW'
        with self.assertRaises(f.Stop):f.decision(r,0,('ND','X',None))
    def test_unexpected_trust_source_does_not_grant(self):
        # Signatures and trust must all be supplied through fixed roots.
        self.assertNotIn('--trust',f.main.__code__.co_consts)
        self.assertEqual(f.TRUST,Path('/etc/ardrec/r115-ftp-t01-trust-v1.json'))
        self.assertEqual(f.REVOCATION,Path('/etc/ardrec/r115-ftp-t01-revocation-v1.json'))
    def test_real_signed_f3_bundle_with_anchored_keys_grants_scope_review_only(self):
        with tempfile.TemporaryDirectory() as t:
            c,a,r,trust=signed_set(Path(t))
            roots={f.TRUST:f1.canonical(trust),f.REVOCATION:f1.canonical(r)}
            with patch.object(f.f1,'validate',return_value={'static_contract_valid':True}):
                status=f.scope(f1.canonical(c),f1.canonical(a),catalog_raw=b'{}',
                    now=datetime(2026,11,20,11,30,45,tzinfo=timezone.utc),
                    root_loader=lambda path:roots[path])
            self.assertEqual(status[0],'VERDADERO')
            self.assertEqual(status[1],'SIGNED_SCOPE_ROOT_ANCHORED_AT_REVIEW_ONLY')
            report=f.decision(f5.report(fx.fixture()),0,status)
            self.assertEqual(report['a5_dispatch'],'NO-GO')
            self.assertIn('SERVICE_READY',report['blocking_gates'])
    def test_real_signed_f3_bundle_stale_revocation_never_grants(self):
        with tempfile.TemporaryDirectory() as t:
            c,a,r,trust=signed_set(Path(t))
            roots={f.TRUST:f1.canonical(trust),f.REVOCATION:f1.canonical(r)}
            with patch.object(f.f1,'validate',return_value={}):
                status=f.scope(f1.canonical(c),f1.canonical(a),catalog_raw=b'{}',
                    now=datetime(2026,11,20,11,33,0,tzinfo=timezone.utc),
                    root_loader=lambda path:roots[path])
            self.assertEqual(status[0],'ND')
    def test_real_signed_revocation_is_false(self):
        with tempfile.TemporaryDirectory() as t:
            c,a,r,trust=signed_set(Path(t),revoked=True)
            roots={f.TRUST:f1.canonical(trust),f.REVOCATION:f1.canonical(r)}
            with patch.object(f.f1,'validate',return_value={}):
                status=f.scope(f1.canonical(c),f1.canonical(a),catalog_raw=b'{}',
                    now=datetime(2026,11,20,11,30,45,tzinfo=timezone.utc),
                    root_loader=lambda path:roots[path])
            self.assertEqual(status[0],'FALSO')
            self.assertEqual(status[1],'SIGNED_REVOCATION_PRESENT')

    def test_offline_no_external_state(self):
        r=f5.report(fx.fixture())
        out=f.decision(r,0,('ND','NOT_PROVISIONED',None))
        self.assertEqual(out['guests_started'],0)
        self.assertIsNone(out['a9_generation'])
        self.assertIsNone(out['a7_confirmed_rf'])
        self.assertEqual(out['a6'],'ND')

if __name__=='__main__':unittest.main()
