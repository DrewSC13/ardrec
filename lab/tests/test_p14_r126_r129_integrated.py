"""R126–R129: guarded source integration, negative permissions, recovery."""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125
from ardrec.coordination import r126_operational_controller as a
from ardrec.coordination import r127_closure_witness as b
from ardrec.coordination import r128_ftp_pilot as c
from ardrec.coordination import r129_a6_a10_recovery as d
from test_p14_r122_operational_boundary import synthetic_capture
from test_p14_r124_root_deny_readback import Fake

REPO=Path(__file__).resolve().parents[2]
CAT=(REPO/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
NOW=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)


@unittest.skipIf(os.geteuid()==0,'requires non-root private journal')
class Integration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        capture_root=self.root/'captures';capture_root.mkdir(mode=0o700)
        p=patch.object(f5,'ROOT',capture_root)
        p.start();self.addCleanup(p.stop)
        data=synthetic_capture()
        self.capture=f5.save_private(data,f5.report(data),root=capture_root)
        self.boundary=r122.build(capture_folder=self.capture,catalog_raw=CAT,head=HEAD,now=NOW)
        self.plan=r123.plan(boundary=self.boundary,catalog_raw=CAT,now=NOW)
        self.root_readback=r124.inspect(head=HEAD,now=NOW,run=Fake())
        self.integrated=r125.build(head=HEAD,catalog_raw=CAT,now=NOW,
            boundary=self.boundary,plan=self.plan,root_report=self.root_readback)
        self.handoff=a.review(head=HEAD,now=NOW,root_report=self.root_readback,
                              integrated_report=self.integrated)
        self.intent=f13.make_intent(case_id='FTP-T01-S01-01',session_id='R126R129',
            assessment_index=1,attempt_id='ATT_R126R129_01',head=HEAD,
            contract_sha256='b'*64,scope_authorization_sha256='c'*64,
            p8_window_sha256='d'*64)
        self.unit={'service_id':'FTP_DEV','case_id':'FTP_T01_S01_01',
             'assessment_index':1,'initial_risk':'1/2',
             'normalized_criticality':'1/3','replacement_risk':'1/4',
             'evidence':[]}
        self.preparation=c.prepare(handoff=self.handoff,intent=self.intent,
                                   profile=f12.DRAFT_BUDGET)

    def journal(self):
        return c.reserve_prepared(preparation=self.preparation,intent=self.intent,
                    profile=f12.DRAFT_BUDGET,root=self.root/'journal')

    def intake(self,folder):
        return c.reconcile(preparation=self.preparation,journal=folder,catalog_raw=CAT)

    def final(self,folder):
        return d.reconcile(intake=self.intake(folder),
                           case=r121.build(folder,CAT,self.unit),catalog_raw=CAT)

    def test_01_handoff_schema(self):self.assertEqual(self.handoff['schema'],a.SCHEMA)
    def test_02_handoff_verified(self):self.assertTrue(a.verify(self.handoff,root_report=self.root_readback,integrated_report=self.integrated))
    def test_03_handoff_no_go(self):self.assertEqual(self.handoff['p8'],'NO-GO')
    def test_04_handoff_no_dispatch(self):self.assertIs(self.handoff['dispatch'],False)
    def test_05_handoff_not_root(self):self.assertIs(self.handoff['root_enforced_grant_verified'],False)
    def test_06_handoff_deny(self):self.assertEqual(self.handoff['root_deny_state'],'OFFLINE_DENY_MATCH')
    def test_07_handoff_document_absent(self):self.assertEqual(self.handoff['document_status'],'DOCUMENTS_NOT_PRESENT')
    def test_08_handoff_wrong_head(self):
        with self.assertRaises(a.Stop):a.review(head='a'*40,now=NOW,root_report=self.root_readback,integrated_report=self.integrated)
    def test_09_handoff_forged_integrated(self):
        r=copy.deepcopy(self.integrated);r['p8']='GO'
        with self.assertRaises(a.Stop):a.review(head=HEAD,now=NOW,root_report=self.root_readback,integrated_report=r)
    def test_10_handoff_forged_root(self):
        r=copy.deepcopy(self.root_readback);r['sha256']='0'*64
        with self.assertRaises(a.Stop):a.review(head=HEAD,now=NOW,root_report=r,integrated_report=self.integrated)
    def test_11_cannot_self_approve(self):
        with self.assertRaisesRegex(a.Stop,'CANNOT_SELF_ISSUE_ROOT_AUTHORITY'):
            a.review(head=HEAD,now=NOW,root_report=self.root_readback,
                     integrated_report=self.integrated,authorizer='self')
    def test_12_handoff_tampered(self):
        report=copy.deepcopy(self.handoff);report['dispatch']=True
        with self.assertRaises(a.Stop):a.verify(report,root_report=self.root_readback,integrated_report=self.integrated)
    def test_13_preparation(self):self.assertEqual(self.preparation['case_key'],f13.key_for_case(self.intent))
    def test_14_preparation_not_dispatch(self):self.assertFalse(self.preparation['dispatch'])
    def test_15_preparation_no_go(self):self.assertEqual(self.preparation['p8'],'NO-GO')
    def test_16_preparation_wrong_head(self):
        r=copy.deepcopy(self.intent);r['head']='a'*40
        with self.assertRaises(c.Stop):c.prepare(handoff=self.handoff,intent=r,profile=f12.DRAFT_BUDGET)
    def test_17_preparation_forged_handoff(self):
        r=copy.deepcopy(self.handoff);r['dispatch']=True
        with self.assertRaises(c.Stop):c.prepare(handoff=r,intent=self.intent,profile=f12.DRAFT_BUDGET)
    def test_18_one_shot_reservation(self):
        folder=self.journal();self.assertTrue(folder.is_dir())
        with self.assertRaises(c.Stop):self.journal()
    def test_19_reconciliation_reserved(self):
        folder=self.journal();r=self.intake(folder)
        self.assertEqual(r['journal_status'],'RESERVED_NO_RETRY')
    def test_20_reconciliation_nd(self):
        self.assertEqual(self.intake(self.journal())['a6'],'ND')
    def test_21_reconciliation_a9(self):
        self.assertIsNone(self.intake(self.journal())['a9_generation'])
    def test_22_reconciliation_tampered_plan(self):
        folder=self.journal();bad=copy.deepcopy(self.preparation);bad['sha256']='a'*64
        with self.assertRaises(c.Stop):c.reconcile(preparation=bad,journal=folder,catalog_raw=CAT)
    def test_23_reconciliation_changed_source(self):
        folder=self.journal();(folder/'reservation.json').write_bytes(b'{}\n')
        with self.assertRaises(c.Stop):self.intake(folder)
    def test_24_reconciliation_no_forged_closure(self):
        folder=self.journal()
        fake={'envelope':{},'pre':{},'post':{}}
        with self.assertRaises(c.Stop):c.reconcile(preparation=self.preparation,journal=folder,
                                                     catalog_raw=CAT,root_witness=fake,now=NOW)
    def test_25_r129_source(self):self.assertEqual(self.final(self.journal())['schema'],d.SCHEMA)
    def test_26_r129_nd(self):self.assertEqual(self.final(self.journal())['a6'],'ND')
    def test_27_r129_interval(self):
        result=self.final(self.journal());self.assertEqual(len(result['a7_mathematical_interval']),2)
    def test_28_r129_no_rf(self):self.assertIsNone(self.final(self.journal())['a7_confirmed_rf'])
    def test_29_r129_no_a8(self):self.assertIsNone(self.final(self.journal())['a8_authoritative_transition'])
    def test_30_r129_no_a9(self):self.assertIsNone(self.final(self.journal())['a9_global_generation'])
    def test_31_r129_replay(self):
        folder=self.journal();receipt=self.final(folder)
        self.assertTrue(d.validate_replay(receipt,intake=self.intake(folder),
                           case=r121.build(folder,CAT,self.unit),catalog_raw=CAT))
    def test_32_r129_forged_generation(self):
        folder=self.journal();receipt=self.final(folder);receipt['a9_global_generation']=1
        with self.assertRaises(d.Stop):d.validate_replay(receipt,intake=self.intake(folder),
                          case=r121.build(folder,CAT,self.unit),catalog_raw=CAT)
    def test_33_r129_persist_and_recover(self):
        folder=self.journal();intake=self.intake(folder);case=r121.build(folder,CAT,self.unit)
        report=d.reconcile(intake=intake,case=case,catalog_raw=CAT)
        archive=d.store_private(report,intake=intake,case=case,catalog_raw=CAT,root=self.root/'audit')
        self.assertEqual(d.verify_private(archive,CAT),report)
    def test_34_r129_manifest_change(self):
        folder=self.journal();intake=self.intake(folder);case=r121.build(folder,CAT,self.unit)
        report=d.reconcile(intake=intake,case=case,catalog_raw=CAT)
        archive=d.store_private(report,intake=intake,case=case,catalog_raw=CAT,root=self.root/'audit')
        (archive/'manifest.json').write_bytes(b'{}\n')
        with self.assertRaises(d.Stop):d.verify_private(archive,CAT)
    def test_35_r129_source_change(self):
        folder=self.journal();intake=self.intake(folder);case=r121.build(folder,CAT,self.unit)
        report=d.reconcile(intake=intake,case=case,catalog_raw=CAT)
        archive=d.store_private(report,intake=intake,case=case,catalog_raw=CAT,root=self.root/'audit')
        (folder/'reservation.json').write_bytes(b'{}\n')
        with self.assertRaises((d.Stop,r121.Stop)):d.verify_private(archive,CAT)
    def test_36_private_modes(self):
        folder=self.journal();intake=self.intake(folder);case=r121.build(folder,CAT,self.unit)
        report=d.reconcile(intake=intake,case=case,catalog_raw=CAT)
        archive=d.store_private(report,intake=intake,case=case,catalog_raw=CAT,root=self.root/'audit')
        self.assertEqual(archive.stat().st_mode&0o777,0o700)
        self.assertTrue(all(p.stat().st_mode&0o777==0o600 for p in archive.iterdir()))
    def test_37_symlink_rejected(self):
        folder=self.journal();intake=self.intake(folder);case=r121.build(folder,CAT,self.unit)
        report=d.reconcile(intake=intake,case=case,catalog_raw=CAT)
        archive=d.store_private(report,intake=intake,case=case,catalog_raw=CAT,root=self.root/'audit')
        (archive/'intake.json').unlink();(archive/'intake.json').symlink_to('/etc/passwd')
        with self.assertRaises((d.Stop,OSError)):d.verify_private(archive,CAT)
    def test_38_no_network_calls(self):
        import socket
        with patch.object(socket,'socket',side_effect=AssertionError('SOCKET_CALLED')):
            self.final(self.journal())
    def test_39_no_process_spawn(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('PROCESS_CALLED')):
            self.final(self.journal())
    def test_40_capabilities(self):
        for module in (a,b,c,d):self.assertEqual(module.capabilities()['p8'],'NO-GO')


class Witness(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.pre=r124.inspect(head=HEAD,now=NOW,
              run=Fake(('ssh','runner','ftp'),'0123456789abcdef'))
        self.post=r124.inspect(head=HEAD,now=NOW+timedelta(seconds=10),run=Fake())
        self.statement={'schema':b.SCHEMA,'head':HEAD,
            'session':'0123456789abcdef','case_id':'FTP-T01-S01-01',
            'family_id':'FTP-T01','pre_readback_sha256':self.pre['sha256'],
            'post_readback_sha256':self.post['sha256'],
            'guard_sha256':r124.PIN,'boot_id':'test-boot-fixture',
            'restoration_receipt_sha256':'a'*64,
            'arm_monotonic_ns':1000000000,
            'restore_monotonic_ns':40000000000,
            'verified_monotonic_ns':42000000000,
            'target_seconds':45,'maximum_seconds':60,
            'crash_test_executed':True,'root_guard_recovered':True,
            'post_deny_state':'OFFLINE_DENY_MATCH','p8':'PILOT_ONLY'}
        self.envelope={'statement':self.statement,
                       'signer_key_id':'test-witness','signature_b64':''}
        self.trust={'schema':b.SCHEMA+'-external-trust',
                    'witness_signer':{'key_id':'test-witness',
                                      'public_key_pem':'-----BEGIN PUBLIC KEY-----\nINVALID\n-----END PUBLIC KEY-----\n'},
                    'scope_signer_key_id':'test-scope',
                    'revocation_signer_key_id':'test-revocation'}

    def test_41_required_distinct_signer(self):
        self.trust['scope_signer_key_id']='test-witness'
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))
    def test_42_reject_bad_signature(self):
        self.envelope['signature_b64']=base64.b64encode(b'\x00'*64).decode()
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))
    def test_43_reject_wrong_topology(self):
        self.pre=r124.inspect(head=HEAD,now=NOW,run=Fake())
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))
    def test_44_reject_bad_time(self):
        self.statement['verified_monotonic_ns']=62000000000
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))
    def test_45_reject_forged_p8(self):
        self.statement['p8']='GO'
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))
    def test_46_reject_future_readback(self):
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW-timedelta(seconds=60))
    def test_47_no_live_key_available_in_test(self):
        with self.assertRaises((b.Stop,OSError)):
            b.verify_root_anchored(envelope=self.envelope,pre=self.pre,
                                   post=self.post,now=NOW+timedelta(seconds=11))
    @unittest.skipUnless(shutil.which('openssl'),'openssl needed for cryptographic test')
    def test_48_real_ed25519_signature_still_not_root_trust(self):
        private=self.folder/'key.pem'; public=self.folder/'pub.pem'
        message=self.folder/'message.bin';signature=self.folder/'sig.bin'
        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(private)],check=True,capture_output=True)
        subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)],check=True,capture_output=True)
        message.write_bytes(b.PREFIX+f1.canonical(self.statement))
        subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(private),'-in',str(message),'-out',str(signature)],check=True,capture_output=True)
        self.envelope['signature_b64']=base64.b64encode(signature.read_bytes()).decode('ascii')
        self.trust['witness_signer']['public_key_pem']=public.read_text('ascii')
        result=b.validate(envelope=self.envelope,pre=self.pre,post=self.post,
                          trust=self.trust,now=NOW+timedelta(seconds=11))
        self.assertFalse(result['external_root_trust_anchored'])
        self.assertFalse(result['physical_closure_claim_accepted'])
        self.assertTrue(result['max_60s_met'])
        self.assertTrue(result['target_45s_met'])
        self.statement['restore_monotonic_ns']+=1
        with self.assertRaises(b.Stop):b.validate(envelope=self.envelope,pre=self.pre,
                                                  post=self.post,trust=self.trust,now=NOW+timedelta(seconds=11))


class OperatorIntakeB1(unittest.TestCase):
    """No signer spoofing: metadata and unsigned-document paths stay NO-GO."""

    def test_49_unsigned_request_invalid_head(self):
        with self.assertRaisesRegex(a.Stop,'UNSIGNED_REQUEST_HEAD_INVALID'):
            a.unsigned_pilot_request(head='not-a-commit',catalog_raw=CAT,
                                      contract_raw=b'{}')

    def test_50_unsigned_request_rejects_missing_contract(self):
        with self.assertRaisesRegex(a.Stop,'UNSIGNED_CONTRACT_REQUIRED'):
            a.unsigned_pilot_request(head=HEAD,catalog_raw=CAT,
                                      contract_raw=None)

    def test_51_unsigned_request_passes_exact_contract(self):
        contract=b'{"case_id":"FTP-T01-01"}\n'
        draft={'authorization_issued_by_this_module':False,
               'production_p8':'NO-GO','catalogue_execution_enabled':False,
               'case_id':'FTP-T01-01','repo_head':HEAD,
               'contract_sha256':f1.digest(contract)}
        from ardrec.coordination import r115_f15_p7_independent_pilot as f15
        with patch.object(f15,'request',return_value=draft) as fn:
            self.assertEqual(a.unsigned_pilot_request(head=HEAD,catalog_raw=CAT,
                              contract_raw=contract),draft)
        fn.assert_called_once_with(head=HEAD,catalog_raw=CAT,
                                   contract_raw=contract)

    def test_52_unsigned_request_rejects_forged_authority(self):
        draft={'authorization_issued_by_this_module':True,
               'production_p8':'GO','catalogue_execution_enabled':True,
               'case_id':'FTP-T01-01','repo_head':HEAD,
               'contract_sha256':f1.digest(b'{}')}
        from ardrec.coordination import r115_f15_p7_independent_pilot as f15
        with patch.object(f15,'request',return_value=draft):
            with self.assertRaisesRegex(a.Stop,'UNSIGNED_REQUEST_AUTHORITY_PROMOTION'):
                a.unsigned_pilot_request(head=HEAD,catalog_raw=CAT,
                                          contract_raw=b'{}')

    def test_53_metadata_never_grants(self):
        out=a.root_document_metadata()
        self.assertFalse(out['root_operational_grant'])
        self.assertFalse(out['signature_verified'])
        self.assertFalse(out['revocation_verified'])
        self.assertEqual(out['p8'],'NO-GO')
        self.assertEqual(set(out['files']),{
            'f15_pilot_trust','f15_pilot_revocation',
            'f7_boot_trust','f7_boot_revocation',
            'f11_traffic_trust','f11_traffic_revocation',
            'r127_root_closure_witness_trust'})
        self.assertTrue(all('private_key' not in str(v) for v in out['files'].values()))

    def test_54_bad_external_document_not_authority(self):
        with self.assertRaises(a.Stop):
            a.signed_documents(contract_raw=b'{}',authorization_raw=b'{}',
                pilot_raw=b'{}',catalog_raw=CAT,head=HEAD,now=NOW)

    def test_55_cli_capabilities_unchanged(self):
        import importlib.util
        target=REPO/'scripts/ardrec_p14_r126_r129_integrated.py'
        spec=importlib.util.spec_from_file_location('r126r129_cli_b1',target)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from contextlib import redirect_stdout
        from io import StringIO
        sink=StringIO()
        with redirect_stdout(sink):
            self.assertEqual(module.main(['--capabilities']),0)
        self.assertIn('NO-GO',sink.getvalue())

    def test_56_cli_partial_documents_fail_closed(self):
        import importlib.util
        from contextlib import redirect_stdout
        from io import StringIO
        target=REPO/'scripts/ardrec_p14_r126_r129_integrated.py'
        spec=importlib.util.spec_from_file_location('r126r129_cli_b1_partial',target)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.REPO=Path.cwd().resolve()
        module.CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
        sink=StringIO()
        with redirect_stdout(sink):
            rc=module.main(['--inspect','--head',HEAD,
                '--capture','/tmp/invalid-capture','--contract','/tmp/contract'])
        self.assertEqual(rc,2)
        self.assertIn('PARTIAL_OR_NON_INSPECT_DOCUMENTS',sink.getvalue())
        self.assertIn('R126_R129_P8=NO-GO',sink.getvalue())

    @unittest.skipIf(os.geteuid()==0,'requires nonroot private output')
    def test_57_cli_unsigned_request_writes_only_private_file(self):
        import importlib.util
        from contextlib import redirect_stdout
        from io import StringIO
        target=REPO/'scripts/ardrec_p14_r126_r129_integrated.py'
        spec=importlib.util.spec_from_file_location('r126r129_cli_b1_request',target)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.REPO=Path.cwd().resolve()
        module.CATALOG=REPO/'lab/operational-catalog-v1/catalog.json'
        with tempfile.TemporaryDirectory() as tmp:
            private=Path(tmp)/'private';private.mkdir(mode=0o700)
            target=private/'unsigned-request.json'
            body={'schema':'NOT_A_PERMIT','production_p8':'NO-GO'}
            fake_result=subprocess.CompletedProcess([],0,HEAD.encode()+b'\n',b'')
            sink=StringIO()
            with patch.object(module.subprocess,'run',return_value=fake_result),\
                 patch.object(module.f2,'private_read',return_value=b'{}'),\
                 patch.object(module.r126,'unsigned_pilot_request',return_value=body),\
                 redirect_stdout(sink):
                rc=module.main(['--unsigned-pilot-request','--head',HEAD,
                               '--contract',str(private/'contract.json'),
                               '--request-output',str(target)])
            self.assertEqual(rc,0,sink.getvalue())
            self.assertEqual(target.read_bytes(),f1.canonical(body))
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            self.assertIn('UNSIGNED_NOT_VALID_FOR_EXECUTION',sink.getvalue())
