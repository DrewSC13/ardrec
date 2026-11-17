"""R59-D: offline A5 result-intake and A6 fail-closed interface tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import hashlib
import json
import os
import subprocess
import stat
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r59d_a5_result_intake as d


class R59DTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.identity = dict(service_id='SSH_DEV', session_id='DEV_TUTOR_001',
                             family_id='SSH-T01', derived_case_id='SSH-T01-S01-01',
                             assessment_index=0, attempt_id='ATT_DEMO_A5',
                             configuration_sha256='a'*64,
                             method_id='SSH_EFFECTIVE_CONFIG_READONLY')
        self.intent = d.build_intent(**self.identity)
        self.empty = d.make_receipt(self.intent)
        self.support = b'SYNTHETIC_DEV_SUPPORT_ONLY\n'
        self.candidate = d.make_receipt(
            self.intent, outcome='INCONCLUSO',
            source_kind='EXTERNAL_UNVERIFIED', support=self.support,
            start_utc='2026-11-16T01:00:00Z',finish_utc='2026-11-16T01:00:01Z')

    def test_intent_ssh_valid(self):
        self.assertTrue(d.verify_intent(self.intent))

    def test_intent_ftp_valid(self):
        x = dict(self.identity, service_id='FTP_DEV', family_id='FTP-T08',
                 derived_case_id='FTP-T08-S01-01',method_id='FTP_EFFECTIVE_CONFIG_READONLY')
        self.assertTrue(d.verify_intent(d.build_intent(**x)))

    def test_intent_smb_valid(self):
        x = dict(self.identity, service_id='SMB_DEV', family_id='SMB-T09',
                 derived_case_id='SMB-T09-S01-01',method_id='SMB_EFFECTIVE_CONFIG_READONLY')
        self.assertTrue(d.verify_intent(d.build_intent(**x)))

    def test_family_wrong_protocol_refused(self):
        x=dict(self.identity,family_id='SMB-T01',derived_case_id='SMB-T01-S01-01')
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_family_out_of_range_refused(self):
        x=dict(self.identity,family_id='SSH-T09',derived_case_id='SSH-T09-S01-01')
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_derived_family_mismatch_refused(self):
        x=dict(self.identity,derived_case_id='SSH-T02-S01-01')
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_wrong_method_refused(self):
        x=dict(self.identity,method_id='FTP_EFFECTIVE_CONFIG_READONLY')
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_bool_assessment_refused(self):
        x=dict(self.identity,assessment_index=True)
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_bad_attempt_id_refused(self):
        x=dict(self.identity,attempt_id='ATT_demo; rm -rf')
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_bad_hash_refused(self):
        x=dict(self.identity,configuration_sha256='0'*63)
        with self.assertRaises(d.IntakeError): d.build_intent(**x)

    def test_intent_rehashed_false_authority_refused(self):
        i=deepcopy(self.intent); i['p8_operational']='GO'; i['sha256']=d.digest({k:v for k,v in i.items() if k!='sha256'})
        with self.assertRaises(d.IntakeError): d.verify_intent(i)

    def test_intent_extra_field_refused(self):
        i=deepcopy(self.intent); i['authorization']='GRANTED'
        with self.assertRaises(d.IntakeError): d.verify_intent(i)

    def test_no_start_zero_support(self):
        report=d.build_candidate(self.intent,self.empty,b'')
        self.assertEqual(report['status'],'DECLARED_NO_START_NO_A5')
        self.assertTrue(d.verify_candidate(report,b''))

    def test_no_start_with_time_refused(self):
        x=deepcopy(self.empty);x['declared_started_at_utc']='2026-11-16T00:00:00Z'
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,b'')

    def test_no_start_with_support_refused(self):
        x=d.make_receipt(self.intent,support=b'x')
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,b'x')

    def test_candidate_unverified_no_a6(self):
        doc=d.build_candidate(self.intent,self.candidate,self.support)
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertIsNone(doc['a7_confirmed_rf'])
        self.assertFalse(doc['a5_physical_start_accredited'])
        self.assertTrue(d.verify_candidate(doc,self.support))

    def test_positive_claim_not_technical_truth(self):
        receipt=d.make_receipt(self.intent,outcome='OBSERVADO_POSITIVO',
                               source_kind='EXTERNAL_UNVERIFIED',support=self.support,
                               start_utc='2026-11-16T01:00:00Z',
                               finish_utc='2026-11-16T01:00:01Z')
        doc=d.build_candidate(self.intent,receipt,self.support)
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertFalse(doc['a6_technical_truth_accredited'])

    def test_case_field_mismatch_refused(self):
        for k,v in [('family_id','SSH-T02'),('derived_case_id','SSH-T02-S01-01'),
                    ('assessment_index',1),('attempt_id','ATT_OTHER'),
                    ('configuration_sha256','b'*64),('session_id','OTHER'),
                    ('method_id','FTP_EFFECTIVE_CONFIG_READONLY')]:
            with self.subTest(k=k):
                x=deepcopy(self.candidate);x[k]=v
                with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_intent_digest_mismatch(self):
        x=deepcopy(self.candidate);x['intent_sha256']='b'*64
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_support_changed_or_missing_refused(self):
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,self.candidate,self.support+b'x')

    def test_real_physical_authority_injected_refused(self):
        x=deepcopy(self.candidate);x['physical_authority_receipt_sha256']='a'*64
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_external_claim_without_times_refused(self):
        x=deepcopy(self.candidate);x['declared_started_at_utc']=None
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_timing_reverse_refused(self):
        x=deepcopy(self.candidate);x['declared_finished_at_utc']='2026-11-16T00:00:00Z'
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_timing_invalid_refused(self):
        x=deepcopy(self.candidate);x['declared_finished_at_utc']='2026-02-30T01:00:00Z'
        with self.assertRaises(d.IntakeError): d.build_candidate(self.intent,x,self.support)

    def test_oversize_support_refused(self):
        with self.assertRaises(d.IntakeError): d.make_receipt(self.intent,support=b'1'*(d.MAX_SUPPORT+1))

    def test_spoofed_a6_even_rehashed_refused(self):
        doc=d.build_candidate(self.intent,self.candidate,self.support)
        doc['a6_classification']='POSITIVO_VALIDO'
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(d.IntakeError): d.verify_candidate(doc,self.support)

    def test_spoofed_p8_even_rehashed_refused(self):
        doc=d.build_candidate(self.intent,self.candidate,self.support)
        doc['p8_operational']='GO'
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(d.IntakeError): d.verify_candidate(doc,self.support)

    def test_spoofed_publication_even_rehashed_refused(self):
        doc=d.build_candidate(self.intent,self.candidate,self.support)
        doc['a9_published_generation']='GEN-FAKE'
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        with self.assertRaises(d.IntakeError): d.verify_candidate(doc,self.support)

    def test_persist_reopen_idempotent(self):
        first=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        second=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        self.assertEqual(first['status'],'CREATED')
        self.assertEqual(second['status'],'REPLAY_IDENTICAL')
        doc=d.verify_stored_candidate(self.root,first['report_sha256'])
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertEqual(doc['sha256'],first['report_sha256'])

    def test_no_start_persist_no_support_file(self):
        first=d.persist_candidate(self.root,self.intent,self.empty,b'')
        self.assertEqual(len(list(self.root.glob('*.bin'))),0)
        self.assertEqual(d.verify_stored_candidate(self.root,first['report_sha256'])['status'],
                         'DECLARED_NO_START_NO_A5')

    def test_reopen_support_tamper_refused(self):
        report=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        p=self.root/('r59d-support-'+d.sha(self.support)+'.bin')
        p.write_bytes(b'tampered')
        with self.assertRaises(d.IntakeError): d.verify_stored_candidate(self.root,report['report_sha256'])

    def test_report_tamper_even_rehashed_refused(self):
        report=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        path=Path(report['report_path'])
        doc=json.loads(path.read_bytes())
        doc['a6_classification']='POSITIVO_VALIDO'
        doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        path.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(d.IntakeError): d.verify_stored_candidate(self.root,report['report_sha256'])

    def test_private_root_mode_denied(self):
        os.chmod(self.root,0o755)
        with self.assertRaises(d.IntakeError): d.persist_candidate(self.root,self.intent,self.empty,b'')

    def test_world_readable_receipt_denied(self):
        report=d.persist_candidate(self.root,self.intent,self.empty,b'')
        os.chmod(report['report_path'],0o644)
        with self.assertRaises(d.IntakeError): d.verify_stored_candidate(self.root,report['report_sha256'])

    def test_symlink_report_denied(self):
        report=d.persist_candidate(self.root,self.intent,self.empty,b'')
        path=Path(report['report_path'])
        raw=path.read_bytes(); path.unlink()
        target=self.root/'external'
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(d.IntakeError): d.verify_stored_candidate(self.root,report['report_sha256'])

    def test_conflicting_existing_support_denied(self):
        p=self.root/('r59d-support-'+d.sha(self.support)+'.bin')
        p.write_bytes(b'changed')
        os.chmod(p,0o600)
        with self.assertRaises(d.IntakeError): d.persist_candidate(self.root,self.intent,self.candidate,self.support)

    def test_duplicate_json_key_refused(self):
        report=d.persist_candidate(self.root,self.intent,self.empty,b'')
        path=Path(report['report_path']); raw=path.read_bytes()
        # Duplicate key in syntactically valid JSON, but exact persisted bytes differ.
        path.write_bytes(raw.replace(b'{', b'{"extra":1,"extra":2,',1))
        with self.assertRaises(d.IntakeError): d.verify_stored_candidate(self.root,report['report_sha256'])

    def test_cli_demo_no_start_replay(self):
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r59d_a5_intake.py'),
             '--demo-no-start','--store-root',str(self.root)]
        first=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        second=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        self.assertEqual(first.returncode,0,first.stderr)
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(json.loads(first.stdout)['status'],'CREATED')
        self.assertEqual(json.loads(second.stdout)['status'],'REPLAY_IDENTICAL')

    def test_cli_verify_stored_document(self):
        saved=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r59d_a5_intake.py'),
             '--verify-sha',saved['report_sha256'],'--store-root',str(self.root)]
        cp=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(json.loads(cp.stdout)['status'],'VERIFIED_REOPENED')

    def test_cli_import_external_candidate(self):
        inputs=self.root/'inputs';inputs.mkdir(mode=0o700)
        paths=[inputs/'intent.json',inputs/'receipt.json',inputs/'support.bin']
        for path,raw in zip(paths,(d.canonical(self.intent),d.canonical(self.candidate),self.support)):
            path.write_bytes(raw)
            os.chmod(path,0o600)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r59d_a5_intake.py'),
             '--import-intent',str(paths[0]),'--import-receipt',str(paths[1]),
             '--import-support',str(paths[2]),'--store-root',str(self.root)]
        cp=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        self.assertEqual(cp.returncode,0,cp.stderr)
        self.assertEqual(json.loads(cp.stdout)['a6_classification'],'ND')

    def test_cli_import_unsafe_permissions_refused(self):
        inputs=self.root/'inputs';inputs.mkdir(mode=0o700)
        paths=[inputs/'intent.json',inputs/'receipt.json',inputs/'support.bin']
        for path,raw in zip(paths,(d.canonical(self.intent),d.canonical(self.candidate),self.support)):
            path.write_bytes(raw);os.chmod(path,0o600)
        os.chmod(paths[1],0o644)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/ardrec_p14_r59d_a5_intake.py'),
             '--import-intent',str(paths[0]),'--import-receipt',str(paths[1]),
             '--import-support',str(paths[2]),'--store-root',str(self.root)]
        cp=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
        self.assertEqual(cp.returncode,23)
        self.assertIn('EXTERNAL_INPUT_MODE_OR_SIZE',cp.stderr)

    def test_constant_content_under_umask000(self):
        old=os.umask(0)
        try:
            report=d.persist_candidate(self.root,self.intent,self.candidate,self.support)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(Path(report['report_path']).stat().st_mode),0o600)
        self.assertTrue(d.verify_stored_candidate(self.root,report['report_sha256']))


if __name__=='__main__':
    unittest.main()
