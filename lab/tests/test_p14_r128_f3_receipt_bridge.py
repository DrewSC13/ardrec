"""B8 pinned-root provenance candidate, F13 consumed once; no real guest I/O."""
import base64
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r128_f3_receipt_bridge as b8

HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
SESSION='0123456789abcdef'


@unittest.skipIf(os.geteuid()==0,'F13 requires nonroot')
class ExistingF3Bridge(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='ardrec-r128-b8-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.intent=f13.make_intent(case_id='FTP-T01-S01-01',
           session_id=SESSION,assessment_index=1,attempt_id='ATT_B8_1',
           head=HEAD,contract_sha256='a'*64,
           scope_authorization_sha256='b'*64,p8_window_sha256='c'*64)
        self.folder=f13.reserve(self.intent,f12.DRAFT_BUDGET.copy(),root=self.root/'f13')
        self.result={'schema':b8.GUEST_SCHEMA,'src':'10.203.31.1','dst':'10.203.31.2',
            'port':21,'case_id':self.intent['case_id'],'tcp':'CONNECTED',
            'response':'RECEIVED','response_hex':b'220 Hello\r\n'.hex()}
        self.receipt={'schema':b8.F3_SCHEMA+'-receipt',
            'status':'FTP_CANDIDATE_RECORDED','opened':True,
            'backup_timer_armed':True,'denies_restored_and_verified':True,
            'result_sha256':b8.dig(self.result),'error':None,'a6':'ND',
            'p8':'NO-GO','p7_calibrated':False,'a9_published':False}
        self.qga={'return':{'exited':True,'exitcode':0,'err-data':'',
            'out-data':base64.b64encode(f1.canonical(self.result)).decode('ascii')}}
        self.manifest={'schema':b8.F3_SCHEMA+'-root-bundle',
            'head':HEAD,'base':'e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc',
            'source_sha256':{'root-pilot.py':b8.F3_SHA256},
            'p8':'NO-GO','window_seconds':60,
            'authority_paths':['contract.json','scope-authorization.json','pilot-permit.json'],
            'network_automatic':False,'a6':'ND',
            'catalog_sha256':'5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'}
        self.context={'schema':'ARDREC-R116-F3-FTP-T01-ROOT-SESSION-v1-signed-review',
                      'head':HEAD,'p8':'NO-GO','a6':'ND','budget':{}}

    def spend(self):
        state=f13.inspect(self.folder)
        spent={'schema':f13.SCHEMA+'-spent',
            'reservation_sha256':state['reservation_sha256'],
            'status':'ATTEMPT_CONSUMED_NO_RETRY','a6':'ND','p8':'NO-GO'}
        h=f13._save(self.folder,'spent.json',spent)
        f13._save(self.folder,'spent.manifest.json',{
            'schema':f13.SCHEMA+'-manifest','file':'spent.json',
            'sha256':h,'case_key':state['case_key'],'p8':'NO-GO'})

    def build(self,**overrides):
        values={'session':SESSION,'journal':self.folder,
                'manifest_raw':f1.canonical(self.manifest),
                'receipt_raw':f1.canonical(self.receipt),
                'result_raw':f1.canonical(self.result),
                'qga_raw':f1.canonical(self.qga),
                'context_raw':f1.canonical(self.context),
                'root_source_sha256':b8.F3_SHA256}
        values.update(overrides)
        return b8.bridge(**values)

    def assertStop(self,reason,fn):
        with self.assertRaises(b8.Stop) as exc:fn()
        self.assertEqual(str(exc.exception),reason)

    def test_01_failclosed_capabilities(self):
        x=b8.capabilities()
        self.assertEqual(x['p8'],'NO-GO')
        self.assertTrue(x['legacy_f3_head_is_historically_pinned'])
        self.assertFalse(x['physical_ftp_window_opened_by_bridge'])

    def test_02_spent_canonical_link(self):
        self.spend()
        report=self.build()
        self.assertEqual(report['case_key'],f13.key_for_case(self.intent))
        self.assertEqual(report['a6'],'ND')
        self.assertIsNone(report['a9'])
        self.assertFalse(report['root_owned_readback_verified'])
        self.assertFalse(report['f13_socket_consumption_performed_by_bridge'])
        self.assertEqual(report['sha256'],b8.dig({k:v for k,v in report.items() if k!='sha256'}))

    def test_03_reserved_cannot_promote(self):
        self.assertStop('F13_MUST_BE_SPENT_WITHOUT_DUPLICATE_SOCKET',self.build)

    def test_04_no_second_read(self):
        self.spend()
        with patch('socket.socket',side_effect=AssertionError('NO SOCKET')):
            self.assertEqual(self.build()['a5'],'ROOT_F3_RESULT_CANDIDATE_ONLY')

    def test_05_session_wrong(self):
        self.spend()
        self.assertStop('F13_SESSION_NOT_PREBOUND',lambda:self.build(session='f'*16))

    def test_06_session_not_hex(self):
        self.spend()
        self.assertStop('SESSION_MUST_BE_FIXED_16_HEX',lambda:self.build(session='session-x'))

    def test_07_source_pin_wrong(self):
        self.spend()
        self.assertStop('F3_ROOT_SOURCE_NOT_PINNED',lambda:self.build(root_source_sha256='0'*64))

    def test_08_manifest_head_wrong(self):
        self.spend();self.manifest['head']='1'*40
        self.assertStop('HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT',self.build)

    def test_09_manifest_source_pin_wrong(self):
        self.spend();self.manifest['source_sha256']['root-pilot.py']='0'*64
        self.assertStop('HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT',self.build)

    def test_10_manifest_window_120(self):
        self.spend();self.manifest['window_seconds']=120
        self.assertStop('HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT',self.build)

    def test_11_manifest_authorizes_network(self):
        self.spend();self.manifest['network_automatic']=True
        self.assertStop('HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT',self.build)

    def test_12_manifest_claims_p8_go(self):
        self.spend();self.manifest['p8']='GO'
        self.assertStop('HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT',self.build)

    def test_13_manifest_extra_field(self):
        self.spend();self.manifest['spurious']=1
        self.assertStop('F3_MANIFEST_FIELDS',self.build)

    def test_14_root_context_wrong_head(self):
        self.spend();self.context['head']='1'*40
        self.assertStop('ROOT_CONTEXT_NOT_THIS_HEAD',self.build)

    def test_15_root_context_false_a6(self):
        self.spend();self.context['a6']='VERDADERO'
        self.assertStop('ROOT_CONTEXT_NOT_THIS_HEAD',self.build)

    def test_16_root_context_schema_wrong(self):
        self.spend();self.context['schema']='WRONG'
        self.assertStop('ROOT_CONTEXT_NOT_THIS_HEAD',self.build)

    def test_17_root_receipt_not_restored(self):
        self.spend();self.receipt['denies_restored_and_verified']=False
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_18_root_receipt_timer_not_armed(self):
        self.spend();self.receipt['backup_timer_armed']=False
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_19_root_receipt_error(self):
        self.spend();self.receipt['error']='TIMEOUT'
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_20_root_receipt_bad_hash(self):
        self.spend();self.receipt['result_sha256']='0'*64
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_21_root_receipt_forged_A6(self):
        self.spend();self.receipt['a6']='VERDADERO'
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_22_root_receipt_forged_A9(self):
        self.spend();self.receipt['a9_published']=True
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_23_result_target_tampered(self):
        self.spend();self.result['dst']='1.1.1.1'
        self.assertStop('F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH',self.build)

    def test_24_result_case_tampered_rehashed(self):
        self.spend();self.result['case_id']='OTHER'
        self.receipt['result_sha256']=b8.dig(self.result)
        self.assertStop('FTP_GUEST_RESULT_SCOPE',self.build)

    def test_25_result_port_tampered_rehashed(self):
        self.spend();self.result['port']=22
        self.receipt['result_sha256']=b8.dig(self.result)
        self.assertStop('FTP_GUEST_RESULT_SCOPE',self.build)

    def test_26_oversized_greeting(self):
        self.spend();self.result['response_hex']=(b'X'*257).hex()
        self.receipt['result_sha256']=b8.dig(self.result)
        self.assertStop('FTP_RESULT_SEMANTICS',self.build)

    def test_27_qga_mismatch(self):
        self.spend();self.qga['return']['out-data']=base64.b64encode(b'{}\n').decode()
        self.assertStop('QGA_AND_RESULT_DIVERGE',self.build)

    def test_28_qga_error(self):
        self.spend();self.qga['return']['exitcode']=1
        self.assertStop('QGA_RECEIPT_NOT_SUCCESSFUL',self.build)

    def test_29_no_canonical(self):
        self.spend();self.assertStop('SOURCE_NOT_CANONICAL',lambda:self.build(result_raw=b' {}\n'))

    def test_30_nonbytes(self):
        self.spend();self.assertStop('SOURCE_BYTES_INVALID',lambda:self.build(result_raw='abc'))

    def test_31_signed_root_path_required(self):
        x=b8.capabilities()
        self.assertTrue(x['independent_current_head_v2_root_executor_still_required'])

    def test_32_no_double_spent(self):
        self.spend()
        with self.assertRaises(FileExistsError):self.spend()

    def test_33_spent_failed_has_no_candidate(self):
        self.spend()
        result=self.build()
        self.assertFalse(result['independent_ftp_origin_attested'])
        self.assertFalse(result['independent_root_closure_attested'])

    def test_34_no_traffic_host_calls(self):
        self.spend()
        with patch('subprocess.run',side_effect=AssertionError('NO HOST RUN')):
            self.assertEqual(self.build()['p8'],'NO-GO')

    def test_35_invalid_json_duplicates(self):
        self.spend();self.assertStop('SOURCE_JSON_INVALID',lambda:self.build(result_raw=b'{"a":1,"a":2}\n'))

    def test_36_source_sha_equals_repository(self):
        src=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r116_f3_root_pilot.py'
        import hashlib
        self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(),b8.F3_SHA256)

    def test_37_source_root_path_fixed(self):
        self.assertEqual(str(b8.ROOT),'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1')
        self.assertEqual(str(b8.SOURCE),'/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py')

    def test_38_f13_result_from_socket_not_accepted(self):
        # Once F13 already has a socket result, never attach an F3 probe to it.
        self.spend()
        f13._save(self.folder,'failure.json',{
            'schema':f13.SCHEMA+'-terminal','status':'FAILED_NO_RETRY',
            'reservation_sha256':f13.inspect(self.folder)['reservation_sha256'],
            'spent_sha256':f1.digest(f1.canonical(f13._read_json(self.folder,'spent.json'))),
            'error_code':'SIMULATED','a6':'ND','p8':'NO-GO',
            'physical_provenance_attested':False})
        # Missing manifest is a fail-closed interrupted transaction.
        with self.assertRaises(f13.Stop):self.build()

    def test_39_fixed_root_commands_only(self):
        with self.assertRaises(b8.Stop):b8._host(('/usr/bin/bash','-c','true','A','B'))

    def test_41_root_metadata_requires_owner_and_exact_mode(self):
        with patch.object(b8,'_host',return_value=b'0|600|1|regular file|30\n'):
            self.assertIn('regular file',b8._stat(b8.SOURCE,directory=False))
        with patch.object(b8,'_host',return_value=b'1000|600|1|regular file|30\n'):
            self.assertStop('ROOT_FILE_OR_DIRECTORY_PERMISSIONS',lambda:b8._stat(b8.SOURCE,directory=False))

    def test_42_root_metadata_symlink_rejected(self):
        with patch.object(b8,'_host',return_value=b'0|600|1|symbolic link|30\n'):
            self.assertStop('ROOT_FILE_OR_DIRECTORY_PERMISSIONS',lambda:b8._stat(b8.SOURCE,directory=False))

    def test_43_root_metadata_hardlink_rejected(self):
        with patch.object(b8,'_host',return_value=b'0|600|2|regular file|30\n'):
            self.assertStop('ROOT_FILE_OR_DIRECTORY_PERMISSIONS',lambda:b8._stat(b8.SOURCE,directory=False))

    def test_44_root_metadata_worldwritable_rejected(self):
        with patch.object(b8,'_host',return_value=b'0|666|1|regular file|30\n'):
            self.assertStop('ROOT_FILE_OR_DIRECTORY_PERMISSIONS',lambda:b8._stat(b8.SOURCE,directory=False))

    def test_45_root_source_pin_exact(self):
        payload=(b8.F3_SHA256+'  '+str(b8.SOURCE)+'\n').encode()
        with patch.object(b8,'_host',return_value=payload):
            self.assertEqual(b8._source_digest(),b8.F3_SHA256)
        with patch.object(b8,'_host',return_value=b'0'*64+b'  bad\n'):
            self.assertStop('INSTALLED_LEGACY_F3_BINARY_NOT_PINNED',b8._source_digest)

    def test_46_root_source_inspection_is_not_approval(self):
        with patch.object(b8,'_stat',return_value='trusted'),patch.object(b8,'_source_digest',return_value=b8.F3_SHA256):
            result=b8.inspect_source()
        self.assertFalse(result['source_is_current_approved_executor'])
        self.assertFalse(result['root_controller_v2_deployed'])

    def test_47_root_reader_directory_fixed(self):
        self.spend()
        content={'manifest.json':f1.canonical(self.manifest),
                 'receipt.json':f1.canonical(self.receipt),
                 'guest-result.json':f1.canonical(self.result),
                 'guest-qga.json':f1.canonical(self.qga),
                 'signed-context.json':f1.canonical(self.context)}
        def fake_host(cmd):
            self.assertIn(cmd[3],('/usr/bin/cat',))
            path=cmd[-1]
            self.assertTrue(path.startswith(str(b8.ROOT)+'/'))
            return content[Path(path).name]
        with patch.object(b8,'inspect_source',return_value={}),patch.object(b8,'_stat',return_value='root-files-unchanged'),patch.object(b8,'_source_digest',return_value=b8.F3_SHA256),patch.object(b8,'_host',side_effect=fake_host):
            report=b8.read_installed(session=SESSION,journal=self.folder)
        self.assertTrue(report['root_owned_readback_verified'])
        self.assertFalse(report['independent_ftp_origin_attested'])
        self.assertEqual(report['a6'],'ND')
        self.assertFalse(report['f13_socket_consumption_performed_by_bridge'])

    def test_48_root_reader_rejects_changed_metadata(self):
        self.spend()
        n=[0]
        def changed(*args,**kwargs):
            n[0]+=1
            return 'a' if n[0]%2 else 'b'
        with patch.object(b8,'inspect_source',return_value={}),patch.object(b8,'_stat',side_effect=changed),patch.object(b8,'_host',return_value=f1.canonical(self.manifest)):
            self.assertStop('ROOT_FILE_METADATA_CHANGED_AFTER_READ',lambda:b8.read_installed(session=SESSION,journal=self.folder))

    def test_49_root_reader_never_accepts_invalid_session(self):
        self.spend()
        self.assertStop('SESSION_INVALID',lambda:b8.read_installed(session='../abc',journal=self.folder))

    def test_50_root_cli_capabilities_no_privileges(self):
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r128_f3_receipt_bridge.py'
        proc=subprocess.run([sys.executable,'-B',str(path),'--capabilities'],
           cwd=Path(__file__).resolve().parents[2],capture_output=True,text=True,
           env={**os.environ,'PYTHONPATH':'src'})
        self.assertEqual(proc.returncode,0,proc.stderr+proc.stdout)
        self.assertIn('NO-GO',proc.stdout)

    def test_51_root_cli_no_unbound_journal(self):
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r128_f3_receipt_bridge.py'
        proc=subprocess.run([sys.executable,'-B',str(path),'--read-installed','--session',SESSION],
           cwd=Path(__file__).resolve().parents[2],capture_output=True,text=True,
           env={**os.environ,'PYTHONPATH':'src'})
        self.assertEqual(proc.returncode,2)
        self.assertIn('SESSION_AND_JOURNAL_REQUIRED',proc.stdout)

    def test_52_root_cli_refuses_unrecognized_flag(self):
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r128_f3_receipt_bridge.py'
        proc=subprocess.run([sys.executable,'-B',str(path),'--arm-deny'],
           cwd=Path(__file__).resolve().parents[2],capture_output=True,text=True,
           env={**os.environ,'PYTHONPATH':'src'})
        self.assertNotEqual(proc.returncode,0)

    def test_40_never_claim_physical_independence(self):
        self.spend();out=self.build()
        self.assertFalse(out['root_owned_readback_verified'])
        self.assertFalse(out['independent_ftp_origin_attested'])


if __name__=='__main__':unittest.main()
