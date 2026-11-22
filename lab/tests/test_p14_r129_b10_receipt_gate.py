"""R129 B10: F13 prebound journal, B9 exported receipts, QGA and A9 denial.

All samples are synthetic and intentionally UNTRUSTED; no physical or root
attestation is asserted.  Uses actual F13 disk journal with a fake QGA result.
"""
from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r128_prebound_session_v2 as bind
from ardrec.coordination import r129_b9_receipt_gate as m

HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
SESSION='a1b2c3d4e5f60718'
CASE='FTP-T01-S01-01'

@unittest.skipIf(os.geteuid()==0,'F13 filesystem tests require nonroot')
class ReceiptB10(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='ardrec-b10-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.intent0=f13.make_intent(case_id=CASE,session_id=SESSION,
            assessment_index=1,attempt_id='ATT_B10_ONCE',head=HEAD,
            contract_sha256='a'*64,scope_authorization_sha256='b'*64,
            p8_window_sha256='c'*64)
        self.journal=f13.reserve(self.intent0,f12.DRAFT_BUDGET.copy(),
                                  root=self.root/'f13')
        self.handoff=bind.spend_before_root(journal=self.journal,head=HEAD,session=SESSION)
        self.intent={'schema':m.B9+'-intent','session':SESSION,'head':HEAD,
            'f13_handoff_sha256':m.digest(self.handoff),
            'root_traffic_grant_sha256':'d'*64,
            'root_deny_grant_sha256':'e'*64,'boot_id':'boot-of-test-only',
            'a6':'ND','p8':'NO-GO'}
        self.guest={'schema':m.GUEST,'src':'10.203.31.1','dst':'10.203.31.2',
            'port':21,'case_id':CASE,'tcp':'CONNECTED','response':'RECEIVED',
            'response_hex':b'220 FTP synthetic greeting\r\n'.hex()}
        payload=(__import__('json').dumps(self.guest,sort_keys=True)+'\n').encode()
        self.qga={'return':{'exited':True,'exitcode':0,'err-data':'',
            'out-data':base64.b64encode(payload).decode('ascii')}}
        self.receipt={'schema':m.B9+'-receipt','session':SESSION,'head':HEAD,
            'case_id':CASE,'f13_handoff_sha256':m.digest(self.handoff),
            'root_traffic_grant_sha256':'d'*64,
            'denies_restored_and_verified':True,'timer_armed':True,
            'traffic_window_opened':True,'guest_result_sha256':m.digest(self.guest),
            'elapsed_monotonic_ns':3_000_000_000,
            'result':'FTP_GUEST_CANDIDATE_ONLY','error':None,
            'a6':'ND','a9':None,'p8':'NO-GO'}

    def run_review(self):
        return m.review(journal=self.journal,handoff=self.handoff,
            intent=self.intent,receipt=self.receipt,
            guest=self.guest,qga=self.qga)

    def fails(self,code):
        with self.assertRaisesRegex(m.Stop,code): self.run_review()

    def test_01_f13_prespent(self):
        self.assertEqual(f13.inspect(self.journal)['status'],'ATTEMPT_CONSUMED_UNRESOLVED')
    def test_02_candidate_complete_220(self):
        self.assertTrue(self.run_review()['banner_is_complete_220'])
    def test_03_a6_never_promoted(self):
        self.assertEqual(self.run_review()['a6'],'ND')
    def test_04_a7_not_confirmed(self):
        self.assertIsNone(self.run_review()['a7_confirmed_rf'])
    def test_05_a8_not_applied(self):
        self.assertIsNone(self.run_review()['a8_applied'])
    def test_06_a9_not_published(self):
        self.assertIsNone(self.run_review()['a9'])
    def test_07_p8_not_granted(self):
        self.assertEqual(self.run_review()['p8'],'NO-GO')
    def test_08_root_not_attested(self):
        self.assertFalse(self.run_review()['independent_root_origin_verified'])
    def test_09_r127_not_attested(self):
        self.assertFalse(self.run_review()['independent_r127_crash_witness_verified'])
    def test_10_a9_barrier(self):
        v=self.run_review();r=m.a9_barrier(candidate=v,journal=self.journal,
            handoff=self.handoff,intent=self.intent,receipt=self.receipt,
            guest=self.guest,qga=self.qga)
        self.assertFalse(r['generation_written'])
        self.assertFalse(r['durable_store_opened'])
    def test_11_a9_changed_report(self):
        v=self.run_review();v['a6']='VERDADERO'
        with self.assertRaisesRegex(m.Stop,'A9_CANDIDATE_MUTATED'):
            m.a9_barrier(candidate=v,journal=self.journal,
                handoff=self.handoff,intent=self.intent,receipt=self.receipt,
                guest=self.guest,qga=self.qga)
    def test_12_no_socket(self):
        with patch('socket.socket',side_effect=AssertionError('network forbidden')):
            self.run_review()
    def test_13_no_durable_store(self):
        with patch('ardrec.persistence.DurableStore.open',side_effect=AssertionError('A9 forbidden')):
            self.run_review()
    def test_14_false_handoff_hash(self):
        self.handoff['spent_sha256']='f'*64;self.fails('F13_PRESPENT')
    def test_15_wrong_handoff_session(self):
        self.handoff['session']='0'*16;self.fails('F13_DURABLE_SOURCE_UNAVAILABLE')
    def test_16_wrong_head(self):
        self.intent['head']='0'*40;self.fails('B9_ROOT_INTENT')
    def test_17_wrong_root_session(self):
        self.intent['session']='0'*16;self.fails('B9_ROOT_INTENT')
    def test_18_wrong_root_handoff(self):
        self.intent['f13_handoff_sha256']='0'*64;self.fails('B9_ROOT_INTENT')
    def test_19_wrong_root_grant(self):
        self.receipt['root_traffic_grant_sha256']='0'*64;self.fails('B9_RECEIPT')
    def test_20_wrong_receipt_case(self):
        self.receipt['case_id']='FTP-T01-S99-99';self.fails('B9_RECEIPT')
    def test_21_fake_a6(self):
        self.receipt['a6']='VERDADERO';self.fails('B9_RECEIPT')
    def test_22_fake_a9(self):
        self.receipt['a9']=1;self.fails('B9_RECEIPT')
    def test_23_fake_p8(self):
        self.receipt['p8']='GO';self.fails('B9_RECEIPT')
    def test_24_restore_missing(self):
        self.receipt['denies_restored_and_verified']=False;self.fails('B9_SUCCESS')
    def test_25_timer_not_armed(self):
        self.receipt['timer_armed']=False;self.fails('B9_SUCCESS')
    def test_26_window_not_opened(self):
        self.receipt['traffic_window_opened']=False;self.fails('B9_SUCCESS')
    def test_27_deadline_exceeded(self):
        self.receipt['elapsed_monotonic_ns']=60_000_000_001;self.fails('B9_SUCCESS')
    def test_28_bogus_success_error(self):
        self.receipt['error']='unexpected';self.fails('B9_SUCCESS')
    def test_29_missing_qga(self):
        self.qga=None;self.fails('B9_GUEST_OUTPUT_INCOMPLETE')
    def test_30_missing_guest(self):
        self.guest=None;self.fails('B9_GUEST_OUTPUT_INCOMPLETE')
    def test_31_wrong_guest_sha(self):
        self.receipt['guest_result_sha256']='0'*64;self.fails('B9_GUEST_RESULT_SHA_DRIFT')
    def test_32_wrong_guest_target(self):
        self.guest['dst']='10.1.1.1';self.fails('GUEST_IDENTITY')
    def test_33_wrong_guest_case(self):
        self.guest['case_id']='FTP-T01-S02-01';self.fails('GUEST_IDENTITY')
    def test_34_wrong_qga_exit(self):
        self.qga['return']['exitcode']=1;self.fails('QGA_TERMINAL')
    def test_35_qga_differs(self):
        self.qga['return']['out-data']=base64.b64encode(b'{}\n').decode();self.fails('QGA_AND_GUEST')
    def test_36_bad_hex(self):
        self.guest['response_hex']='nothex';self.fails('GUEST_RESPONSE_NOT_HEX')
    def test_37_bad_tcp_semantics(self):
        self.guest['tcp']='FAILED';self.fails('GUEST_CONNECT_ERROR')
    def test_38_error_status_without_guest(self):
        self.receipt.update(result='NO_GO_ATTEMPT_CONSUMED',error='root failed',
            guest_result_sha256=None,denies_restored_and_verified=False)
        self.guest=self.qga=None
        d=self.run_review()
        self.assertEqual(d['a5'],'UNRESOLVED_OR_FAILED_SINGLE_ATTEMPT')
        self.assertIsNone(d['guest_result_candidate_sha256'])
    def test_39_error_status_with_guest_still_no_a6(self):
        self.receipt.update(result='NO_GO_ATTEMPT_CONSUMED',error='timeout',
            elapsed_monotonic_ns=61_000_000_000)
        self.assertEqual(self.run_review()['a6'],'ND')
    def test_40_forged_failure_but_success(self):
        self.receipt['result']='NO_GO_ATTEMPT_CONSUMED';self.fails('B9_FALSE_FAILURE')
    def test_41_no_guest_in_success(self):
        self.receipt['guest_result_sha256']=None
        self.guest=self.qga=None
        self.fails('B9_GUEST_SOURCE_MISSING')
    def test_42_json_duplicate_claim(self):
        fake=b'{"x":1,"x":2}\n'
        self.qga['return']['out-data']=base64.b64encode(fake).decode()
        self.fails('QGA_JSON_DUPLICATE_FIELD')
    def test_43_added_receipt_field(self):
        self.receipt['fake']='GO';self.fails('B9_RECEIPT_FIELDS')
    def test_44_extra_guest_field(self):
        self.guest['password']='x';self.fails('GUEST_FIELDS')
    def test_45_corrupt_f13_journal(self):
        (self.journal/'spent.json').write_bytes(b'corrupt')
        self.fails('F13_DURABLE_SOURCE_UNAVAILABLE')
    def test_46_bad_qga_base64(self):
        self.qga['return']['out-data']='!!!';self.fails('QGA_OUTPUT_INVALID')
    def test_47_no_verified_220_even_if_complete(self):
        self.assertFalse(self.run_review()['independent_a6_technical_truth_accredited'])
    def test_48_capabilities(self):
        d=m.capabilities()
        self.assertFalse(d['global_durable_store_write'])
        self.assertTrue(d['ftp_220_does_not_prove_vulnerability'])

if __name__=='__main__':unittest.main()
