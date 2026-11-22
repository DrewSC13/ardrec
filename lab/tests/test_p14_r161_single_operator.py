"""R161 source-only tests. No sudo, guest start, firewall or actual FTP traffic."""
from __future__ import annotations
from datetime import datetime,timedelta,timezone
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from ardrec.coordination import r161_single_operator as m

HEAD='a'*40
TREE='b'*40
BOOT='01234567-89ab-cdef-0123-456789abcdef'
SESSION='d'*16
NOW=datetime(2026,11,22,12,0,0,tzinfo=timezone.utc)
UID=1000
HASH='d'*64

class FakeProcess:
    def __init__(self,rc=0,out=b'',err=b''):
        self.returncode=rc
        self.stdout=out
        self.stderr=err

def b9_pre(**kwargs):
    out={'schema':'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-preflight',
        'head':HEAD,'session':SESSION,'case_id':'FTP-T01-S01-01',
        'host_changes':0,'traffic_opened':False,'p8':'NO-GO','a6':'ND',
        'traffic_grant_sha256':HASH,'root_deny_grant_sha256':HASH,
        'f13_handoff_sha256':HASH,'traffic_permit_until':m.utc(NOW+timedelta(seconds=20)),
        'budget':{'one_attempt':True}}
    out.update(kwargs)
    return m.canon(out)

def b9_receipt(**kwargs):
    out={'schema':'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-receipt',
        'head':HEAD,'session':SESSION,'case_id':'FTP-T01-S01-01',
        'denies_restored_and_verified':True,'timer_armed':True,
        'result':'FTP_GUEST_CANDIDATE_ONLY',
        'guest_result_sha256':HASH,'elapsed_monotonic_ns':20_000_000_000,
        'error':None,'p8':'NO-GO','a6':'ND','a9':None}
    out.update(kwargs)
    return m.canon(out)

class R161Tests(unittest.TestCase):
    def setUp(self):
        self.doc=m.consent_document(head=HEAD,tree=TREE,boot_id=BOOT,
            operator_uid=UID,session=SESSION,now=NOW)

    def validate(self,doc=None,now=NOW):
        return m.validate_consent(self.doc if doc is None else doc,
            head=HEAD,tree=TREE,boot_id=BOOT,operator_uid=UID,now=now)

    def denied(self,reason,doc=None,now=NOW):
        with self.assertRaisesRegex(m.Stop,reason):self.validate(doc,now=now)

    def test_01_schema(self):self.assertEqual(self.doc['schema'],m.SCHEMA+'-consent')
    def test_02_user_mode(self):self.assertEqual(self.doc['operator_mode'],'SELF_ATTESTED_DEVELOPMENT')
    def test_03_not_independent(self):self.assertIs(self.doc['independent_authority'],False)
    def test_04_no_network_authority(self):self.assertIs(self.doc['grants_network_traffic'],False)
    def test_05_no_root_authority(self):self.assertIs(self.doc['grants_root_privileges'],False)
    def test_06_no_vm_boot(self):self.assertIs(self.doc['grants_vm_start'],False)
    def test_07_no_p7(self):self.assertEqual(self.doc['p7'],'DRAFT_NOT_FROZEN')
    def test_08_no_p8(self):self.assertEqual(self.doc['p8'],'NO-GO')
    def test_09_no_a6(self):self.assertEqual(self.doc['a6'],'ND')
    def test_10_no_a9(self):self.assertEqual(self.doc['a9'],'NOT_PUBLISHED')
    def test_11_valid(self):self.assertEqual(self.validate()['session'],SESSION)
    def test_12_head_change(self):
        doc=dict(self.doc,head='e'*40);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_13_tree_change(self):
        doc=dict(self.doc,tree='e'*40);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_14_boot_change(self):
        doc=dict(self.doc,boot_id='00000000-0000-0000-0000-000000000000')
        self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_15_operator_change(self):
        doc=dict(self.doc,operator_uid=1);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_16_false_independent(self):
        doc=dict(self.doc,independent_authority=True);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_17_network_authorization_forgery(self):
        doc=dict(self.doc,grants_network_traffic=True);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_18_vm_start_forgery(self):
        doc=dict(self.doc,grants_vm_start=True);self.denied('CONSENT_AUTHORITY_SCOPE_INVALID',doc)
    def test_19_extra_field(self):
        doc=dict(self.doc,permission='yes');self.denied('CONSENT_FIELDS_INVALID',doc)
    def test_20_expired(self):self.denied('CONSENT_EXPIRED_OR_INVALID',now=NOW+timedelta(minutes=10))
    def test_21_future(self):self.denied('CONSENT_EXPIRED_OR_INVALID',now=NOW-timedelta(seconds=1))
    def test_22_bad_session(self):
        doc=dict(self.doc,session='bad');self.denied('CONSENT_SESSION_INVALID',doc)
    def test_23_canonical(self):self.assertEqual(m.parse(m.canon(self.doc)),self.doc)
    def test_24_noncanonical(self):
        with self.assertRaises(m.Stop):m.parse(b'{"a": 1}\n')
    def test_25_duplicate_json(self):
        with self.assertRaises(m.Stop):m.parse(b'{"a":1,"a":2}\n')
    def test_26_large_json(self):
        with self.assertRaises(m.Stop):m.parse(b'x'*(m.MAX_JSON+1))
    def test_27_no_nan(self):
        with self.assertRaises(m.Stop):m.parse(b'{"value":NaN}\n')
    def test_28_preflight_valid(self):
        self.assertEqual(m.validate_b9_preflight(b9_pre(),expected_head=HEAD,
               expected_session=SESSION,now=NOW)['case_id'],'FTP-T01-S01-01')
    def test_29_preflight_wrong_head(self):
        with self.assertRaisesRegex(m.Stop,'B9_PREFLIGHT_IDENTITY_INVALID'):
            m.validate_b9_preflight(b9_pre(head='e'*40),
                expected_head=HEAD,expected_session=SESSION,now=NOW)
    def test_30_preflight_wrong_session(self):
        with self.assertRaisesRegex(m.Stop,'B9_PREFLIGHT_IDENTITY_INVALID'):
            m.validate_b9_preflight(b9_pre(session='e'*16),
                expected_head=HEAD,expected_session=SESSION,now=NOW)
    def test_31_preflight_traffic_open(self):
        with self.assertRaisesRegex(m.Stop,'B9_PREFLIGHT_UNSAFE'):
            m.validate_b9_preflight(b9_pre(traffic_opened=True),
                expected_head=HEAD,expected_session=SESSION,now=NOW)
    def test_32_preflight_expiry(self):
        with self.assertRaisesRegex(m.Stop,'B9_TRAFFIC_WINDOW_TOO_SHORT'):
            m.validate_b9_preflight(b9_pre(traffic_permit_until=m.utc(NOW+timedelta(seconds=3))),
                expected_head=HEAD,expected_session=SESSION,now=NOW)
    def test_33_preflight_hash(self):
        with self.assertRaisesRegex(m.Stop,'B9_SIGNED_EVIDENCE_MISSING'):
            m.validate_b9_preflight(b9_pre(traffic_grant_sha256='garbage'),
                expected_head=HEAD,expected_session=SESSION,now=NOW)
    def test_34_receipt_valid(self):
        self.assertEqual(m.validate_b9_receipt(b9_receipt(),head=HEAD,
               session=SESSION)['result'],'FTP_GUEST_CANDIDATE_ONLY')
    def test_35_receipt_deny_false(self):
        with self.assertRaisesRegex(m.Stop,'B9_DENY_RESTORATION_OR_RESULT_UNVERIFIED'):
            m.validate_b9_receipt(b9_receipt(denies_restored_and_verified=False),
                head=HEAD,session=SESSION)
    def test_36_receipt_no_go(self):
        with self.assertRaisesRegex(m.Stop,'B9_DENY_RESTORATION_OR_RESULT_UNVERIFIED'):
            m.validate_b9_receipt(b9_receipt(result='NO_GO_ATTEMPT_CONSUMED'),
                head=HEAD,session=SESSION)
    def test_37_receipt_forged_independent_result(self):
        with self.assertRaisesRegex(m.Stop,'B9_RECEIPT_AUTHORITY_INVALID'):
            m.validate_b9_receipt(b9_receipt(p8='GO'),head=HEAD,session=SESSION)
    def test_38_exact_argv(self):
        self.assertEqual(m.agent_command('--inspect-root'),(
           '/usr/bin/sudo','-n','--','/usr/bin/python3','-I','-B',m.AGENT,'--inspect-root'))
    def test_39_forbid_arbitrary_argv(self):
        with self.assertRaisesRegex(m.Stop,'UNSUPPORTED_B9_ACTION'):
            m.agent_command('--restore-deny')
    def test_40_no_actual_agent_present(self):
        if not Path(m.AGENT).exists():
            with self.assertRaisesRegex(m.Stop,'B9_ROOT_EXECUTOR_ABSENT'):
                m.root_call('--inspect-root',timeout=20)

class R161SessionTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid()==0:self.skipTest('nonroot runtime only')
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)/'one'
        self.folder.mkdir(mode=0o700)
        self.now=NOW
        self.consent=m.canon(m.consent_document(head=HEAD,tree=TREE,boot_id=BOOT,
            operator_uid=os.geteuid(),session=SESSION,now=NOW))
        self.calls=[]

    def runner(self,cmd,seconds):
        self.calls.append((cmd,seconds))
        if cmd[-1]=='--inspect-root':return FakeProcess(out=b9_pre())
        return FakeProcess(out=b9_receipt())

    def operate(self,confirmation=m.MAGIC_CONFIRM,runner=None):
        return m.run_session(folder=self.folder,consent_raw=self.consent,
            head=HEAD,tree=TREE,boot_id=BOOT,operator_uid=os.geteuid(),
            now=NOW,confirmation=confirmation,
            runner=self.runner if runner is None else runner)

    def test_41_execute_once_with_readback(self):
        x=self.operate()
        self.assertEqual(x['result'],'B9_REPORTED_CANDIDATE_WITH_DENY_RESTORED')
        self.assertEqual(len(self.calls),2)
        self.assertEqual(m.parse(m.private_read(self.folder/('receipt-'+SESSION+'.json'))),x)

    def test_42_attempt_journal(self):
        self.operate();intent=m.parse(m.private_read(self.folder/('attempt-'+SESSION+'.json')))
        self.assertIs(intent['independent_authority'],False)
        self.assertEqual(intent['root_grant_sha256'],HASH)

    def test_43_refuse_replay(self):
        self.operate()
        with self.assertRaisesRegex(m.Stop,'ONE_SHOT_ALREADY_EXISTS'):self.operate()
        self.assertEqual(len(self.calls),3) # preflight of second attempt, no second pilot

    def test_44_consent_required(self):
        with self.assertRaisesRegex(m.Stop,'PHYSICAL_OPERATOR_CONFIRMATION_REQUIRED'):
            self.operate(confirmation='wrong')
        self.assertFalse(self.calls)

    def test_45_preflight_denies(self):
        def deny(cmd,seconds):
            self.calls.append((cmd,seconds))
            return FakeProcess(rc=23,err=b'NO-GO')
        with self.assertRaisesRegex(m.Stop,'B9_ROOT_PREFLIGHT_REFUSED'):
            self.operate(runner=deny)
        self.assertFalse(list(self.folder.iterdir()))

    def test_46_b9_denies_after_preflight(self):
        def denied(cmd,seconds):
            self.calls.append((cmd,seconds))
            return FakeProcess(out=b9_pre()) if len(self.calls)==1 else FakeProcess(rc=23)
        x=self.operate(runner=denied)
        self.assertEqual(x['result'],'B9_DENIED_OR_UNKNOWN_MANUAL_DENY_REVIEW')
        self.assertTrue((self.folder/('attempt-'+SESSION+'.json')).exists())

    def test_47_b9_bad_receipt_cannot_pass(self):
        def malformed(cmd,seconds):
            self.calls.append((cmd,seconds))
            return FakeProcess(out=b9_pre()) if len(self.calls)==1 else FakeProcess(out=b'{}\n')
        x=self.operate(runner=malformed)
        self.assertEqual(x['result'],'B9_DENIED_OR_UNKNOWN_MANUAL_DENY_REVIEW')

    def test_48_timeout_manual_deny_review(self):
        def timeout(cmd,seconds):
            self.calls.append((cmd,seconds))
            if len(self.calls)==1:return FakeProcess(out=b9_pre())
            raise subprocess.TimeoutExpired(cmd,timeout=seconds)
        x=self.operate(runner=timeout)
        self.assertEqual(x['result'],'B9_EXECUTION_UNKNOWN_MANUAL_DENY_REVIEW')

    def test_49_private_directory_enforced(self):
        self.folder.chmod(0o755)
        with self.assertRaisesRegex(m.Stop,'PRIVATE_DIRECTORY_INVALID'):self.operate()

    def test_50_receipt_symlink_denied(self):
        (self.folder/('attempt-'+SESSION+'.json')).symlink_to('/tmp/x')
        with self.assertRaisesRegex(m.Stop,'ONE_SHOT_ALREADY_EXISTS'):self.operate()

    def test_51_one_time_fresh(self):
        self.operate()
        self.assertTrue((self.folder/('receipt-'+SESSION+'.json')).exists())

    def test_52_bad_consent(self):
        raw=self.consent.replace(b'SELF_ATTESTED_DEVELOPMENT',b'INDEPENDENT_APPROVED')
        with self.assertRaises(m.Stop):
            m.run_session(folder=self.folder,consent_raw=raw,head=HEAD,
              tree=TREE,boot_id=BOOT,operator_uid=os.geteuid(),now=NOW,
              confirmation=m.MAGIC_CONFIRM,runner=self.runner)

    def test_53_permission_files(self):
        self.operate()
        for p in self.folder.iterdir():self.assertEqual(p.stat().st_mode&0o777,0o600)

    def test_54_read_symlink(self):
        path=self.folder/'consent.json';path.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(m.Stop,'FILE_PATH_INVALID'):m.private_read(path)

    def test_55_read_hardlink(self):
        path=self.folder/'consent.json';m.private_create(path,self.consent)
        os.link(path,self.folder/'link')
        with self.assertRaisesRegex(m.Stop,'PRIVATE_FILE_INVALID'):m.private_read(path)

    def test_56_no_pilot_if_short_traffic_window(self):
        def short(cmd,seconds):
            self.calls.append((cmd,seconds))
            return FakeProcess(out=b9_pre(traffic_permit_until=m.utc(NOW+timedelta(seconds=2))))
        with self.assertRaisesRegex(m.Stop,'B9_TRAFFIC_WINDOW_TOO_SHORT'):
            self.operate(runner=short)
        self.assertEqual(len(self.calls),1)

if __name__=='__main__':unittest.main()
