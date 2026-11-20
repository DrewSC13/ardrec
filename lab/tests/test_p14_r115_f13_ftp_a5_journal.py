"""R115-F13 conformance: exclusively fake sockets and private tmpdirs."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as m

HEAD='9a322675e11b706be59658c695cc8167c06c601a'


def intent(**updates):
    values={
        'case_id':'FTP-T01-S01-01','session_id':'TEST_DEV_01',
        'assessment_index':0,'attempt_id':'ATT_R115_F13_ONCE_01',
        'head':HEAD,'contract_sha256':'a'*64,
        'scope_authorization_sha256':'b'*64,'p8_window_sha256':'c'*64,
    }
    values.update(updates)
    return m.make_intent(**values)


class FakeSocket:
    family=socket.AF_INET
    type=socket.SOCK_STREAM
    def __init__(self,parts=(b'220 Service ready\r\n',), *, fail=None):
        self.parts=list(parts)
        self.calls=0
        self.fail=fail
        self.timeout=None
        self.peer=('10.203.31.2',21)
    def getpeername(self):return self.peer
    def settimeout(self,t):self.timeout=t
    def recv(self,size):
        self.calls+=1
        if self.fail: raise self.fail
        if not self.parts:return b''
        part=self.parts.pop(0)
        if len(part)>size:self.parts.insert(0,part[size:])
        return part[:size]


class Clock:
    def __init__(self):self.t=0.0
    def __call__(self):self.t+=.001;return self.t


@unittest.skipIf(os.geteuid()==0,'secure private receipt needs nonroot operator')
class JournalTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)/'journal'
        self.p=f12.DRAFT_BUDGET.copy()
        self.ctx=intent()

    def reserve(self,ctx=None,p=None):
        return m.reserve(ctx or self.ctx,p or self.p,root=self.root)

    def consume(self,folder=None,s=None,guard=None):
        if folder is None:folder=self.reserve()
        if s is None:s=FakeSocket()
        return m.consume_reserved(folder,s,
             current_p8_guard=(lambda:True) if guard is None else guard,
             monotonic=Clock())

    def test_01_capabilities_are_no_go(self):
        c=m.capabilities();self.assertEqual(c['p8'],'NO-GO');self.assertEqual(c['a6'],'ND')
        self.assertFalse(c['opens_sockets']);self.assertFalse(c['issues_authority'])

    def test_02_intent_canonical(self):
        self.assertEqual(m.check_intent(self.ctx),self.ctx)

    def test_03_reject_case_mismatch(self):
        with self.assertRaises(m.Stop):intent(case_id='SMB-T01-S01-01')

    def test_04_reject_invalid_session(self):
        with self.assertRaises(m.Stop):intent(session_id='../../etc')

    def test_05_reject_bad_attempt(self):
        with self.assertRaises(m.Stop):intent(attempt_id='RET_01')

    def test_06_reject_bool_assessment(self):
        with self.assertRaises(m.Stop):intent(assessment_index=False)

    def test_07_reject_sha_of_bad_length(self):
        with self.assertRaises(m.Stop):intent(p8_window_sha256='a')

    def test_08_reject_missing_intent_attribute(self):
        c=intent();c.pop('head');
        with self.assertRaises(m.Stop):m.check_intent(c)

    def test_09_irrevocable_reservation(self):
        f=self.reserve();self.assertEqual(m.inspect(f)['status'],'RESERVED_NO_RETRY')
        self.assertEqual((f/'reservation.json').stat().st_mode&0o777,0o600)
        self.assertEqual(f.stat().st_mode&0o777,0o700)

    def test_10_attempt_id_cannot_reset_budget(self):
        self.reserve()
        with self.assertRaises(FileExistsError):self.reserve(intent(attempt_id='ATT_ALT_02'))

    def test_11_head_cannot_reset_budget(self):
        self.reserve()
        with self.assertRaises(FileExistsError):self.reserve(intent(head='d'*40))

    def test_12_profile_cannot_reset_budget(self):
        self.reserve()
        with self.assertRaises(FileExistsError):self.reserve(p={**self.p,'max_recv_bytes':512})

    def test_13_invalid_budget_no_folder_created(self):
        with self.assertRaises(f12.Stop):self.reserve(p={**self.p,'additional_attempts':1})
        self.assertFalse(self.root.exists())

    def test_14_one_result_validated(self):
        f=self.reserve();sock=FakeSocket();doc=self.consume(f,sock)
        self.assertEqual(sock.calls,1)
        self.assertEqual(doc['status'],'RESULT_CANDIDATE_ONLY')
        self.assertEqual(doc['a6'],'ND')
        self.assertIsNone(doc['a9'])
        self.assertFalse(doc['physical_provenance_attested'])
        self.assertEqual(m.inspect(f),doc)

    def test_15_multiline_and_negative_still_candidate(self):
        f=self.reserve()
        status=self.consume(f,FakeSocket((b'421 Unavailable\r\n',)))
        self.assertEqual(status['status'],'RESULT_CANDIDATE_ONLY')
        t=m._read_json(f,'result.json')
        self.assertFalse(t['audit']['reply_complete_220'])

    def test_16_second_consume_denied_before_socket(self):
        f=self.reserve();self.consume(f)
        s=FakeSocket()
        with self.assertRaisesRegex(m.Stop,'ATTEMPT_ALREADY_SPENT'):self.consume(f,s)
        self.assertEqual(s.calls,0)

    def test_17_guard_rejection_spends_attempt(self):
        f=self.reserve();s=FakeSocket()
        with self.assertRaisesRegex(m.Stop,'A5_CAPTURE_FAILED_NO_RETRY'):
            self.consume(f,s,lambda:False)
        self.assertEqual(s.calls,0)
        self.assertEqual(m.inspect(f)['status'],'FAILED_NO_RETRY')
        with self.assertRaises(m.Stop):self.consume(f,s)

    def test_18_socket_error_spends_attempt(self):
        f=self.reserve();s=FakeSocket(fail=OSError('private detail'))
        # The meter charges failed recv; F10 counts only successful recv.
        # Cross-module reconciliation therefore MUST reject the candidate.
        with self.assertRaises(m.Stop):self.consume(f,s)
        self.assertEqual(m.inspect(f)['status'],'FAILED_NO_RETRY')
        self.assertEqual(s.calls,1)

    def test_19_wrong_peer_spends_attempt(self):
        f=self.reserve();s=FakeSocket();s.peer=('10.203.31.3',21)
        with self.assertRaises(m.Stop):self.consume(f,s)
        self.assertEqual(s.calls,0)
        self.assertEqual(m.inspect(f)['status'],'FAILED_NO_RETRY')

    def test_20_inflight_is_not_retried(self):
        f=self.reserve();r=m._read_json(f,'reservation.json')
        digest=m._save(f,'spent.json',{'schema':m.SCHEMA+'-spent',
              'reservation_sha256':f1.digest(f1.canonical(r)),
              'status':'ATTEMPT_CONSUMED_NO_RETRY','a6':'ND','p8':'NO-GO'})
        m._save(f,'spent.manifest.json',{'schema':m.SCHEMA+'-manifest',
              'file':'spent.json','sha256':digest,'case_key':r['case_key'],
              'p8':'NO-GO'})
        self.assertEqual(m.inspect(f)['status'],'ATTEMPT_CONSUMED_UNRESOLVED')
        with self.assertRaises(m.Stop):self.consume(f)

    def test_21_detect_tampered_raw_in_result(self):
        f=self.reserve();self.consume(f)
        p=f/'result.json';rec=json.loads(p.read_text())
        rec['f10']['raw_b64']='QQ=='
        p.write_bytes(f1.canonical(rec))
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_22_detect_tampered_meter(self):
        f=self.reserve();self.consume(f)
        p=f/'result.json';rec=json.loads(p.read_text())
        rec['meter']['recv_calls']+=1
        p.write_bytes(f1.canonical(rec))
        with self.assertRaises((m.Stop,f12.Stop)):m.inspect(f)

    def test_23_detect_forged_a6(self):
        f=self.reserve();self.consume(f)
        p=f/'result.json';rec=json.loads(p.read_text())
        rec['a6']='VERDADERO';p.write_bytes(f1.canonical(rec))
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_24_detect_forged_a9(self):
        f=self.reserve();self.consume(f)
        p=f/'result.json';rec=json.loads(p.read_text())
        rec['a9']='GEN1';p.write_bytes(f1.canonical(rec))
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_25_detect_extra_file(self):
        f=self.reserve();(f/'unapproved.txt').write_text('x')
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_26_detect_symlink_instead_of_reservation(self):
        f=self.reserve();p=f/'reservation.json';new=f/'original.json'
        p.rename(new);p.symlink_to(new)
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_27_reject_open_directory(self):
        f=self.reserve();f.chmod(0o755)
        with self.assertRaises(m.Stop):m.inspect(f)

    def test_28_reject_root_symlink(self):
        r=Path(self.t.name)/'root-link';r.symlink_to(self.t.name)
        with self.assertRaises(m.Stop):m.reserve(self.ctx,self.p,root=r)

    def test_29_reject_broken_json(self):
        f=self.reserve();p=f/'reservation.json';p.write_bytes(b'{\n')
        with self.assertRaises((m.Stop,f1.Rejected)):m.inspect(f)

    def test_30_cli_capabilities_no_network(self):
        script=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r115_f13_ftp_a5_journal.py'
        p=subprocess.run([sys.executable,str(script),'--capabilities'],
                         capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(json.loads(p.stdout)['opens_sockets'])

    def test_31_cli_replays_candidate(self):
        f=self.reserve();self.consume(f)
        script=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r115_f13_ftp_a5_journal.py'
        p=subprocess.run([sys.executable,str(script),'--inspect-receipt',str(f)],
                         capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'],'RESULT_CANDIDATE_ONLY')

    def test_32_no_ambient_network_api(self):
        self.assertNotIn('connect',m.capabilities())
        with patch('socket.socket',side_effect=AssertionError('socket opened')):
            f=self.reserve();self.assertEqual(m.inspect(f)['p8'],'NO-GO')

if __name__ == '__main__':unittest.main()
