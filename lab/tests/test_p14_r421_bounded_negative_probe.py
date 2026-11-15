"""R42.1: no accidental QGA, exact one-probe scope and fail-closed receipts."""
from __future__ import annotations

import base64
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ardrec.coordination import r421_bounded_negative_probe as r421
from ardrec.coordination import r42_isolation_baseline as r42
from ardrec.coordination import r41_ssh_resume as r41


def live():
    return {'phase':'SSH_RUNNING',**r421._host_known_fields()}


def counters(value=0):
    return {key:{'handle':100+i,'packets':value,'bytes':value*64}
            for i,key in enumerate(r42.EXPECTED_RULES)}


def source():
    return {'r420_report_sha256':r421.R420_PIN,'r420_file_sha256':'a'*64,
            'r411_report_sha256':'b'*64}


def nic():
    return [{'name':'ens3','hardware-address':r421.PROBE_MAC,
             'ip-addresses':[{'ip-address-type':'ipv4',
                              'ip-address':r421.PROBE_SOURCE,'prefix':r421.PROBE_PREFIX}]}]


def status(sent=1,got=0,exitcode=1):
    raw=f'1 packets transmitted, {got} received, 100% packet loss\n' if sent == 1 else \
        f'{sent} packets transmitted, {got} received\n'
    return {'exited':True,'exitcode':exitcode,
            'out-data':base64.b64encode(raw.encode()).decode(),
            'err-data':''}


def evidence(sent=1,got=0):
    return {'guest_nic_confirmed':True,'guest_pid':123,
            'request':r421.GUEST_EXEC,
            'exit':r421.safe_agent_status(status(sent,got))}


def result(sent=1,got=0):
    return r421.report(source(),live(),live(),counters(),counters(1),
                       evidence(sent,got),captured_at_utc=r41.now_utc())


class R421Tests(unittest.TestCase):
    def test_constants_bounded(self):
        self.assertEqual(r421.GUEST_EXEC['arguments']['arg'],
                         ['-n','-I','10.203.30.2','-c','1','-W','1','10.203.30.1'])
        self.assertEqual(r421.MAX_STATUS_CHECKS,8)
        self.assertEqual(r421.PROBE_PREFIX,28)

    def test_nic_good(self):
        self.assertIsNone(r421.validate_guest_nic(nic()))

    def test_nic_mac_mismatch(self):
        bad=nic(); bad[0]['hardware-address']='52:54:00:ad:30:03'
        with self.assertRaises(r421.R421Error):r421.validate_guest_nic(bad)

    def test_nic_ip_mismatch(self):
        bad=nic(); bad[0]['ip-addresses'][0]['ip-address']='10.203.30.3'
        with self.assertRaises(r421.R421Error):r421.validate_guest_nic(bad)

    def test_nic_duplicate_mac_rejected(self):
        with self.assertRaises(r421.R421Error):r421.validate_guest_nic(nic()+nic())

    def test_nic_wrong_prefix(self):
        bad=nic();bad[0]['ip-addresses'][0]['prefix']=16
        with self.assertRaises(r421.R421Error):r421.validate_guest_nic(bad)

    def test_prior_unverified_24_prefix_rejected(self):
        bad=nic();bad[0]['ip-addresses'][0]['prefix']=24
        with self.assertRaisesRegex(r421.R421Error,
                                    'guest_expected_nic_and_ipv4_not_confirmed'):
            r421.validate_guest_nic(bad)

    def test_extra_ipv4_alias_rejected(self):
        bad=nic()
        bad[0]['ip-addresses'].append({'ip-address-type':'ipv4',
                                      'ip-address':'10.203.30.3','prefix':28})
        with self.assertRaises(r421.R421Error):r421.validate_guest_nic(bad)

    def test_agent_status_one_sent_zero_received(self):
        self.assertEqual(r421.safe_agent_status(status())['transmitted'],1)
        self.assertEqual(r421.safe_agent_status(status())['received'],0)

    def test_agent_status_pending(self):
        self.assertEqual(r421.safe_agent_status({'exited':False}),{'exited':False})

    def test_agent_status_over_bound(self):
        with self.assertRaises(r421.R421Error):r421.safe_agent_status(status(2,0))

    def test_agent_status_truncated(self):
        x=status();x['out-truncated']=True
        with self.assertRaises(r421.R421Error):r421.safe_agent_status(x)

    def test_agent_status_invalid_exitcode(self):
        with self.assertRaises(r421.R421Error):r421.safe_agent_status(status(1,0,42))

    def test_agent_status_bad_base64(self):
        x=status();x['out-data']='BAD@@'
        with self.assertRaises(Exception):r421.safe_agent_status(x)

    def test_agent_status_oversized(self):
        x=status();x['out-data']='A'*8193
        with self.assertRaises(r421.R421Error):r421.safe_agent_status(x)

    def test_agent_qga_reject_shell(self):
        h=r421.Host.__new__(r421.Host)
        with self.assertRaises(r421.R421Error):
            h.qga({'execute':'guest-exec','arguments':{'path':'/bin/sh'}})

    def test_agent_qga_reject_extra_ping(self):
        h=r421.Host.__new__(r421.Host)
        with self.assertRaises(r421.R421Error):
            h.qga({'execute':'guest-exec','arguments':{
                **r421.GUEST_EXEC['arguments'],'arg':['-c','100']}})

    def test_report_one_packet_not_isolation(self):
        doc=result()
        self.assertEqual(doc['status'],'BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO')
        self.assertFalse(doc['isolation_proven'])
        self.assertEqual(doc['guest_verified_ipv4_prefix'],28)
        self.assertTrue(r421.verify_report(doc))

    def test_report_unexpected_reply(self):
        self.assertEqual(result(1,1)['status'],'UNEXPECTED_REPLY_REVIEW_NO_GO')

    def test_report_zero_sent(self):
        self.assertEqual(result(0,0)['status'],'INCONCLUSIVE_GUEST_PROBE_NO_GO')

    def test_false_isolation_even_rehashed(self):
        doc=result();doc['isolation_proven']=True;r421.seal(doc)
        with self.assertRaises(r421.R421Error):r421.verify_report(doc)

    def test_false_p8_even_rehashed(self):
        doc=result();doc['p8_operational']='GO';r421.seal(doc)
        with self.assertRaises(r421.R421Error):r421.verify_report(doc)

    def test_false_prefix_even_rehashed(self):
        doc=result();doc['guest_verified_ipv4_prefix']=24;r421.seal(doc)
        with self.assertRaises(r421.R421Error):r421.verify_report(doc)

    def test_tampered_digest_rejected(self):
        doc=result();doc['status']='OTHER'
        with self.assertRaises(r421.R421Error):r421.verify_report(doc)

    def test_false_status_even_rehashed(self):
        doc=result();doc['status']='UNEXPECTED_REPLY_REVIEW_NO_GO';r421.seal(doc)
        with self.assertRaises(r421.R421Error):r421.verify_report(doc)

    def test_counter_reset_rejected(self):
        with self.assertRaises(Exception):
            r421.report(source(),live(),live(),counters(2),counters(1),
                        evidence(),captured_at_utc=r41.now_utc())

    def test_report_source_pin(self):
        wrong=source();wrong['r420_report_sha256']='c'*64
        with self.assertRaises(r421.R421Error):
            r421.report(wrong,live(),live(),counters(),counters(),
                        evidence(),captured_at_utc=r41.now_utc())

    def test_preflight_no_guest_control(self):
        class FakeHost:pass
        with patch.object(r421,'snapshot',side_effect=[(live(),counters()),(live(),counters())]),\
             patch.object(r421.Host,'qga',side_effect=AssertionError('QGA must not be called')):
            out=r421.preflight(FakeHost())
        self.assertFalse(out['guest_agent_contacted'])
        self.assertEqual(out['status'],'READY_FOR_SEPARATE_AUTHORIZED_ONE_PACKET_ATTEMPT')

    def test_preflight_background_activity_denied(self):
        with patch.object(r421,'snapshot',side_effect=[(live(),counters()),(live(),counters(1))]):
            with self.assertRaises(r421.R421Error):r421.preflight(object())

    def test_preflight_host_changed_denied(self):
        other=live();other['active_domains']=[]
        with patch.object(r421,'snapshot',side_effect=[(live(),counters()),(other,counters())]):
            with self.assertRaises(r421.R421Error):r421.preflight(object())

    def test_no_authorization_no_guest(self):
        with patch.object(r421,'source_chain',side_effect=AssertionError('sources')),\
             patch.object(r421.Host,'qga',side_effect=AssertionError('guest')):
            with self.assertRaises(r421.R421Error):
                r421.attempt(r420_dir=Path('/bad'),r411_dir=Path('/bad'),
                             r41_dir=Path('/bad'),r40_dir=Path('/bad'),
                             r39_dir=Path('/bad'),pre_dir=Path('/bad'),
                             boot_dir=Path('/bad'),receipt_dir=Path('/bad'),authorized=False)

    def test_authorized_exact_one_exec_and_receipt(self):
        class Fake:
            def __init__(self):self.sent=[]
            def qga(self,cmd):
                self.sent.append(cmd)
                if cmd==r421.GUEST_PING:return {}
                if cmd==r421.GUEST_INTERFACES:return nic()
                if cmd==r421.GUEST_EXEC:return {'pid':123}
                return status()
        fake=Fake()
        with TemporaryDirectory() as temp:
            parent=Path(temp);parent.chmod(0o700)
            receipt=parent/'receipt'
            with patch.object(r421,'source_chain',return_value=source()),\
                 patch.object(r421,'preflight',return_value={
                     'host_readback':live(),
                     'counter_handles':{k:v['handle'] for k,v in counters().items()}}),\
                 patch.object(r421,'snapshot',side_effect=[
                     (live(),counters()),(live(),counters()),(live(),counters(1))]):
                doc=r421.attempt(r420_dir=parent,r411_dir=parent,r41_dir=parent,
                                 r40_dir=parent,r39_dir=parent,pre_dir=parent,
                                 boot_dir=parent,receipt_dir=receipt,authorized=True,host=fake)
            self.assertEqual(fake.sent.count(r421.GUEST_EXEC),1)
            self.assertEqual(doc['status'],'BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO')
            self.assertTrue((receipt/r421.INTENT).is_file())
            self.assertTrue((receipt/r421.RESULT).is_file())
            self.assertEqual((receipt).stat().st_mode & 0o777,0o700)
            self.assertEqual((receipt/r421.RESULT).stat().st_mode & 0o777,0o600)
            self.assertFalse(doc['isolation_proven'])

    def test_failed_agent_records_intent_and_no_retry(self):
        class Fake:
            def __init__(self):self.called=0
            def qga(self,cmd):
                self.called+=1
                raise RuntimeError('agent_unavailable')
        fake=Fake()
        with TemporaryDirectory() as temp:
            parent=Path(temp);parent.chmod(0o700)
            receipt=parent/'receipt'
            with patch.object(r421,'source_chain',return_value=source()),\
                 patch.object(r421,'preflight',return_value={
                     'host_readback':live(),
                     'counter_handles':{k:v['handle'] for k,v in counters().items()}}),\
                 patch.object(r421,'snapshot',return_value=(live(),counters())):
                with self.assertRaisesRegex(r421.R421Error,'REVIEW_REQUIRED'):
                    r421.attempt(r420_dir=parent,r411_dir=parent,r41_dir=parent,
                                 r40_dir=parent,r39_dir=parent,pre_dir=parent,
                                 boot_dir=parent,receipt_dir=receipt,authorized=True,host=fake)
            self.assertEqual(fake.called,1)
            self.assertTrue((receipt/r421.INTENT).is_file())
            self.assertTrue((receipt/'r421_failure.json').is_file())
            self.assertFalse((receipt/r421.RESULT).exists())

    def test_public_parent_rejected(self):
        with TemporaryDirectory() as tmp:
            folder=Path(tmp)/'public';folder.mkdir();folder.chmod(0o755)
            with self.assertRaises(Exception):r41._make_dir(folder/'receipt')


if __name__ == '__main__':unittest.main()
