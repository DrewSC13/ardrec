"""R42.3 unit tests: no host, libvirt, sudo, or packets."""
from __future__ import annotations
import base64
import copy
import tempfile
from pathlib import Path
import unittest
from unittest import mock
from ardrec.coordination import r423_guest_path_inventory as r423
from ardrec.coordination import r41_ssh_resume as r41

ROUTE=b'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\nens3 001ECB0A 00000000 0001 0 0 0 F0FFFFFF 0 0 0\n'
ARP=b'IP address       HW type     Flags       HW address            Mask     Device\n'

def vals(route=ROUTE,arp=ARP,tx=b'10\n',rx=b'20\n'):
    return [{'path':p,'pid':i+5,'raw':data,'sha256':r41.sha(data)} for i,(p,data)
             in enumerate(zip(r423.READ_PATHS,(route,arp,tx,rx)))]

def source():
    return {'r422_report_sha256':r423.R422_PIN,'r422_file_sha256':'a'*64,
            'r421_report_sha256':'b'*64}

def host_state():
    return {'phase':'SSH_RUNNING'}

class R423Tests(unittest.TestCase):
    def test_fixed_allowlist_only(self):
        for p in r423.READ_PATHS:
            self.assertTrue(r423.exact_request(r423.cat_request(p)))
        for p in ('/etc/shadow','/bin/sh','/proc/sys/net/ipv4/ip_forward'):
            with self.assertRaises(r423.R423Error):r423.cat_request(p)

    def test_non_cat_guest_exec_rejected(self):
        self.assertFalse(r423.exact_request({'execute':'guest-exec','arguments':{
            'path':'/usr/bin/ping','arg':['-c','1'],'capture-output':True}}))

    def test_shell_argument_injection_rejected(self):
        req=r423.cat_request(r423.READ_PATHS[0]);req['arguments']['arg'].append('/etc/shadow')
        self.assertFalse(r423.exact_request(req))

    def test_invalid_status_pid_rejected(self):
        for pid in (0,-1,True,2**31,'5'):
            self.assertFalse(r423.exact_request({'execute':'guest-exec-status','arguments':{'pid':pid}}))

    def test_good_status_pid_allowed(self):
        self.assertTrue(r423.exact_request({'execute':'guest-exec-status','arguments':{'pid':55}}))

    def test_good_decode(self):
        b=base64.b64encode(ROUTE).decode()
        self.assertEqual(r423.decode_status({'exited':True,'exitcode':0,'out-data':b}),ROUTE)

    def test_pending_decode(self):
        self.assertIsNone(r423.decode_status({'exited':False}))

    def test_failed_exit_rejected(self):
        with self.assertRaises(r423.R423Error):
            r423.decode_status({'exited':True,'exitcode':1})

    def test_truncated_output_rejected(self):
        with self.assertRaises(r423.R423Error):
            r423.decode_status({'exited':True,'exitcode':0,'out-truncated':True})

    def test_bad_base64_rejected(self):
        with self.assertRaises(r423.R423Error):
            r423.decode_status({'exited':True,'exitcode':0,'out-data':'!!!'})

    def test_stderr_rejected(self):
        with self.assertRaises(r423.R423Error):
            r423.decode_status({'exited':True,'exitcode':0,
                                 'err-data':base64.b64encode(b'error').decode()})

    def test_route_direct(self):
        self.assertEqual(r423.analyze_route(ROUTE),'DIRECT_ENS3_EXPECTED')

    def test_route_missing(self):
        self.assertEqual(r423.analyze_route(ROUTE.splitlines()[0]+b'\n'),'NO_EXPECTED_DIRECT_ROUTE')

    def test_route_unexpected_interface(self):
        self.assertEqual(r423.analyze_route(ROUTE.replace(b'ens3',b'eth0')),
                         'ROUTE_PRESENT_BUT_UNEXPECTED')

    def test_route_unexpected_gateway(self):
        self.assertEqual(r423.analyze_route(ROUTE.replace(b'00000000',b'01000000')),
                         'ROUTE_PRESENT_BUT_UNEXPECTED')

    def test_route_bad_format(self):
        with self.assertRaises(r423.R423Error):r423.analyze_route(b'bad\n')

    def test_route_bad_mask(self):
        self.assertEqual(r423.analyze_route(ROUTE.replace(b'F0FFFFFF',b'00FFFFFF')),
                         'NO_EXPECTED_DIRECT_ROUTE')

    def test_arp_absent(self):
        self.assertEqual(r423.analyze_arp(ARP),'ABSENT')

    def test_arp_incomplete(self):
        self.assertEqual(r423.analyze_arp(ARP+b'10.203.30.1 0x1 0x0 00:00:00:00:00:00 * ens3\n'),
                         'INCOMPLETE')

    def test_arp_resolved(self):
        self.assertEqual(r423.analyze_arp(ARP+b'10.203.30.1 0x1 0x2 52:54:00:ff:ff:ff * ens3\n'),
                         'RESOLVED')

    def test_arp_duplicate_rejected(self):
        row=b'10.203.30.1 0x1 0x0 00:00:00:00:00:00 * ens3\n'
        with self.assertRaises(r423.R423Error):r423.analyze_arp(ARP+row+row)

    def test_counter_bounds(self):
        self.assertEqual(r423.parse_stat(b'0\n'),0)
        self.assertEqual(r423.parse_stat(str(2**64-1).encode()+b'\n'),2**64-1)
        for val in (b'-1\n',b'5 6\n',b'18446744073709551616\n'):
            with self.assertRaises(r423.R423Error):r423.parse_stat(val)

    def test_make_report_and_verify(self):
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            doc=r423.make_report(source(),host_state(),host_state(),vals(),r41.now_utc())
            self.assertEqual(doc['status'],r423.STATUS_DIRECT)
            self.assertTrue(r423.verify_report(doc))

    def test_route_unexpected_review(self):
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            doc=r423.make_report(source(),host_state(),host_state(),
                vals(route=ROUTE.replace(b'ens3',b'eth0')),r41.now_utc())
            self.assertEqual(doc['status'],r423.STATUS_REVIEW)

    def test_source_pin_rejected(self):
        src=source();src['r422_report_sha256']='f'*64
        with self.assertRaises(r423.R423Error):
            r423.make_report(src,host_state(),host_state(),vals(),r41.now_utc())

    def test_modified_read_hash_rejected(self):
        rows=vals();rows[1]['sha256']='f'*64
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            with self.assertRaises(r423.R423Error):
                r423.make_report(source(),host_state(),host_state(),rows,r41.now_utc())

    def test_host_drift_rejected(self):
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            with self.assertRaises(r423.R423Error):
                r423.make_report(source(),host_state(),{'phase':'OTHER'},vals(),r41.now_utc())

    def test_falsified_authority_rejected(self):
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            doc=r423.make_report(source(),host_state(),host_state(),vals(),r41.now_utc())
            for key in ('isolation_proven','test_packets_injected','operational_dispatch'):
                mutant=copy.deepcopy(doc);mutant[key]=True
                mutant['sha256']=r41.sha(r41.canon({k:v for k,v in mutant.items() if k!='sha256'}))
                with self.assertRaises(r423.R423Error):r423.verify_report(mutant)

    def test_falsified_sha_rejected(self):
        with mock.patch.object(r423.r422.r411,'_validate_running'):
            doc=r423.make_report(source(),host_state(),host_state(),vals(),r41.now_utc())
            doc['guest_tx_packets_snapshot']=30
            with self.assertRaises(r423.R423Error):r423.verify_report(doc)

    def test_preflight_never_contacts_qga(self):
        host=mock.Mock()
        host.qga.side_effect=AssertionError('QGA must not be contacted')
        with mock.patch.object(r423,'load_source',return_value=source()),\
             mock.patch.object(r423.r422,'preflight',return_value={
                'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
                'host_readback':host_state()}):
            out=r423.perform(r422_dir=Path('/a'),r421_dir=Path('/a'),r420_dir=Path('/a'),
                r411_dir=Path('/a'),r41_dir=Path('/a'),r40_dir=Path('/a'),
                r39_dir=Path('/a'),pre_dir=Path('/a'),boot_dir=Path('/a'),
                receipt_dir=Path('/unused'),preflight_only=True,host=host)
            self.assertEqual(out['p8_operational'],'NO-GO')
        host.qga.assert_not_called()

    def test_no_authorization_blocks_before_qga(self):
        host=mock.Mock()
        with mock.patch.object(r423,'load_source',return_value=source()),\
             mock.patch.object(r423.r422,'preflight',return_value={
                'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
                'host_readback':host_state()}):
            with self.assertRaises(r423.R423Error):
                r423.perform(r422_dir=Path('/a'),r421_dir=Path('/a'),r420_dir=Path('/a'),
                r411_dir=Path('/a'),r41_dir=Path('/a'),r40_dir=Path('/a'),
                r39_dir=Path('/a'),pre_dir=Path('/a'),boot_dir=Path('/a'),
                receipt_dir=Path('/unused'),host=host)
        host.qga.assert_not_called()

    def test_read_only_command_and_pid(self):
        out=b'5\n'; data=base64.b64encode(out).decode()
        class FakeHost:
            def __init__(self):self.calls=[]
            def qga(self,request):
                self.calls.append(request)
                if request['execute']=='guest-exec':return {'pid':12}
                return {'exited':True,'exitcode':0,'out-data':data}
        host=FakeHost()
        result=r423.read_guest_file(host,r423.READ_PATHS[2])
        self.assertEqual(result['raw'],out)
        self.assertEqual([x['execute'] for x in host.calls],['guest-exec','guest-exec-status'])

    def test_intent_created_before_guest_reads(self):
        with tempfile.TemporaryDirectory() as td:
            parent=Path(td);parent.chmod(0o700)
            receipt=parent/'receipt'
            h=mock.Mock()
            def qga(req):
                self.assertTrue((receipt/r423.INTENT).exists())
                if req==r423.r421.GUEST_PING:return {}
                if req==r423.r421.GUEST_INTERFACES:return []
                raise AssertionError('No other QGA requests expected')
            h.qga.side_effect=qga
            with mock.patch.object(r423,'load_source',return_value=source()),\
                 mock.patch.object(r423.r422,'preflight',return_value={
                    'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
                    'host_readback':host_state()}),\
                 mock.patch.object(r423.r421,'validate_guest_nic',side_effect=ValueError('test_stop')):
                with self.assertRaises(r423.R423Error):
                    r423.perform(r422_dir=Path('/a'),r421_dir=Path('/a'),r420_dir=Path('/a'),
                        r411_dir=Path('/a'),r41_dir=Path('/a'),r40_dir=Path('/a'),
                        r39_dir=Path('/a'),pre_dir=Path('/a'),boot_dir=Path('/a'),
                        receipt_dir=receipt,host=h,authorized=True)
            self.assertTrue((receipt/r423.INTENT).exists())
            self.assertTrue((receipt/r423.FAILURE).exists())
            self.assertTrue((receipt/'SHA256SUMS').exists())

if __name__=='__main__':unittest.main()
