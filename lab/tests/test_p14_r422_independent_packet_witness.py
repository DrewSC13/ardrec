"""R42.2 isolated safety and parsing tests. No host, QGA or packet access."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from ardrec.coordination import r422_independent_packet_witness as r422
from ardrec.coordination import r421_bounded_negative_probe as r421
from ardrec.coordination import r41_ssh_resume as r41

MAC=bytes.fromhex(r421.PROBE_MAC.replace(':',''))
SOURCE=bytes([10,203,30,2])
TARGET=bytes([10,203,30,1])
MARKER='c3a4b5d6e7f80102'


def eth(typ,data,mac=MAC):
    return b'\xff'*6+mac+struct.pack('!H',typ)+data

def arp():
    return eth(0x0806,b'\x00\x01\x08\x00\x06\x04\x00\x01'+MAC+SOURCE+b'\x00'*6+TARGET)

def ping(marker=MARKER):
    raw=bytes.fromhex(marker)
    icmp=b'\x08\x00\x00\x00\x12\x34\x00\x01'+b'\x00'*16+raw+b'\x00'*32
    ip=bytearray(20)
    ip[0]=0x45; ip[9]=1; ip[12:16]=SOURCE; ip[16:20]=TARGET
    ip[2:4]=struct.pack('!H',20+len(icmp))
    return eth(0x0800,bytes(ip)+icmp)

def pcap(*frames, linktype=1, snaplen=128):
    out=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,snaplen,linktype)
    for f in frames:
        out+=struct.pack('<IIII',100,0,min(len(f),snaplen),len(f))+f[:snaplen]
    return out

def host_state():
    return {'phase':'SSH_RUNNING', **r421._host_known_fields()}

def counters():
    return {k:{'handle':index+10,'packets':0,'bytes':0}
            for index,k in enumerate(r422.r42.EXPECTED_RULES)}

def agent(marker=MARKER,received=0,transmitted=1,exitcode=1):
    return {'guest_nic_confirmed':True,'guest_pid':56,
            'request':r422.marked_command(marker),
            'exit':{'exited':True,'received':received,'transmitted':transmitted,
                    'exitcode':exitcode,'stdout_sha256':'a'*64,
                    'stderr_sha256':'b'*64}}

def report(rawtap=None,rawbridge=None,agent_record=None):
    source={'source_r421_report_sha256':r422.R421_REPORT_PIN,
            'source_r421_file_sha256':'a'*64,
            'source_r420_report_sha256':'b'*64}
    return r422.make_report(source,host_state(),host_state(),counters(),counters(),
        {'tap':rawtap if rawtap is not None else pcap(),
         'bridge':rawbridge if rawbridge is not None else pcap()},
        MARKER,agent_record if agent_record is not None else agent(),r41.now_utc())

def rehash(doc):
    doc['sha256']=r41.sha(r41.canon({k:v for k,v in doc.items() if k!='sha256'}))

class R422Tests(unittest.TestCase):
    def test_empty_pcap_is_valid_zero(self):
        self.assertEqual(r422.pcap_records(pcap(),MARKER)['frames'],0)

    def test_arp_observation(self):
        self.assertEqual(r422.pcap_records(pcap(arp()),MARKER)['matching_arp_requests'],1)

    def test_marked_icmp_observation(self):
        self.assertEqual(r422.pcap_records(pcap(ping()),MARKER)['marked_icmp_echo_requests'],1)

    def test_other_icmp_not_attributed(self):
        self.assertEqual(r422.pcap_records(pcap(ping('0102030405060708')),MARKER)['other_frames'],1)

    def test_wrong_mac_rejected(self):
        with self.assertRaises(r422.R422Error):
            r422.pcap_records(pcap(eth(0x0806,arp()[14:],b'\x02'*6)),MARKER)

    def test_truncated_pcap_rejected(self):
        with self.assertRaises(r422.R422Error):
            r422.pcap_records(pcap(arp())[:-2],MARKER)

    def test_wrong_linktype_rejected(self):
        with self.assertRaises(r422.R422Error):
            r422.pcap_records(pcap(linktype=113),MARKER)

    def test_wrong_snaplen_rejected(self):
        with self.assertRaises(r422.R422Error):
            r422.pcap_records(pcap(snaplen=65535),MARKER)

    def test_too_many_packets_rejected(self):
        with self.assertRaises(r422.R422Error):
            r422.pcap_records(pcap(*([arp()]*13)),MARKER)

    def test_invalid_marker_rejected(self):
        for token in ('', 'ABCDEF0123456789','f'*32,'c'*15):
            with self.assertRaises(r422.R422Error):
                r422.marked_command(token)

    def test_marker_fixed_single_guest_command(self):
        cmd=r422.marked_command(MARKER)
        self.assertEqual(cmd['arguments']['arg'].count('1'),2)
        self.assertEqual(cmd['arguments']['path'],'/usr/bin/ping')
        self.assertIn(MARKER,cmd['arguments']['arg'])
        self.assertEqual(cmd['arguments']['arg'][-1],r421.PROBE_TARGET)

    def test_qga_rejects_other_exec(self):
        h=object.__new__(r422.Host)
        with self.assertRaises(Exception):
            h.qga({'execute':'guest-exec','arguments':{'path':'/bin/sh','arg':[]}})

    def test_status_no_egress(self):
        self.assertEqual(report()['status'],'NO_GUEST_EGRESS_WITNESSED_NO_GO')

    def test_status_tap_only(self):
        self.assertEqual(report(pcap(arp()))['status'],'TAP_ONLY_PACKET_WITNESSED_NO_GO')

    def test_status_bridge_observed(self):
        self.assertEqual(report(pcap(arp()),pcap(arp()))['status'],
                         'BRIDGE_PACKET_WITNESSED_REVIEW_NO_GO')

    def test_status_unexpected_reply(self):
        self.assertEqual(report(pcap(arp()),agent_record=agent(received=1,exitcode=0))['status'],
                         'UNEXPECTED_REPLY_REVIEW_NO_GO')

    def test_status_inconclusive_guest(self):
        self.assertEqual(report(agent_record=agent(transmitted=None,received=None,exitcode=2))['status'],
                         'INCONCLUSIVE_PACKET_WITNESS_NO_GO')

    def test_rehashed_isolation_claim_rejected(self):
        d=report(pcap(arp()))
        d['isolation_proven']=True
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_rehashed_fake_destination_rejected(self):
        d=report()
        d['independent_destination_witness_available']=True
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_rehashed_false_status_rejected(self):
        d=report()
        d['status']='TAP_ONLY_PACKET_WITNESSED_NO_GO'
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_rehashed_counter_delta_rejected(self):
        d=report()
        d['counter_delta_unattributed']['input:iifname']['packets']=1
        rehash(d)
        with self.assertRaises(Exception):r422.verify_report(d)

    def test_source_pin_rejected(self):
        d=report()
        d['source_r421_report_sha256']='a'*64
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_pcap_data_is_sealed_in_receipt(self):
        d=report(pcap(arp()))
        with tempfile.TemporaryDirectory() as root:
            parent=Path(root)
            with mock.patch.object(r41,'_make_dir', wraps=r41._make_dir):
                dest=parent/'witness';r41._make_dir(dest)
                intent=b'{}\n';r41._write_once(dest/r422.INTENT,intent)
                r422.persist(dest,d,{'tap':pcap(arp()),'bridge':pcap()},intent)
                self.assertEqual((dest/r422.CAPTURES['tap']).read_bytes(),pcap(arp()))
                for rel in (r422.RESULT,*r422.CAPTURES.values(),r422.INTENT):
                    self.assertEqual((dest/rel).stat().st_mode & 0o777,0o600)
                self.assertIn(r422.RESULT,(dest/'SHA256SUMS').read_text())

    def test_observers_retain_tty_session_but_get_independent_process_group(self):
        # Simulated producer; never launches real sudo, tcpdump, libvirt or packets.
        import os
        import subprocess
        import sys
        script = ("import sys,struct,time;"
                  "sys.stdout.buffer.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,128,1));"
                  "sys.stdout.buffer.flush();time.sleep(8)")
        launched = []
        def launcher(argv, **opts):
            self.assertEqual(opts.get('process_group'), 0)
            self.assertNotIn('start_new_session', opts)
            self.assertEqual(argv[:4], ['/usr/bin/sudo','-n','--','/usr/bin/timeout'])
            proc = subprocess.Popen([sys.executable,'-B','-c',script], **opts)
            launched.append(proc)
            self.assertEqual(os.getpgid(proc.pid), proc.pid)
            self.assertEqual(os.getsid(proc.pid), os.getsid(0))
            return proc
        observers = r422.Observers('/usr/bin/tcpdump','/usr/bin/sudo',launcher=launcher)
        try:
            observers.start()
            self.assertEqual(set(observers.head), {'tap','bridge'})
            self.assertEqual(len(launched), 2)
        finally:
            observers.abort()
        self.assertTrue(all(proc.poll() is not None for proc in launched))

    def test_pcap_mutation_rejected_before_write(self):
        d=report(pcap(arp()))
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'witness';r41._make_dir(dest)
            r41._write_once(dest/r422.INTENT,b'{}\n')
            with self.assertRaises(r422.R422Error):
                r422.persist(dest,d,{'tap':pcap(),'bridge':pcap()},b'{}\n')
            self.assertFalse((dest/r422.RESULT).exists())

    def test_explicit_authorization_required_before_sources(self):
        with mock.patch.object(r422,'load_source',side_effect=AssertionError('source called')):
            with self.assertRaises(r422.R422Error):
                r422.attempt(r421_dir=Path('/irrelevant'),r420_dir=Path('/irrelevant'),
                    r411_dir=Path('/irrelevant'),r41_dir=Path('/irrelevant'),
                    r40_dir=Path('/irrelevant'),r39_dir=Path('/irrelevant'),
                    pre_dir=Path('/irrelevant'),boot_dir=Path('/irrelevant'),
                    receipt_dir=Path('/irrelevant'),authorized=False)

    def test_preflight_never_calls_guest_agent(self):
        fake={'status':'READY_FOR_SEPARATE_AUTHORIZED_ONE_PACKET_ATTEMPT',
              'host_readback':host_state()}
        with mock.patch.object(r421,'preflight',return_value=fake):
            o=r422.preflight(object(),finder=lambda:'/usr/bin/tcpdump')
        self.assertEqual(o['status'],'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT')
        self.assertFalse(o['guest_agent_contacted'])

    def test_preflight_missing_tcpdump_denied(self):
        fake={'status':'READY_FOR_SEPARATE_AUTHORIZED_ONE_PACKET_ATTEMPT',
              'host_readback':host_state()}
        with mock.patch.object(r421,'preflight',return_value=fake):
            with self.assertRaises(r422.R422Error):
                r422.preflight(object(),finder=lambda:r422.need(False,'tcpdump_unavailable'))

    def test_invalid_capture_scope_rejected(self):
        d=report()
        d['capture_interfaces']['tap']='eth0'
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_false_positive_delivered_witness_rejected(self):
        d=report()
        d['tap_capture_is_proof_of_delivery']=True
        rehash(d)
        with self.assertRaises(r422.R422Error):r422.verify_report(d)

    def test_deny_previous_unmarked_guest_exec(self):
        h=object.__new__(r422.Host)
        with self.assertRaises(r422.R422Error):
            h.qga(r421.GUEST_EXEC)

    def test_receipt_pcap_bytes_and_intent_binding(self):
        d=report(pcap(arp()))
        intent=r422.seal({'schema':r422.INTENT_SCHEMA,'source_main':r422.MAIN_PIN,
            'source_r421_report_sha256':r422.R421_REPORT_PIN,
            'exact_guest_command':r422.marked_command(MARKER),
            'authorized_by_operator_cli':True,'guest_attempt_limit':1,
            'p8_operational':'NO-GO'})
        raw=r41.canon(intent)+b'\n'
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'r422';r41._make_dir(dest)
            r41._write_once(dest/r422.INTENT,raw)
            r422.persist(dest,d,{'tap':pcap(arp()),'bridge':pcap()},raw)
            def files(directory,expected):
                with mock.patch.object(r422,'verified_directory',side_effect=None):
                    return {name:(directory/name).read_bytes() for name in expected}
            with mock.patch.object(r422,'verified_directory',side_effect=files):
                checked=r422.verify_private_receipt(dest)
            self.assertEqual(checked['sha256'],d['sha256'])

    def test_capture_failure_before_guest_exec_is_recorded(self):
        source={'source_r421_report_sha256':r422.R421_REPORT_PIN,
                'source_r421_file_sha256':'a'*64,
                'source_r420_report_sha256':'b'*64}
        class FakeHost:
            def __init__(self):self.commands=[];self.bin={'sudo':'/usr/bin/sudo'}
            def qga(self,command):
                self.commands.append(command)
                if command==r421.GUEST_PING:return {}
                if command==r421.GUEST_INTERFACES:return []
                raise AssertionError('Guest-exec must not occur')
        class BrokenObserver:
            def __init__(self):self.head={};self.jobs={};self.aborted=False
            def start(self):raise r422.R422Error('capture_not_ready')
            def abort(self):self.aborted=True
        host=FakeHost()
        watcher=BrokenObserver()
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(r422,'load_source',return_value=source), \
             mock.patch.object(r422,'preflight',return_value={'host_readback':host_state()}), \
             mock.patch.object(r421,'snapshot',return_value=(host_state(),counters())), \
             mock.patch.object(r421,'validate_guest_nic',return_value=None):
            dest=Path(root)/'probe'
            with self.assertRaises(r422.R422Error):
                r422.attempt(r421_dir=Path('/x'),r420_dir=Path('/x'),
                   r411_dir=Path('/x'),r41_dir=Path('/x'),r40_dir=Path('/x'),
                   r39_dir=Path('/x'),pre_dir=Path('/x'),boot_dir=Path('/x'),
                   receipt_dir=dest,authorized=True,host=host,
                   observer_factory=lambda:watcher)
            self.assertTrue((dest/r422.INTENT).is_file())
            self.assertTrue((dest/r422.FAILURE).is_file())
            self.assertTrue((dest/'SHA256SUMS').is_file())
            self.assertFalse((dest/r422.RESULT).exists())
            self.assertTrue(watcher.aborted)
            self.assertNotIn('guest-exec',[c.get('execute') for c in host.commands])

    def _r421_receipt_source(self, directory, *, absent=(), extra=(), tamper=()):
        """Construct an exact private R42.1 success receipt (no external calls)."""
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
        source = {'r420_report_sha256': 'b'*64,
                  'r420_file_sha256': 'c'*64,
                  'r411_report_sha256': 'd'*64}
        prior = {
            'sha256':r422.R421_REPORT_PIN,
            'status':'BOUNDED_NEGATIVE_PROBE_OBSERVED_NO_GO',
            'source_r420_report_sha256':source['r420_report_sha256'],
            'source_r420_file_sha256':source['r420_file_sha256'],
            'source_r411_report_sha256':source['r411_report_sha256'],
            'isolation_proven':False, 'p8_operational':'NO-GO',
        }
        contents = {
            r421.INTENT: b'{"schema":"ardrec-p14-r421-one-probe-intent-v1"}\n',
            r421.RESULT: r41.canon(prior)+b'\n',
        }
        contents.update({name:b'not-allowed\n' for name in extra})
        contents = {name:raw for name,raw in contents.items() if name not in absent}
        for name,raw in contents.items():
            path=directory/name
            path.write_bytes(raw)
            path.chmod(0o600)
        sums=''.join(r41.sha(raw)+'  '+name+'\n' for name,raw in contents.items())
        (directory/'SHA256SUMS').write_text(sums,encoding='ascii')
        (directory/'SHA256SUMS').chmod(0o600)
        for name in tamper:
            (directory/name).write_bytes(b'changed but digest still original\n')
        return source,contents

    def _read_r421_receipt(self, directory, source):
        with mock.patch.object(r421,'source_chain',return_value=source), \
             mock.patch.object(r421,'verify_report',return_value=True):
            return r422.load_source(directory,*([Path('/unused')]*7))

    def test_complete_r421_receipt_inventory_is_exact_and_accepted(self):
        self.assertEqual(r422.PRIOR_FILES,frozenset({r421.INTENT,r421.RESULT}))
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'prior'
            source,raw=self._r421_receipt_source(dest)
            output=self._read_r421_receipt(dest,source)
            self.assertEqual(output['source_r421_report_sha256'],r422.R421_REPORT_PIN)
            self.assertEqual(output['source_r421_file_sha256'],r41.sha(raw[r421.RESULT]))
            self.assertEqual(output['source_r420_report_sha256'],source['r420_report_sha256'])

    def test_missing_prior_intent_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'prior'
            source,_=self._r421_receipt_source(dest,absent=(r421.INTENT,))
            with self.assertRaisesRegex(Exception,'source_inventory_mismatch'):
                self._read_r421_receipt(dest,source)

    def test_unexpected_prior_file_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'prior'
            source,_=self._r421_receipt_source(dest,extra=('unexpected.json',))
            with self.assertRaisesRegex(Exception,'source_inventory_mismatch'):
                self._read_r421_receipt(dest,source)

    def test_tampered_prior_intent_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'prior'
            source,_=self._r421_receipt_source(dest,tamper=(r421.INTENT,))
            with self.assertRaisesRegex(Exception,'source_digest_mismatch_r421_intent.json'):
                self._read_r421_receipt(dest,source)

    def test_tampered_prior_result_is_denied(self):
        with tempfile.TemporaryDirectory() as root:
            dest=Path(root)/'prior'
            source,_=self._r421_receipt_source(dest,tamper=(r421.RESULT,))
            with self.assertRaisesRegex(Exception,'source_digest_mismatch_r421_negative_probe.json'):
                self._read_r421_receipt(dest,source)

if __name__=='__main__':unittest.main()
