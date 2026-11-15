"""R46: exact read-only host evidence, strict drift rejection, private receipts."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

from ardrec.coordination import r46_ssh_transition_audit as r46

NFT = b'''table bridge ardrec_r34_guard { # handle 12
  chain input { # handle 1
    type filter hook input priority filter; policy accept;
    iifname { "a33d30r", "a33d30t", "a33d31r", "a33d31t", "a33d32r", "a33d32t" } counter packets 0 bytes 0 drop # handle 5
  }
  chain output { # handle 2
    type filter hook output priority filter; policy accept;
    oifname { "a33d30r", "a33d30t", "a33d31r", "a33d31t", "a33d32r", "a33d32t" } counter packets 0 bytes 0 drop # handle 7
  }
  chain forward { # handle 3
    type filter hook forward priority filter; policy accept;
    iifname { "a33d30r", "a33d30t", "a33d31r", "a33d31t", "a33d32r", "a33d32t" } counter packets 0 bytes 0 drop # handle 9
    oifname { "a33d30r", "a33d30t", "a33d31r", "a33d31t", "a33d32r", "a33d32t" } counter packets 0 bytes 0 drop # handle 11
  }
}
'''


def sample() -> dict[str, bytes]:
    xml = r46.r33.render_xml(r46.r33.R32_RECEIPT_FILE_SHA256)
    return {
      'ssh-inactive.xml': xml['domain-ssh.xml'],
      'runner-inactive.xml': xml['domain-runner.xml'],
      'r33-deny-nwfilter.xml': r46.r34.deny_filter_xml(),
      'r34-bridge-deny.txt': NFT,
      'nwfilter-list.txt': b'UUID Name\n' + r46.OLD_FILTER.encode() + b'\n',
      'bridge-ipv4.txt': b'',
      'vm-states.json': r46.canon(r46.EXPECTED_RESTORE_STATE) + b'\n',
    }


def xml_mutate(raw: bytes, path: str, key: str, value: str) -> bytes:
    doc=ET.fromstring(raw)
    target=doc.find(path)
    assert target is not None
    target.set(key,value)
    return ET.tostring(doc)


class R46AuditTests(unittest.TestCase):
    def setUp(self):
        self.sample=sample()
        self.patched=mock.patch.object(r46.r45, 'verify_directory',
                                       return_value={'sha256':r46.R45_REPORT_PIN,'p8_operational':'NO-GO'})
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def audit(self, snapshot=None):
        return r46.verify_live_observation(snapshot or self.sample, Path('/not-touched'))

    def test_complete_readonly_audit(self):
        report=self.audit()
        self.assertEqual(report['p8_operational'],'NO-GO')
        self.assertFalse(report['operational_dispatch'])
        self.assertFalse(report['host_mutations'])
        self.assertFalse(report['rollback_tested'])
        self.assertEqual(report['domain_states'], {'ssh':'RUNNING','runner':'SHUTOFF'})
        self.assertEqual(len(report['observed_runner']['nics']),3)
        self.assertEqual(len(report['snapshot_files']),7)

    def test_expected_exact_ssh_identity(self):
        v=r46.verify_domain(self.sample['ssh-inactive.xml'],'ssh')
        self.assertEqual(v['nics'][0]['tap'],'a33d30t')
        self.assertEqual(v['nics'][0]['filter'],r46.OLD_FILTER)

    def test_runner_3_interfaces(self):
        v=r46.verify_domain(self.sample['runner-inactive.xml'],'runner')
        self.assertEqual(len(v['nics']),3)

    def test_changed_mac_blocks(self):
        d=deepcopy(self.sample)
        d['ssh-inactive.xml']=xml_mutate(d['ssh-inactive.xml'],'./devices/interface/mac','address','ff:ff:ff:ff:ff:ff')
        with self.assertRaisesRegex(r46.R46AuditError,'domain_nic_or_filter_drift'):self.audit(d)

    def test_changed_filter_blocks(self):
        d=deepcopy(self.sample)
        d['ssh-inactive.xml']=xml_mutate(d['ssh-inactive.xml'],'./devices/interface/filterref','filter','other')
        with self.assertRaisesRegex(r46.R46AuditError,'domain_nic_or_filter_drift'):self.audit(d)

    def test_removed_runner_nic_blocks(self):
        d=deepcopy(self.sample)
        doc=ET.fromstring(d['runner-inactive.xml'])
        devices=doc.find('./devices'); interfaces=doc.findall('./devices/interface')
        devices.remove(interfaces[-1])
        d['runner-inactive.xml']=ET.tostring(doc)
        with self.assertRaisesRegex(r46.R46AuditError,'domain_nic_count_drift'):self.audit(d)

    def test_changed_disk_blocks(self):
        d=deepcopy(self.sample)
        d['runner-inactive.xml']=xml_mutate(d['runner-inactive.xml'],'./devices/disk/source','file','/tmp/other.qcow2')
        with self.assertRaisesRegex(r46.R46AuditError,'domain_disk_drift'):self.audit(d)

    def test_added_hostdev_blocks(self):
        d=deepcopy(self.sample)
        root=ET.fromstring(d['ssh-inactive.xml']); ET.SubElement(root.find('./devices'),'hostdev')
        d['ssh-inactive.xml']=ET.tostring(root)
        with self.assertRaisesRegex(r46.R46AuditError,'unapproved_device'):self.audit(d)

    def test_widened_nwfilter_blocks(self):
        d=deepcopy(self.sample)
        xml=ET.fromstring(d['r33-deny-nwfilter.xml'])
        xml.find('rule').set('action','accept')
        d['r33-deny-nwfilter.xml']=ET.tostring(xml)
        with self.assertRaisesRegex(r46.R46AuditError,'nwfilter_not_deny_all'):self.audit(d)

    def test_nft_guard_exact_counters_irrelevant(self):
        r46.verify_nft_guard(NFT)
        r46.verify_nft_guard(NFT.replace(b'packets 0 bytes 0',b'packets 1 bytes 48'))

    def test_nft_reject_accept_or_missing_drop(self):
        with self.assertRaises(r46.R46AuditError):r46.verify_nft_guard(NFT.replace(b'drop # handle 9',b'accept # handle 9'))
        with self.assertRaises(r46.R46AuditError):r46.verify_nft_guard(NFT.replace(b'a33d32t',b'outside0'))

    def test_nft_reject_extra_rule(self):
        changed=NFT.replace(b'  chain output',b'    counter drop\n  chain output')
        with self.assertRaises(r46.R46AuditError):r46.verify_nft_guard(changed)

    def test_filters_must_not_be_installed(self):
        d=deepcopy(self.sample)
        d['nwfilter-list.txt']+=r46.r45.FILTER_SSH.encode()+b'\n'
        with self.assertRaisesRegex(r46.R46AuditError,'candidate_filter_already_defined'):self.audit(d)

    def test_bridge_ipv4_forbidden(self):
        d=deepcopy(self.sample)
        d['bridge-ipv4.txt']=b'8: br33d30 inet 10.203.30.1/28\n'
        with self.assertRaisesRegex(r46.R46AuditError,'bridge_has_ipv4_address'):self.audit(d)

    def test_state_gates_english_and_spanish(self):
        self.assertEqual(r46.normalize_state(b'ejecutando\n','ssh'),'RUNNING')
        self.assertEqual(r46.normalize_state(b'running\n','ssh'),'RUNNING')
        self.assertEqual(r46.normalize_state(b'apagado\n','runner'),'SHUTOFF')
        self.assertEqual(r46.normalize_state(b'shut off\n','runner'),'SHUTOFF')
        with self.assertRaises(r46.R46AuditError):r46.normalize_state(b'paused\n','ssh')

    def test_r45_report_pin(self):
        with mock.patch.object(r46.r45,'verify_directory',return_value={'sha256':'0'*64,'p8_operational':'NO-GO'}):
            with self.assertRaisesRegex(r46.R46AuditError,'r45_source_receipt_mismatch'):self.audit()

    def test_limited_host_command_allowlist(self):
        invocations=[]
        def runner(argv, **kwargs):
            invocations.append(argv)
            self.assertNotIn('shell',kwargs)
            self.assertIn('--readonly', ' '.join(argv) if 'virsh' in ' '.join(argv) else '--readonly')
            if 'domstate' in argv:
                return SimpleNamespace(returncode=0, stdout=(b'running\n' if argv[-1]==r46.SSH_DOMAIN else b'shut off\n'),stderr=b'')
            if 'dumpxml' in argv:
                key='ssh-inactive.xml' if argv[-1]==r46.SSH_DOMAIN else 'runner-inactive.xml'
            elif 'nwfilter-dumpxml' in argv:key='r33-deny-nwfilter.xml'
            elif 'nwfilter-list' in argv:key='nwfilter-list.txt'
            elif any(Path(part).name == 'nft' for part in argv):key='r34-bridge-deny.txt'
            else:key='bridge-ipv4.txt'
            return SimpleNamespace(returncode=0,stdout=self.sample[key],stderr=b'')
        with mock.patch.object(r46,'_which',side_effect=lambda n,a:{'sudo':'/usr/bin/sudo','virsh':'/usr/bin/virsh','nft':'/usr/sbin/nft','ip':'/usr/bin/ip'}[n]):
            out=r46.capture_host(runner)
        self.assertEqual(out,self.sample)
        self.assertEqual(len(invocations),8)
        self.assertTrue(all(not {'start','define','destroy','attach-interface','detach-interface','-f'}.intersection(cmd) for cmd in invocations))

    def test_private_immutable_receipt_and_reverification(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            dest=root/'r46-ssh-audit-20261115T030000Z-5663'
            with mock.patch.object(r46,'capture_host',return_value=self.sample):
                report=r46.prepare_receipt(dest,Path('/fake'))
            self.assertEqual(report,r46.verify_receipt(dest,Path('/fake')))
            self.assertEqual(len(list(dest.iterdir())),9)
            self.assertEqual((dest/r46.SUMS).stat().st_mode & 0o777,0o600)
            with mock.patch.object(r46,'capture_host',side_effect=AssertionError('verify must not access host')):
                self.assertEqual(r46.verify_receipt(dest,Path('/fake'))['p8_operational'],'NO-GO')
            with self.assertRaisesRegex(r46.R46AuditError,'receipt_already_exists'):
                r46.prepare_receipt(dest,Path('/fake'))
            (dest/'ssh-inactive.xml').write_bytes(b'bad')
            with self.assertRaises(r46.R46AuditError):r46.verify_receipt(dest,Path('/fake'))

    def test_no_receipt_after_host_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            path=root/'r46-ssh-audit-20261115T030000Z-5663'
            changed=deepcopy(self.sample)
            changed['bridge-ipv4.txt']=b'bridge has ip'
            with mock.patch.object(r46,'capture_host',return_value=changed):
                with self.assertRaises(r46.R46AuditError):r46.prepare_receipt(path,Path('/fake'))
            self.assertFalse(path.exists())

    def test_insecure_parent_blocks_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o755)
            try:
                with self.assertRaisesRegex(r46.R46AuditError,'private_parent_required'):
                    r46.prepare_receipt(root/'r46-ssh-audit-20261115T030000Z-5663',Path('/fake'))
            finally:root.chmod(0o700)

    def test_no_risk_claims(self):
        report=self.audit()
        self.assertIsNone(report['final_risk'])
        self.assertIsNone(report['published_generation'])
        self.assertFalse(report['positive_control_verified'])
        self.assertFalse(report['isolation_proven'])
        self.assertEqual(report['real_pentesting'],'NOT_EXECUTED')

if __name__=='__main__': unittest.main()
