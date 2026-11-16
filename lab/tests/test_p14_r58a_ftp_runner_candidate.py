"""Offline adversarial tests for the additive-only runner FTP NIC candidate."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r58a_ftp_runner_candidate.py'
SPEC = importlib.util.spec_from_file_location('r58a_ftp_candidate',SCRIPT)
module=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
m=module


def runner(*, ssh_mac='52:54:00:ad:30:01', ftp=False, smb=False,
           filter=m.FILTER, extra='', name=m.DOMAIN, badssh=False) -> bytes:
    old=f'''    <interface type='network'>
      <mac address='{ssh_mac}'/>
      <source network='ardrec-r33-dev-net-ssh'/>
      <target dev='a33d30r'/>
      <model type='virtio'/>
      <filterref filter='{filter}'/>
    </interface>'''
    more=''
    if ftp:
        more=f'''\n    <interface type='network'>
      <mac address='{m.MAC}'/>
      <source network='{m.NET}'/>
      <target dev='{m.TAP}'/>
      <model type='virtio'/>
      <filterref filter='{m.FILTER}'/>
    </interface>'''
    if smb:
        more='''\n    <interface type='network'>
      <mac address='52:54:00:ad:32:01'/>
      <source network='ardrec-r33-dev-net-smb'/>
      <target dev='a33d32r'/>
      <model type='virtio'/>
      <filterref filter='ardrec-r33-block-until-containment'/>
    </interface>'''
    if badssh:
        old=old.replace("<target dev='a33d30r'/>","<target dev='wrong'/>")
    return f'''<domain type='kvm'>
  <name>{name}</name>
  <memory unit='MiB'>3072</memory>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'><source file='/tmp/TEST-ONLY.qcow2'/></disk>
{old}{more}
    <serial type='pty'/>
    {extra}
  </devices>
</domain>
'''.encode()


def valid_report():
    return {'result':'BLOCKED_FTP_RUNNER_NIC_MISSING',
            'four_dev_domains_off':True,
            'ftp_network_inactive':True,
            'nft_r34':'DENY_STRUCTURE_MATCHED_FOUR_SCOPED_DROPS',
            'nwfilter_r34':'DROP_ALL_DEFINITION_MATCHED',
            'ftp_nic':{'runner_ftp':'MISSING_IN_INACTIVE_XML','runner_ssh':'MATCHED'},
            'source_git_head':m.SOURCE_HEAD,
            'observed_git_head':m.SOURCE_HEAD}


class TestAdditiveCandidate(unittest.TestCase):
    def test_candidate_is_single_addition(self):
        raw=runner()
        candidate, meta=m.build_candidate(raw)
        self.assertEqual(candidate.count(b"<interface type='network'>"),2)
        self.assertTrue(meta['existing_xml_bytes_preserved'])
        self.assertEqual(meta['original_xml_sha256'],m.sha(raw))
        self.assertEqual(meta['candidate_xml_sha256'],m.sha(candidate))
        self.assertTrue(len(candidate)>len(raw))

    def test_no_model_change(self):
        candidate, _=m.build_candidate(runner())
        nics=ET.fromstring(candidate).findall('devices/interface')
        self.assertEqual(nics[1].find('model').get('type'),'virtio')
        self.assertEqual(nics[1].find('filterref').get('filter'),m.FILTER)

    def test_disk_node_stays_byte_exact(self):
        raw=runner()
        after,_=m.build_candidate(raw)
        source=b"<source file='/tmp/TEST-ONLY.qcow2'/>"
        self.assertEqual(raw.count(source),1)
        self.assertEqual(after.count(source),1)

    def test_source_header_preserved(self):
        raw=runner()
        after,_=m.build_candidate(raw)
        self.assertEqual(after.split(b'\n')[0],raw.split(b'\n')[0])

    def test_one_ssh_interface_only(self):
        with self.assertRaisesRegex(m.GateError,'RUNNER_NOT_SSH_ONLY'):
            m.build_candidate(runner(ftp=True))

    def test_smb_already_present_fails(self):
        with self.assertRaisesRegex(m.GateError,'RUNNER_NOT_SSH_ONLY'):
            m.build_candidate(runner(smb=True))

    def test_ssh_mac_drift(self):
        with self.assertRaisesRegex(m.GateError,'SSH_NIC_IDENTITY_OR_DENY_DRIFT'):
            m.build_candidate(runner(ssh_mac='52:54:00:ff:ff:ff'))

    def test_ssh_filter_drift(self):
        with self.assertRaisesRegex(m.GateError,'SSH_NIC_IDENTITY_OR_DENY_DRIFT'):
            m.build_candidate(runner(filter='OTHER'))

    def test_wrong_ssh_tap(self):
        with self.assertRaisesRegex(m.GateError,'SSH_NIC_IDENTITY_OR_DENY_DRIFT'):
            m.build_candidate(runner(badssh=True))

    def test_wrong_domain(self):
        with self.assertRaisesRegex(m.GateError,'WRONG_RUNNER_DOMAIN'):
            m.build_candidate(runner(name='ardrec-r33-dev-ftp'))

    def test_external_entities_forbidden(self):
        raw=b'<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + runner()
        with self.assertRaisesRegex(m.GateError,'UNSAFE_XML'):
            m.build_candidate(raw)

    def test_comments_forbidden(self):
        with self.assertRaisesRegex(m.GateError,'UNSAFE_XML'):
            m.build_candidate(runner(extra='<!-- TEST ONLY -->'))

    def test_non_utf8_forbidden(self):
        with self.assertRaises(m.GateError):
            m.build_candidate(runner()+b'\xff')

    def test_bad_xml(self):
        with self.assertRaisesRegex(m.GateError,'INVALID_XML'):
            m.build_candidate(b'<domain>')

    def test_anchor_missing(self):
        with self.assertRaisesRegex(m.GateError,'RUNNER_INTERFACE_ANCHOR_NOT_EXACT'):
            m.build_candidate(runner().replace(b'    </interface>',b'    </interface><foo/>'))

    def test_wrong_indent(self):
        with self.assertRaisesRegex(m.GateError,'XML_INDENT_NOT_SAFE'):
            m.build_candidate(runner().replace(b'    </interface>',b'</interface>'))

    def test_unexpected_host_device(self):
        with self.assertRaisesRegex(m.GateError,'RUNNER_UNEXPECTED_HOST_DEVICE_OR_GRAPHICS'):
            m.build_candidate(runner(extra="<hostdev mode='subsystem' type='pci'/>"))

    def test_graphics_forbidden(self):
        with self.assertRaisesRegex(m.GateError,'RUNNER_UNEXPECTED_HOST_DEVICE_OR_GRAPHICS'):
            m.build_candidate(runner(extra="<graphics type='spice'/>"))

    def test_inserted_fields_exact(self):
        a,_=m.build_candidate(runner())
        nic=ET.fromstring(a).findall('devices/interface')[1]
        m.strict_new_ftp_nic(nic)
        nic[1].set('network','untrusted-network')
        with self.assertRaisesRegex(m.GateError,'CANDIDATE_FTP_NIC_NOT_EXACT'):
            m.strict_new_ftp_nic(nic)


class TestReadonlyHostGate(unittest.TestCase):
    def mocked_prior(self, r=None, xml=None):
        prior=Mock()
        prior.read_host.return_value=valid_report() if r is None else r
        prior.run_readonly.return_value=runner() if xml is None else xml
        return prior

    def test_normal_readonly_plan(self):
        p=self.mocked_prior()
        plan=m.plan_from_host(p)
        self.assertEqual(plan['result'],'FTP_RUNNER_XML_CANDIDATE_VERIFIED_IN_MEMORY_ONLY')
        self.assertFalse(plan['libvirt_definition_modified'])
        self.assertFalse(plan['f11_guard_first_execution_attested'])
        self.assertFalse(plan['candidate_xml_written'])
        self.assertEqual(plan['p8'],'NO-GO')
        self.assertEqual(plan['observed_git_head'],m.SOURCE_HEAD)
        self.assertEqual(p.read_host.call_count,2)
        self.assertEqual(p.run_readonly.call_count,2)

    def test_no_ftp_when_readonly_snapshot_bad(self):
        p=self.mocked_prior({'result':'OTHER'})
        with self.assertRaisesRegex(m.GateError,'FIRST_READONLY_GATE_NOT_MATCHED'):
            m.plan_from_host(p)
        p.run_readonly.assert_not_called()

    def test_no_running_vm(self):
        r=valid_report();r['four_dev_domains_off']=False
        with self.assertRaisesRegex(m.GateError,'FIRST_READONLY_GATE_NOT_MATCHED'):
            m.plan_from_host(self.mocked_prior(r))

    def test_no_active_ftp_net(self):
        r=valid_report();r['ftp_network_inactive']=False
        with self.assertRaisesRegex(m.GateError,'FIRST_READONLY_GATE_NOT_MATCHED'):
            m.plan_from_host(self.mocked_prior(r))

    def test_no_r34_weakened(self):
        r=valid_report();r['nft_r34']='BAD'
        with self.assertRaisesRegex(m.GateError,'FIRST_READONLY_GATE_NOT_MATCHED'):
            m.plan_from_host(self.mocked_prior(r))

    def test_no_missing_nwfilter(self):
        r=valid_report();r['nwfilter_r34']='UNKNOWN'
        with self.assertRaisesRegex(m.GateError,'FIRST_READONLY_GATE_NOT_MATCHED'):
            m.plan_from_host(self.mocked_prior(r))

    def test_double_read_drift_detected(self):
        p=self.mocked_prior()
        p.run_readonly.side_effect=[runner(),runner().replace(b'3072',b'4096')]
        with self.assertRaisesRegex(m.GateError,'RUNNER_XML_CHANGED_BETWEEN_READS'):
            m.plan_from_host(p)

    def test_double_gate_drift_detected(self):
        p=self.mocked_prior()
        after=valid_report();after['ftp_nic']={'runner_ftp':'MATCHED'}
        p.read_host.side_effect=[valid_report(),after]
        with self.assertRaisesRegex(m.GateError,'READONLY_GATE_CHANGED_DURING_PLAN'):
            m.plan_from_host(p)

    def test_wrong_git_head_during_plan(self):
        p=self.mocked_prior()
        after=valid_report();after['observed_git_head']='0'*40
        p.read_host.side_effect=[valid_report(),after]
        with self.assertRaisesRegex(m.GateError,'REPOSITORY_HEAD_CHANGED_DURING_PLAN'):
            m.plan_from_host(p)

    def test_subprocess_not_directly_used(self):
        self.assertFalse(hasattr(m,'subprocess'))

    def test_prior_hash_pinned(self):
        self.assertEqual(m.PRIOR_SHA256,
          '9b778d8414241d2f69dd53c8a90b944441d82b17b365378edc38ca53a3adad6d')

    def test_readonly_libvirt_command(self):
        p=self.mocked_prior()
        m.plan_from_host(p)
        p.run_readonly.assert_called_with(['/usr/bin/virsh','--readonly',
                '-c','qemu:///system','dumpxml',m.DOMAIN,'--inactive'])


if __name__=='__main__':
    unittest.main()
