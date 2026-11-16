"""Adversarial source-only tests for R58-A FTP-NIC observation; no host reads."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'ardrec_p14_r58a_ftp_nic_preflight.py'
spec = importlib.util.spec_from_file_location('ardrec_ftp_nic', SCRIPT)
assert spec is not None and spec.loader is not None
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def domain(role, included):
    root=ET.Element('domain', {'type':'kvm'})
    ET.SubElement(root,'name').text=m.DOMAIN_PREFIX+role
    devices=ET.SubElement(root,'devices')
    for key in included:
        net,mac,tap=m.NIC[key]
        i=ET.SubElement(devices,'interface',{'type':'network'})
        ET.SubElement(i,'mac',{'address':mac})
        ET.SubElement(i,'source',{'network':net})
        ET.SubElement(i,'target',{'dev':tap})
        ET.SubElement(i,'filterref',{'filter':m.FILTER})
    return ET.tostring(root)


def network():
    root=ET.Element('network')
    ET.SubElement(root,'name').text=m.NET
    ET.SubElement(root,'bridge',{'name':m.BRIDGE,'stp':'off','delay':'0'})
    ET.SubElement(root,'mac',{'address':'52:54:00:00:00:01'})
    ET.SubElement(root,'dns',{'enable':'no'})
    return root


def deny_xml():
    root=ET.Element('filter',{'name':m.FILTER,'chain':'root'})
    rule=ET.SubElement(root,'rule',{'action':'drop','direction':'inout','priority':'1000'})
    ET.SubElement(rule,'all')
    return ET.tostring(root)


def nft():
    rows=[{'metainfo':{'version':'1.1.7'}},
          {'table':{'family':'bridge','name':m.TABLE}}]
    for name in ('input','output','forward'):
        rows.append({'chain':{'name':name,'family':'bridge','table':m.TABLE,
            'hook':name,'type':'filter','prio':-200,'policy':'accept'}})
    for chain,field in [('input','iifname'),('output','oifname'),
                        ('forward','iifname'),('forward','oifname')]:
        rows.append({'rule':{'family':'bridge','table':m.TABLE,'chain':chain,
            'expr':[{'match':{'op':'==','left':{'meta':{'key':field}},
                'right':{'set':sorted(m.TAPS)}}},
                {'counter':{'packets':0,'bytes':0}}, {'drop':None}]}})
    return {'nftables':rows}


class TestPreflight(unittest.TestCase):
    def test_expected_ssh_only_runner_blocks_ftp(self):
        n=m.audit_domain_nics(domain('runner',['runner_ssh']),domain('ftp',['ftp_target']))
        self.assertEqual(n['runner_ftp'],'MISSING_IN_INACTIVE_XML')
        d=m.decide(n,network=m.audit_network(ET.tostring(network())),
            nft_status=m.audit_nft(json.dumps(nft()).encode()),
            filter_status=m.audit_filter(deny_xml()),four_off=True,
            ftp_network_inactive=True)
        self.assertEqual(d['result'],'BLOCKED_FTP_RUNNER_NIC_MISSING')
        self.assertEqual(d['p8'],'NO-GO')
        self.assertFalse(d['boot_guard_first_start_attested'])

    def test_ftp_present_is_not_authorization(self):
        n=m.audit_domain_nics(domain('runner',['runner_ssh','runner_ftp']),domain('ftp',['ftp_target']))
        d=m.decide(n,network=m.audit_network(ET.tostring(network())),
            nft_status=m.audit_nft(json.dumps(nft()).encode()),
            filter_status=m.audit_filter(deny_xml()),four_off=True,
            ftp_network_inactive=True)
        self.assertEqual(d['result'],'FTP_NIC_PRESENT_NOT_AUTHORIZED_TO_START')
        self.assertFalse(d['effective_binding_attested'])

    def test_three_runner_nics_ok(self):
        n=m.audit_domain_nics(domain('runner',['runner_ssh','runner_ftp','runner_smb']),
                              domain('ftp',['ftp_target']))
        self.assertEqual(n['runner_ftp'],'MATCHED')
        self.assertEqual(n['runner_smb'],'MATCHED')

    def test_unknown_tap_fails(self):
        raw=domain('runner',['runner_ssh'])
        x=ET.fromstring(raw)
        x.find('devices/interface/target').set('dev','external-tap')
        with self.assertRaises(m.Blocked):
            m.audit_domain_nics(ET.tostring(x),domain('ftp',['ftp_target']))

    def test_unguarded_ftp_runner_rejected(self):
        x=ET.fromstring(domain('runner',['runner_ssh','runner_ftp']))
        x.findall('devices/interface/filterref')[-1].set('filter','unrestricted')
        with self.assertRaises(m.Blocked):
            m.audit_domain_nics(ET.tostring(x),domain('ftp',['ftp_target']))

    def test_wrong_mac_rejected(self):
        x=ET.fromstring(domain('ftp',['ftp_target']))
        x.find('devices/interface/mac').set('address','52:54:00:11:22:33')
        with self.assertRaises(m.Blocked):
            m.audit_domain_nics(domain('runner',['runner_ssh']),ET.tostring(x))

    def test_duplicate_tap_rejected(self):
        with self.assertRaises(m.Blocked):
            m.audit_domain_nics(domain('runner',['runner_ssh','runner_ssh']),
                                domain('ftp',['ftp_target']))

    def test_network_normalization_allow_generated_mac(self):
        d=m.audit_network(ET.tostring(network()))
        self.assertFalse(d['ip_or_forward_in_xml'])
        self.assertFalse(d['ipv6_explicitly_attested'])

    def test_network_forward_fails(self):
        x=network()
        ET.SubElement(x,'forward',{'mode':'nat'})
        with self.assertRaises(m.Blocked):
            m.audit_network(ET.tostring(x))

    def test_network_ip_fails(self):
        x=network()
        ET.SubElement(x,'ip',{'address':'10.203.31.1'})
        with self.assertRaises(m.Blocked):
            m.audit_network(ET.tostring(x))

    def test_network_dns_fails(self):
        x=network()
        x.find('dns').set('enable','yes')
        with self.assertRaises(m.Blocked):
            m.audit_network(ET.tostring(x))

    def test_deny_filter_drop_all(self):
        self.assertEqual(m.audit_filter(deny_xml()),'DROP_ALL_DEFINITION_MATCHED')

    def test_deny_filter_allow_fails(self):
        x=ET.fromstring(deny_xml())
        x.find('rule').set('action','accept')
        with self.assertRaises(m.Blocked):
            m.audit_filter(ET.tostring(x))

    def test_r34_nft_expected(self):
        self.assertTrue(m.audit_nft(json.dumps(nft()).encode()).startswith('DENY_STRUCTURE'))

    def test_nft_missing_drop_fails(self):
        d=nft()
        d['nftables'][-1]['rule']['expr'].pop()
        with self.assertRaises(m.Blocked):
            m.audit_nft(json.dumps(d).encode())

    def test_nft_wrong_tap_set_fails(self):
        d=nft()
        d['nftables'][-1]['rule']['expr'][0]['match']['right']['set'].pop()
        with self.assertRaises(m.Blocked):
            m.audit_nft(json.dumps(d).encode())

    def test_nft_additional_allow_fails(self):
        d=nft()
        d['nftables'].append(d['nftables'][-1])
        with self.assertRaises(m.Blocked):
            m.audit_nft(json.dumps(d).encode())

    def test_running_guest_blocks(self):
        n=m.audit_domain_nics(domain('runner',['runner_ssh']),domain('ftp',['ftp_target']))
        args=dict(network=m.audit_network(ET.tostring(network())),
            nft_status=m.audit_nft(json.dumps(nft()).encode()),
            filter_status=m.audit_filter(deny_xml()),
            four_off=False,ftp_network_inactive=True)
        with self.assertRaises(m.Blocked):
            m.decide(n,**args)

    def test_active_ftp_network_blocks(self):
        n=m.audit_domain_nics(domain('runner',['runner_ssh']),domain('ftp',['ftp_target']))
        args=dict(network=m.audit_network(ET.tostring(network())),
            nft_status=m.audit_nft(json.dumps(nft()).encode()),
            filter_status=m.audit_filter(deny_xml()),
            four_off=True,ftp_network_inactive=False)
        with self.assertRaises(m.Blocked):
            m.decide(n,**args)

    def test_reject_xml_doctype(self):
        with self.assertRaises(m.Blocked):
            m.audit_filter(b'<!DOCTYPE x><filter/>')

    def test_host_readonly_normal_path_mocked(self):
        base=['/usr/bin/virsh','--readonly','-c','qemu:///system']
        nftcmd=['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a',
                'list','table','bridge',m.TABLE]
        values={
            tuple(['/usr/bin/git','-C',str(m.REPO),'rev-parse','HEAD']):
                (m.SOURCE_COMMIT+'\n').encode(),
            tuple(['/usr/bin/git','-C',str(m.REPO),'merge-base',
                   '--is-ancestor',m.SOURCE_COMMIT,'HEAD']):b'',
            tuple(nftcmd): json.dumps(nft()).encode(),
            tuple(base+['nwfilter-dumpxml',m.FILTER]): deny_xml(),
            tuple(base+['dumpxml',m.DOMAIN_PREFIX+'runner','--inactive']):
                domain('runner',['runner_ssh']),
            tuple(base+['dumpxml',m.DOMAIN_PREFIX+'ftp','--inactive']):
                domain('ftp',['ftp_target']),
            tuple(base+['net-dumpxml',m.NET]): ET.tostring(network()),
            tuple(base+['net-list','--name']): b'default\n',
        }
        for role in ('runner','ssh','ftp','smb'):
            values[tuple(base+['domstate',m.DOMAIN_PREFIX+role])]=b'shut off\n'
        def simulated_read(cmd):
            return values[tuple(cmd)]
        with mock.patch.object(m.Path,'cwd',return_value=m.REPO), \
             mock.patch.object(m,'run_readonly',side_effect=simulated_read) as reader:
            report=m.read_host()
        self.assertEqual(report['result'],'BLOCKED_FTP_RUNNER_NIC_MISSING')
        self.assertEqual(reader.call_count,13)
        self.assertEqual(report['observed_git_head'], m.SOURCE_COMMIT)
        self.assertEqual(report['physical_mutations'],0)
        self.assertEqual(report['p8'],'NO-GO')

    def test_descendant_head_accepted_by_readonly_gate(self):
        # A post-merge commit must not invalidate read-only provenance checks.
        base=['/usr/bin/virsh','--readonly','-c','qemu:///system']
        nftcmd=['/usr/bin/sudo','-n','--','/usr/sbin/nft','-j','-a','list','table','bridge',m.TABLE]
        values={
            tuple(['/usr/bin/git','-C',str(m.REPO),'rev-parse','HEAD']): b'1'*40+b'\n',
            tuple(['/usr/bin/git','-C',str(m.REPO),'merge-base',
                   '--is-ancestor',m.SOURCE_COMMIT,'HEAD']): b'',
            tuple(nftcmd):json.dumps(nft()).encode(),
            tuple(base+['nwfilter-dumpxml',m.FILTER]):deny_xml(),
            tuple(base+['dumpxml',m.DOMAIN_PREFIX+'runner','--inactive']):
                domain('runner',['runner_ssh']),
            tuple(base+['dumpxml',m.DOMAIN_PREFIX+'ftp','--inactive']):
                domain('ftp',['ftp_target']),
            tuple(base+['net-dumpxml',m.NET]):ET.tostring(network()),
            tuple(base+['net-list','--name']):b'default\n',
        }
        for role in ('runner','ssh','ftp','smb'):
            values[tuple(base+['domstate',m.DOMAIN_PREFIX+role])]=b'shut off\n'
        with mock.patch.object(m.Path,'cwd',return_value=m.REPO), \
             mock.patch.object(m,'run_readonly',side_effect=lambda cmd:values[tuple(cmd)]):
            report=m.read_host()
        self.assertEqual(report['observed_git_head'],'1'*40)
        self.assertEqual(report['source_git_head'],m.SOURCE_COMMIT)

    def test_ancestry_required_and_fails_closed(self):
        cmd=['/usr/bin/git','-C',str(m.REPO),'merge-base',
             '--is-ancestor',m.SOURCE_COMMIT,'HEAD']
        cp=mock.Mock(returncode=1,stdout=b'',stderr=b'')
        with mock.patch.object(m.subprocess,'run',return_value=cp):
            with self.assertRaisesRegex(m.Blocked,'HOST_READ_FAILED'):
                m.run_readonly(cmd)

    def test_unapproved_host_command_fails_before_subprocess(self):
        with self.assertRaises(m.Blocked):
            m.run_readonly(['/usr/bin/virsh','start','ardrec-r33-dev-ftp'])


if __name__=='__main__':
    unittest.main()
