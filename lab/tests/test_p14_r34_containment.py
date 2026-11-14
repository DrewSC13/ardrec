"""R34 deny-first, XML provenance and read-only host preflight tests."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r33_offline_topology as t33
from ardrec.coordination import r34_containment as t
from test_p14_r33_topology import fixture_r32

class Runner:
    def __init__(self,*,filter_conflict=False,network_conflict=False,tap_conflict=False,
                 nft_collision=False,readonly_failure=False):
        self.calls=[]
        self.filter_conflict=filter_conflict
        self.network_conflict=network_conflict
        self.tap_conflict=tap_conflict
        self.nft_collision=nft_collision
        self.readonly_failure=readonly_failure
    def __call__(self,cmd,**kw):
        self.calls.append((cmd,kw))
        if self.readonly_failure: return mock.Mock(returncode=1,stdout=b'',stderr=b'No access')
        if cmd[:1]==['/usr/bin/virsh']:
            if cmd[-1]=='nwfilter-list':
                data=b' UUID   Name\n----------------------------------\n'
                if self.filter_conflict:data+=b' abcde  ardrec-r33-block-until-containment\n'
            elif cmd[-3:]==['net-list','--all','--name']:
                data=b'ardrec-r33-dev-net-ssh\n' if self.network_conflict else b''
            else:data=b''
        elif cmd[:3]==['/usr/sbin/ip','-j','link']:
            data=b'[ {"ifname":"a33d30t"} ]' if self.tap_conflict else b'[ {"ifname":"lo"} ]'
        elif '-j' in cmd and 'tables' in cmd:
            tab={'nftables':[{'table':{'family':'bridge','name':t.NFT_TABLE}}]} if self.nft_collision else {'nftables':[]}
            data=json.dumps(tab).encode()
        else:data=b'validated\n'
        return mock.Mock(returncode=0,stdout=data,stderr=b'')

class R34Tests(unittest.TestCase):
    def setUp(self):
        self.r33=t33.make_report(fixture_r32(), t33.R32_RECEIPT_FILE_SHA256,prepared=True)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'recibos-r33-xml-fake'
        self.path.mkdir(mode=0o700)
        for name,raw in t33.render_xml(t33.R32_RECEIPT_FILE_SHA256).items():
            f=self.path/name;f.write_bytes(raw);f.chmod(0o600)
        self.receipt=self.path/'r33_topology_receipt.json'
        self.receipt.write_bytes(t33.canon(self.r33)+b'\n');self.receipt.chmod(0o600)
        self.sha=t.sha(self.receipt.read_bytes())
        self.pin=mock.patch.object(t,'SOURCE_FILE_SHA',self.sha)
        self.pin.start();self.addCleanup(self.pin.stop)

    def policy_dir(self):
        d=Path(self.temp.name)/'recibos-r34-policy-test'
        d.mkdir(mode=0o700)
        return d

    def test_source_pins_outer_receipt_and_seven_xml(self):
        r,data=t.source_load(self.receipt,self.sha)
        self.assertEqual(r,self.r33)
        self.assertEqual(len(data),7)

    def test_source_reject_changed_xml(self):
        f=self.path/'domain-ssh.xml';f.write_bytes(f.read_bytes()+b' ')
        with self.assertRaises(t.ContainmentError): t.source_load(self.receipt,self.sha)

    def test_source_reject_forged_r33_authority(self):
        self.r33['vm_started']=True
        self.r33['sha256']=t33.digest(t33.canon({k:v for k,v in self.r33.items() if k!='sha256'}))
        self.receipt.write_bytes(t33.canon(self.r33)+b'\n')
        with self.assertRaises(t.ContainmentError): t.source_load(self.receipt,self.sha)

    def test_source_reject_bad_pin(self):
        with self.assertRaises(t.ContainmentError):t.source_load(self.receipt,'a'*64)

    def test_source_reject_symlink(self):
        link=self.path/'foreign'
        link.symlink_to(self.receipt)
        with self.assertRaises(t.ContainmentError): t.secure_file(link)

    def test_nft_scoped_drop_only(self):
        raw=t.nft_bytes().decode()
        self.assertIn('table bridge '+t.NFT_TABLE,raw)
        self.assertIn('hook forward priority -200',raw)
        self.assertNotIn('flush',raw)
        self.assertNotIn('accept\n',raw)
        self.assertEqual(raw.count('counter drop'),4)
        for name in t.TAPS:self.assertEqual(raw.count('"'+name+'"'),4)
        self.assertEqual(len(t.TAPS),6)

    def test_nft_tamper_rejected(self):
        with self.assertRaises(t.ContainmentError): t.verify_nft(t.nft_bytes()+b'flush ruleset\n')

    def test_filter_drops_everything(self):
        x=ET.fromstring(t.deny_filter_xml())
        self.assertEqual(x.get('name'),t33.DENY_FILTER)
        self.assertEqual(len(x.findall('rule')),1)
        self.assertEqual(x.find('rule').get('direction'),'inout')
        self.assertIsNotNone(x.find('rule/all'))

    def test_filter_modified_to_accept_rejected(self):
        raw=t.deny_filter_xml().replace(b'action="drop"',b'action="accept"')
        with self.assertRaises(t.ContainmentError):t.verify_filter(raw)

    def test_plan_no_subprocess(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('unexpected subprocess')):
            a=t.report(self.r33)
            b=t.report(self.r33)
        self.assertEqual(t.canon(a),t.canon(b))
        self.assertTrue(t.verify_report(a))
        self.assertFalse(a['host_containment_installed'])
        self.assertEqual(a['mode'],'PLAN_ONLY')

    def test_rehashed_false_operational_claim_rejected(self):
        d=t.report(self.r33)
        d['operational_dispatch']=True
        d['sha256']=t.sha(t.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(t.ContainmentError):t.verify_report(d)

    def test_prepare_offline_exact_three_files_and_permissions(self):
        d=self.policy_dir()
        with mock.patch('subprocess.run',side_effect=AssertionError('should be offline')):
            r=t.prepare(d,self.r33)
        self.assertEqual(len(list(d.iterdir())),3)
        self.assertTrue(t.verify_report(r))
        self.assertEqual(r['mode'],'OFFLINE_PREPARED')
        for f in d.iterdir():self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
        self.assertEqual(json.loads((d/t.POLICY_RECEIPT).read_text()),r)

    def test_prepare_cannot_overwrite(self):
        d=self.policy_dir();t.prepare(d,self.r33)
        before={f.name:f.read_bytes() for f in d.iterdir()}
        with self.assertRaises(t.ContainmentError):t.prepare(d,self.r33)
        self.assertEqual(before,{f.name:f.read_bytes() for f in d.iterdir()})

    def test_prepare_world_readable_dir_rejected(self):
        d=self.policy_dir();d.chmod(0o755)
        with self.assertRaises(t.ContainmentError):t.prepare(d,self.r33)

    def test_load_prepared_policy_drift_rejected(self):
        d=self.policy_dir();t.prepare(d,self.r33)
        (d/t.BRIDGE_NFT_FILE).write_bytes(b'invalid')
        with self.assertRaises(t.ContainmentError):t.load_prepared(d,self.r33)

    def _host(self,**options):
        d=self.policy_dir();t.prepare(d,self.r33)
        runner=Runner(**options)
        with mock.patch.object(t.shutil,'which',side_effect=lambda x:{
            'nft':'/usr/sbin/nft','ip':'/usr/sbin/ip','virsh':'/usr/bin/virsh',
            'virt-xml-validate':'/usr/bin/virt-xml-validate'}.get(x)):
            result=t.host_preflight(self.r33,d,runner=runner)
        return result,runner

    def test_readonly_host_preflight_success(self):
        d,runner=self._host()
        self.assertTrue(t.verify_host_report(d))
        self.assertEqual(d['mode'],'READONLY_HOST_PREFLIGHT')
        self.assertFalse(d['firewall_modified'])
        self.assertFalse(d['vm_started'])
        cmdtexts=[' '.join(c) for c,_ in runner.calls]
        self.assertTrue(any(' -c -f -' in x for x in cmdtexts))
        self.assertFalse(any('net-start' in x or 'virsh define' in x or 'nft -f -' in x for x in cmdtexts))

    def test_host_reject_prior_filter(self):
        with self.assertRaises(t.ContainmentError):self._host(filter_conflict=True)

    def test_host_reject_prior_network(self):
        with self.assertRaises(t.ContainmentError):self._host(network_conflict=True)

    def test_host_reject_tap_collision(self):
        with self.assertRaises(t.ContainmentError):self._host(tap_conflict=True)

    def test_host_reject_nft_collision(self):
        with self.assertRaises(t.ContainmentError):self._host(nft_collision=True)

    def test_host_fail_closed_when_sudo_denied(self):
        with self.assertRaises(t.ContainmentError):self._host(readonly_failure=True)

    def test_host_schema_false_authority_rejected(self):
        d,_=self._host()
        d['network_started']=True
        d['sha256']=t.sha(t.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaises(t.ContainmentError):t.verify_host_report(d)

if __name__=='__main__':unittest.main()
