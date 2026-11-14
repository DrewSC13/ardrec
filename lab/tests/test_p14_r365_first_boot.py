"""R36.5 isolated first boot: non-operational tests, no libvirt calls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r365_first_boot as b

SOURCES = {
    'r363_sha256':'a'*64, 'r364_sha256':'b'*64,
    'r35_file_sha256':'c'*64,'r36_file_sha256':'d'*64,'r361_file_sha256':'e'*64,
}

class FakeHost:
    def __init__(self, failure=None):
        self.failure = failure
        self.calls=[]
        self.commands=[]
    def activate_ssh_network(self):
        self.calls.append('NETWORK')
        if self.failure == 'NETWORK':
            raise RuntimeError('network command failed')
    def activate_ssh_domain(self):
        self.calls.append('DOMAIN')
        if self.failure == 'DOMAIN':
            raise RuntimeError('domain command failed')


class Unit(unittest.TestCase):
    def test_r363_files_and_r364_files_bounded(self):
        self.assertEqual(len(b.R363_FILES),27)
        self.assertEqual(b.R364_FILES,frozenset({'r364_report.json'}))
        self.assertIn('nft.json',b.R363_FILES)
    def test_strict_digest(self):
        d={'schema':'test', 'state':'ok'}
        d['sha256']=b.sha(b.canonical(d))
        b.check_digest(d,'test')
        d['state']='tamper'
        with self.assertRaises(b.BootError):b.check_digest(d,'test')
    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(b.BootError):b.read_json(b'{"a":1,"a":2}')
    def test_nonfinite_json_rejected(self):
        with self.assertRaises(b.BootError):b.read_json(b'{"a":NaN}')
    def test_memory_nonzero(self):
        self.assertGreater(b.memory_available_mib(),0)
    def test_preflight_provenance_rejects_changed_status(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700)
            d={'schema':b.SCHEMA,'status':'FAKE_READY','mode':'PREFLIGHT_ONLY',
               'source_evidence':SOURCES,'host_state':{'phase':'BEFORE'},
               'storage_verified':True,'host_mutations':[], 'attempted_mutations':[],
               'network_started':False,'vm_started':False,'operational_dispatch':False,
               'failure_code':None,'guest_isolation_tested':False,'p8_operational':'NO-GO'}
            b.seal_receipts(p,d,[])
            with self.assertRaisesRegex(b.BootError,'preflight_receipt_not_ready'):
                b.verify_preflight_receipt(p,SOURCES)
    def test_preflight_provenance_accepts_exact(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700)
            d={'schema':b.SCHEMA,'status':'READY_FOR_EXPLICIT_FIRST_BOOT',
               'mode':'PREFLIGHT_ONLY', 'source_evidence':SOURCES,
               'host_state':{'phase':'BEFORE'},'storage_verified':True,
               'host_mutations':[],'attempted_mutations':[],
               'network_started':False,'vm_started':False,'operational_dispatch':False,
               'failure_code':None,'guest_isolation_tested':False,'p8_operational':'NO-GO'}
            b.seal_receipts(p,d,[])
            found=b.verify_preflight_receipt(p,SOURCES)
            self.assertEqual(found['status'],'READY_FOR_EXPLICIT_FIRST_BOOT')
            with self.assertRaises(b.BootError):b.verify_preflight_receipt(p,{**SOURCES,'r35_file_sha256':'x'*64})
    def test_preflight_provenance_rejects_mutating_command(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700)
            d={'schema':b.SCHEMA,'status':'READY_FOR_EXPLICIT_FIRST_BOOT',
               'mode':'PREFLIGHT_ONLY','source_evidence':SOURCES,
               'host_state':{'phase':'BEFORE'},'storage_verified':True,
               'host_mutations':[],'attempted_mutations':[],
               'network_started':False,'vm_started':False,'operational_dispatch':False,
               'failure_code':None,'guest_isolation_tested':False,'p8_operational':'NO-GO'}
            b.seal_receipts(p,d,[{'argv':['virsh','start','foo']}])
            with self.assertRaisesRegex(b.BootError,'preflight_receipt_contains_write'):
                b.verify_preflight_receipt(p,SOURCES)
    def test_no_unauthenticated_activation(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(b.BootError,'authorization_requires_preflight'):
                b.perform(archive=Path('/fake'),receipt_dir=Path(td)/'x',r35_dir=Path('/a'),
                r36_dir=Path('/b'),r361_dir=Path('/c'),r363_dir=Path('/d'),r364_dir=Path('/e'),
                authorized=True,host=FakeHost())
    def case(self,authorize=False,failure=None):
        parent=tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        root=Path(parent.name)
        root.chmod(0o700)
        host=FakeHost(failure)
        with mock.patch.object(b,'verify_prior',return_value=SOURCES),\
             mock.patch.object(b,'verify_preflight_receipt',return_value={'sha256':'f'*64}),\
             mock.patch.object(b.r35,'verify_source_bundle',return_value={'r32':{}}),\
             mock.patch.object(b,'verify_storage'),\
             mock.patch.object(b,'current',side_effect=lambda h,*,phase:{'phase':phase}),\
             mock.patch.object(b,'memory_available_mib',return_value=9000):
            result=b.perform(archive=Path('/fake'),receipt_dir=root/'receipts',
                      r35_dir=root,r36_dir=root,r361_dir=root,r363_dir=root,
                      r364_dir=root,preflight_dir=root if authorize else None,
                      authorized=authorize,host=host)
        self.assertTrue((root/'receipts'/'SHA256SUMS').exists())
        self.assertIsNone(result.get('final_risk'))
        self.assertEqual(result['p8_operational'],'NO-GO')
        self.assertFalse(result['guest_isolation_tested'])
        self.assertEqual(result['real_service_testing'],'NOT_EXECUTED')
        self.assertEqual(stat.S_IMODE((root/'receipts'/'r365_report.json').stat().st_mode),0o600)
        return result,host
    def test_preflight_zero_writes(self):
        r,h=self.case()
        self.assertEqual(r['status'],'READY_FOR_EXPLICIT_FIRST_BOOT')
        self.assertEqual(h.calls,[])
        self.assertEqual(r['attempted_mutations'],[])
    def test_exact_ssh_first_boot_order(self):
        r,h=self.case(authorize=True)
        self.assertEqual(r['status'],'FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED')
        self.assertEqual(h.calls,['NETWORK','DOMAIN'])
        self.assertEqual(len(r['host_mutations']),2)
        self.assertTrue(r['network_started'])
        self.assertTrue(r['vm_started'])
    def test_failed_network_start_is_partial_not_nochange(self):
        r,h=self.case(authorize=True,failure='NETWORK')
        self.assertEqual(r['status'],'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(h.calls,['NETWORK'])
        self.assertEqual(len(r['attempted_mutations']),1)
        self.assertEqual(r['host_mutations'],[])
        self.assertFalse(r['network_started'])
    def test_failed_domain_start_preserves_network_only(self):
        r,h=self.case(authorize=True,failure='DOMAIN')
        self.assertEqual(r['status'],'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(h.calls,['NETWORK','DOMAIN'])
        self.assertTrue(r['network_started'])
        self.assertFalse(r['vm_started'])
    def test_cannot_reuse_receipt_dir(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700)
            with self.assertRaisesRegex(b.BootError,'receipt_destination_invalid'):
                b._receipt_directory(p)
    def test_source_still_no_isolation_proof(self):
        r,_=self.case(authorize=True)
        self.assertFalse(r['guest_isolation_tested'])
        self.assertEqual(r['experimental_validation'],'NOT_RUN')

if __name__=='__main__':unittest.main()

from test_p14_r35_inactive_deployment import (
    FakeHostRunner, BINARIES,
)
from test_p14_r33_topology import fixture_r32
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r33_offline_topology as t33

class RealReadbackTests(unittest.TestCase):
    """Exercise the REAL R35 validators with libvirt-like normalized XML."""
    class Runner(FakeHostRunner):
        def __init__(self,root):
            super().__init__(fixture_r32(),root,normalized_network=True,normalized_domain=True)
            self.nft_installed=True
            self.filter_defined=True
            self.networks_defined=list(r35.NETWORKS)
            self.domains_defined=list(r35.DOMAINS)
            self.network_running=False
            self.ssh_running=False
        def __call__(self,argv,**kwargs):
            cmd=argv[3:] if argv[0]=='/usr/bin/sudo' else argv
            if cmd[0]=='/usr/bin/virsh':
                args=(cmd[4:] if len(cmd)>3 and cmd[1]=='--readonly'
                      else cmd[3:])
                if args == ['net-start',b.SSH_NETWORK]:
                    self.network_running=True
                    return mock.Mock(returncode=0,stdout=b'network started',stderr=b'')
                if args == ['start',b.SSH_DOMAIN]:
                    self.ssh_running=True
                    return mock.Mock(returncode=0,stdout=b'VM started',stderr=b'')
                if args == ['net-list','--name']:
                    return mock.Mock(returncode=0,stdout=(b.SSH_NETWORK+'\n').encode()
                                     if self.network_running else b'',stderr=b'')
                if args == ['list','--name']:
                    return mock.Mock(returncode=0,stdout=(b.SSH_DOMAIN+'\n').encode()
                                     if self.ssh_running else b'',stderr=b'')
            if cmd[0]=='/usr/sbin/ip':
                names=['lo']
                if self.network_running:names.append(t33.NET_BRIDGE['ssh'])
                if self.ssh_running:names.append('a33d30t')
                return mock.Mock(returncode=0,stdout=json.dumps([{'ifname':i} for i in names]).encode(),stderr=b'')
            return super().__call__(argv,**kwargs)

    def test_r35_readbacks_before_mid_and_after(self):
        with tempfile.TemporaryDirectory() as td:
            fake=self.Runner(Path(td))
            host=b.FirstBootHost(runner=fake,which=lambda name:BINARIES.get(name))
            macs={
                'ssh':r35.SSH_BRIDGE_MAC_R353,
                'ftp':'52:54:00:12:34:56',
                'smb':'52:54:00:65:43:21',
            }
            with mock.patch.object(r35,'R354_EXISTING_BRIDGE_MACS',macs):
                self.assertEqual(b.current(host,phase='BEFORE')['phase'],'BEFORE')
                host.activate_ssh_network()
                self.assertEqual(b.current(host,phase='NETWORK_ONLY')['phase'],'NETWORK_ONLY')
                host.activate_ssh_domain()
                self.assertEqual(b.current(host,phase='SSH_RUNNING')['phase'],'SSH_RUNNING')
            writes=[r['argv'] for r in host.commands if 'net-start' in r['argv'] or 'start' in r['argv']]
            self.assertEqual(len(writes),2)
            self.assertEqual(writes[0][-2:],['net-start',b.SSH_NETWORK])
            self.assertEqual(writes[1][-2:],['start',b.SSH_DOMAIN])
    def test_phase_rejects_premature_ssh_start(self):
        with tempfile.TemporaryDirectory() as td:
            fake=self.Runner(Path(td))
            host=b.FirstBootHost(runner=fake,which=lambda name:BINARIES.get(name))
            fake.network_running=True
            with self.assertRaises((b.BootError,r35.R35Error)):
                b.current(host,phase='BEFORE')
