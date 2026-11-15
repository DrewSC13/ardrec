"""R47 explicit two-filter staging: no VM start, network, nft or dispatch."""
from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET
from ardrec.coordination import r47_filter_stage as r47
from ardrec.coordination import r46_ssh_transition_audit as r46
from ardrec.coordination import r45_ssh_positive_candidate as r45
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

def sample():
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


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.base.chmod(0o700)
        self.r45dir=self.base/'r45-fake'
        self.r46dir=self.base/'r46-fake'
        self.r45dir.mkdir(mode=0o700)
        self.r46dir.mkdir(mode=0o700)
        for name,raw in r45.build_files().items():
            (self.r45dir/name).write_bytes(raw)
        self.orig=sample()
        for name,raw in self.orig.items():
            (self.r46dir/name).write_bytes(raw)
            (self.r46dir/name).chmod(0o600)
        self.p1=mock.patch.object(r45,'verify_directory',return_value={'sha256':r47.R45_PIN,'p8_operational':'NO-GO'})
        self.p2=mock.patch.object(r46,'verify_receipt',return_value={'sha256':r47.R46_PIN,'p8_operational':'NO-GO'})
        self.p1.start();self.p2.start()
        self.addCleanup(self.p1.stop);self.addCleanup(self.p2.stop)
        self.root=self.base/'r47-filter-stage-20261115T030000Z-5663'
        self.calls=[]
        self.after={**self.orig}
        self.after['nwfilter-list.txt']=self.orig['nwfilter-list.txt']+r45.FILTER_SSH.encode()+b'\n'+r45.FILTER_RUNNER.encode()+b'\n'
        self.phase=False

    def capture(self):
        return self.after if self.phase else self.orig

    def fake_run(self,cmd,**kwargs):
        self.assertNotIn('shell',kwargs)
        self.assertNotIn('start',cmd)
        self.calls.append(cmd)
        if 'nwfilter-define' in cmd:
            self.assertEqual(cmd[-2],'nwfilter-define')
            if 'runner-ssh' in cmd[-1]:self.phase=True
            return SimpleNamespace(returncode=0,stdout=b'filter defined\n',stderr=b'')
        if 'dumpxml' in cmd and 'nwfilter-dumpxml' not in cmd:
            return SimpleNamespace(returncode=0,stdout=self.orig['ssh-inactive.xml'],stderr=b'')
        self.assertIn('nwfilter-dumpxml',cmd)
        fname='runner-ssh-nwfilter-candidate.xml' if cmd[-1]==r45.FILTER_RUNNER else 'ssh-nwfilter-candidate.xml'
        return SimpleNamespace(returncode=0,stdout=(self.r45dir/fname).read_bytes(),stderr=b'')

    def fake_stage(self):
        return r47.stage(self.r45dir,self.r46dir,self.root,capture=self.capture,run=self.fake_run)

    def test_plan_no_host_calls(self):
        with mock.patch.object(r46,'capture_host',side_effect=AssertionError('no host')):
            d=r47.plan(self.r45dir,self.r46dir)
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertFalse(d['host_filter_additions_applied'])
        self.assertEqual(d['original_state'],r46.EXPECTED_RESTORE_STATE)
        self.assertEqual(len(d['definitions_sha256']),2)
        self.assertEqual(d['sha256'],r47.sha(r47.canon({k:v for k,v in d.items() if k!='sha256'})))

    def test_stage_two_definitions_and_verify(self):
        doc=self.fake_stage()
        self.assertTrue(doc['host_filter_additions_applied'])
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertEqual(len([x for x in self.calls if 'nwfilter-define' in x]),2)
        self.assertTrue(all('nwfilter-define' in x or 'nwfilter-dumpxml' in x or 'dumpxml' in x for x in self.calls))
        self.assertEqual(len(list(self.root.iterdir())),5)
        self.assertEqual(doc['sha256'],r47.verify_receipt(self.r45dir,self.r46dir,self.root,capture=self.capture,run=self.fake_run)['sha256'])

    def test_staged_root_private(self):
        self.fake_stage()
        self.assertEqual(self.root.stat().st_mode&0o777,0o700)
        self.assertTrue(all(x.stat().st_mode&0o777==0o600 for x in self.root.iterdir()))

    def test_second_stage_refused(self):
        self.fake_stage()
        with self.assertRaisesRegex(r47.R47Error,'private_stage_path_invalid'):
            self.fake_stage()

    def test_fail_first_define_preserves_intent(self):
        def fail(cmd,**kw):
            if 'nwfilter-define' in cmd:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'failed')
            return self.fake_run(cmd,**kw)
        with self.assertRaisesRegex(r47.R47Error,'host_call_failed'):
            r47.stage(self.r45dir,self.r46dir,self.root,capture=self.capture,run=fail)
        self.assertEqual([x.name for x in self.root.iterdir()],[r47.INTENT_NAME])

    def test_fail_second_define_preserves_first_record(self):
        def fail(cmd,**kw):
            if 'nwfilter-define' in cmd and 'runner' in cmd[-1]:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'failed')
            return self.fake_run(cmd,**kw)
        with self.assertRaises(r47.R47Error):
            r47.stage(self.r45dir,self.r46dir,self.root,capture=self.capture,run=fail)
        self.assertEqual(set(x.name for x in self.root.iterdir()),{r47.INTENT_NAME,'r47-defined-1.json'})
        self.assertFalse((self.root/r47.RECEIPT_NAME).exists())

    def test_unexpected_host_state_blocks_before_writes(self):
        broken={**self.orig,'bridge-ipv4.txt':b'wrong'}
        with self.assertRaises(r46.R46AuditError):
            r47.stage(self.r45dir,self.r46dir,self.root,capture=lambda:broken,run=self.fake_run)
        self.assertFalse(self.root.exists());self.assertEqual(self.calls,[])

    def test_live_source_drift_blocks_before_writes(self):
        broken={**self.orig,'ssh-inactive.xml':self.orig['ssh-inactive.xml']+b' '}
        with self.assertRaisesRegex(r47.R47Error,'live_drift'):
            r47.stage(self.r45dir,self.r46dir,self.root,capture=lambda:broken,run=self.fake_run)
        self.assertFalse(self.root.exists())

    def test_unapproved_live_filter_blocks_before_mutation(self):
        def live_wrong(cmd,**kw):
            if 'dumpxml' in cmd and 'nwfilter-dumpxml' not in cmd:
                x=ET.fromstring(self.orig['ssh-inactive.xml'])
                x.find('./devices/interface/filterref').set('filter',r45.FILTER_SSH)
                return SimpleNamespace(returncode=0,stdout=ET.tostring(x),stderr=b'')
            return self.fake_run(cmd,**kw)
        with self.assertRaisesRegex(r47.R47Error,'ssh_live_filter_or_identity_drift'):
            r47.stage(self.r45dir,self.r46dir,self.root,capture=self.capture,run=live_wrong)
        self.assertFalse(self.root.exists())

    def test_live_domain_filter_unchanged_after_stage(self):
        self.fake_stage()
        self.assertTrue(any('dumpxml' in x and r46.SSH_DOMAIN in x for x in self.calls))

    def test_tampered_definition_receipt_rejected(self):
        self.fake_stage()
        p=self.root/'r47-defined-1.json'
        x=json.loads(p.read_bytes());x['sha256']='0'*64
        p.write_bytes(r47.canon(x)+b'\n')
        # Even if an attacker updates the checksum manifest, libvirt readback must match.
        files=[r47.INTENT_NAME,'r47-defined-1.json','r47-defined-2.json',r47.RECEIPT_NAME]
        (self.root/r47.SUMS).write_bytes((''.join(f'{r47.sha((self.root/n).read_bytes())}  {n}\n' for n in sorted(files))).encode())
        with self.assertRaisesRegex(r47.R47Error,'filter_operation_receipt_invalid'):
            r47.verify_receipt(self.r45dir,self.r46dir,self.root,capture=self.capture,run=self.fake_run)

    def test_filter_definition_mismatch_rejected(self):
        x=ET.fromstring(r45.filter_candidate(runner=False));x.find('rule').set('action','drop')
        with self.assertRaisesRegex(r47.R47Error,'libvirt_filter_definition_drift'):
            r47._check_definition(ET.tostring(x),r45.filter_candidate(runner=False))

    def test_filter_definition_whitespace_accepted(self):
        xml=r45.filter_candidate(runner=False)
        root=ET.fromstring(xml)
        self.assertIsNone(r47._check_definition(ET.tostring(root),xml))

    def test_post_host_domain_drift_blocked(self):
        self.after['runner-inactive.xml']=b'<changed />'
        with self.assertRaisesRegex(r47.R47Error,'post_host_drift'):
            self.fake_stage()
        self.assertTrue((self.root/r47.INTENT_NAME).is_file())
        self.assertFalse((self.root/r47.RECEIPT_NAME).exists())

    def test_post_host_nft_drift_blocked(self):
        self.after['r34-bridge-deny.txt']=self.orig['r34-bridge-deny.txt'].replace(b'drop # handle 5',b'accept # handle 5')
        with self.assertRaises(r46.R46AuditError):self.fake_stage()

    def test_post_filter_inventory_other_added_blocked(self):
        self.after['nwfilter-list.txt']+=b'unexpected-filter\n'
        with self.assertRaisesRegex(r47.R47Error,'post_filter_inventory_unexpected'):self.fake_stage()

    def test_missing_candidate_readback_blocks(self):
        self.after['nwfilter-list.txt']=self.orig['nwfilter-list.txt']+r45.FILTER_SSH.encode()+b'\n'
        with self.assertRaises(r47.R47Error):self.fake_stage()

    def test_insecure_parent_rejected(self):
        self.base.chmod(0o755)
        with self.assertRaisesRegex(r47.R47Error,'private_parent_required'):self.fake_stage()

    def test_symlink_destination_rejected(self):
        self.root.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(r47.R47Error):self.fake_stage()

    def test_receipt_mutation_rejected(self):
        self.fake_stage()
        with (self.root/r47.RECEIPT_NAME).open('ab') as f:f.write(b'altered')
        with self.assertRaises(r47.R47Error):r47.verify_receipt(self.r45dir,self.r46dir,self.root,capture=self.capture,run=self.fake_run)

    def test_missing_stage_file_rejected(self):
        self.fake_stage()
        (self.root/'r47-defined-2.json').unlink()
        with self.assertRaises(r47.R47Error):r47.verify_receipt(self.r45dir,self.r46dir,self.root,capture=self.capture,run=self.fake_run)

    def test_wrong_r46_receipt_rejected(self):
        with mock.patch.object(r46,'verify_receipt',return_value={'sha256':'0'*64}):
            with self.assertRaisesRegex(r47.R47Error,'r46_receipt_drift'):self.fake_stage()
        self.assertFalse(self.root.exists())

    def test_stage_has_no_sudo_nft_or_vm_commands(self):
        self.fake_stage()
        for cmd in self.calls:
            self.assertEqual(cmd[:4],['/usr/bin/sudo','-n','--','/usr/bin/virsh'])
            self.assertNotIn('start',cmd)
            self.assertNotIn('destroy',cmd)
            self.assertNotIn('attach-interface',cmd)
            self.assertNotIn('define',cmd)
            self.assertNotIn('nft',cmd)

if __name__=='__main__':unittest.main()
