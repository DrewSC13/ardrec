"""R112-F10R: postreboot SSH-runner->FTP->SMB provenance, no physical VM."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, mock

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
import ardrec_p14_r112_f10_targets_boot as f10
from ardrec.coordination import r112_f12_postreboot_boot as f12core

class F10RPostRebootTests(TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='f10r-test-')
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.ssh_plan=base/'sshplan';self.runner_plan=base/'runplan'
        self.ssh_boot=base/'sshboot';self.runner_boot=base/'runboot'
        for p in (self.ssh_plan,self.runner_plan,self.ssh_boot,self.runner_boot):p.mkdir()
        self.ssh={'role':'ssh','guest_states':f12core.expected('ssh',True),
                  'traffic_authorized':False,'p8_operational':'NO-GO'}
        from hashlib import sha256
        from ardrec.coordination.r112_f10_targets_boot import digest
        sr=b'{}\n';rr=b'{"runner":true}\n'
        self.ssh['receipt_bytes']=None
        self.runner={'role':'runner','guest_states':f12core.expected('runner',True),
                     'predecessor_sha256':digest(sr),'traffic_authorized':False,
                     'p8_operational':'NO-GO','protocol_tested':False}
        self.ssh.pop('receipt_bytes')
        for path,doc in ((self.ssh_boot/'receipt.json',self.ssh),
                         (self.runner_boot/'receipt.json',self.runner)):
            path.write_text(json.dumps(doc))
        self.ssh_sha=digest((self.ssh_boot/'receipt.json').read_bytes())
        self.runner['predecessor_sha256']=self.ssh_sha
        (self.runner_boot/'receipt.json').write_text(json.dumps(self.runner))
        self.runner_sha=digest((self.runner_boot/'receipt.json').read_bytes())
        substitutions={
            'F12_SSH_PLAN':self.ssh_plan,'F12_RUNNER_PLAN':self.runner_plan,
            'F12_SSH_BOOT':self.ssh_boot,'F12_RUNNER_BOOT':self.runner_boot,
            'F12_SSH_RECEIPT_SHA':self.ssh_sha,
            'F12_RUNNER_RECEIPT_SHA':self.runner_sha}
        self.patches=[]
        for k,v in substitutions.items():
            patcher=mock.patch.object(f10,k,v);patcher.start();self.addCleanup(patcher.stop)
        self.replayer=mock.patch.object(f10.f12cli,'replay',side_effect=[self.ssh,self.runner]);self.stub=self.replayer.start();self.addCleanup(self.replayer.stop)
    def test_runner_f12_chain_success(self):
        self.assertEqual(f10.previous_runner(),self.runner_sha)
        self.assertEqual(self.stub.call_count,2)
    def test_ftp_anchor_points_to_f12_not_f9(self):
        doc=f10.previous_receipt('ftp')
        self.assertEqual(doc['type'],'F12_RUNNER')
        self.assertEqual(doc['receipt_sha256'],self.runner_sha)
        self.assertIn('runboot',doc['receipt'])
        self.assertNotIn('r112-f9',doc['receipt'])
    def test_wrong_ssh_hash_rejected(self):
        with mock.patch.object(f10,'F12_SSH_RECEIPT_SHA','0'*64):
            with self.assertRaisesRegex(ValueError,'F12_PHYSICAL_PREDECESSOR_CHANGED'):
                f10.previous_runner()
    def test_wrong_runner_hash_rejected(self):
        with mock.patch.object(f10,'F12_RUNNER_RECEIPT_SHA','0'*64):
            with self.assertRaisesRegex(ValueError,'F12_PHYSICAL_PREDECESSOR_CHANGED'):
                f10.previous_runner()
    def test_bad_guest_state_rejected(self):
        wrong=dict(self.runner,guest_states=f12core.expected('runner',False))
        self.stub.side_effect=[self.ssh,wrong]
        with self.assertRaisesRegex(ValueError,'F12_PHYSICAL_PREDECESSOR_REPLAY_INVALID'):
            f10.previous_runner()
    def test_traffic_authorized_rejected(self):
        wrong=dict(self.runner,traffic_authorized=True)
        self.stub.side_effect=[self.ssh,wrong]
        with self.assertRaisesRegex(ValueError,'F12_PHYSICAL_PREDECESSOR_REPLAY_INVALID'):
            f10.previous_runner()
    def test_replay_drift_rejected(self):
        self.stub.side_effect=[self.ssh,dict(self.runner,role='ssh')]
        with self.assertRaisesRegex(ValueError,'F12_PHYSICAL_PREDECESSOR_REPLAY_INVALID'):
            f10.previous_runner()
    def test_missing_private_boot_dir_rejected(self):
        with mock.patch.object(f10,'F12_SSH_BOOT',Path('/absent/f10r-sha-boot')):
            with self.assertRaisesRegex(ValueError,'F12_PRIVATE_PREDECESSOR_MISSING'):
                f10.previous_runner()
    def test_smb_posixpath_accepted(self):
        ftpplan=Path(self.tmp.name)/'plan-fake'
        ftpboot=Path(self.tmp.name)/'boot-fake'
        ftpboot.mkdir(); ftpplan.mkdir()
        receipt=ftpboot/'receipt.json';receipt.write_bytes(b'{"kind":"FTP"}\n')
        with mock.patch.object(f10,'previous_runner',return_value=self.runner_sha),\
             mock.patch.object(f10,'private'),\
             mock.patch.object(f10,'replay',return_value={
                'target':'ftp','ftp_running':True,'smb_running':False,'traffic_authorized':False}):
            result=f10.previous_receipt('smb',ftpplan,receipt)
        self.assertEqual(result['type'],'F10_FTP')
    def test_smb_wrong_types_rejected(self):
        with mock.patch.object(f10,'previous_runner',return_value=self.runner_sha):
            for a,b in ((None,None),('string',Path('/tmp/r.json')),(Path('/tmp'),12)):
                with self.assertRaisesRegex(ValueError,'SMB_REQUIRES_FTP_PLAN_AND_RECEIPT'):
                    f10.previous_receipt('smb',a,b)
    def test_scope_rejects_ftp_previous(self):
        with self.assertRaisesRegex(ValueError,'FTP_MUST_LINK_F12_ONLY'):
            f10.previous_receipt('ftp',Path('/tmp/a'),Path('/tmp/b'))
