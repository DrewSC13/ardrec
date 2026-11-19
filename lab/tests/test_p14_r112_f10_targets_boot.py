"""R112-F10: deterministic regression fixtures only; NO VM is started."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import hashlib
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f10_targets_boot as f10
from ardrec.coordination import r112_f9_runner_boot as f9
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
from test_p14_r112_f9_runner_boot import after_runner
from test_p14_r112_f8_ssh_positive_boot import after_ssh, successful_command


def advance(before,role):
    result=deepcopy(before)
    result['snapshot']['probes'][f'vm-{role}-state']['stdout']='running\n'
    for net in f10.NETWORKS:
        key=f'net-{net}-xml'
        raw=result['snapshot']['probes'][key]['stdout']
        if '<network>' in raw:
            result['snapshot']['probes'][key]['stdout']=raw.replace(
                '<network>','<network connections="3">',1)
    result['snapshot']['summary']=legacy.summarize(result['snapshot']['probes'])
    return result

class TargetBootTests(unittest.TestCase):
    def setUp(self):
        ssh=after_ssh()
        self.ftp_before=after_runner(ssh)
        self.ftp_after=advance(self.ftp_before,'ftp')
        self.smb_before=self.ftp_after
        self.smb_after=advance(self.smb_before,'smb')

    def fixture(self,role):
        if role=='ftp':
            before,after=self.ftp_before,self.ftp_after
        else:
            before,after=self.smb_before,self.smb_after
        doc=f10.ticket(role,1795094100,'a'*64)
        sha=hashlib.sha256(f10.canon(doc)).hexdigest()
        grant={'directory_stat':'0:0 700 '+f10.LEASE_ROOT,
               'lease_stat':'0:0 600 1 '+str(len(f10.canon(doc)))+' '+f10.lease(role),
               'lease_sha256':sha}
        claims={kind:{'stat':'0:0 600 1 65 '+path,'content':sha+'\n'}
                for kind,path in f10.markers(role).items()}
        live=before['snapshot']['probes'][f'vm-{role}-inactive-xml']['stdout']
        return before,after,doc,grant,claims,live

    def classify(self,role,**changes):
        before,after,doc,grant,claims,live=self.fixture(role)
        return f10.classify(changes.get('before',before),changes.get('after',after),
             changes.get('started',successful_command()),changes.get('live',live),
             changes.get('doc',doc),changes.get('grant',grant),
             changes.get('claims',claims),role,legacy=legacy,f4=f4)

    def test_ftp_boot_denied_traffic(self):
        rec=self.classify('ftp')
        self.assertEqual(rec['target'],'ftp')
        self.assertTrue(rec['ftp_running'])
        self.assertFalse(rec['smb_running'])
        self.assertFalse(rec['traffic_authorized'])
        self.assertEqual(rec['p8_operational'],'NO-GO')

    def test_smb_boot_denied_traffic(self):
        rec=self.classify('smb')
        self.assertEqual(rec['target'],'smb')
        self.assertTrue(rec['smb_running'])
        self.assertFalse(rec['protocol_tested'])

    def test_allowlist_exact_two(self):
        self.assertEqual(f10.TARGETS,('ftp','smb'))
        for role in ('ssh','runner','all','','FTP',None):
            with self.assertRaises(ValueError): f10.guest(role)

    def test_one_boot_command_per_target(self):
        for role in f10.TARGETS:
            self.assertEqual(f10.start(role),('sudo','-n','virsh','-c',
                             'qemu:///system','start','ardrec-r33-dev-'+role))

    def test_separate_lease_and_markers(self):
        self.assertNotEqual(f10.lease('ftp'),f10.lease('smb'))
        self.assertTrue(set(f10.markers('ftp').values()).isdisjoint(
                        set(f10.markers('smb').values())))

    def test_ticket_ttl_and_no_authority(self):
        for role in f10.TARGETS:
            doc=f10.ticket(role,1,'a'*64)
            self.assertEqual(doc['expires_at']-doc['issued_at'],180)
            self.assertEqual(doc['p8_operational'],'NO-GO')
            self.assertEqual(doc['mode'],'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY')

    def test_ticket_invalid_input(self):
        for role,now,nonce in [('ftp',0,'a'*64),('ftp',True,'a'*64),
                               ('ftp',1,'Z'*64),('smb',1,'x'),
                               ('ssh',1,'a'*64)]:
            with self.assertRaises(ValueError): f10.ticket(role,now,nonce)

    def test_ftp_missing_runner_rejected(self):
        changed=deepcopy(self.ftp_before)
        changed['snapshot']['probes']['vm-runner-state']['stdout']='shut off\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('ftp',before=changed)

    def test_ftp_before_requires_ftp_off(self):
        with self.assertRaises(ValueError): self.classify('ftp',before=self.ftp_after)

    def test_smb_before_requires_ftp_running(self):
        with self.assertRaises(ValueError): self.classify('smb',before=self.ftp_before)

    def test_smb_before_requires_smb_off(self):
        with self.assertRaises(ValueError): self.classify('smb',before=self.smb_after)

    def test_after_requires_target_running(self):
        for role in f10.TARGETS:
            before,_,_,_,_,_=self.fixture(role)
            with self.assertRaises(ValueError):self.classify(role,after=before)

    def test_after_ssh_must_remain_running(self):
        changed=deepcopy(self.ftp_after)
        changed['snapshot']['probes']['vm-ssh-state']['stdout']='shut off\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('ftp',after=changed)

    def test_after_runner_must_remain_running(self):
        changed=deepcopy(self.smb_after)
        changed['snapshot']['probes']['vm-runner-state']['stdout']='shut off\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('smb',after=changed)

    def test_ftp_must_remain_running_after_smb(self):
        changed=deepcopy(self.smb_after)
        changed['snapshot']['probes']['vm-ftp-state']['stdout']='shut off\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('smb',after=changed)

    def test_bridge_drift_denied(self):
        changed=deepcopy(self.ftp_after)
        key='net-ftp-xml'
        changed['snapshot']['probes'][key]['stdout']=changed['snapshot']['probes'][key]['stdout'].replace(
            'br33d31','br33zz')
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('ftp',after=changed)

    def test_forwarding_drift_denied(self):
        changed=deepcopy(self.smb_after)
        key='net-smb-xml'
        changed['snapshot']['probes'][key]['stdout']=changed['snapshot']['probes'][key]['stdout'].replace(
            '</network>','<forward mode="nat"/></network>')
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('smb',after=changed)

    def test_hook_drift_denied(self):
        changed=deepcopy(self.ftp_after)
        changed['snapshot']['probes']['f11-hook-hash']['stdout']='0'*64+' /x\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('ftp',after=changed)

    def test_nwfilter_drift_denied(self):
        changed=deepcopy(self.ftp_after)
        key='deny-nwfilter-xml'
        changed['snapshot']['probes'][key]['stdout']=changed['snapshot']['probes'][key]['stdout'].replace(
            'action="drop"','action="accept"')
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify('ftp',after=changed)

    def test_live_extra_nic_denied(self):
        _,_,_,_,_,live=self.fixture('ftp')
        live=live.replace('</devices>','<interface type="network"/></devices>')
        with self.assertRaises(ValueError): self.classify('ftp',live=live)

    def test_live_extra_host_device_denied(self):
        _,_,_,_,_,live=self.fixture('smb')
        live=live.replace('</devices>','<hostdev/></devices>')
        with self.assertRaises(ValueError): self.classify('smb',live=live)

    def test_cross_target_ticket_rejected(self):
        _,_,doc,_,_,_=self.fixture('ftp')
        with self.assertRaises(ValueError):self.classify('smb',doc=doc)

    def test_tampered_grant_hash_rejected(self):
        _,_,_,grant,_,_=self.fixture('ftp')
        grant['lease_sha256']='0'*64
        with self.assertRaises(ValueError):self.classify('ftp',grant=grant)

    def test_missing_f11_phase_rejected(self):
        _,_,_,_,claims,_=self.fixture('ftp')
        claims.pop('active')
        with self.assertRaises(ValueError):self.classify('ftp',claims=claims)

    def test_invalid_f11_permissions_rejected(self):
        _,_,_,_,claims,_=self.fixture('smb')
        claims['used']['stat']=claims['used']['stat'].replace('600','644')
        with self.assertRaises(ValueError):self.classify('smb',claims=claims)

    def test_generic_start_failure_not_evidence(self):
        failed=successful_command();failed['rc']=1
        with self.assertRaises(ValueError):self.classify('ftp',started=failed)

    def test_no_unattested_traffic_or_p8(self):
        for role in f10.TARGETS:
            rec=self.classify(role)
            self.assertFalse(rec['traffic_authorized'])
            self.assertFalse(rec['protocol_tested'])
            self.assertFalse(rec['a5_dispatched'])
            self.assertEqual(rec['a6'],'ND')
            self.assertFalse(rec['a9'])

    def test_script_does_not_destroy_restart_or_enable_network(self):
        script=(REPO/'scripts/ardrec_p14_r112_f10_targets_boot.py').read_text()
        self.assertNotIn("'destroy'",script)
        self.assertNotIn("'net-start'",script)
        self.assertNotIn("'nft','add'",script)
        self.assertNotIn('subprocess.Popen(',script)
        self.assertIn('TARGET_BOOT_ALREADY_ATTEMPTED',script)
        self.assertIn("store(path/'boot.once'",script)

if __name__=='__main__':unittest.main()
