"""R112-F12: offline adversarial assertions only; never start real VM."""
from __future__ import annotations
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f12_postreboot_boot as f12
from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_f9_runner_boot as f9
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f6_hook_lifecycle as f6
from test_p14_r112_f7_libvirt_negative import measured
from test_p14_r112_f8_ssh_positive_boot import after_ssh,successful_command
from test_p14_r112_f9_runner_boot import after_runner

class PostRebootBootTests(unittest.TestCase):
    def setUp(self):
        self.ssh_before=measured()
        self.ssh_after=after_ssh(self.ssh_before)
        self.runner_before=self.ssh_after
        self.runner_after=after_runner(self.runner_before)

    def fixture(self,role):
        before,after=(self.ssh_before,self.ssh_after) if role=='ssh' else (
                     self.runner_before,self.runner_after)
        doc=f12.ticket(role,1795094100,'a'*64)
        hashed=hashlib.sha256(f12.canon(doc)).hexdigest()
        lease=f12.lease(role)
        grant={'directory_stat':'0:0 700 '+f12.ROOT_LEASE,
               'lease_stat':'0:0 600 1 '+str(len(f12.canon(doc)))+' '+lease,
               'lease_sha256':hashed}
        claims={k:{'stat':'0:0 600 1 65 '+v,'content':hashed+'\n'}
                for k,v in f12.markers(role).items()}
        live=before['snapshot']['probes'][f'vm-{role}-inactive-xml']['stdout']
        pred={'type':'F11N_NETWORKS' if role=='ssh' else 'F12_SSH',
              'plan':'/private/plan','receipt':'/private/receipt.json',
              'sha256':'c'*64}
        return (before,after,doc,grant,claims,live,pred)

    def classify(self,role,**replacement):
        before,after,doc,grant,claims,live,pred=self.fixture(role)
        return f12.classify(replacement.get('before',before),
            replacement.get('after',after),
            replacement.get('started',successful_command()),
            replacement.get('live',live),replacement.get('doc',doc),
            replacement.get('grant',grant),replacement.get('claims',claims),
            role,replacement.get('pred',pred),legacy,f4,f6)

    def mutate(self,record,key,value):
        result=deepcopy(record)
        result['snapshot']['probes'][key]['stdout']=value
        result['snapshot']['summary']=legacy.summarize(result['snapshot']['probes'])
        return result

    def test_roles_are_ssh_then_runner_only(self):
        self.assertEqual(f12.ROLES,('ssh','runner'))
        for role in ('ftp','smb','all','','SSH',None):
            with self.assertRaises(ValueError):f12.allowed(role)

    def test_start_allowlist_exact(self):
        for role in f12.ROLES:
            self.assertEqual(f12.command(role),('sudo','-n','virsh','-c',
                 'qemu:///system','start','ardrec-r33-dev-'+role))

    def test_stage_order_and_expected_states(self):
        self.assertEqual(f12.expected('ssh'),{'ssh':'SHUTOFF','runner':'SHUTOFF','ftp':'SHUTOFF','smb':'SHUTOFF'})
        self.assertEqual(f12.expected('ssh',True)['runner'],'SHUTOFF')
        self.assertEqual(f12.expected('runner')['ssh'],'RUNNING')
        self.assertEqual(f12.expected('runner',True)['runner'],'RUNNING')

    def test_new_ticket_no_traffic(self):
        for role in f12.ROLES:
            doc=f12.ticket(role,1,'a'*64)
            self.assertEqual(doc['expires_at']-doc['issued_at'],180)
            self.assertEqual(doc['p8_operational'],'NO-GO')
            self.assertEqual(doc['mode'],'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY')

    def test_ticket_invalid_nonce(self):
        for role in f12.ROLES:
            with self.assertRaises(ValueError):f12.ticket(role,1,'X'*64)

    def test_independent_leases_and_claims(self):
        self.assertNotEqual(f12.lease('ssh'),f12.lease('runner'))
        self.assertTrue(set(f12.markers('ssh').values()).isdisjoint(
                        f12.markers('runner').values()))

    def test_ssh_new_boot_valid(self):
        result=self.classify('ssh')
        self.assertEqual(result['role'],'ssh')
        self.assertFalse(result['traffic_authorized'])
        self.assertEqual(result['vm_starts_in_this_attempt'],1)
        self.assertEqual(result['a6'],'ND')

    def test_runner_new_boot_valid(self):
        result=self.classify('runner')
        self.assertEqual(result['guest_states']['runner'],'RUNNING')
        self.assertEqual(result['guest_states']['ssh'],'RUNNING')
        self.assertFalse(result['protocol_tested'])
        self.assertEqual(result['p8_operational'],'NO-GO')

    def test_ssh_precondition_all_off(self):
        with self.assertRaises(ValueError):
            f12.audited(self.ssh_after,'ssh',False,legacy,f4,f6)

    def test_runner_precondition_ssh_on(self):
        with self.assertRaises(ValueError):
            f12.audited(self.ssh_before,'runner',False,legacy,f4,f6)

    def test_runner_after_requires_running(self):
        with self.assertRaises(ValueError):
            self.classify('runner',after=self.runner_before)

    def test_ssh_after_requires_running(self):
        with self.assertRaises(ValueError):
            self.classify('ssh',after=self.ssh_before)

    def test_ftp_must_remain_off(self):
        changed=self.mutate(self.runner_after,'vm-ftp-state','running\n')
        with self.assertRaises(ValueError):self.classify('runner',after=changed)

    def test_smb_must_remain_off(self):
        changed=self.mutate(self.runner_after,'vm-smb-state','running\n')
        with self.assertRaises(ValueError):self.classify('runner',after=changed)

    def test_bridge_drift_not_tolerated(self):
        old=self.ssh_after['snapshot']['probes']['net-ssh-xml']['stdout']
        changed=self.mutate(self.ssh_after,'net-ssh-xml',old.replace('br33d30','br33bad'))
        with self.assertRaises(ValueError):self.classify('ssh',after=changed)

    def test_nat_not_tolerated(self):
        old=self.runner_after['snapshot']['probes']['net-smb-xml']['stdout']
        changed=self.mutate(self.runner_after,'net-smb-xml',old.replace(
            '</network>','<forward mode="nat"/></network>'))
        with self.assertRaises(ValueError):self.classify('runner',after=changed)

    def test_hook_drift_not_tolerated(self):
        changed=self.mutate(self.ssh_after,'f11-hook-hash','0'*64+' /wrong\n')
        with self.assertRaises(ValueError):self.classify('ssh',after=changed)

    def test_r34_drift_not_tolerated(self):
        changed=deepcopy(self.runner_after)
        import json
        payload=json.loads(changed['snapshot']['probes']['r34-nft']['stdout'])
        payload['nftables'].pop()
        changed=self.mutate(self.runner_after,'r34-nft',json.dumps(payload))
        with self.assertRaises(ValueError):self.classify('runner',after=changed)

    def test_missing_claim_rejected(self):
        before,after,doc,grant,claims,live,pred=self.fixture('ssh')
        claims.pop('active')
        with self.assertRaises(ValueError):self.classify('ssh',claims=claims)

    def test_claim_wrong_owner_rejected(self):
        before,after,doc,grant,claims,live,pred=self.fixture('runner')
        claims['stage']['stat']=claims['stage']['stat'].replace('0:0','1000:1000')
        with self.assertRaises(ValueError):self.classify('runner',claims=claims)

    def test_failed_start_rejected(self):
        command=successful_command();command['rc']=1
        with self.assertRaises(ValueError):self.classify('ssh',started=command)

    def test_additional_interface_rejected(self):
        before,after,doc,grant,claims,live,pred=self.fixture('runner')
        altered=live.replace('</devices>','<interface type="network"/></devices>')
        with self.assertRaises(ValueError):self.classify('runner',live=altered)

    def test_wrong_predecessor_rejected(self):
        for role in f12.ROLES:
            before,after,doc,grant,claims,live,pred=self.fixture(role)
            pred['type']='OTHER'
            with self.assertRaisesRegex(ValueError,'PREDECESSOR_TYPE_CHANGED'):
                self.classify(role,pred=pred)

    def test_boundary_exact_no_change(self):
        self.assertTrue(f12.boundary(self.ssh_before,deepcopy(self.ssh_before),
                       'ssh',legacy,f4,f6))

    def test_boundary_vm_state_change_rejected(self):
        with self.assertRaises(ValueError):
            f12.boundary(self.ssh_before,self.ssh_after,'ssh',legacy,f4,f6)

    def test_boundary_dynamic_connections_allowed(self):
        after=deepcopy(self.ssh_before)
        for service in f12.NETWORKS:
            key='net-'+service+'-xml'
            xml=after['snapshot']['probes'][key]['stdout']
            after['snapshot']['probes'][key]['stdout']=xml.replace(
                '<network>','<network connections="0">',1)
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        self.assertTrue(f12.boundary(self.ssh_before,after,'ssh',legacy,f4,f6))

    def test_no_unauthorized_host_operations_in_cli(self):
        source=(REPO/'scripts/ardrec_p14_r112_f12_postreboot_boot.py').read_text()
        self.assertNotIn("'net-start'",source)
        self.assertNotIn("'destroy'",source)
        self.assertNotIn("'shutdown'",source)
        self.assertNotIn("'nft','add'",source)
        self.assertIn("write(path/'boot.once'",source)

if __name__=='__main__':unittest.main()
