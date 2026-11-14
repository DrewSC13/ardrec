"""R39: synthetic independent oracles; NO libvirt or VM access."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r39_ssh_reconciliation as r39
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r35_inactive_deployment as r35

S='f'*64
CAPTURE='2026-11-14T21:40:00Z'


def chain():
    return {
        'preflight_report_sha256': S,
        'preflight_file_sha256': '1'*64,
        'first_boot_report_sha256': '2'*64,
        'first_boot_file_sha256': '3'*64,
        'first_boot_commands_sha256': '4'*64,
        'source_evidence': {'test':'synthetic'},
    }


def live():
    return {'phase':'NETWORK_ONLY',
            'active_networks':[r365.SSH_NETWORK],
            'active_domains':[],
            'reserved_links':[r365.t33.NET_BRIDGE['ssh']],
            'bridge_macs':copy.deepcopy(r35.R354_EXISTING_BRIDGE_MACS),
            'deny_first_still_verified':True}


def row(argv, rc=0):
    return json.dumps({'argv':argv,'returncode':rc},sort_keys=True).encode()+b'\n'


def ledger():
    return b''.join([
        row(['/usr/bin/virsh','--readonly','-c','qemu:///system','net-list','--name']),
        row(['/usr/bin/sudo','-n','--','/usr/bin/virsh','-c','qemu:///system','net-start',r365.SSH_NETWORK]),
        row(['/usr/bin/virsh','--readonly','-c','qemu:///system','list','--name']),
        row(['/usr/bin/sudo','-n','--','/usr/bin/virsh','-c','qemu:///system','start',r365.SSH_DOMAIN])
    ])


class ReconciliationTests(unittest.TestCase):
    def test_reconciles_network_active_domain_off(self):
        source=chain(); state=live()
        result=r39.reconcile(source,state,captured_at_utc=CAPTURE)
        self.assertTrue(r39.verify_report(result))
        self.assertEqual(result['status'],r39.RESULT)
        self.assertFalse(result['guest_isolation_tested'])
        self.assertEqual(result['p8_operational'],'NO-GO')
        self.assertFalse(result['operational_dispatch'])
        self.assertIsNone(result['final_risk'])
        self.assertEqual(source,chain())
        self.assertEqual(state,live())
        self.assertEqual(result,r39.reconcile(source,state,captured_at_utc=CAPTURE))

    def test_vm_running_unexpected(self):
        state=live();state['active_domains']=[r365.SSH_DOMAIN]
        with self.assertRaisesRegex(r39.R39Error,'live_state_not_network_only'):
            r39.reconcile(chain(),state,captured_at_utc=CAPTURE)

    def test_network_inactive_unexpected(self):
        state=live();state['active_networks']=[]
        with self.assertRaises(r39.R39Error):
            r39.reconcile(chain(),state,captured_at_utc=CAPTURE)

    def test_extra_bridge_rejected(self):
        state=live();state['reserved_links'].append('br33d31')
        with self.assertRaises(r39.R39Error):
            r39.reconcile(chain(),state,captured_at_utc=CAPTURE)

    def test_policy_unverified_rejected(self):
        state=live();state['deny_first_still_verified']=False
        with self.assertRaises(r39.R39Error):
            r39.reconcile(chain(),state,captured_at_utc=CAPTURE)

    def test_mac_drift_rejected(self):
        state=live();state['bridge_macs']['ssh']='52:54:00:00:00:00'
        with self.assertRaises(r39.R39Error):
            r39.reconcile(chain(),state,captured_at_utc=CAPTURE)

    def test_noncanonical_capture_rejected(self):
        with self.assertRaisesRegex(r39.R39Error,'capture_time_noncanonical'):
            r39.reconcile(chain(),live(),captured_at_utc='2026-11-14T21:40:0Z')

    def test_mutated_report_rejected(self):
        out=r39.reconcile(chain(),live(),captured_at_utc=CAPTURE)
        out['p8_operational']='GO'
        with self.assertRaises(r39.R39Error):
            r39.verify_report(out)

    def test_rehashed_false_authority_rejected(self):
        out=r39.reconcile(chain(),live(),captured_at_utc=CAPTURE)
        out['guest_isolation_tested']=True
        out['sha256']=r39.sha(r39.canon({k:v for k,v in out.items() if k!='sha256'}))
        with self.assertRaisesRegex(r39.R39Error,'reconciliation_false_authority'):
            r39.verify_report(out)

    def test_ledger_exact_order(self):
        rows=r39._calls_from_ledger(ledger())
        self.assertEqual(len(rows),2)

    def test_ledger_wrong_order_rejected(self):
        raw=(row(['/usr/bin/virsh','-c','qemu:///system','start',r365.SSH_DOMAIN])+
             row(['/usr/bin/virsh','-c','qemu:///system','net-start',r365.SSH_NETWORK]))
        with self.assertRaisesRegex(r39.R39Error,'boot_ledger_activation_order_invalid'):
            r39._calls_from_ledger(raw)

    def test_ledger_unexpected_guest_action_rejected(self):
        raw=ledger()+row(['/usr/bin/virsh','-c','qemu:///system','destroy',r365.SSH_DOMAIN])
        with self.assertRaises(r39.R39Error):
            r39._calls_from_ledger(raw)

    def test_ledger_failed_start_rejected(self):
        raw=(row(['/usr/bin/virsh','-c','qemu:///system','net-start',r365.SSH_NETWORK])+ 
             row(['/usr/bin/virsh','-c','qemu:///system','start',r365.SSH_DOMAIN],1))
        with self.assertRaisesRegex(r39.R39Error,'boot_ledger_activation_failure'):
            r39._calls_from_ledger(raw)

    def test_ledger_shell_rejected(self):
        with self.assertRaisesRegex(r39.R39Error,'boot_ledger_unknown_executable'):
            r39._calls_from_ledger(ledger()+row(['/bin/sh','-c','virsh start foo']))

    def test_readonly_virsh_command_scope(self):
        host=object.__new__(r39.ReadOnlyHost)
        host.bin={'sudo':'/usr/bin/sudo','virsh':'/usr/bin/virsh'}
        log=[]
        host.run=lambda argv,**kwargs:log.append(argv) or b'good'
        self.assertEqual(host.virsh_ro(['domstate',r365.SSH_DOMAIN]),b'good')
        self.assertEqual(log[0][:7],['/usr/bin/sudo','-n','--','/usr/bin/virsh','--readonly','-c','qemu:///system'])
        for args in (['start',r365.SSH_DOMAIN],['net-start',r365.SSH_NETWORK],
                     ['dumpxml','foreign-domain','--inactive']):
            with self.assertRaisesRegex(r39.R39Error,'virsh_scope_invalid'):
                host.virsh_ro(args)
        self.assertEqual(len(log),1)

    def test_inherited_activation_is_explicitly_forbidden(self):
        host=object.__new__(r39.ReadOnlyHost)
        with self.assertRaisesRegex(r39.R39Error,'r39_mutation_forbidden'):
            host.activate_ssh_network()
        with self.assertRaisesRegex(r39.R39Error,'r39_mutation_forbidden'):
            host.activate_ssh_domain()

    def test_capture_current_has_no_activation(self):
        host=mock.Mock()
        expected=live()
        with mock.patch.object(r39.r365,'current',return_value=expected) as current:
            result=r39.capture_current(host)
        self.assertIs(result,expected)
        current.assert_called_once_with(host,phase='NETWORK_ONLY')
        host.activate_ssh_domain.assert_not_called()
        host.activate_ssh_network.assert_not_called()

    def test_local_receipt_permissions_and_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);base.chmod(0o700)
            dst=base/'r39-receipts'
            report=r39.reconcile(chain(),live(),captured_at_utc=CAPTURE)
            r39.persist_private(dst,report)
            data=(dst/'r39_reconciliation.json').read_bytes()
            self.assertEqual(json.loads(data),report)
            self.assertEqual((dst/'SHA256SUMS').read_bytes(),
                             hashlib.sha256(data).hexdigest().encode()+b'  r39_reconciliation.json\n')
            self.assertEqual(stat.S_IMODE(dst.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((dst/'r39_reconciliation.json').stat().st_mode),0o600)
            with self.assertRaises(r39.R39Error):
                r39.persist_private(dst,report)

    def test_world_access_parent_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);base.chmod(0o755)
            with self.assertRaisesRegex(r39.R39Error,'receipt_parent_not_private'):
                r39.persist_private(base/'foo',r39.reconcile(chain(),live(),captured_at_utc=CAPTURE))

    def test_symlink_destination_parent_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'private').mkdir(mode=0o700)
            (root/'alias').symlink_to(root/'private',target_is_directory=True)
            with self.assertRaisesRegex(r39.R39Error,'receipt_destination_invalid'):
                r39.persist_private(root/'alias'/'receipt',r39.reconcile(chain(),live(),captured_at_utc=CAPTURE))

    def test_r365_receipt_chain_valid_fixture(self):
        f={'schema':r365.SCHEMA,'mode':'FIRST_BOOT_AUTHORIZED',
            'status':'FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED',
            'source_main':r365.EXPECTED_MAIN,'source_archive_sha256':r35.ARCHIVE_SHA256,
            'source_evidence':{'fixture':'r365-synthetic'},'source_preflight_sha256':S,
            'storage_verified':True,'host_state':{'phase':'BEFORE'},
            'network_phase_readback':{'phase':'NETWORK_ONLY'},
            'final_readback':{'phase':'SSH_RUNNING'},
            'attempted_mutations':r39.EXPECTED_ATTEMPTS[:],
            'host_mutations':r39.EXPECTED_ATTEMPTS[:],
            'network_started':True,'vm_started':True,
            'guest_isolation_tested':False,'real_service_testing':'NOT_EXECUTED',
            'operational_dispatch':False,'final_risk':None,'experimental_validation':'NOT_RUN',
            'p8_operational':'NO-GO','automatic_rollback':False,'failure_code':None}
        f['sha256']=r39.sha(r39.canon(f))
        payload=r39.canon(f)+b'\n'
        documents=[{'r365_report.json':payload, 'commands.jsonl':ledger()},
                   {'r365_report.json':b'preflight-synthetic', 'commands.jsonl':b'readonly'}]
        with mock.patch.object(r39,'verified_directory',side_effect=documents), \
             mock.patch.object(r39.r365,'verify_preflight_receipt',
                               return_value={'sha256':S}):
            summary=r39.read_r365_chain(Path('/preflight'),Path('/boot'))
        self.assertEqual(summary['first_boot_report_sha256'],f['sha256'])
        self.assertEqual(summary['source_evidence'],f['source_evidence'])
        self.assertEqual(summary['first_boot_commands_sha256'],hashlib.sha256(ledger()).hexdigest())

    def test_r365_first_boot_receipt_rehashed_claim_rejected(self):
        s=chain()
        f={'schema':r365.SCHEMA,'mode':'FIRST_BOOT_AUTHORIZED',
            'status':'FIRST_BOOT_DENY_POLICY_PRESENT_UNTESTED',
            'source_main':r365.EXPECTED_MAIN,'source_archive_sha256':r35.ARCHIVE_SHA256,
            'source_evidence':s['source_evidence'],'source_preflight_sha256':S,
            'storage_verified':True,'host_state':{'phase':'BEFORE'},
            'network_phase_readback':{'phase':'NETWORK_ONLY'},
            'final_readback':{'phase':'SSH_RUNNING'},
            'attempted_mutations':r39.EXPECTED_ATTEMPTS,
            'host_mutations':r39.EXPECTED_ATTEMPTS,
            'network_started':True,'vm_started':True,
            'guest_isolation_tested':False,'real_service_testing':'NOT_EXECUTED',
            'operational_dispatch':False,'final_risk':None,'experimental_validation':'NOT_RUN',
            'p8_operational':'NO-GO','automatic_rollback':False,'failure_code':None}
        f['sha256']=r39.sha(r39.canon(f))
        doc=copy.deepcopy(f)
        doc['guest_isolation_tested']=True
        doc['sha256']=r39.sha(r39.canon({k:v for k,v in doc.items() if k!='sha256'}))
        with mock.patch.object(r39,'verified_directory',return_value={
            'r365_report.json':r39.canon(doc), 'commands.jsonl':ledger()}):
            with self.assertRaisesRegex(r39.R39Error,'first_boot_source_contract_invalid'):
                r39.read_r365_chain(Path('/preflight'),Path('/boot'))

if __name__=='__main__':unittest.main()
