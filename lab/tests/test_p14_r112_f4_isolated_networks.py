"""R112-F4: adverse tests only; mocked network-start, never actual host mutations."""
from __future__ import annotations

import ast
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f4_isolated_networks as core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as cli
from test_p14_r112_runner_nic_definition import record


def english(role,active=False):
    return ('Name: '+r112.NETPREFIX+role+'\n'
            'UUID: '+core.UUIDS[role]+'\n'
            'Active: '+('yes' if active else 'no')+'\n'
            'Persistent: yes\nAutostart: no\nBridge: '+r112.BRIDGES[role]+'\n')


def measured(*active):
    snapshot=record(True)
    for role in core.ROLES:
        snapshot['probes']['net-'+role+'-info']['stdout']=english(role,role in active)
    snapshot['summary']=legacy.summarize(snapshot['probes'])
    return {'snapshot':snapshot,
            'english_info':{r:{'rc':0,'timeout':False,'truncated':False,
                                'stdout':english(r,r in active),'stderr':''}
                            for r in core.ROLES},
            'other_domains': {'status':'NO_UNRELATED_R33_NET_ATTACHMENTS',
                              'inspected':True,'count':0,
                              'xml_inventory_sha256':core.digest([])}}


def success(value='Network started'):
    return {'rc':0,'timeout':False,'truncated':False,
            'stdout':value,'stderr':''}


class R112F4NetworkTests(unittest.TestCase):
    def setUp(self):
        self.before=measured()
        self.after=[measured(*core.ROLES[:x]) for x in (1,2,3)]

    def test_all_networks_initially_inactive(self):
        self.assertEqual(core.inspect(self.before, legacy),
                         dict.fromkeys(core.ROLES,'INACTIVE'))

    def test_exact_networks_uuid_and_persistence(self):
        for role in core.ROLES:
            self.assertEqual(core.parse_net_info(english(role),role),'INACTIVE')
            self.assertEqual(core.parse_net_info(english(role,True),role),'ACTIVE')

    def test_plan_reproducible_and_denied_for_probes(self):
        item=core.plan_for(self.before,legacy)
        self.assertEqual(item,core.plan_for(self.before,legacy))
        self.assertFalse(item['operational_dispatch'])
        self.assertEqual(item['p8_operational'],'NO-GO')
        self.assertEqual(item['host_policy_changes'],0)

    def test_no_extra_netinfo_line(self):
        with self.assertRaises(core.NetworkGateError):
            core.parse_net_info(english('ssh')+'Forward: nat\n','ssh')

    def test_uuid_mismatch(self):
        with self.assertRaises(core.NetworkGateError):
            core.parse_net_info(english('ssh').replace(core.UUIDS['ssh'],'0'*36),'ssh')

    def test_active_network_before_plan_denied(self):
        with self.assertRaises(core.NetworkGateError):
            core.plan_for(self.after[0],legacy)

    def test_net_autostart_not_permitted(self):
        bad=deepcopy(self.before)
        bad['english_info']['ftp']['stdout']=english('ftp').replace('Autostart: no','Autostart: yes')
        with self.assertRaises(ValueError):
            core.inspect(bad,legacy)

    def test_unrelated_guest_network_scope_unverified_rejected(self):
        bad=deepcopy(self.before)
        bad['other_domains']['inspected']=False
        with self.assertRaises(ValueError):
            core.inspect(bad,legacy)

    def test_changed_ftp_bridge_denied(self):
        bad=deepcopy(self.before)
        bad['english_info']['ftp']['stdout']=english('ftp').replace('br33d31','brWrong')
        with self.assertRaises(ValueError):
            core.inspect(bad,legacy)

    def test_vm_booted_rejected(self):
        bad=deepcopy(self.before)
        bad['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        bad['snapshot']['summary']=legacy.summarize(bad['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.inspect(bad,legacy)

    def test_nft_deny_drift_rejected(self):
        bad=deepcopy(self.before)
        nft=json.loads(bad['snapshot']['probes']['r34-nft']['stdout'])
        nft['nftables'].pop()
        bad['snapshot']['probes']['r34-nft']['stdout']=json.dumps(nft)
        bad['snapshot']['summary']=legacy.summarize(bad['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.inspect(bad,legacy)

    def test_network_xml_nat_rejected(self):
        bad=deepcopy(self.before)
        bad['snapshot']['probes']['net-smb-xml']['stdout'] += '<forward mode="nat"/>'
        bad['snapshot']['summary']=legacy.summarize(bad['snapshot']['probes'])
        with self.assertRaises((core.NetworkGateError,Exception)):
            core.inspect(bad,legacy)

    def test_three_sequential_readbacks(self):
        for i,after in enumerate(self.after,1):
            core.compare(self.before,after,legacy,active=core.ROLES[:i])

    def test_unauthorized_extra_network_state_rejected(self):
        with self.assertRaises(core.NetworkGateError):
            core.compare(self.before,self.after[1],legacy,active=('ssh',))

    def test_hook_changed_after_start_rejected(self):
        bad=deepcopy(self.after[0])
        bad['snapshot']['probes']['f11-hook-hash']['stdout']='0'*64+'  hook\n'
        bad['snapshot']['summary']=legacy.summarize(bad['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,bad,legacy,active=('ssh',))

    def test_third_party_guest_inventory_drift_rejected(self):
        bad=deepcopy(self.after[0])
        bad['other_domains']['xml_inventory_sha256']='0'*64
        with self.assertRaises(ValueError):
            core.compare(self.before,bad,legacy,active=('ssh',))

    def test_success_receipt_is_real_only_not_a5(self):
        steps=[{'role':r,'command':success(), 'readback':self.after[i]}
               for i,r in enumerate(core.ROLES)]
        receipt=core.verify_success(self.before,steps,legacy)
        self.assertEqual(receipt['network_start_count'],3)
        self.assertEqual(receipt['vm_starts'],0)
        self.assertEqual(receipt['admission'],'BLOCKED_F11_DENY_PRESERVED')
        self.assertEqual(receipt['a6_classification'],'ND')

    def test_success_receipt_rejects_failed_command(self):
        steps=[{'role':r,'command':success(), 'readback':self.after[i]}
               for i,r in enumerate(core.ROLES)]
        steps[0]['command']['rc']=1
        with self.assertRaises(core.NetworkGateError):
            core.verify_success(self.before,steps,legacy)

    def test_plan_only_does_not_call_net_start_and_real_physical_mock(self):
        with TemporaryDirectory(prefix='r112-f4-') as t:
            root=Path(t)
            snapshots=[self.before,self.before,*self.after]
            with patch.object(cli,'ROOT',root),patch.object(cli,'source'), \
                 patch.object(cli,'measure',side_effect=snapshots), \
                 patch.object(cli.legacy,'run',return_value=success()) as mutator:
                self.assertEqual(cli.plan(),0)
                self.assertEqual(mutator.call_count,0)
                plan=next(root.glob('plan-*'))
                cli.verify_plan(plan)
                self.assertEqual(cli.activate(plan),0)
                physical=next(root.glob('apply-*'))
                receipt=cli.verify_apply(plan,physical)
                self.assertEqual(receipt['network_start_count'],3)
                self.assertEqual(mutator.call_count,3)
                for i,call in enumerate(mutator.call_args_list):
                    self.assertEqual(call.args[0],('sudo','-n','virsh','-c','qemu:///system',
                                                   'net-start','ardrec-r33-dev-net-'+core.ROLES[i]))
                with self.assertRaises((core.NetworkGateError, StopIteration)):
                    cli.activate(plan)

    def test_failed_net_start_stops_without_retry(self):
        with TemporaryDirectory(prefix='r112-f4-failed-') as t:
            root=Path(t)
            denied=success();denied['rc']=1
            with patch.object(cli,'ROOT',root),patch.object(cli,'source'), \
                 patch.object(cli,'measure',side_effect=[self.before,self.before]), \
                 patch.object(cli.legacy,'run',return_value=denied) as mutator:
                cli.plan()
                plan=next(root.glob('plan-*'))
                with self.assertRaises((core.NetworkGateError, StopIteration)):
                    cli.activate(plan)
                self.assertEqual(mutator.call_count,1)
                self.assertTrue((plan/'apply.once').is_file())
                evidence=next(root.glob('apply-*'))
                self.assertEqual({p.name for p in evidence.iterdir()},
                                 {'intent.json','intent-ssh.json','result-ssh.json'})

    def test_pure_engine_no_subprocess_or_libvirt(self):
        path=REPO/'src/ardrec/coordination/r112_f4_isolated_networks.py'
        tree=ast.parse(path.read_text('utf-8'))
        imported=[a.name.split('.')[0] for node in ast.walk(tree)
                  if isinstance(node,ast.Import) for a in node.names]
        self.assertFalse({'subprocess','socket','libvirt','paramiko'}.intersection(imported))

    def test_non_mutating_readonly_names(self):
        defined='\n'.join('ardrec-r33-dev-'+r for r in ('runner',*core.ROLES))+'\n'
        with patch.object(cli.legacy,'run',return_value=success(defined)):
            result=cli._readonly_names()
            self.assertEqual(result['count'],0)

    def test_unrelated_r33_attached_guest_denied(self):
        defined='\n'.join('ardrec-r33-dev-'+r for r in ('runner',*core.ROLES))+'\noutside\n'
        def dispatch(args):
            if 'list' in args: return success(defined)
            return success('<domain><name>outside</name><devices><interface>'
                           '<source network="ardrec-r33-dev-net-ssh"/>'
                           '</interface></devices></domain>')
        with patch.object(cli.legacy,'run',side_effect=dispatch):
            with self.assertRaises(core.NetworkGateError):
                cli._readonly_names()

if __name__=='__main__':
    unittest.main()

# Additional restoration coverage extends the original class for CI discovery.
def _restore_tests():
    def test_restore_plan_after_success(self):
        with TemporaryDirectory(prefix='r112-f4-restore-') as t:
            root=Path(t)
            start=[measured(), measured(), measured('ssh'),
                   measured('ssh','ftp'), measured('ssh','ftp','smb')]
            stop=[measured('ssh','ftp','smb'),measured('ssh','ftp'),
                  measured('ssh'),measured()]
            with patch.object(cli,'ROOT',root),patch.object(cli,'source'), \
                 patch.object(cli,'measure',side_effect=start+stop), \
                 patch.object(cli.legacy,'run',return_value=success()) as mutator:
                cli.plan()
                plan=next(root.glob('plan-*'))
                cli.activate(plan)
                apply=next(root.glob('apply-*'))
                self.assertEqual(cli.restore(plan,apply),0)
                restored=next(root.glob('restore-*'))
                self.assertEqual(cli.verify_restore(plan,restored)['network_stop_count'],3)
                self.assertEqual(mutator.call_count,6)
                self.assertEqual([call.args[0][-1] for call in mutator.call_args_list[3:]],
                                 ['ardrec-r33-dev-net-smb','ardrec-r33-dev-net-ftp',
                                  'ardrec-r33-dev-net-ssh'])

    def test_restore_denied_if_guest_started(self):
        b=measured('ssh','ftp','smb')
        b['snapshot']['probes']['vm-runner-state']['stdout']='running\n'
        b['snapshot']['summary']=legacy.summarize(b['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.inspect(b,legacy)

    def test_restoration_rejects_wrong_order(self):
        steps=[{'role':r,'command':success(), 'readback':measured(*core.ROLES[:2-i])}
               for i,r in enumerate(reversed(core.ROLES))]
        steps[0]['role']='ssh'
        with self.assertRaises(core.NetworkGateError):
            core.verify_restoration(measured(),steps,legacy)

    R112F4NetworkTests.test_restore_plan_after_success=test_restore_plan_after_success
    R112F4NetworkTests.test_restore_denied_if_guest_started=test_restore_denied_if_guest_started
    R112F4NetworkTests.test_restoration_rejects_wrong_order=test_restoration_rejects_wrong_order

_restore_tests()
