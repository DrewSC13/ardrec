"""F11N offline regression fixtures. Never invokes real libvirt starts."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import json
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'lab/tests')]
import ardrec_p14_r112_f11n_postreboot_network as cli
from ardrec.coordination import r112_f11_postreboot_network as core
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
from test_p14_r112_f7_libvirt_negative import measured as real_style_fixture
from test_p14_r112_f4_isolated_networks import english


def fixture(*active):
    data=deepcopy(real_style_fixture())
    for role in core.NETWORKS:
        value=english(role,role in active)
        data['english_info'][role]['stdout']=value
        data['snapshot']['probes']['net-'+role+'-info']['stdout']=value
    data['snapshot']['summary']=legacy.summarize(data['snapshot']['probes'])
    return data


def good_step(role,after):
    return {'role':role,'command':{'rc':0,'stdout':'Network started\n',
             'stderr':'','timeout':False,'truncated':False},'after':after}


class RebootNetworkTests(unittest.TestCase):
    def setUp(self):
        self.before=fixture()
        self.after=[fixture(*core.NETWORKS[:i]) for i in (1,2,3)]

    def test_before_all_inactive(self):
        self.assertEqual(core.network_states(self.before,legacy,f4),
                         {'ssh':'INACTIVE','ftp':'INACTIVE','smb':'INACTIVE'})

    def test_three_staged_transitions(self):
        for idx,after in enumerate(self.after,1):
            self.assertTrue(core.compare(self.before,after,core.NETWORKS[:idx],legacy,f4))

    def test_exact_three_steps_receipt(self):
        steps=[good_step(role,snapshot) for role,snapshot in zip(core.NETWORKS,self.after)]
        rec=core.verify_steps(self.before,steps,legacy,f4)
        self.assertEqual(rec['network_start_count'],3)
        self.assertEqual(rec['guest_start_count'],0)
        self.assertFalse(rec['traffic_authorized'])
        self.assertEqual(rec['p8_operational'],'NO-GO')

    def test_reject_out_of_order_transition(self):
        with self.assertRaises(ValueError):
            core.compare(self.before,self.after[0],('ftp',),legacy,f4)

    def test_reject_running_guest(self):
        broken=deepcopy(self.after[0])
        broken['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_changed_bridge(self):
        broken=deepcopy(self.after[0])
        key='net-ssh-xml'
        broken['snapshot']['probes'][key]['stdout']=broken['snapshot']['probes'][key]['stdout'].replace('br33d30','br33bad')
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_added_forwarding(self):
        broken=deepcopy(self.after[0])
        key='net-ssh-xml'
        broken['snapshot']['probes'][key]['stdout']=broken['snapshot']['probes'][key]['stdout'].replace('</network>','<forward mode="nat"/></network>')
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_changed_hook(self):
        broken=deepcopy(self.after[0])
        broken['snapshot']['probes']['f11-hook-hash']['stdout']='0'*64+' /hook\n'
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_nft_missing_rule(self):
        broken=deepcopy(self.after[0])
        key='r34-nft'
        nft=json.loads(broken['snapshot']['probes'][key]['stdout'])
        nft['nftables'].pop()
        broken['snapshot']['probes'][key]['stdout']=json.dumps(nft)
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_nwfilter_relaxation(self):
        broken=deepcopy(self.after[0])
        key='deny-nwfilter-xml'
        broken['snapshot']['probes'][key]['stdout']=broken['snapshot']['probes'][key]['stdout'].replace('action="drop"','action="accept"')
        broken['snapshot']['summary']=legacy.summarize(broken['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_unrelated_attachment_uncertainty(self):
        broken=deepcopy(self.after[0]);broken['other_domains']['inspected']=False
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_truncated_snapshot(self):
        broken=deepcopy(self.after[0]);broken['snapshot']['probes']['r34-nft']['truncated']=True
        with self.assertRaises(ValueError):
            core.compare(self.before,broken,('ssh',),legacy,f4)

    def test_reject_failure_in_one_step(self):
        steps=[good_step(role,snapshot) for role,snapshot in zip(core.NETWORKS,self.after)]
        steps[1]['command']['rc']=1
        with self.assertRaises(ValueError):
            core.verify_steps(self.before,steps,legacy,f4)

    def test_reject_previously_active_network(self):
        with self.assertRaises(ValueError):
            core.compare(self.after[0],self.after[1],('ssh','ftp'),legacy,f4)

    def test_runtime_root_connections_only_tolerated(self):
        changed=deepcopy(self.after[0])
        key='net-ssh-xml'
        raw=changed['snapshot']['probes'][key]['stdout']
        if '<network>' in raw:
            changed['snapshot']['probes'][key]['stdout']=raw.replace('<network>','<network connections="1">',1)
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        self.assertTrue(core.compare(self.before,changed,('ssh',),legacy,f4))

    def test_mocked_three_real_commands_and_replay(self):
        # Controlled unit fake only. Real transitions are host-measured on Prometheus.
        snapshots=[self.before,self.before,*self.after]
        calls=[]
        def network_command(argv,timeout=30):
            calls.append(tuple(argv))
            return {'rc':0,'stdout':'Network started\n','stderr':'',
                    'timeout':False,'truncated':False}
        with TemporaryDirectory(prefix='f11n-test-') as tmp, \
             patch.object(cli,'ROOT',Path(tmp)/'lab'), \
             patch.object(cli,'source'), \
             patch.object(cli,'no_leases'), \
             patch.object(cli,'read_host',side_effect=deepcopy(snapshots)), \
             patch.object(cli,'cmd',side_effect=network_command):
            self.assertEqual(cli.plan(),0)
            plan=next(cli.ROOT.glob('plan-*'))
            self.assertEqual(cli.activate(plan),0)
            receipt=next(cli.ROOT.glob('apply-*'))
            self.assertEqual(cli.replay(plan,receipt)['network_start_count'],3)
            self.assertEqual([c[-1] for c in calls],
                             ['ardrec-r33-dev-net-'+r for r in core.NETWORKS])
            self.assertTrue((plan/'apply.once').is_file())

    def test_mocked_failed_command_keeps_one_time_marker(self):
        with TemporaryDirectory(prefix='f11n-fail-') as tmp, \
             patch.object(cli,'ROOT',Path(tmp)/'lab'), \
             patch.object(cli,'source'), \
             patch.object(cli,'no_leases'), \
             patch.object(cli,'read_host',side_effect=deepcopy([self.before,self.before])), \
             patch.object(cli,'cmd',return_value={
                 'rc':1,'stdout':'','stderr':'failed',
                 'timeout':False,'truncated':False}) as called:
            self.assertEqual(cli.plan(),0)
            plan=next(cli.ROOT.glob('plan-*'))
            with self.assertRaisesRegex(ValueError,'NETWORK_START_FAILED_OR_UNCERTAIN'):
                cli.activate(plan)
            called.assert_called_once()
            self.assertEqual(len(list(cli.ROOT.glob('apply-*'))),1)
            self.assertEqual((plan/'apply.once').read_bytes(),b'ATTEMPTED\n')
            with self.assertRaisesRegex(ValueError,'ALREADY_ATTEMPTED'):
                cli.activate(plan)
            called.assert_called_once()

    def test_only_network_starts_in_physical_script(self):
        source=(ROOT/'scripts/ardrec_p14_r112_f11n_postreboot_network.py').read_text()
        self.assertIn("'net-start'",source)
        self.assertNotIn("'virsh','-c','qemu:///system','start'",source)
        self.assertNotIn("'nft','add'",source)
        self.assertNotIn("'net-destroy'",source)
        self.assertIn("'apply.once'",source)
        self.assertIn("NO_RETRY_NO_ROLLBACK_NO_HOST_CLEANUP",source)

if __name__=='__main__':unittest.main()
