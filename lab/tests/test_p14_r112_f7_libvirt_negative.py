"""R112-F7: exact physical-negative contract, without starting real VM in CI."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest
import json

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f7_libvirt_negative as core
from ardrec.coordination import r112_f6_hook_lifecycle as f6core
import ardrec_p14_r112_f7_libvirt_negative as cli
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
from test_p14_r112_f6_hook_lifecycle import f5_ready_fixture


def measured():
    _, old=f5_ready_fixture()
    d=deepcopy(old)
    d['snapshot']['probes']['f11-hook-hash']['stdout']=core.HOOK_SHA+'  '+f6core.HOST_HOOK+'\n'
    d['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+f6core.HOST_HOOK+'\n'
    d['snapshot']['summary']=legacy.summarize(d['snapshot']['probes'])
    return d


def start_result(rc=1,marker=True,prepare=True):
    return {'rc':rc,'stdout':'', 'timeout':False,'truncated':False,
            'stderr':('error: Hook script execution failed: ' +
                      ('prepare begin - : ' if prepare else '') +
                      (core.DENIAL if marker else 'other libvirt error'))}


class PhysicalNegativeTests(unittest.TestCase):
    def setUp(self):
        self.d=TemporaryDirectory(prefix='r112-f7-unit-')
        self.addCleanup(self.d.cleanup)
        self.root=Path(self.d.name)
        p=patch.object(cli,'ROOT',self.root)
        p.start();self.addCleanup(p.stop)

    def test_source_exact_parent_and_p8(self):
        self.assertEqual(len(core.PARENT),40)
        self.assertEqual(core.START,('sudo','-n','virsh','-c','qemu:///system',
                                     'start','ardrec-r33-dev-ssh'))
        self.assertEqual(core.HOOK_SHA,f6core.NEW_HOOK_SHA256)

    def test_real_style_after_snapshot_is_valid(self):
        core.boundary(measured(),legacy,f4,f6core)

    def test_denied_by_libvirt_and_still_shutoff(self):
        m=measured()
        r=core.classify(m,deepcopy(m),start_result(),legacy,f4,f6core)
        self.assertTrue(r['libvirt_denied_with_exact_hook_marker'])
        self.assertEqual(r['physical_guest_starts'],0)
        self.assertEqual(r['physical_start_commands_attempted'],1)

    def test_generic_error_not_accepted(self):
        m=measured()
        with self.assertRaisesRegex(ValueError,'LIBVIRT_HOOK_DENIAL_NOT_ATTESTED'):
            core.classify(m,m,start_result(marker=False),legacy,f4,f6core)

    def test_wrong_hook_phase_not_accepted(self):
        m=measured()
        with self.assertRaisesRegex(ValueError,'LIBVIRT_HOOK_DENIAL_NOT_ATTESTED'):
            core.classify(m,m,start_result(prepare=False),legacy,f4,f6core)

    def test_successful_start_never_accepted(self):
        m=measured()
        with self.assertRaisesRegex(ValueError,'LIBVIRT_HOOK_DENIAL_NOT_ATTESTED'):
            core.classify(m,m,start_result(rc=0),legacy,f4,f6core)

    def test_timeout_is_not_a_denial(self):
        m=measured();x=start_result();x['timeout']=True
        with self.assertRaises(ValueError):
            core.classify(m,m,x,legacy,f4,f6core)

    def test_truncated_log_is_not_proof(self):
        m=measured();x=start_result();x['truncated']=True
        with self.assertRaises(ValueError):
            core.classify(m,m,x,legacy,f4,f6core)

    def test_guest_running_after_command_rejected(self):
        m=measured();a=deepcopy(m)
        a['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.classify(m,a,start_result(),legacy,f4,f6core)

    def test_nft_rule_drift_rejected(self):
        m=measured();a=deepcopy(m)
        nft=json.loads(a['snapshot']['probes']['r34-nft']['stdout'])
        nft['nftables'].pop()
        a['snapshot']['probes']['r34-nft']['stdout']=json.dumps(nft)
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.classify(m,a,start_result(),legacy,f4,f6core)

    def test_hook_digest_change_rejected(self):
        m=measured();a=deepcopy(m)
        a['snapshot']['probes']['f11-hook-hash']['stdout']='a'*64+'  '+f6core.HOST_HOOK+'\n'
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.classify(m,a,start_result(),legacy,f4,f6core)

    def test_network_deactivation_rejected(self):
        m=measured();a=deepcopy(m)
        a['english_info']['ssh']['stdout']=a['english_info']['ssh']['stdout'].replace('Active: yes','Active: no')
        with self.assertRaises(ValueError):
            core.classify(m,a,start_result(),legacy,f4,f6core)

    def test_missing_runner_nic_rejected(self):
        m=measured()
        m['snapshot']['summary']['domain_inventory']['runner']['interfaces'].pop()
        with self.assertRaises(ValueError):
            core.boundary(m,legacy,f4,f6core)

    def test_real_one_probe_and_durable_replay(self):
        m=measured()
        # All host calls are mocked. Exactly one physical mutation is allowed.
        with patch.object(cli,'source'), \
             patch.object(cli,'verify_f6',return_value='a'*64), \
             patch.object(cli,'admit_current',return_value=deepcopy(m)), \
             patch.object(cli.f6,'capture',return_value=deepcopy(m)), \
             patch.object(cli.legacy,'run',return_value=start_result()) as host:
            self.assertEqual(cli.plan(Path('/f6plan'),Path('/f6receipt')),0)
            plan=next(self.root.glob('plan-*'))
            self.assertEqual(cli.negative_probe(plan,Path('/f6plan'),Path('/f6receipt')),0)
            receipt=next(self.root.glob('probe-*'))
            self.assertEqual(cli.verify_probe(plan,receipt,Path('/f6plan'),Path('/f6receipt'))['physical_guest_starts'],0)
            host.assert_called_once_with(core.START)
            with self.assertRaisesRegex(ValueError,'ALREADY_ATTEMPTED'):
                cli.negative_probe(plan,Path('/f6plan'),Path('/f6receipt'))

    def test_inconclusive_probe_stops_without_retry(self):
        m=measured()
        with patch.object(cli,'source'), \
             patch.object(cli,'verify_f6',return_value='a'*64), \
             patch.object(cli,'admit_current',return_value=deepcopy(m)), \
             patch.object(cli.f6,'capture',return_value=deepcopy(m)), \
             patch.object(cli.legacy,'run',return_value=start_result(marker=False)) as host:
            self.assertEqual(cli.plan(Path('/f6plan'),Path('/f6receipt')),0)
            plan=next(self.root.glob('plan-*'))
            self.assertEqual(cli.negative_probe(plan,Path('/f6plan'),Path('/f6receipt')),24)
            host.assert_called_once_with(core.START)
            self.assertTrue((plan/'probe.once').exists())
            self.assertEqual(len(list(self.root.glob('probe-*'))),1)
            with self.assertRaisesRegex(ValueError,'ALREADY_ATTEMPTED'):
                cli.negative_probe(plan,Path('/f6plan'),Path('/f6receipt'))

    def test_no_lease_root_precondition(self):
        m=measured()
        ok={'rc':0,'stdout':'','stderr':'','timeout':False,'truncated':False}
        def probe(cmd):
            if cmd[:5]==('sudo','-n','test','!','-e'):
                return {**ok,'rc':1}
            return ok
        with patch.object(cli.f5,'inspect_scope'),patch.object(cli,'host',side_effect=probe),\
             patch.object(cli,'readok',return_value=''),patch.object(cli.f6,'capture',return_value=m):
            with self.assertRaisesRegex(ValueError,'F11_LEASE_ROOT_EXISTS'):
                cli.admit_current()

    def test_unrelated_running_domain_precondition(self):
        m=measured()
        ok={'rc':0,'stdout':'','stderr':'','timeout':False,'truncated':False}
        with patch.object(cli.f5,'inspect_scope'),patch.object(cli,'host',return_value=ok),\
             patch.object(cli,'readok',return_value='unrelated-vm\n'),\
             patch.object(cli.f6,'capture',return_value=m):
            with self.assertRaisesRegex(ValueError,'RUNNING_VM_PRESENT'):
                cli.admit_current()

    def test_script_contains_no_recovery_destroy_or_restart(self):
        src=(REPO/'scripts/ardrec_p14_r112_f7_libvirt_negative.py').read_text()
        self.assertNotIn("'virsh','destroy'",src)
        self.assertNotIn("'systemctl','restart'",src)
        self.assertNotIn("'nft','-f'",src)
        self.assertIn('NEGATIVE_PROBE_ALREADY_ATTEMPTED',src)

if __name__=='__main__':
    unittest.main()
