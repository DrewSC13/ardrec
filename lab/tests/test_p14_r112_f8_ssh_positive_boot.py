"""R112-F8: adversarial no-host test of the real positive QEMU SSH boot contract."""
from __future__ import annotations
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f8_ssh_positive_boot as core
import ardrec_p14_r112_f8_ssh_positive_boot as cli
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f6_hook_lifecycle as f6
from test_p14_r112_f7_libvirt_negative import measured


def after_ssh(before=None):
    a=deepcopy(before if before is not None else measured())
    a['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
    a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
    return a


def successful_command():
    return {'rc':0,'stdout':'Domain started\n','stderr':'',
            'timeout':False,'truncated':False}


def fabricated_proofs(doc):
    raw=core.canon(doc)
    sha=hashlib.sha256(raw).hexdigest()
    grant={'directory_stat':'0:0 700 '+core.LEASE_ROOT,
           'lease_stat':'0:0 600 1 '+str(len(raw))+' '+core.LEASE_PATH,
           'lease_sha256':sha}
    claims={kind:{'stat':'0:0 600 1 65 '+path,'content':sha+'\n'}
            for kind,path in core.MARKERS.items()}
    return grant,claims

class PositiveBootTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix='r112-f8-test-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        p=patch.object(cli,'ROOT',self.root)
        p.start();self.addCleanup(p.stop)
        self.before=measured()
        self.after=after_ssh(self.before)
        self.doc=core.ticket(1795094100,'a'*64)
        self.grant,self.claims=fabricated_proofs(self.doc)
        self.live=self.before['snapshot']['probes']['vm-ssh-inactive-xml']['stdout']

    def classify(self,*,before=None,after=None,start=None,live=None,doc=None,
                 grant=None,claims=None):
        return core.classify(before if before is not None else self.before,
              after if after is not None else self.after,
              start if start is not None else successful_command(),
              live if live is not None else self.live,
              doc if doc is not None else self.doc,
              grant if grant is not None else self.grant,
              claims if claims is not None else self.claims,
              legacy,f4,f6)

    def test_exact_target_and_source(self):
        self.assertEqual(core.START,('sudo','-n','virsh','-c','qemu:///system',
                                    'start','ardrec-r33-dev-ssh'))
        self.assertEqual(len(core.PARENT),40)
        self.assertEqual(len(core.HOOK_SHA),64)

    def test_ticket_exact_and_short_lifetime(self):
        self.assertEqual(self.doc['expires_at']-self.doc['issued_at'],180)
        self.assertEqual(self.doc['phases'],['prepare','start','started'])
        self.assertEqual(self.doc['p8_operational'],'NO-GO')

    def test_ticket_rejects_invalid_nonce_and_clock(self):
        for now,nonce in ((0,'a'*64),(True,'a'*64),(1,'g'*64),(1,'abc')):
            with self.assertRaises(ValueError):core.ticket(now,nonce)

    def test_exact_physical_boot_fixture(self):
        self.assertEqual(self.classify()['guest_running'],True)
        self.assertEqual(self.classify()['f11_boot_phases_attested'],
                         ['prepare','start','started'])
        self.assertFalse(self.classify()['traffic_granted'])

    def test_no_service_protocol_or_p8_claim(self):
        r=self.classify()
        self.assertEqual(r['a6'],'ND')
        self.assertEqual(r['a7_rf'],'NOT_CONFIRMED')
        self.assertFalse(r['service_protocol_verified'])
        self.assertEqual(r['p8_operational'],'NO-GO')

    def test_preflight_requires_four_offline(self):
        with self.assertRaisesRegex(ValueError,'VM_STATE_ssh'):
            core.audited(self.after,ssh_running=False,legacy=legacy,f4=f4,f6=f6)

    def test_start_without_running_guest_rejected(self):
        with self.assertRaisesRegex(ValueError,'VM_STATE_ssh'):
            self.classify(after=self.before)

    def test_running_runner_rejected(self):
        a=deepcopy(self.after)
        a['snapshot']['probes']['vm-runner-state']['stdout']='running\n'
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaisesRegex(ValueError,'VM_STATE_runner'):
            self.classify(after=a)

    def test_broken_nft_rule_rejected(self):
        a=deepcopy(self.after)
        import json
        content=json.loads(a['snapshot']['probes']['r34-nft']['stdout'])
        content['nftables'].pop()
        a['snapshot']['probes']['r34-nft']['stdout']=json.dumps(content)
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):self.classify(after=a)

    def test_hook_hash_drift_rejected(self):
        a=deepcopy(self.after)
        a['snapshot']['probes']['f11-hook-hash']['stdout']='f'*64+'  '+f6.core.HOST_HOOK+'\n'
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):self.classify(after=a)

    def test_network_deactivation_rejected(self):
        a=deepcopy(self.after)
        a['english_info']['ssh']['stdout']=a['english_info']['ssh']['stdout'].replace(
            'Active: yes','Active: no')
        with self.assertRaises(ValueError):self.classify(after=a)

    def test_modified_inactive_guest_xml_rejected(self):
        a=deepcopy(self.after)
        a['snapshot']['probes']['vm-ssh-inactive-xml']['stdout'] = (
            a['snapshot']['probes']['vm-ssh-inactive-xml']['stdout'].replace(
              'a33d30t','compromised'))
        a['snapshot']['summary']=legacy.summarize(a['snapshot']['probes'])
        with self.assertRaises(ValueError):self.classify(after=a)

    def test_extra_host_device_in_live_xml_rejected(self):
        raw=self.live.replace('</devices>', '<hostdev mode="subsystem"/>'+'</devices>')
        with self.assertRaises(ValueError):self.classify(live=raw)

    def test_generic_virsh_error_not_boot_evidence(self):
        result=successful_command();result['rc']=1
        with self.assertRaisesRegex(ValueError,'START_NOT_ACKNOWLEDGED'):
            self.classify(start=result)

    def test_timeout_not_boot_evidence(self):
        result=successful_command();result['timeout']=True
        with self.assertRaises(ValueError):self.classify(start=result)

    def test_missing_active_hook_phase_rejected(self):
        claims=deepcopy(self.claims);claims['active']['content']='b'*64+'\n'
        with self.assertRaisesRegex(ValueError,'STAGE_CLAIM_NOT_COMPLETED_active'):
            self.classify(claims=claims)

    def test_missing_prepare_hook_phase_rejected(self):
        claims=deepcopy(self.claims);claims.pop('used')
        with self.assertRaises(ValueError):self.classify(claims=claims)

    def test_claim_with_wrong_mode_rejected(self):
        claims=deepcopy(self.claims)
        claims['stage']['stat']=claims['stage']['stat'].replace('600','644')
        with self.assertRaises(ValueError):self.classify(claims=claims)

    def test_root_lease_hash_changed_rejected(self):
        grant=deepcopy(self.grant);grant['lease_sha256']='b'*64
        with self.assertRaises(ValueError):self.classify(grant=grant)

    def test_script_does_not_auto_shutdown_or_change_firewall(self):
        text=(REPO/'scripts/ardrec_p14_r112_f8_ssh_positive_boot.py').read_text()
        self.assertNotIn("'nft','-f'",text)
        self.assertNotIn("'virsh','destroy'",text)
        self.assertNotIn("'systemctl','restart'",text)
        self.assertIn('NO_RETRY_NO_AUTOMATIC_SHUTDOWN',text)
        self.assertEqual(text.count('host(core.START,timeout=90)'),1)

    def test_real_f7_f6_core_contract_matches_physical_style_snapshot(self):
        """Avoid mock of F7/F6 boundary; previously AttributeError on host."""
        expected=deepcopy(self.before)
        self.assertTrue(cli.f7_core.same(self.before,expected,legacy,f4,f6.core))

    def test_preboot_drift_never_issues_lease_or_start(self):
        """Fail before boot.once, any root write, or virsh start on host drift."""
        drift=deepcopy(self.before)
        drift['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        drift['snapshot']['summary']=legacy.summarize(drift['snapshot']['probes'])
        with patch.object(cli,'source'), \
             patch.object(cli,'provenance',return_value='c'*64), \
             patch.object(cli,'host_preflight',side_effect=[deepcopy(self.before),drift]), \
             patch.object(cli,'host',side_effect=AssertionError('HOST_CALL_NOT_ALLOWED')) as host:
            self.assertEqual(cli.plan(Path('/f7plan'),Path('/f7receipt'),
                                      Path('/f6plan'),Path('/f6receipt')),0)
            plan=next(self.root.glob('plan-*'))
            with self.assertRaises(ValueError):
                cli.boot(plan,Path('/f7plan'),Path('/f7receipt'),
                         Path('/f6plan'),Path('/f6receipt'))
            self.assertFalse((plan/'boot.once').exists())
            self.assertEqual(list(self.root.glob('boot-*')),[])
            host.assert_not_called()

    def test_plan_and_one_real_boot_durable_replay_mocked(self):
        with patch.object(cli,'source'), \
             patch.object(cli,'provenance',return_value='c'*64), \
             patch.object(cli,'host_preflight',return_value=deepcopy(self.before)), \
             patch.object(cli.f6,'capture',return_value=deepcopy(self.after)), \
             patch.object(cli,'grant_readback',return_value=self.grant), \
             patch.object(cli,'claim_readback',return_value=self.claims), \
             patch.object(cli.time,'time',return_value=1795094100), \
             patch.object(cli.secrets,'token_hex',return_value='a'*64):
            def fake(cmd,*,timeout=16):
                if cmd[:4]==('virsh','--readonly','-c','qemu:///system'):
                    return {**successful_command(),'stdout':self.live}
                return successful_command()
            with patch.object(cli,'host',side_effect=fake) as host:
                self.assertEqual(cli.plan(Path('/f7plan'),Path('/f7receipt'),
                                          Path('/f6plan'),Path('/f6receipt')),0)
                plan=next(self.root.glob('plan-*'))
                self.assertEqual(cli.boot(plan,Path('/f7plan'),Path('/f7receipt'),
                                          Path('/f6plan'),Path('/f6receipt')),0)
                receipt=next(self.root.glob('boot-*'))
                v=cli.verify_boot(plan,receipt,Path('/f7plan'),Path('/f7receipt'),
                                  Path('/f6plan'),Path('/f6receipt'))
                self.assertTrue(v['guest_running'])
                self.assertEqual(sum(args.args[0]==core.START for args in
                                     host.call_args_list),1)
                with self.assertRaisesRegex(ValueError,'ALREADY_ATTEMPTED'):
                    cli.boot(plan,Path('/f7plan'),Path('/f7receipt'),
                             Path('/f6plan'),Path('/f6receipt'))

    def test_uncertain_start_stops_no_retry(self):
        with patch.object(cli,'source'), \
             patch.object(cli,'provenance',return_value='c'*64), \
             patch.object(cli,'host_preflight',return_value=deepcopy(self.before)), \
             patch.object(cli.f6,'capture',return_value=deepcopy(self.after)), \
             patch.object(cli,'grant_readback',return_value=self.grant), \
             patch.object(cli.time,'time',return_value=1795094100), \
             patch.object(cli.secrets,'token_hex',return_value='a'*64):
            def fake(cmd,*,timeout=16):
                r=successful_command()
                if tuple(cmd)==core.START:
                    r['rc']=1;r['stderr']='device error'
                return r
            with patch.object(cli,'host',side_effect=fake) as host:
                self.assertEqual(cli.plan(Path('/f7plan'),Path('/f7receipt'),
                                          Path('/f6plan'),Path('/f6receipt')),0)
                plan=next(self.root.glob('plan-*'))
                self.assertEqual(cli.boot(plan,Path('/f7plan'),Path('/f7receipt'),
                                          Path('/f6plan'),Path('/f6receipt')),24)
                self.assertEqual(sum(args.args[0]==core.START for args in
                                     host.call_args_list),1)
                self.assertTrue((plan/'boot.once').exists())

if __name__=='__main__':unittest.main()
