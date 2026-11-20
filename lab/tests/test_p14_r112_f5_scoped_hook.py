"""R112-F5: one-start root lease hook, denied physical installation defaults."""
from __future__ import annotations
import ast
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f5_scoped_hook as core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f5_scoped_hook as cli
from test_p14_r112_f4_isolated_networks import measured

CANDIDATE=REPO/'lab/f11-runtime-v2/00-ardrec-r33-admission'
spec=importlib.util.spec_from_file_location('f11_scoped_candidate',str(CANDIDATE))
# Shebang file has no .py extension.
from importlib.machinery import SourceFileLoader
spec=importlib.util.spec_from_loader('f11_scoped_candidate',
                                    SourceFileLoader('f11_scoped_candidate',str(CANDIDATE)))
hook=importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def ticket(role,*,issued=995,expires=1195):
    return dict(schema=hook.SCHEMA,guest='ardrec-r33-dev-'+role,
                issued_at=issued,expires_at=expires,nonce='1'*64,
                mode='ONE_START_ONLY_NO_TRAFFIC_AUTHORITY',
                p8_operational='NO-GO',r34_policy='DENY_PRESERVED',
                scope='R112_LAB_BOOT_PREAUTHORIZATION_ONLY',
                phases=['prepare','start','started'])


class R112F5HookTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix='r112-f5-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'lease-root'
        self.root.mkdir(mode=0o700)
        self.patch_root=patch.object(hook,'TRUST_ROOT',self.root)
        self.patch_uid=patch.object(hook,'TRUST_UID',os.geteuid())
        self.patch_root.start();self.addCleanup(self.patch_root.stop)
        self.patch_uid.start();self.addCleanup(self.patch_uid.stop)

    def install_ticket(self,role='ssh',obj=None):
        item=ticket(role) if obj is None else obj
        target=self.root/('allow-ardrec-r33-dev-'+role+'.json')
        target.write_text(json.dumps(item,sort_keys=True),encoding='utf-8')
        target.chmod(0o600)
        return target

    def event(self,role='ssh',verb='prepare',*,now=1000):
        return hook.decision(['ardrec-r33-dev-'+role,verb,'begin','-'],now=now)

    def test_candidate_source_pinned(self):
        self.assertEqual(core.sha(CANDIDATE.read_bytes()),core.CANDIDATE)

    def test_no_lease_denies_all_four(self):
        for role in core.GUESTS:
            self.assertEqual(self.event(role)[0],79)

    def test_unknown_r33_guest_denied(self):
        self.assertEqual(self.event('not-a-vm')[0],79)

    def test_unrelated_guest_not_affected(self):
        self.assertEqual(hook.decision(['unrelated-vm','prepare','begin','-']),
                         (0,'OUT_OF_SCOPE'))

    def test_shutdown_allowed_without_grant(self):
        self.assertEqual(hook.decision(['ardrec-r33-dev-runner','stopped','end','-'])[0],0)

    def test_wrong_extra_is_denied(self):
        self.assertEqual(hook.decision(['ardrec-r33-dev-ssh','prepare','begin','INVALID'])[0],79)

    def test_reconnect_denied_even_with_lease(self):
        self.install_ticket()
        self.assertEqual(self.event('ssh','reconnect')[0],79)

    def test_ticket_boot_phases_complete_exactly_once(self):
        self.install_ticket()
        self.assertEqual(self.event('ssh','prepare')[0],0)
        self.assertEqual(self.event('ssh','start')[0],0)
        self.assertEqual(self.event('ssh','started')[0],0)
        self.assertEqual(self.event('ssh','prepare')[0],79)

    def test_token_other_vm_does_not_authorize(self):
        self.install_ticket('runner')
        self.assertEqual(self.event('ssh')[0],79)
        self.assertEqual(self.event('runner')[0],0)

    def test_invalid_expiry_denied(self):
        self.install_ticket(obj=ticket('ssh',issued=100,expires=1100))
        self.assertEqual(self.event()[0],79)

    def test_expired_lease_denied(self):
        self.install_ticket()
        self.assertEqual(self.event(now=1195)[0],79)

    def test_wrong_nonce_denied(self):
        obj=ticket('ssh');obj['nonce']='abc'
        self.install_ticket(obj=obj)
        self.assertEqual(self.event()[0],79)

    def test_claim_not_written_without_authority(self):
        self.assertEqual(self.event()[0],79)
        self.assertFalse(list(self.root.glob('used-*')))

    def test_insecure_directory_denied(self):
        self.install_ticket()
        self.root.chmod(0o755)
        self.assertEqual(self.event()[0],79)

    def test_permissive_lease_file_denied(self):
        path=self.install_ticket();path.chmod(0o644)
        self.assertEqual(self.event()[0],79)

    def test_symlink_ticket_denied(self):
        path=self.install_ticket()
        path.rename(self.root/'real.json')
        path.symlink_to(self.root/'real.json')
        self.assertEqual(self.event()[0],79)

    def test_duplicate_json_keys_denied(self):
        path=self.install_ticket()
        path.write_bytes(path.read_bytes().replace(b'"schema":',b'"schema":"spoof","schema":'))
        self.assertEqual(self.event()[0],79)

    def test_replacing_ticket_after_claim_denied(self):
        path=self.install_ticket()
        self.assertEqual(self.event()[0],0)
        obj=ticket('ssh');obj['nonce']='2'*64
        path.write_text(json.dumps(obj,sort_keys=True));path.chmod(0o600)
        self.assertEqual(self.event('ssh','start')[0],79)

    def test_without_prepare_start_always_denied(self):
        self.install_ticket()
        self.assertEqual(self.event('ssh','start')[0],79)
        self.assertEqual(self.event('ssh','started')[0],79)

    def test_reboot_failed_stage_does_not_retry(self):
        self.install_ticket()
        self.assertEqual(self.event()[0],0)
        self.assertEqual(self.event()[0],79)

    def test_ticket_for_each_guest_requires_independent_claim(self):
        for role in core.GUESTS:
            self.install_ticket(role)
        for role in core.GUESTS:
            self.assertEqual(self.event(role)[0],0)
        for role in core.GUESTS:
            self.assertEqual(self.event(role)[0],79)

    def test_no_libvirt_subprocess_nft_imports_in_hook(self):
        tree=ast.parse(CANDIDATE.read_text('utf-8'))
        names={alias.name.split('.')[0] for n in ast.walk(tree)
               if isinstance(n,ast.Import) for alias in n.names}
        self.assertFalse(names & {'subprocess','libvirt','socket','paramiko'})

    def test_plan_for_actual_r112_f4_fixture(self):
        before=measured('ssh','ftp','smb')
        doc=core.plan_for(before,core.CANDIDATE,legacy,f4)
        self.assertEqual(doc['vm_starts'],0)
        self.assertFalse(doc['guest_traffic_allowed'])
        self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_plan_rejects_network_not_active(self):
        with self.assertRaises(ValueError):
            core.plan_for(measured(),core.CANDIDATE,legacy,f4)

    def test_post_accepts_only_changed_hook_sha(self):
        before=measured('ssh','ftp','smb')
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.CANDIDATE+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        result=core.check_post(before,after,legacy,f4,r112)
        self.assertEqual(result['new_hook_sha256'],core.CANDIDATE)
        self.assertEqual(result['vm_starts'],0)

    def test_post_rejects_host_drift(self):
        before=measured('ssh','ftp','smb')
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.CANDIDATE+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.check_post(before,after,legacy,f4,r112)

    def test_source_cli_has_only_install_and_atomic_move_host_mutations(self):
        source=(REPO/'scripts/ardrec_p14_r112_f5_scoped_hook.py').read_text('utf-8')
        self.assertIn("'sudo','-n','install'",source)
        self.assertIn("'sudo','-n','mv'",source)
        self.assertNotIn("'virsh','start'",source)
        self.assertNotIn('nft -f',source)

    def test_root_install_command_and_private_physical_receipt_replay(self):
        before=measured('ssh','ftp','smb')
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.CANDIDATE+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        expected_negative={r:{'returncode':79,'deny':True}
                           for r in (*core.GUESTS,'reconnect')}
        ok={'rc':0,'timeout':False,'truncated':False,'stdout':'','stderr':''}
        with TemporaryDirectory(prefix='r112-f5-host-test-') as dirname:
            root=Path(dirname)
            with patch.object(cli,'ROOT',root), patch.object(cli,'source'), \
                 patch.object(cli,'inspect_scope'), \
                 patch.object(cli,'_measurement',side_effect=[before,before,after]), \
                 patch.object(cli,'get_hash',return_value=core.CANDIDATE), \
                 patch.object(cli,'negative_tests',return_value=expected_negative), \
                 patch.object(cli,'probe',return_value=ok) as host:
                self.assertEqual(cli.plan(),0)
                path=next(root.glob('plan-*'))
                self.assertEqual(cli.install(path),0)
                attempt=next(root.glob('apply-*'))
                self.assertEqual(cli.verify_apply(path,attempt)['new_permits'],0)
                self.assertEqual(host.call_count,2)
                self.assertEqual(host.call_args_list[0].args[0],
                    ('sudo','-n','install','-o','root','-g','root','-m','0755',
                     str(cli.CANDIDATE),core.STAGING))
                self.assertEqual(host.call_args_list[1].args[0],
                    ('sudo','-n','mv','-T','--',core.STAGING,core.HOST_HOOK))
                with self.assertRaises(ValueError):
                    cli.install(path)

    def test_uncertain_physical_install_never_auto_retried(self):
        before=measured('ssh','ftp','smb')
        bad={'rc':1,'timeout':False,'truncated':False,'stdout':'','stderr':'permission'}
        with TemporaryDirectory(prefix='r112-f5-reject-') as dirname:
            root=Path(dirname)
            with patch.object(cli,'ROOT',root), patch.object(cli,'source'), \
                 patch.object(cli,'inspect_scope'), \
                 patch.object(cli,'_measurement',return_value=before), \
                 patch.object(cli,'probe',return_value=bad) as host:
                self.assertEqual(cli.plan(),0)
                path=next(root.glob('plan-*'))
                with self.assertRaises(ValueError):
                    cli.install(path)
                self.assertTrue((path/'install.once').is_file())
                self.assertEqual(host.call_count,1)
                self.assertEqual({p.name for p in next(root.glob('apply-*')).iterdir()},
                                 {'intent.json','stage-result.json'})

    def test_post_rejects_changed_nft_rule(self):
        before=measured('ssh','ftp','smb')
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.CANDIDATE+'  '+core.HOST_HOOK+'\n'
        nft=json.loads(after['snapshot']['probes']['r34-nft']['stdout'])
        nft['nftables'].pop()
        after['snapshot']['probes']['r34-nft']['stdout']=json.dumps(nft)
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        with self.assertRaises(ValueError):
            core.check_post(before,after,legacy,f4,r112)


if __name__=='__main__':
    unittest.main()
