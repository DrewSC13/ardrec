"""R112-F6: lifecycle repair tests (not experimental VM observations)."""
from __future__ import annotations
import ast
from copy import deepcopy
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f6_hook_lifecycle as core
from ardrec.coordination import r112_f5_scoped_hook as f5_core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
import ardrec_p14_r112_f5_scoped_hook as f5
import ardrec_p14_r112_f6_hook_lifecycle as cli
from test_p14_r112_f4_isolated_networks import measured
from test_p14_r112_f5_scoped_hook import ticket

CANDIDATE=REPO/'lab/f11-runtime-v3/00-ardrec-r33-admission'
loader=SourceFileLoader('r112_f6_hook_candidate',str(CANDIDATE))
spec=importlib.util.spec_from_loader('r112_f6_hook_candidate',loader)
hook=importlib.util.module_from_spec(spec)
loader.exec_module(hook)


def f5_ready_fixture():
    old=measured('ssh','ftp','smb')
    current=deepcopy(old)
    key='f11-hook-hash'
    current['snapshot']['probes'][key]['stdout']=core.OLD_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
    current['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 5236 '+core.HOST_HOOK+'\n'
    current['snapshot']['summary']=legacy.summarize(current['snapshot']['probes'])
    return old,current


class R112F6HookTests(unittest.TestCase):
    def setUp(self):
        d=TemporaryDirectory(prefix='r112-f6-')
        self.addCleanup(d.cleanup)
        self.root=Path(d.name)/'root'
        self.root.mkdir(mode=0o700)
        a=patch.object(hook,'TRUST_ROOT',self.root)
        b=patch.object(hook,'TRUST_UID',os.geteuid())
        a.start();b.start()
        self.addCleanup(a.stop);self.addCleanup(b.stop)

    def grant(self,role='ssh',item=None):
        p=self.root/('allow-ardrec-r33-dev-'+role+'.json')
        p.write_text(json.dumps(ticket(role) if item is None else item,sort_keys=True))
        p.chmod(0o600)
        return p

    def event(self,role='ssh',operation='prepare',stage='begin',extra='-',now=1000):
        return hook.decision(['ardrec-r33-dev-'+role,operation,stage,extra],now=now)

    def test_pinned_hook_bytes(self):
        self.assertEqual(core.hashlib.sha256(CANDIDATE.read_bytes()).hexdigest(),
                         core.NEW_HOOK_SHA256)

    def test_four_guests_denied_without_lease(self):
        for guest in core.GUESTS:
            self.assertEqual(self.event(guest)[0],79)

    def test_unknown_ardrec_guest_denied(self):
        self.assertEqual(self.event('unexpected')[0],79)

    def test_unrelated_guest_untouched(self):
        self.assertEqual(hook.decision(['other-guest','prepare','begin','-'])[0],0)

    def test_release_shutdown_reason_accepted(self):
        for reason in ('shutdown','destroyed','crashed','failed','saved',
                       'from snapshot','unknown','daemon'):
            self.assertEqual(self.event('runner','release','end',reason)[0],0)

    def test_stopped_without_lease_allowed(self):
        self.assertEqual(self.event('ftp','stopped','end')[0],0)

    def test_wrong_extra_for_prepare_denied(self):
        self.grant()
        self.assertEqual(self.event(extra='shutdown')[0],79)

    def test_reconnect_without_completed_boot_denied(self):
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_reconnect_with_valid_lease_but_no_claim_denied(self):
        self.grant()
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_reconnect_after_only_prepare_denied(self):
        self.grant(); self.assertEqual(self.event()[0],0)
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_reconnect_after_start_without_started_denied(self):
        self.grant()
        self.assertEqual(self.event()[0],0)
        self.assertEqual(self.event(operation='start')[0],0)
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_complete_boot_stages_allow_reconnect_after_expiry(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        self.assertEqual(self.event(operation='reconnect',now=20000)[0],0)
        self.assertEqual(self.event()[0],79)
        for kind in ('used','stage','active'):
            self.assertEqual((self.root/f'{kind}-ardrec-r33-dev-ssh.sha256').stat().st_mode & 0o777,0o600)

    def test_ticket_cannot_start_other_guest(self):
        self.grant('ssh')
        self.assertEqual(self.event('runner')[0],79)

    def test_missing_prepare_denies_start(self):
        self.grant()
        self.assertEqual(self.event(operation='start')[0],79)

    def test_missing_start_denies_started(self):
        self.grant()
        self.assertEqual(self.event()[0],0)
        self.assertEqual(self.event(operation='started')[0],79)

    def test_double_start_denied(self):
        self.grant()
        self.assertEqual(self.event()[0],0)
        self.assertEqual(self.event(operation='start')[0],0)
        self.assertEqual(self.event(operation='start')[0],79)

    def test_double_started_denied(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        self.assertEqual(self.event(operation='started')[0],79)

    def test_new_grant_cannot_override_used_marker(self):
        p=self.grant()
        self.assertEqual(self.event()[0],0)
        changed=ticket('ssh');changed['nonce']='2'*64
        p.write_text(json.dumps(changed));p.chmod(0o600)
        self.assertEqual(self.event()[0],79)

    def test_tampered_active_marker_denies_reconnect(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        active=self.root/'active-ardrec-r33-dev-ssh.sha256'
        active.write_text('f'*64+'\n'); active.chmod(0o600)
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_symlink_active_marker_denies_reconnect(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        active=self.root/'active-ardrec-r33-dev-ssh.sha256'
        active.rename(self.root/'other.txt')
        active.symlink_to(self.root/'other.txt')
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_wrong_claim_permissions_denies_reconnect(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        (self.root/'used-ardrec-r33-dev-ssh.sha256').chmod(0o644)
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_root_mode_drift_denies_reconnect(self):
        self.grant()
        for op in ('prepare','start','started'):
            self.assertEqual(self.event(operation=op)[0],0)
        self.root.chmod(0o755)
        self.assertEqual(self.event(operation='reconnect')[0],79)

    def test_expired_lease_denies_prepare(self):
        self.grant()
        self.assertEqual(self.event(now=1195)[0],79)

    def test_attach_and_restore_still_denied(self):
        for verb in ('attach','restore','migrate'):
            self.assertEqual(self.event(operation=verb)[0],79)

    def test_hook_never_invokes_subprocess_or_libvirt(self):
        tree=ast.parse(CANDIDATE.read_text())
        imports=set()
        for item in ast.walk(tree):
            if isinstance(item,ast.Import):
                imports.update(n.name.split('.')[0] for n in item.names)
            elif isinstance(item,ast.ImportFrom) and item.module:
                imports.add(item.module.split('.')[0])
        self.assertFalse(imports & {'subprocess','libvirt','socket','paramiko'})


class R112F6BoundaryTests(unittest.TestCase):
    def test_real_style_f5_baseline_valid(self):
        historic,current=f5_ready_fixture()
        f5.core.check_post(historic,current,legacy,f4,r112)
        self.assertEqual(core.proposal(current,'a'*64,legacy,f4)['guest_starts'],0)

    def test_host_policy_permits_only_hook_sha_change(self):
        _,before=f5_ready_fixture()
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.NEW_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+core.HOST_HOOK+'\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        core.result(before,after,legacy,f4,r112)

    def test_changed_nft_rejected(self):
        _,before=f5_ready_fixture()
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.NEW_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+core.HOST_HOOK+'\n'
        nft=json.loads(after['snapshot']['probes']['r34-nft']['stdout'])
        nft['nftables'].pop()
        after['snapshot']['probes']['r34-nft']['stdout']=json.dumps(nft)
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        with self.assertRaises(ValueError): core.result(before,after,legacy,f4,r112)

    def test_running_guest_rejected(self):
        _,before=f5_ready_fixture()
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.NEW_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['vm-ssh-state']['stdout']='running\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        with self.assertRaises(ValueError): core.result(before,after,legacy,f4,r112)

    def test_network_state_drift_rejected(self):
        _,before=f5_ready_fixture()
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.NEW_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+core.HOST_HOOK+'\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        after['english_info']['ssh']['stdout']=after['english_info']['ssh']['stdout'].replace('Active: yes','Active: no')
        with self.assertRaises(ValueError): core.result(before,after,legacy,f4,r112)

    def test_physical_install_mock_has_two_root_mutations_and_private_replay(self):
        historic,before=f5_ready_fixture()
        after=deepcopy(before)
        after['snapshot']['probes']['f11-hook-hash']['stdout']=core.NEW_HOOK_SHA256+'  '+core.HOST_HOOK+'\n'
        after['snapshot']['probes']['f11-hook-stat']['stdout']='0:0 755 6641 '+core.HOST_HOOK+'\n'
        after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
        controls={**{r:{'prepare_denied':True,'rc':79} for r in core.GUESTS},
                  'reconnect':{'denied_without_completed_boot':True,'rc':79},
                  'shutdown':{'stopped':True,'release_shutdown':True,
                              'release_destroyed':True}}
        ok={'rc':0,'timeout':False,'truncated':False,'stdout':'','stderr':''}
        with TemporaryDirectory(prefix='r112-f6-mocked-host-') as dirname:
            with patch.object(cli,'ROOT',Path(dirname)), \
                 patch.object(cli,'source'), \
                 patch.object(cli,'original_receipt',return_value=(historic,'a'*64)), \
                 patch.object(cli,'inspect_host'), \
                 patch.object(cli,'capture',side_effect=[before,before,after]), \
                 patch.object(cli,'controls',return_value=controls), \
                 patch.object(cli.f5,'get_hash',return_value=core.NEW_HOOK_SHA256), \
                 patch.object(cli,'probe',return_value=ok) as host:
                self.assertEqual(cli.plan(Path('/unused/plan'),Path('/unused/receipt')),0)
                path=next(Path(dirname).glob('plan-*'))
                self.assertEqual(cli.install(path),0)
                receipt=next(Path(dirname).glob('apply-*'))
                self.assertEqual(cli.verify_apply(path,receipt)['vm_starts'],0)
                self.assertEqual(host.call_count,2)
                self.assertEqual(host.call_args_list[0].args[0],
                                 ('sudo','-n','install','-o','root','-g','root','-m','0755',
                                  str(cli.CANDIDATE),core.STAGE))
                self.assertEqual(host.call_args_list[1].args[0],
                                 ('sudo','-n','mv','-T','--',core.STAGE,core.HOST_HOOK))
                with self.assertRaises(ValueError): cli.install(path)

    def test_failed_stage_never_retries(self):
        historic,before=f5_ready_fixture()
        fail={'rc':1,'timeout':False,'truncated':False,'stdout':'','stderr':'denied'}
        with TemporaryDirectory(prefix='r112-f6-failed-stage-') as dirname:
            with patch.object(cli,'ROOT',Path(dirname)), \
                 patch.object(cli,'source'), \
                 patch.object(cli,'original_receipt',return_value=(historic,'a'*64)), \
                 patch.object(cli,'inspect_host'), \
                 patch.object(cli,'capture',return_value=before), \
                 patch.object(cli,'probe',return_value=fail) as host:
                self.assertEqual(cli.plan(Path('/unused/plan'),Path('/unused/receipt')),0)
                path=next(Path(dirname).glob('plan-*'))
                with self.assertRaises(ValueError): cli.install(path)
                self.assertEqual(host.call_count,1)
                self.assertTrue((path/'install.once').exists())
                with self.assertRaises(ValueError): cli.install(path)

    def test_f6_cli_has_no_start_or_network_mutations(self):
        src=(REPO/'scripts/ardrec_p14_r112_f6_hook_lifecycle.py').read_text()
        self.assertNotIn("'virsh','start'",src)
        self.assertNotIn("'nft','-f'",src)
        self.assertNotIn("'systemctl','restart'",src)
        self.assertIn("'sudo','-n','mv'",src)

if __name__=='__main__':
    unittest.main()
