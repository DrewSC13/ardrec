"""R116-F12 negative-first tests: current-source deny-only boot and bounded backup.

No VM, socket, timer or nftables call. Every privileged operation is mocked or
rejected. The old R115 modules are never altered by this rebase.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
from unittest.mock import patch
import types
import unittest

from ardrec.coordination import r116_f12_controlled_boot as f7
from ardrec.coordination import r116_f12_runner_ftp_boot as f8
from ardrec.coordination import r116_f3_pilot_session_policy as policy

REPO=Path(__file__).resolve().parents[2]

def script(name):
    path=REPO/'scripts'/name
    spec=importlib.util.spec_from_file_location('r116f12_'+name.replace('.py',''),path)
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

root=script('ardrec_p14_r116_f3_root_pilot.py')
guard=script('ardrec_p14_r116_f1_root_deny_guard.py')
NOW=datetime(2026,11,20,tzinfo=timezone.utc)

class Provenance(unittest.TestCase):
    def test_rebased_branch(self):
        self.assertEqual(f7.BRANCH,'feat/p14-r116-piloto-ftp-fisico-a5-a10')
    def test_merge_base(self):
        self.assertEqual(f7.BASE,'46dccd948d2d61c4fd777c64dafad3efa71cf035')
    def test_new_receipt_roots(self):
        self.assertEqual(f7.ROOT.name,'r116-f12-one-boot-deny-v1')
        self.assertEqual(f8.ROOT.name,'r116-f12-runner-ftp-deny-v1')
    def test_not_importing_previous_boot(self):
        self.assertIs(f8.f7,f7)
    def test_not_inheriting_trust(self):
        self.assertEqual(f7.PERMIT_TRUST.name,'r116-boot-trust-v1.json')
        self.assertEqual(f7.PERMIT_REVOCATION.name,'r116-boot-revocation-v1.json')
    def test_new_crypto_domains(self):
        self.assertIn(b'R116-F12',f7.PERMIT_PREFIX)
        self.assertIn(b'R116-F12',f7.REVOKE_PREFIX)
        self.assertNotIn(b'R115-F7',f7.PERMIT_PREFIX)
    def test_no_old_boot_path_in_root_replay(self):
        from inspect import getsource
        s=getsource(root.review_boot_provenance)
        self.assertIn('r116-f12-runner-ftp-deny-v1',s)
        self.assertNotIn('r115-f8-runner-ftp-deny-v1',s)
    def test_rebased_ssh_no_go_contract(self):
        self.assertIn(f7.command('ssh')[0],('sudo','virsh'))
        self.assertEqual(f7.pre_states('ssh'),{'ssh':'OFF','runner':'OFF','ftp':'OFF','smb':'OFF'})
        self.assertEqual(f7.post_states('ftp')['smb'],'OFF')
    def test_explicit_root_boot_required(self):
        self.assertIn('r116_f12_controlled_boot.py',(REPO/'src/ardrec/coordination/r116_f12_controlled_boot.py').read_text())
    def test_schema_separated_from_r115(self):
        self.assertIn('R116-F12',f7.SCHEMA)
        self.assertIn('R116-F12',f8.SCHEMA)

class SignedAdmission(unittest.TestCase):
    def test_scope_current_head_rejected_when_outdated(self):
        cr=json.dumps({'source_commit':'a'*40}).encode()
        with patch.object(f7,'git_guard',return_value='b'*40),patch.object(f7.f1,'load',return_value={'source_commit':'a'*40}):
            with self.assertRaisesRegex(f7.Stop,'CURRENT_HEAD'):
                f7.scope_required(cr,b'bad',now=NOW)
    def test_scope_reviewer_returns_no_go_on_false(self):
        with patch.object(f7,'git_guard',return_value='a'*40),patch.object(f7.f1,'load',return_value={'source_commit':'a'*40}),patch.object(f7.f6,'CATALOG',Path('/tmp/ardrec-f12-draft')),patch.object(Path,'read_bytes',return_value=b'draft'),patch.object(f7.current,'current_scope_review',return_value=('FALSO','REVOKED','a'*64)):
            with self.assertRaisesRegex(f7.Stop,'NOT_AUTHORIZED'):
                f7.scope_required(b'c',b'a',now=NOW)
    def test_scope_reviewer_current_head_is_passed(self):
        with patch.object(f7,'git_guard',return_value='a'*40),patch.object(f7.f1,'load',return_value={'source_commit':'a'*40}),patch.object(f7.f6,'CATALOG',Path('/tmp/ardrec-f12-draft')),patch.object(Path,'read_bytes',return_value=b'draft'),patch.object(f7.current,'current_scope_review',return_value=('VERDADERO','CURRENT','a'*64)) as reviewer:
            result=f7.scope_required(b'c',b'a',now=NOW)
        self.assertEqual(result[0],'VERDADERO')
        self.assertEqual(reviewer.call_args.kwargs['head'],'a'*40)
    def test_missing_external_boot_trust_rejected(self):
        with self.assertRaises((OSError,f7.Stop)):
            f7._secure_root(Path('/etc/ardrec/no-such-file-r116-f12'))
    def test_unsigned_boot_permit_rejected(self):
        with self.assertRaises((OSError,ValueError)):
            f7.signed_boot_permit({'contract_sha256':'a'*64,'authorization_sha256':'b'*64},b'bad',b'bad',b'bad',now=NOW)
    def test_predecessor_cannot_be_smb(self):
        with self.assertRaises(f8.Stop):
            f8.predecessor('smb',Path('/tmp/plan'),Path('/tmp/boot'))
    def test_replay_rejects_wrong_data(self):
        with patch.object(f8,'_read_plan',side_effect=f8.Stop('NO_REPLAY')):
            with self.assertRaises(f8.Stop):
                f8.replay(Path('/tmp/no'),Path('/tmp/no'))

class Timer(unittest.TestCase):
    def test_backup_delay_distinct_from_pilot_cap(self):
        self.assertEqual(guard.BACKUP_DELAY_SECONDS,45)
        self.assertEqual(guard.DURATION,60)
        self.assertEqual(policy.MAX_WINDOW,60)
    def test_guard_source_manifest_after_change(self):
        m=json.loads((REPO/'lab/operational-controller/r116-f1-root-bundle.json').read_bytes())
        self.assertEqual(m['guard_sha256'],hashlib.sha256((REPO/'scripts/ardrec_p14_r116_f1_root_deny_guard.py').read_bytes()).hexdigest())
    def test_root_f3_lock_after_change(self):
        lock=json.loads((REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json').read_bytes())
        files=lock['files'];self.assertEqual(len(files),33)
        for name,digest in files.items():
            src=REPO/('scripts/ardrec_p14_r116_f3_root_pilot.py' if name=='root-pilot.py' else 'src/'+name.removeprefix('runtime/'))
            self.assertEqual(hashlib.sha256(src.read_bytes()).hexdigest(),digest,name)
    def test_timer_45_requires_authoritative_receipt(self):
        with patch.object(root,'run',return_value=json.dumps({'timer_verified':True,'duration_seconds':60,'opens_ports':False}).encode()):
            with self.assertRaises(root.Stop):root.f1_arm('a'*16)
    def test_timer_accepts_45s_with_60s_ceiling(self):
        with patch.object(root,'run',return_value=json.dumps({'timer_verified':True,'duration_seconds':60,'backup_delay_seconds':45,'opens_ports':False}).encode()):
            self.assertEqual(root.f1_arm('a'*16)['backup_delay_seconds'],45)
    def test_boot_replay_fails_wrong_root(self):
        with patch.object(root,'safe',return_value=root.canon({'schema':root.SCHEMA+'-f8-boot-reference','plan':'/etc/passwd','boot':'/etc/group'})):
            with self.assertRaises(root.Stop):root.review_boot_provenance({})
    def test_no_automatic_authorization(self):
        self.assertEqual(policy.capabilities()['ordinary_p8'],'NO-GO')
        self.assertFalse(policy.capabilities()['installs_or_arms_automatically'])
    def test_no_physical_claim(self):
        self.assertNotIn('PILOT_COMPLETED',str(guard.main(['--capabilities'])))

if __name__=='__main__':unittest.main()
