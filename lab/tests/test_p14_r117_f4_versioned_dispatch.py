"""R117-F4 negative-first verification; no guest, root, nftables or network access."""
from __future__ import annotations
import hashlib,json,os,tempfile
from pathlib import Path
from unittest.mock import patch
import unittest
from datetime import datetime,timezone
from ardrec.coordination import r116_f12_controlled_boot as hist7
from ardrec.coordination import r116_f12_runner_ftp_boot as hist8
from ardrec.coordination import r117_f4_controlled_boot as f7
from ardrec.coordination import r117_f4_runner_ftp_boot as f8
from ardrec.coordination import r117_f4_root_release as release
from ardrec.coordination import r117_f3_current_git_admission as gitgate
import ardrec_p14_r117_f4_dispatch_audit as audit

REPO=Path(__file__).resolve().parents[2]
SH=lambda b:hashlib.sha256(b).hexdigest()

# The exact replacement list is intentionally duplicated in tests; a new
# modification to versioned engines must be reviewed and represented here.
F7_MAP=[
 ('ARDREC-R116-F12','ARDREC-R117-F4'),
 ('R116-F12','R117-F4'),
 ('r116-f12-one-boot-deny-v1','r117-f4-one-boot-deny-v1'),
 ('feat/p14-r116-piloto-ftp-fisico-a5-a10','feat/p14-r117-piloto-real-a5-a10'),
 ('46dccd948d2d61c4fd777c64dafad3efa71cf035','fdb6efa0c297ce18b28cddb9494514f51d88bdb4'),
 ('/etc/ardrec/r116-boot-trust-v1.json','/etc/ardrec/r117-f4-boot-trust-v1.json'),
 ('/etc/ardrec/r116-boot-revocation-v1.json','/etc/ardrec/r117-f4-boot-revocation-v1.json'),
 ('src/ardrec/coordination/r116_f12_controlled_boot.py','src/ardrec/coordination/r117_f4_controlled_boot.py'),
 ('R116_BOOT_SCOPE_NOT_CURRENT_HEAD','R117_BOOT_SCOPE_NOT_CURRENT_HEAD'),
 ('R115_F7_','R117_F4_SSH_'),
]
F8_MAP=[
 ('ARDREC-R116-F12','ARDREC-R117-F4'),
 ('R116-F12','R117-F4'),
 ('r116-f12-runner-ftp-deny-v1','r117-f4-runner-ftp-deny-v1'),
 ('from ardrec.coordination import r116_f12_controlled_boot as f7','from ardrec.coordination import r117_f4_controlled_boot as f7'),
 ('src/ardrec/coordination/r116_f12_runner_ftp_boot.py','src/ardrec/coordination/r117_f4_runner_ftp_boot.py'),
 ('R115_F8_','R117_F4_CHAIN_'),
]
def expected_engine(source,mapping):
    for old,new in mapping:
        assert old in source,(old,'BASE_DRIFT')
        source=source.replace(old,new)
    return source

def expected_f7():
    s=expected_engine((REPO/'src/ardrec/coordination/r116_f12_controlled_boot.py').read_text(),F7_MAP)
    old='from ardrec.coordination import r116_f2_current_pilot_gate as current'
    assert s.count(old)==1
    s=s.replace(old,old+'\nfrom ardrec.coordination import r117_f4_root_release as release_guard')
    old="for path in ('src/ardrec/coordination/r117_f4_controlled_boot.py',):"
    assert s.count(old)==1
    s=s.replace(old,"for path in ('src/ardrec/coordination/r117_f4_controlled_boot.py',\n                     'src/ardrec/coordination/r117_f4_root_release.py'):")
    old='    plan,before,legacy_before=_read_plan(folder)'
    assert s.count(old)==1
    return s.replace(old,'    release_guard.require_attested_release(head)\n'+old)

def expected_f8():
    s=expected_engine((REPO/'src/ardrec/coordination/r116_f12_runner_ftp_boot.py').read_text(),F8_MAP)
    old='from ardrec.coordination import r117_f4_controlled_boot as f7'
    assert s.count(old)==1
    s=s.replace(old,old+'\nfrom ardrec.coordination import r117_f4_root_release as release_guard')
    old='    spec,before,legacy_before=_read_plan(plan_dir)'
    assert s.count(old)==1
    return s.replace(old,'    release_guard.require_attested_release(head)\n'+old)

class VersionedContract(unittest.TestCase):
    def test_01_exact_f7_derivation(self):self.assertEqual((REPO/'src/ardrec/coordination/r117_f4_controlled_boot.py').read_text(),expected_f7())
    def test_02_exact_f8_derivation(self):self.assertEqual((REPO/'src/ardrec/coordination/r117_f4_runner_ftp_boot.py').read_text(),expected_f8())
    def test_03_old_branch_immutable(self):self.assertEqual(hist7.BRANCH,'feat/p14-r116-piloto-ftp-fisico-a5-a10')
    def test_04_old_base_immutable(self):self.assertEqual(hist7.BASE,'46dccd948d2d61c4fd777c64dafad3efa71cf035')
    def test_05_new_branch_exact(self):self.assertEqual(f7.BRANCH,gitgate.ACTIVE_BRANCH)
    def test_06_new_merge_ancestor(self):self.assertEqual(f7.BASE,gitgate.MERGED_R116)
    def test_07_new_roots_distinct(self):
        self.assertNotEqual(f7.ROOT,hist7.ROOT);self.assertNotEqual(f8.ROOT,hist8.ROOT)
    def test_08_new_crypto_domain(self):
        self.assertIn(b'R117-F4',f7.PERMIT_PREFIX)
        self.assertIn(b'R117-F4',f7.REVOKE_PREFIX)
        self.assertNotEqual(f7.PERMIT_PREFIX,hist7.PERMIT_PREFIX)
    def test_09_external_root_trust_distinct(self):
        self.assertNotEqual(f7.PERMIT_TRUST,hist7.PERMIT_TRUST)
        self.assertNotEqual(f7.PERMIT_REVOCATION,hist7.PERMIT_REVOCATION)
    def test_10_chain_linkage_not_r116(self):self.assertIs(f8.f7,f7)
    def test_11_historical_chain_unchanged(self):self.assertIs(hist8.f7,hist7)
    def test_12_ssh_one_start(self):
        self.assertEqual(f7.ORDER,('ssh','runner','ftp'))
        self.assertEqual(f7.pre_states('ssh'),dict.fromkeys(('ssh','runner','ftp','smb'),'OFF'))
    def test_13_ftp_keeps_smb_off(self):self.assertEqual(f7.post_states('ftp')['smb'],'OFF')
    def test_14_unknown_guest_denied(self):
        with self.assertRaises(f7.Stop):f7.command('smb')
    def test_15_unknown_role_denied(self):
        with self.assertRaises(f8.Stop):f8._claimed('smb')
    def test_16_missing_predecessor_denied(self):
        with patch.object(f7,'state_gate',return_value={'all_deny':'MATCH','p8':'NO-GO'}):
            with self.assertRaises(f8.Stop):f8.plan_spec('runner','a'*40,b'a',b'b',{}, {},None,datetime.now(timezone.utc))
    def test_17_schema_separated(self):
        self.assertIn('R117-F4',f7.SCHEMA);self.assertIn('R117-F4',f8.SCHEMA)
    def test_18_missing_external_scope_denied(self):
        with patch.object(f7,'git_guard',return_value='a'*40),patch.object(f7.f1,'load',return_value={'source_commit':'b'*40}):
            with self.assertRaises(f7.Stop):f7.scope_required(b'a',b'b',now=datetime.now(timezone.utc))
    def test_19_unsigned_boot_permit_denied(self):
        with self.assertRaises((ValueError,OSError,KeyError)):
            f7.signed_boot_permit({},b'a',b'b',b'c',now=datetime.now(timezone.utc))
    def test_20_staging_blocks_ssh_before_plan(self):
        with patch.object(f7,'git_guard',return_value='a'*40),patch.object(release,'require_attested_release',side_effect=release.Stop('UNSTAGED')) as check,patch.object(f7,'_read_plan',side_effect=AssertionError('touched plan')):
            with self.assertRaisesRegex(release.Stop,'UNSTAGED'):
                f7._boot_ssh(Path('/tmp/no'),Path('/tmp/a'),Path('/tmp/b'),Path('/tmp/c'))
        check.assert_called_once_with('a'*40)
    def test_21_staging_blocks_runner_before_plan(self):
        with patch.object(f8,'_check_sources',return_value='a'*40),patch.object(release,'require_attested_release',side_effect=release.Stop('UNSTAGED')) as check,patch.object(f8,'_read_plan',side_effect=AssertionError('touched plan')):
            with self.assertRaisesRegex(release.Stop,'UNSTAGED'):
                f8.boot(Path('/tmp/no'),Path('/tmp/a'),Path('/tmp/b'),Path('/tmp/c'))
        check.assert_called_once_with('a'*40)
    def test_22_f7_cli_requires_mode(self):
        with self.assertRaises(SystemExit):f7.main([])
    def test_23_f8_cli_requires_mode(self):
        with self.assertRaises(SystemExit):f8.main([])
    def test_24_f7_cli_unauthorized_boot(self):
        with patch.object(f7,'_boot_ssh',side_effect=AssertionError('unexpected boot')):
            self.assertEqual(f7.main(['--boot','--role','ssh']),23)
    def test_25_f8_cli_unauthorized_boot(self):
        with patch.object(f8,'boot',side_effect=AssertionError('unexpected boot')):
            self.assertEqual(f8.main(['--boot','--role','runner']),23)

class ReleaseBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.obj=audit.audit_offline(REPO)
    def test_26_manifest_exact(self):self.assertEqual(set(self.obj['source_sha256']),set(release.SRC))
    def test_27_manifest_no_go(self):self.assertEqual((self.obj['pilot'],self.obj['a6'],self.obj['p8']),('DRAFT','ND','NO-GO'))
    def test_28_hist_lock(self):self.assertEqual(self.obj['root_f3_immutable_source_count'],33)
    def test_29_modified_release_pin_denied(self):
        with tempfile.TemporaryDirectory() as t:
            dst=Path(t)
            (dst/'lab/operational-controller').mkdir(parents=True)
            m=json.loads((REPO/audit.MANIFEST).read_text());m['source_sha256'][release.SRC[0]]='0'*64
            (dst/audit.MANIFEST).write_text(json.dumps(m))
            (dst/audit.LOCK).write_bytes((REPO/audit.LOCK).read_bytes())
            with self.assertRaisesRegex(audit.Stop,'DISPATCH_BYTES_CHANGED'):
                audit.audit_offline(dst)
    def test_30_reject_missing_release_manifest(self):
        with self.assertRaises((OSError,release.Stop)):
            release.require_attested_release('a'*40)
    def test_31_reject_wrong_release_head(self):
        with self.assertRaises(release.Stop):release.require_attested_release('z'*40)
    def test_32_reject_tampered_pilot_manifest(self):
        receipt={'schema':release.RELEASE_SCHEMA,'head':'a'*40,
                 'source_sha256':{s:SH((REPO/s).read_bytes()) for s in release.SRC},
                 'pilot_schema':release.PILOT_SCHEMA,'pilot_manifest_sha256':'0'*64,
                 'p8':'NO-GO','authorized_to_boot':False}
        with patch.object(release,'root_bytes',return_value=json.dumps(receipt).encode()),patch.object(release,'RECEIPT',release.RECEIPT):
            with self.assertRaises(release.Stop):release.require_attested_release('a'*40,repo=REPO,reader=lambda path: json.dumps(receipt).encode())
    def test_33_reject_incorrect_authorized_to_boot(self):
        receipt={'schema':release.RELEASE_SCHEMA,'head':'a'*40,
                 'source_sha256':{s:SH((REPO/s).read_bytes()) for s in release.SRC},
                 'pilot_schema':release.PILOT_SCHEMA,'pilot_manifest_sha256':'0'*64,
                 'p8':'NO-GO','authorized_to_boot':True}
        with patch.object(release,'root_bytes',return_value=json.dumps(receipt).encode()),patch.object(release,'RECEIPT',release.RECEIPT):
            with self.assertRaisesRegex(release.Stop,'RELEASE_SCOPE'):
                release.require_attested_release('a'*40,repo=REPO,reader=lambda path: json.dumps(receipt).encode())
    def test_34_audit_root_mode_requires_root(self):
        with patch.object(audit.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(audit.Stop,'ROOT_ONLY'):audit.audit_root()
    def test_35_script_no_default_mode(self):
        with self.assertRaises(SystemExit):audit.main([])
    def test_36_offline_mode_no_guest(self):
        with patch.object(audit,'audit_offline',return_value=self.obj),patch.object(audit,'audit_root',side_effect=AssertionError('host')):
            self.assertEqual(audit.main(['--offline']),0)
    def test_37_root_inspect_old_only(self):
        with patch.object(audit,'audit_root',return_value=('1'*40,'F12_SIGNED_UNCHANGED_R117_DISPATCH_NOT_RELEASED')):
            self.assertEqual(audit.main(['--root']),0)
    def test_38_source_mode_suppresses_boot(self):
        with patch.object(audit,'audit_current',return_value=('a'*40,self.obj)),patch.object(f7,'_boot_ssh',side_effect=AssertionError('boot')):
            self.assertEqual(audit.main(['--source']),0)
    def test_39_wrong_root_file_mode_denied(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'test.json';p.write_text('x')
            with self.assertRaises((OSError,release.Stop)):
                release.root_bytes(p)
    def test_40_source_scope_against_traversal(self):
        self.assertTrue(all('/../' not in x for x in release.SRC))

if __name__=='__main__':unittest.main()
