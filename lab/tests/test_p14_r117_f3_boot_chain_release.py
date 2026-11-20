"""R117-F3 test signed R117 boundary without editing R116 closure or root."""
from __future__ import annotations
from pathlib import Path
import hashlib,importlib.util,json
from unittest.mock import patch
import unittest
from ardrec.coordination import r116_f12_controlled_boot as hist
from ardrec.coordination import r116_f12_runner_ftp_boot as chain
from ardrec.coordination import r117_f3_current_git_admission as active

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('r117f3_gate',REPO/'scripts/ardrec_p14_r117_f3_boot_chain_gate.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class TestImmutableHistory(unittest.TestCase):
    def test_r116_branch_unchanged(self):self.assertEqual(hist.BRANCH,'feat/p14-r116-piloto-ftp-fisico-a5-a10')
    def test_r116_merge_base_unchanged(self):self.assertEqual(hist.BASE,'46dccd948d2d61c4fd777c64dafad3efa71cf035')
    def test_r116_f7_f8_shared(self):self.assertIs(chain.f7,hist)
    def test_current_branch_separate(self):self.assertEqual(active.ACTIVE_BRANCH,'feat/p14-r117-piloto-real-a5-a10')
    def test_r117_ancestor_exact(self):self.assertEqual(active.MERGED_R116,'fdb6efa0c297ce18b28cddb9494514f51d88bdb4')
    def test_no_auto_boot_grant(self):self.assertEqual(active.boundary()['boot_dispatcher'],'NOT_RELEASED_FOR_R117')
    def test_safe_states(self):self.assertEqual(hist.pre_states('ssh'),{'ssh':'OFF','runner':'OFF','ftp':'OFF','smb':'OFF'})
    def test_no_automatic_traffic(self):self.assertFalse(active.boundary()['traffic_opened'])
    def test_role_preflight_denies_unknown(self):
        with self.assertRaisesRegex(active.Stop,'R117_ROLE_UNKNOWN'):active.role_preflight({},'smb')
    def test_role_preflight_rejects_denial(self):
        with patch.object(hist,'state_gate',return_value={'all_deny':'NO','p8':'NO-GO'}):
            with self.assertRaises(active.Stop):active.role_preflight({},'ssh')
    def test_role_preflight_valid(self):
        with patch.object(hist,'state_gate',return_value={'all_deny':'MATCH','p8':'NO-GO'}):
            self.assertEqual(active.role_preflight({},'runner')['all_deny'],'MATCH')

class TestCurrentGitGate(unittest.TestCase):
    def mock_git(self,branch=None,signature='G',ancestor=0):
        calls=[]
        def fake(argv,**k):
            calls.append(tuple(argv))
            if argv[1:]==('rev-parse','--show-toplevel'):out=str(active.REPO)
            elif argv[1:]==('branch','--show-current'):out=branch or active.ACTIVE_BRANCH
            elif argv[1:]==('rev-parse','HEAD'):out='a'*40
            elif argv[1:]==('status','--porcelain=v1','--untracked-files=all'):out=''
            elif argv[1:]==('log','-1','--format=%G?'):out=signature
            elif argv[1]=='merge-base':return {'stdout':'','rc':ancestor,'timeout':False,'truncated':False}
            elif argv[1]=='ls-files' or argv[1]=='diff':return {'stdout':'','rc':0,'timeout':False,'truncated':False}
            else:raise AssertionError(argv)
            return {'stdout':out+'\n','rc':0,'timeout':False,'truncated':False}
        return fake,calls
    def test_current_signed_head(self):
        fake,calls=self.mock_git()
        with patch.object(active.Path,'cwd',return_value=active.REPO),patch.object(hist,'_run',side_effect=fake):
            self.assertEqual(active.git_guard(),'a'*40)
        self.assertIn(('git','merge-base','--is-ancestor',active.MERGED_R116,'a'*40),calls)
        self.assertEqual(sum(x[1]=='ls-files' for x in calls),3)
    def test_old_branch_rejected(self):
        fake,_=self.mock_git(branch=hist.BRANCH)
        with patch.object(active.Path,'cwd',return_value=active.REPO),patch.object(hist,'_run',side_effect=fake):
            with self.assertRaisesRegex(active.Stop,'GIT_BRANCH_DRIFT'):active.git_guard()
    def test_bad_signature_rejected(self):
        fake,_=self.mock_git(signature='E')
        with patch.object(active.Path,'cwd',return_value=active.REPO),patch.object(hist,'_run',side_effect=fake):
            with self.assertRaisesRegex(active.Stop,'NOT_VERIFIED_G'):active.git_guard()
    def test_wrong_ancestor_rejected(self):
        fake,_=self.mock_git(ancestor=1)
        with patch.object(active.Path,'cwd',return_value=active.REPO),patch.object(hist,'_run',side_effect=fake):
            with self.assertRaisesRegex(active.Stop,'MERGE_NOT_ANCESTOR'):active.git_guard()
    def test_wrong_cwd_rejected(self):
        with patch.object(active.Path,'cwd',return_value=Path('/tmp')):
            with self.assertRaisesRegex(active.Stop,'WRONG_REPOSITORY'):active.git_guard()
    def test_scope_wrong_head_rejected(self):
        with patch.object(active,'git_guard',return_value='a'*40),patch.object(active.scope,'load',return_value={'source_commit':'b'*40}):
            with self.assertRaisesRegex(active.Stop,'SCOPE_WRONG_HEAD'):active.signed_scope(b'c',b'a',now=None)

class TestRootPins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock=json.loads((REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json').read_bytes())
        cls.pins=gate.exact_lock(cls.lock)
    def test_root_f3_source_count(self):self.assertEqual(len(self.pins),33)
    def test_root_source_integrity(self):self.assertTrue(gate.check_sources(self.pins,REPO))
    def test_hist_source_pin_valid(self):
        name='runtime/ardrec/coordination/r116_f12_controlled_boot.py'
        self.assertEqual(self.pins[name],hashlib.sha256((REPO/'src/ardrec/coordination/r116_f12_controlled_boot.py').read_bytes()).hexdigest())
    def test_release_is_historical(self):self.assertIn('F12_SIGNED',gate.root_relation(self.pins,self.pins))
    def test_unknown_source_set_refused(self):
        bad=dict(self.pins);bad.pop('root-pilot.py')
        with self.assertRaisesRegex(gate.Stop,'ROOT_PIN_SET_CHANGED'):gate.root_relation(bad,self.pins)
    def test_modified_source_digest_refused(self):
        bad=dict(self.pins);bad['root-pilot.py']='f'*64
        with self.assertRaisesRegex(gate.Stop,'ROOT_RELEASE_TAMPERED'):gate.root_relation(bad,self.pins)
    def test_lock_untrusted_base_refused(self):
        bad=dict(self.lock);bad['base']='0'*40
        with self.assertRaisesRegex(gate.Stop,'LOCK_BASE_CHANGED'):gate.exact_lock(bad)
    def test_lock_traversal_refused(self):
        bad=dict(self.lock);pins=dict(self.pins);pins['../pwn.py']=pins.pop('runtime/ardrec/coordination/r115_dev_admission_contract.py');bad['files']=pins
        with self.assertRaisesRegex(gate.Stop,'LOCK_PATH_OR_SHA'):gate.exact_lock(bad)
    def test_source_bytes_tampered(self):
        bad=dict(self.pins);bad['root-pilot.py']='a'*64
        with self.assertRaisesRegex(gate.Stop,'SOURCE_TAMPER'):gate.check_sources(bad,REPO)
    def test_root_inspect_denies_nonroot(self):
        with patch.object(gate.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(gate.Stop,'ROOT_AUDIT_REQUIRES_ROOT'):gate.root_audit(self.pins)
    def test_no_default_mode(self):
        with self.assertRaises(SystemExit):gate.main([])
    def test_source_mode_no_root_access(self):
        with patch.object(gate,'source_audit',return_value=('a'*40,self.pins)),patch.object(gate,'root_audit',side_effect=AssertionError('host access')):
            self.assertEqual(gate.main(['--source']),0)
    def test_root_mode_no_write(self):
        with patch.object(gate,'LOCK',REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json'),patch.object(gate,'root_audit',return_value=('F12_SIGNED_UNCHANGED_R117_DISPATCH_NOT_RELEASED','1'*40)):
            self.assertEqual(gate.main(['--root']),0)

if __name__=='__main__':unittest.main()
