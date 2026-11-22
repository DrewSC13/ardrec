"""R138: ampliación restrictiva de procedencia F7/F8. Sin libvirt, sudo ni tráfico."""
from __future__ import annotations
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
import subprocess

from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f8_runner_ftp_boot as f8


class ProvenanceTests(TestCase):
    def fake(self, *, branch=None, head=None, legacy_rc=0, active_rc=0,
             status='', signature='G', tracked=True, clean=True, cwd=True):
        branch = f7.ACTIVE_BRANCH if branch is None else branch
        head = f7.ACTIVE_BASE if head is None else head
        captured = []
        def respond(argv, **_kwargs):
            args = tuple(argv)
            captured.append(args)
            rc, value = 0, ''
            if args == ('git','rev-parse','--show-toplevel'):
                value = str(Path.cwd().resolve()) if cwd else '/tmp/other-repo'
            elif args == ('git','branch','--show-current'):
                value = branch
            elif args == ('git','rev-parse','HEAD'):
                value = head
            elif args == ('git','status','--porcelain=v1','--untracked-files=all'):
                value = status
            elif args == ('git','log','-1','--format=%G?'):
                value = signature
            elif args[:3] == ('git','merge-base','--is-ancestor'):
                if args[3] == f7.BASE: rc = legacy_rc
                elif args[3] == f7.ACTIVE_BASE: rc = active_rc
                else: raise AssertionError('UNKNOWN_BASE')
            elif args[:3] == ('git','ls-files','--error-unmatch'):
                rc = 0 if tracked else 1
            elif args[:3] == ('git','diff','--quiet'):
                rc = 0 if clean else 1
            else:
                raise AssertionError(args)
            return subprocess.CompletedProcess(args,rc,(value+'\n').encode(),b'')
        return respond,captured

    def guard(self, *, for_boot=True, **kwargs):
        runner, commands = self.fake(**kwargs)
        with patch.object(f7,'REPO',Path.cwd().resolve()):
            return f7.git_guard(for_boot=for_boot,runner=runner),commands

    def refusal(self, reason, **kwargs):
        with self.assertRaisesRegex(f7.Stop,reason): self.guard(**kwargs)

    def test_01_historical_identity_immutable(self):
        self.assertEqual(f7.BRANCH,'feat/p14-r115-a3-p7-a6-real')
        self.assertEqual(f7.BASE,'6ce42a1143d50f7adf69ea3159b56c0e993c45cb')

    def test_02_current_branch_pinned_identity(self):
        self.assertEqual(f7.ACTIVE_BRANCH,'feat/ardrec-cierre-operacional-experimental')
        self.assertEqual(f7.ACTIVE_BASE,'b43b9488ad7f89d728ea24430b789342f758c4a0')

    def test_03_new_branch_requires_both_ancestors(self):
        head, commands = self.guard()
        self.assertEqual(head,f7.ACTIVE_BASE)
        expected={('git','merge-base','--is-ancestor',f7.BASE,head),
                  ('git','merge-base','--is-ancestor',f7.ACTIVE_BASE,head)}
        self.assertTrue(expected <= set(commands))

    def test_04_historical_branch_still_allowed(self):
        head, commands = self.guard(branch=f7.BRANCH,head=f7.BASE)
        self.assertEqual(head,f7.BASE)
        self.assertNotIn(('git','merge-base','--is-ancestor',f7.ACTIVE_BASE,head),commands)

    def test_05_unknown_branch_rejected(self):
        self.refusal('GIT_BRANCH_MISMATCH',branch='feat/unauthorized-branch')

    def test_06_active_base_missing_rejected(self):
        self.refusal('SIGNED_R136_BASE_NOT_ANCESTOR',active_rc=1)

    def test_07_historical_base_missing_rejected(self):
        self.refusal('SIGNED_F1_F6_BASE_NOT_ANCESTOR',legacy_rc=1)

    def test_08_wrong_worktree_rejected(self):
        self.refusal('GIT_ROOT_MISMATCH',cwd=False)

    def test_09_unsigned_rejected(self):
        self.refusal('UNTRUSTED_OR_UNSIGNED_HEAD',signature='N')

    def test_10_unknown_signature_rejected(self):
        self.refusal('UNTRUSTED_OR_UNSIGNED_HEAD',signature='U')

    def test_11_dirty_source_rejected(self):
        self.refusal('SOURCE_TREE_NOT_CLEAN',status=' M src/example.py')

    def test_12_untracked_source_rejected(self):
        self.refusal('SOURCE_TREE_NOT_CLEAN',status='?? payload.py')

    def test_13_uncommitted_F7_rejected(self):
        self.refusal('F7_SOURCE_NOT_COMMITTED',tracked=False)

    def test_14_modified_F7_rejected(self):
        self.refusal('F7_SOURCE_CHANGED',clean=False)

    def test_15_invalid_head_rejected(self):
        self.refusal('INVALID_HEAD',head='short')

    def test_16_normal_check_does_not_require_source_files(self):
        head, commands=self.guard(for_boot=False,tracked=False)
        self.assertEqual(head,f7.ACTIVE_BASE)
        self.assertFalse(any(args[:3]==('git','ls-files','--error-unmatch') for args in commands))

    def test_17_F8_delegates_to_F7_and_checks_its_own_sources(self):
        args=[]
        def pretend(argv, **_kwargs):
            args.append(tuple(argv))
            return {'rc':0}
        with patch.object(f7,'git_guard',return_value=f7.ACTIVE_BASE) as check, \
             patch.object(f7,'_run',side_effect=pretend):
            self.assertEqual(f8._check_sources(),f7.ACTIVE_BASE)
            check.assert_called_once_with(for_boot=True)
            self.assertEqual(len(args),4)
            self.assertTrue(all('r115_f8' in str(a) or 'ardrec_p14_r115_f8' in str(a) for a in args))

    def test_18_F8_denies_without_F7_provenance(self):
        with patch.object(f7,'git_guard',side_effect=f7.Stop('SIGNED_R136_BASE_NOT_ANCESTOR')):
            with self.assertRaisesRegex(f7.Stop,'SIGNED_R136_BASE_NOT_ANCESTOR'):
                f8._check_sources()

    def test_19_no_automatic_operation_exposed_by_bridge(self):
        self.assertEqual(f7.ORDER,('ssh','runner','ftp'))
        self.assertNotIn('smb',f7.ORDER)
        self.assertEqual(f7.PERMIT_TRUST,Path('/etc/ardrec/r115-boot-trust-v1.json'))
        self.assertEqual(f7.PERMIT_REVOCATION,Path('/etc/ardrec/r115-boot-revocation-v1.json'))


if __name__=='__main__':
    import unittest
    unittest.main()
