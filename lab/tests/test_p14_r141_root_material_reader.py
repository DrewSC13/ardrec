"""R141 hostile filesystem tests in an unprivileged private fixture.

The original B4/B9 real pins are preserved; synthetic payload fixture hashes
are substituted ONLY inside isolated unit tests and never grant authority.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock

from ardrec.coordination import r141_root_material_reader as m

B4_BYTES = b'R141 test-only B4 synthetic source\n'
B9_BYTES = b'R141 test-only B9 synthetic source\n'


def build(root):
    for directory in {
        'var', 'var/lib', 'var/lib/ardrec', m.DROP,
        m.DROP + '/B4', m.DROP + '/B9',
        'etc', 'etc/ardrec',
        'var/lib/ardrec/r116-f3-ftp-pilot-root-v1',
        'var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority',
    }:
        path = root / directory
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o700)
    for label, names in (('B4', m.B4_FILES), ('B9', m.B9_FILES)):
        for name in names:
            target = root / m.DROP / label / name
            raw = m.canonical({'schema': 'ARDREC-R141-SYNTHETIC-TEST-ONLY-v1',
                               'name': label + '/' + name})
            if label == 'B4' and name == 'root-controller.py':
                raw = B4_BYTES
            if label == 'B9' and name == 'root-executor.py':
                raw = B9_BYTES
            if name == 'lock':
                raw = b'ARDREC-R128-B9-ROOT-LOCK\n'
            target.write_bytes(raw)
            target.chmod(0o600)
    approval = root / m.DROP / 'approval.json'
    approval.write_bytes(m.canonical({'schema': 'ARDREC-R141-SYNTHETIC-APPROVAL-UNTRUSTED-v1'}))
    approval.chmod(0o600)
    for name, source in (*m.POLICY.items(), ('f8_reference', m.BOOT_REFERENCE)):
        path = root / source
        path.write_bytes(m.canonical({
            'schema': 'ARDREC-R141-SYNTHETIC-TEST-ONLY-v1',
            'item': name,
        }))
        path.chmod(0o600)


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ardrec-r141-fixture-')
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        build(self.root)
        self.p1 = mock.patch.object(m, 'B4_SHA', m.digest(B4_BYTES))
        self.p2 = mock.patch.object(m, 'B9_SHA', m.digest(B9_BYTES))
        self.p1.start()
        self.p2.start()
        self.addCleanup(self.p1.stop)
        self.addCleanup(self.p2.stop)
        self.addCleanup(self.temp.cleanup)

    @contextmanager
    def reader(self):
        with m.LockedTree(self.root, owner=os.geteuid()) as tree:
            yield tree

    def check_error(self, code, call=None):
        with self.reader() as reader:
            with self.assertRaisesRegex((m.Refusal, OSError), code):
                (call or (lambda: m.capture(reader)) )()

    def test_01_valid_capture(self):
        with self.reader() as r:
            result = m.capture(r)
        self.assertEqual(result['receipt']['payload_count'], 13)
        self.assertEqual(result['receipt']['external_count'], 13)
        self.assertFalse(result['receipt']['root_install_authorized'])
        self.assertFalse(result['receipt']['documentary_approval_is_authority'])

    def test_02_inspect_release_no_authority(self):
        with self.reader() as r:
            out = m.inspect_release_input(reader=r, head='a' * 40)
        self.assertEqual(out['receipt']['source_head_claimed'], 'a'*40)
        self.assertFalse(out['receipt']['ed25519_review_complete'])

    def test_03_source_pins_genuine_literal(self):
        self.assertEqual(m.B4_SHA, m.digest(B4_BYTES))
        self.assertEqual(m.B9_SHA, m.digest(B9_BYTES))

    def test_04_source_b4_corruption(self):
        target = self.root / m.DROP / 'B4/root-controller.py'
        target.write_bytes(b'modified B4')
        self.check_error('B4_SOURCE_PIN_MISMATCH')

    def test_05_source_b9_corruption(self):
        target = self.root / m.DROP / 'B9/root-executor.py'
        target.write_bytes(b'modified B9')
        self.check_error('B9_SOURCE_PIN_MISMATCH')

    def test_06_invalid_lock(self):
        (self.root/m.DROP/'B9/lock').write_bytes(b'WRONG\n')
        self.check_error('B9_LOCK_INVALID')

    def test_07_missing_b4_file(self):
        (self.root/m.DROP/'B4/grant.json').unlink()
        self.check_error('B4_ENTRIES_UNEXPECTED')

    def test_08_extra_b9_file(self):
        (self.root/m.DROP/'B9/extra.json').write_text('x')
        self.check_error('B9_ENTRIES_UNEXPECTED')

    def test_09_unexpected_top_level_file(self):
        (self.root/m.DROP/'extra.json').write_text('x')
        self.check_error('DROP_ENTRIES_UNEXPECTED')

    def test_10_symlink_b4_source(self):
        source = self.root/m.DROP/'B4/root-controller.py'
        source.unlink()
        source.symlink_to(self.root/m.DROP/'B9/root-executor.py')
        self.check_error('')

    def test_11_symlink_b4_directory(self):
        folder = self.root/m.DROP/'B4'
        shutil.rmtree(folder)
        folder.symlink_to(self.root/m.DROP/'B9',target_is_directory=True)
        self.check_error('')

    def test_12_symlink_middle_directory(self):
        folder = self.root/'var/lib/ardrec'
        moved = self.root/'elsewhere'
        folder.rename(moved)
        folder.symlink_to(moved, target_is_directory=True)
        self.check_error('')

    def test_13_file_mode_group_readable(self):
        (self.root/m.DROP/'B4/grant.json').chmod(0o640)
        self.check_error('FILE_METADATA_INVALID')

    def test_14_file_mode_world_readable(self):
        (self.root/m.DROP/'B4/grant.json').chmod(0o604)
        self.check_error('FILE_METADATA_INVALID')

    def test_15_file_mode_executable(self):
        (self.root/m.DROP/'B4/grant.json').chmod(0o700)
        self.check_error('FILE_METADATA_INVALID')

    def test_16_hardlink_file(self):
        original = self.root/m.DROP/'B4/grant.json'
        os.link(original,self.root/'hardlink-to-grant')
        self.check_error('FILE_METADATA_INVALID')

    def test_17_zero_length_file(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'')
        self.check_error('FILE_METADATA_INVALID')

    def test_18_overlong_file(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'a'*(m.MAX_FILE+1))
        self.check_error('FILE_METADATA_INVALID')

    def test_19_private_parent_mode(self):
        (self.root/m.DROP/'B4').chmod(0o750)
        self.check_error('DIRECTORY_NOT_PRIVATE')

    def test_20_group_writable_ancestor(self):
        (self.root/'var/lib').chmod(0o770)
        self.check_error('DIRECTORY_METADATA_INVALID')

    def test_21_noncanonical_json(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'{"schema": "x"}\n')
        self.check_error('JSON_NONCANONICAL')

    def test_22_duplicate_json_key(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'{"a":1,"a":2}\n')
        self.check_error('JSON_DUPLICATE_KEY')

    def test_23_nonfinite_json(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'{"a":NaN}\n')
        self.check_error('JSON_NONFINITE')

    def test_24_invalid_json(self):
        (self.root/m.DROP/'B4/grant.json').write_bytes(b'{broken}\n')
        self.check_error('JSON_INVALID')

    def test_25_trust_file_missing(self):
        (self.root/m.POLICY['root_trust']).unlink()
        self.check_error('')

    def test_26_revocation_file_missing(self):
        (self.root/m.POLICY['release_revocation']).unlink()
        self.check_error('')

    def test_27_release_trust_symlink(self):
        path = self.root/m.POLICY['release_trust']
        path.unlink()
        path.symlink_to(self.root/m.POLICY['pilot_trust'])
        self.check_error('')

    def test_28_f8_reference_missing(self):
        (self.root/m.BOOT_REFERENCE).unlink()
        self.check_error('')

    def test_29_no_policies_receipt_still_denies(self):
        with self.reader() as r:
            result = m.capture(r,include_policies=False)
        self.assertEqual(result['receipt']['external_count'],0)
        self.assertFalse(result['receipt']['root_install_authorized'])

    def test_30_untrusted_head_invalid(self):
        with self.reader() as r:
            with self.assertRaisesRegex(m.Refusal,'HEAD_INVALID'):
                m.inspect_release_input(reader=r,head='branch/main')

    def test_31_relative_path_rejected(self):
        for path in ('../etc/secret','a/../b','a//b','/tmp/x','a/./x',''):
            with self.subTest(path=path):
                with self.assertRaises(m.Refusal):
                    m.components(path)

    def test_32_reader_closed(self):
        reader = m.LockedTree(self.root,owner=os.geteuid())
        with self.assertRaisesRegex(m.Refusal,'READER_CLOSED'):
            reader.read(m.DROP+'/B4/grant.json')

    def test_33_wrong_root_owner(self):
        with self.assertRaisesRegex(m.Refusal,'FILE_OWNER_INVALID'):
            with m.LockedTree(self.root,owner=os.geteuid()+1):
                pass

    def test_34_root_dir_not_private(self):
        self.root.chmod(0o755)
        with self.assertRaisesRegex(m.Refusal,'DIRECTORY_NOT_PRIVATE'):
            with m.LockedTree(self.root,owner=os.geteuid()):
                pass

    def test_35_root_symlink(self):
        link = self.root/'root-symlink'
        link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(m.Refusal,'ROOT_SYMLINK_DENIED'):
            with m.LockedTree(link,owner=os.geteuid()):
                pass

    def test_36_readonly_mode_no_mutation(self):
        with self.reader() as r:
            self.assertEqual(len(m.capture(r)['payload']),13)
        self.assertFalse(any('receipt' in x.name for x in self.root.rglob('*')))

    def test_37_capabilities(self):
        c=m.capabilities()
        self.assertFalse(c['root_install_available'])
        self.assertFalse(c['independent_agent_installed'])
        self.assertEqual(c['p8'],'NO-GO')
        with self.assertRaisesRegex(m.Refusal,'INDEPENDENT_PRIVILEGED_AGENT_REQUIRED'):
            m.fixed_root_readonly()

    def test_38_no_privileged_actions(self):
        with mock.patch.object(m.os, 'system', side_effect=AssertionError('shell')):
            with self.reader() as r:
                self.assertEqual(m.capture(r)['receipt']['traffic_enabled'],False)
        with self.assertRaises(m.Refusal):
            m.LockedTree(Path('/'),owner=0)

    def test_39_name_replaced_during_read(self):
        target=self.root/m.DROP/'B4/root-controller.py'
        replacement=self.root/'replacement'
        replacement.write_bytes(B4_BYTES)
        replacement.chmod(0o600)
        original_os_read=m.os.read
        changed=[False]
        def read_with_swap(fd,count):
            if not changed[0] and os.fstat(fd).st_ino == target.stat().st_ino:
                changed[0]=True
                os.replace(replacement,target)
            return original_os_read(fd,count)
        with mock.patch.object(m.os, 'read', side_effect=read_with_swap):
            self.check_error('FILE_CHANGED_DURING_READ|FILE_METADATA_INVALID')

    def test_40_capture_uses_separate_byte_snapshots(self):
        with self.reader() as r:
            first=m.capture(r)
        (self.root/m.DROP/'B4/grant.json').write_bytes(m.canonical({'fresh':True}))
        with self.reader() as r:
            second=m.capture(r)
        self.assertNotEqual(first['receipt']['content_sha256'],second['receipt']['content_sha256'])
        self.assertFalse(second['receipt']['root_install_authorized'])


if __name__ == '__main__':
    unittest.main()
