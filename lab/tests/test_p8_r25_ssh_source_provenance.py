#!/usr/bin/env python3
"""R25: independent synthetic source-byte tests, no guestfish/QCOW2/network."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import p8_r25_ssh_source_provenance as r25
import p8_r25_private_ssh_source_collect as collector

ROOT = b'# Client test fixture\nInclude /etc/ssh/ssh_config.d/*.conf\nHost *\n    ServerAliveInterval 0\n'
FRAG = b'# Synthetic only\nMatch host lab.example\n    IdentityFile none\n'


def sample():
    return r25.analyze(ROOT, {'10-local.conf': FRAG}, ['NOTE', '10-local.conf'], r25.IMAGE_SHA)


class PositiveSyntheticTests(unittest.TestCase):
    def test_basic_capture_shape(self):
        doc = sample()
        self.assertEqual(doc['source_file_count'], 2)
        self.assertEqual(doc['fragment_file_count'], 1)
        self.assertEqual(doc['unresolved_include_directive_count'], 1)
        self.assertEqual(doc['source_bytes_total'], len(ROOT)+len(FRAG))
        self.assertEqual(r25.validate(doc), doc)

    def test_stable_digest(self):
        self.assertEqual(r25.digest_json(sample()), r25.digest_json(copy.deepcopy(sample())))

    def test_content_is_not_in_receipt(self):
        doc = sample()
        self.assertNotIn('ServerAliveInterval', str(doc))
        self.assertNotIn('IdentityFile', str(doc))
        self.assertNotIn('lab.example', str(doc))

    def test_no_elevation(self):
        doc = sample()
        for name in ('include_graph_resolved', 'effective_client_config_verified',
                     'effective_loader_verified', 'runtime_binary_identity_verified',
                     'client_capability_verified', 'dispatch_allowed',
                     'guest_binaries_executed', 'guest_services_contacted'):
            self.assertIs(doc[name], False)

    def test_directory_normalization(self):
        self.assertEqual(r25.normalize_directory_entries(['README','z.conf','a.conf']),
                         ['a.conf','z.conf'])

    def test_zero_fragments(self):
        doc = r25.analyze(ROOT, {}, [], r25.IMAGE_SHA)
        self.assertEqual(doc['source_file_count'], 1)
        self.assertEqual(doc['fragment_file_count'], 0)

    def test_case_insensitive_lexical_markers(self):
        lines=b' # Include fake\ninclude /a\nHost *\nmAtCh final all\n'
        self.assertEqual(r25.inspect_directives(lines)['lexical_directives'],
                         {'include': 1, 'host': 1, 'match': 1})

    def test_frozen_profiles(self):
        x=r25.public_contract()
        self.assertEqual(len(x['target_profiles']),8)
        self.assertIs(x['material_observation_already_performed'],False)
        self.assertIs(x['dispatch_allowed'],False)

    def test_strict_operator_commands(self):
        with self.assertRaises(r25.SourceError): collector.gf('command','echo bad')
        with self.assertRaises(r25.SourceError): collector.gf('sh','-c')

    def test_filename_case(self):
        self.assertEqual(r25.normalize_directory_entries(['D.conf','9.conf','a-b.c.conf']),
                         ['9.conf','D.conf','a-b.c.conf'])

    def test_source_hash_changes_with_actual_bytes(self):
        a=sample()
        b=r25.analyze(ROOT+b'\n', {'10-local.conf': FRAG},
                      ['NOTE','10-local.conf'], r25.IMAGE_SHA)
        self.assertNotEqual(a['source_files'][0]['sha256'],b['source_files'][0]['sha256'])

    def test_status_not_capability(self):
        self.assertIn('NOT_EFFECTIVE', sample()['result'])

    def test_no_shell_command_in_collector(self):
        with self.assertRaises(r25.SourceError): collector.gf('download', '/etc/x', '--rw')

    def test_permissive_unrelated_directory_name_skipped(self):
        doc=r25.analyze(ROOT, {}, ['README'], r25.IMAGE_SHA)
        self.assertEqual(doc['fragment_file_count'],0)
        self.assertEqual(doc['directory_entries_observed'],1)


class PoisonedReceiptTests(unittest.TestCase):
    def reject(self, fn):
        doc=copy.deepcopy(sample())
        fn(doc)
        with self.assertRaises((r25.SourceError,TypeError,AttributeError)):
            r25.validate(doc)


def make_mutation(fn):
    def test(self):self.reject(fn)
    return test


MUTATIONS={
 'wrong_version':lambda d:d.update(schema_version='9'),
 'wrong_scope':lambda d:d.update(scope='APPROVED'),
 'wrong_base':lambda d:d.update(base_main_commit='0'*40),
 'wrong_image':lambda d:d.update(image_sha256='0'*64),
 'count_more':lambda d:d.update(source_file_count=100),
 'total_more':lambda d:d.update(source_bytes_total=123),
 'fragment_count_more':lambda d:d.update(fragment_file_count=29),
 'directory_count_less':lambda d:d.update(directory_entries_observed=0),
 'include_count_more':lambda d:d.update(unresolved_include_directive_count=80),
 'approval':lambda d:d.update(profiles_approved=1),
 'authorized_case':lambda d:d.update(cases_authorized=1),
 'authority_true':lambda d:d.update(case_authorized=True),
 'dispatch_true':lambda d:d.update(dispatch_allowed=True),
 'guest_exec':lambda d:d.update(guest_binaries_executed=True),
 'network':lambda d:d.update(guest_services_contacted=True),
 'stored_contents':lambda d:d.update(private_file_contents_stored=True),
 'claimed_effective_config':lambda d:d.update(effective_client_config_verified=True),
 'claimed_effective_loader':lambda d:d.update(effective_loader_verified=True),
 'claimed_runtime_binary':lambda d:d.update(runtime_binary_identity_verified=True),
 'claimed_capability':lambda d:d.update(client_capability_verified=True),
 'claimed_include_resolved':lambda d:d.update(include_graph_resolved=True),
 'not_observed':lambda d:d.update(source_bytes_measured=False),
 'status_promoted':lambda d:d.update(result='APPROVED'),
 'missing_root':lambda d:d['source_files'].pop(0),
 'duplicate_file':lambda d:d['source_files'].append(copy.deepcopy(d['source_files'][1])),
 'file_root_swap':lambda d:d['source_files'].reverse(),
 'file_path_traversal':lambda d:d['source_files'][1].update(guest_path='/etc/ssh/ssh_config.d/../../bad.conf'),
 'file_wrong_directory':lambda d:d['source_files'][1].update(guest_path='/etc/other/test.conf'),
 'file_malformed_hash':lambda d:d['source_files'][1].update(sha256='x'*64),
 'file_negative_size':lambda d:d['source_files'][1].update(bytes=-1),
 'file_zero_size':lambda d:d['source_files'][1].update(bytes=0),
 'file_line_negative':lambda d:d['source_files'][1].update(line_count=-1),
 'file_include_negative':lambda d:d['source_files'][1].update(include_directives_lexical=-1),
 'file_host_negative':lambda d:d['source_files'][1].update(host_directives_lexical=-1),
 'file_match_negative':lambda d:d['source_files'][1].update(match_directives_lexical=-1),
 'unexpected_receipt_field':lambda d:d.update(secret='oops'),
 'missing_receipt_field':lambda d:d.pop('case_authorized'),
 'missing_file_field':lambda d:d['source_files'][1].pop('bytes'),
 'extra_file_field':lambda d:d['source_files'][1].update(raw_config='password'),
 'wrong_ssh_count':lambda d:d.update(ssh_profile_candidate_count=29),
 'boolean_instead_count':lambda d:d.update(profiles_approved=False),
}
for key,fn in MUTATIONS.items():
    setattr(PoisonedReceiptTests,'test_reject_'+key,make_mutation(fn))


class PoisonedInputTests(unittest.TestCase):
    def reject(self,root=ROOT,fragments=None,entries=None,sha=None):
        with self.assertRaises((r25.SourceError,TypeError,AttributeError)):
            r25.analyze(root, {'10-local.conf':FRAG} if fragments is None else fragments,
                        ['10-local.conf'] if entries is None else entries,
                        r25.IMAGE_SHA if sha is None else sha)

    def test_wrong_image(self):self.reject(sha='f'*64)
    def test_root_nul(self):self.reject(root=b'a\x00b')
    def test_root_empty(self):self.reject(root=b'')
    def test_root_not_bytes(self):self.reject(root='not bytes')
    def test_root_invalid_utf8(self):self.reject(root=b'\xff')
    def test_root_too_large(self):self.reject(root=b'x'*(r25.MAX_FILE_BYTES+1))
    def test_too_many_fragments(self):
        self.reject(fragments={}, entries=[f'{i}.conf' for i in range(33)])
    def test_filename_traversal(self):self.reject(entries=['../test.conf'])
    def test_filename_backslash(self):self.reject(entries=['a\\b.conf'])
    def test_duplicate_entries(self):self.reject(entries=['10-local.conf']*2)
    def test_unknown_fragment(self):self.reject(fragments={'unexpected.conf':FRAG})
    def test_missing_fragment(self):self.reject(fragments={})
    def test_bad_fragment_byte(self):self.reject(fragments={'10-local.conf':b'\xff'})
    def test_fragment_nul(self):self.reject(fragments={'10-local.conf':b'c\x00'})
    def test_guestfish_wrong_path(self):
        with self.assertRaises(r25.SourceError):collector.gf('download','../../bad','-')




class ExactAliasBoundaryTests(unittest.TestCase):
    """Synthetic only: no libguestfs, no QCOW2, no network."""

    def alias_receipt(self):
        return r25.analyze(ROOT, {r25.ALIAS_NAME: FRAG},
                           [r25.ALIAS_NAME], r25.IMAGE_SHA,
                           aliases={r25.ALIAS_PATH: r25.ALIAS_TARGET})

    def test_exact_alias_provenance_captured(self):
        d = self.alias_receipt()
        self.assertEqual(r25.validate(d), d)
        self.assertEqual(d['source_alias_count'], 1)
        self.assertEqual(d['source_aliases'], [
            {'guest_path': r25.ALIAS_PATH,
             'resolved_regular_path': r25.ALIAS_TARGET}])
        self.assertEqual(d['source_files'][1]['sha256'],
                         __import__('hashlib').sha256(FRAG).hexdigest())
        self.assertIs(d['effective_client_config_verified'], False)

    def test_unknown_alias_cannot_enter_pure_model(self):
        for aliases in (
            {r25.ALIAS_PATH: '/etc/passwd'},
            {'/etc/ssh/ssh_config.d/10-evil.conf': r25.ALIAS_TARGET},
            {r25.ALIAS_PATH: r25.ALIAS_TARGET, 'x': 'y'},
            [r25.ALIAS_PATH],
            {r25.ALIAS_PATH: r25.ALIAS_TARGET+'/'},
        ):
            with self.subTest(aliases=aliases):
                with self.assertRaises(r25.SourceError):
                    r25.analyze(ROOT, {r25.ALIAS_NAME: FRAG},
                                [r25.ALIAS_NAME], r25.IMAGE_SHA,
                                aliases=aliases)

    def test_alias_requires_matching_fragment(self):
        with self.assertRaises(r25.SourceError):
            r25.analyze(ROOT, {}, [], r25.IMAGE_SHA,
                        aliases={r25.ALIAS_PATH: r25.ALIAS_TARGET})

    def test_missing_alias_count_blocks(self):
        d = self.alias_receipt()
        d['source_alias_count'] = 0
        with self.assertRaises(r25.SourceError):r25.validate(d)

    def test_forged_alias_target_blocks(self):
        d = self.alias_receipt()
        d['source_aliases'][0]['resolved_regular_path'] = '/etc/shadow'
        with self.assertRaises(r25.SourceError):r25.validate(d)

    @staticmethod
    def guestfish_mock(alias_target=None, aliases=None, not_regular=None,
                       parent_link=None, readlink_after=None):
        alias_target = (r25.ALIAS_TARGET if alias_target is None else alias_target)
        aliases = set([r25.ALIAS_PATH] if aliases is None else aliases)
        lookups = []
        def execute(op, *args):
            lookups.append((op, *args))
            path = args[0]
            if op == 'is-symlink':
                return b'true\n' if path in aliases or path == parent_link else b'false\n'
            if op == 'is-dir':
                return b'true\n'
            if op == 'is-file':
                return b'false\n' if path == not_regular else b'true\n'
            if op == 'readlink':
                n = sum(x[0] == 'readlink' for x in lookups)
                if n >= 2 and readlink_after is not None:
                    return readlink_after.encode() + b'\n'
                return alias_target.encode() + b'\n'
            if op == 'ls':
                return (r25.ALIAS_NAME + '\n').encode()
            if op == 'download':
                if path == r25.ROOT_PATH:return ROOT
                if path == r25.ALIAS_TARGET:return FRAG
                raise AssertionError('unexpected symlink/directive download '+str(path))
            raise AssertionError('unexpected guestfish op '+op)
        return execute, lookups

    def test_collector_uses_only_exact_target_for_bytes(self):
        fn, calls = self.guestfish_mock()
        with mock.patch.object(collector,'gf',side_effect=fn):
            d = collector.read_only_material()
        self.assertEqual(d['source_alias_count'], 1)
        self.assertIn(('download', r25.ALIAS_TARGET, '-'), calls)
        self.assertNotIn(('download', r25.ALIAS_PATH, '-'), calls)

    def test_unknown_link_target_blocks(self):
        for target in ('../../etc/passwd','/etc/passwd',
                       r25.ALIAS_TARGET+'x', '/usr/lib/systemd/ssh_config.d/../bad.conf'):
            with self.subTest(target=target):
                fn, _ = self.guestfish_mock(alias_target=target)
                with mock.patch.object(collector,'gf',side_effect=fn):
                    with self.assertRaises(r25.SourceError):collector.read_only_material()

    def test_target_symlink_blocks(self):
        fn, calls = self.guestfish_mock(aliases={r25.ALIAS_PATH,r25.ALIAS_TARGET})
        with mock.patch.object(collector,'gf',side_effect=fn):
            with self.assertRaises(r25.SourceError):collector.read_only_material()
        self.assertNotIn(('download',r25.ALIAS_TARGET,'-'),calls)

    def test_target_parent_symlink_blocks(self):
        fn, calls = self.guestfish_mock(parent_link='/usr/lib/systemd')
        with mock.patch.object(collector,'gf',side_effect=fn):
            with self.assertRaises(r25.SourceError):collector.read_only_material()
        self.assertNotIn(('download',r25.ALIAS_TARGET,'-'),calls)

    def test_target_not_regular_blocks(self):
        fn, calls = self.guestfish_mock(not_regular=r25.ALIAS_TARGET)
        with mock.patch.object(collector,'gf',side_effect=fn):
            with self.assertRaises(r25.SourceError):collector.read_only_material()
        self.assertNotIn(('download',r25.ALIAS_TARGET,'-'),calls)

    def test_unexpected_other_symlink_blocks(self):
        fn, _ = self.guestfish_mock(aliases={r25.ALIAS_PATH,
             r25.FRAGMENT_DIR+'/22-rogue.conf'})
        with mock.patch.object(collector,'gf',side_effect=fn):
            with self.assertRaises(r25.SourceError):
                collector.fragment_source('22-rogue.conf')

    def test_readlink_mutation_blocks(self):
        fn, _ = self.guestfish_mock(readlink_after='/etc/shadow')
        with mock.patch.object(collector,'gf',side_effect=fn):
            with self.assertRaises(r25.SourceError):collector.read_only_material()

    def test_regular_fragment_no_redirect(self):
        filename='21-ordinary.conf'
        def fake(op,*args):
            path=args[0]
            if op == 'is-symlink':return b'false\n'
            if op == 'is-file':return b'true\n'
            if op == 'download':
                self.assertEqual(path, r25.FRAGMENT_DIR+'/'+filename)
                return FRAG
            raise AssertionError('unexpected '+op)
        with mock.patch.object(collector,'gf',side_effect=fake):
            content,target=collector.fragment_source(filename)
        self.assertEqual(content, FRAG)
        self.assertIsNone(target)

    def test_unknown_boolean_blocks(self):
        with mock.patch.object(collector,'gf',return_value=b'unsure\n'):
            with self.assertRaises(r25.SourceError):
                collector.guest_bool('is-symlink',r25.ALIAS_PATH)


if __name__=='__main__':unittest.main()
