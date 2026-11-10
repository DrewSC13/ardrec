#!/usr/bin/env python3
"""R26 independent adversarial tests: synthetic catalogs ONLY."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import p8_r26_ssh_include_graph as r26

FIXTURE = Path(__file__).resolve().parents[1] / 'p8-r26-ssh-include-graph-v1/cases.json'


def invoke_case(row):
    sources = {r26.ROOT: row['root_text'].encode('utf-8')}
    sources.update({p: v.encode('utf-8') for p, v in row['files'].items()})
    aliases = ({r26.ALIAS: r26.ALIAS_TARGET} if row['synthetic_alias_exact'] else {})
    return r26.analyze_synthetic_sources(sources, aliases=aliases)


class FrozenCases(unittest.TestCase):
    def test_all_frozen_cases(self):
        obj = json.loads(FIXTURE.read_bytes())
        self.assertEqual(obj['scope'], 'SYNTHETIC_ONLY_NO_REAL_SSH_FILES')
        self.assertGreaterEqual(len(obj['cases']), 12)
        for row in obj['cases']:
            with self.subTest(name=row['name']):
                if row['expect'] == 'FAIL_CLOSED':
                    with self.assertRaises(r26.GraphError):
                        invoke_case(row)
                else:
                    out = invoke_case(row)
                    self.assertEqual(out['status'], row['expect'])
                    self.assertEqual(out['candidate_edge_count'], row['candidate_edges'])
                    self.assertEqual(out['conditional_edges_not_evaluated'], row['conditional_edges'])
                    self.assertFalse(out['real_qcow2_access'])
                    self.assertFalse(out['real_include_graph_resolved'])
                    self.assertFalse(out['effective_ssh_configuration_verified'])
                    self.assertFalse(out['dispatch_allowed'])
                    self.assertEqual(out['authorized_profiles'], 0)
                    self.assertEqual(out['authorized_cases'], 0)
                    self.assertTrue(all('content' not in e for e in out['candidate_edges']))

    def test_glob_lexicographic_order(self):
        cases = json.loads(FIXTURE.read_text())['cases']
        obj = invoke_case(next(c for c in cases if c['name'] == 'glob_sorted'))
        self.assertEqual([e['target'].rsplit('/', 1)[-1] for e in obj['candidate_edges']],
                         ['10-a.conf', '21-b.conf'])

    def test_nested_inherited_host_condition_is_not_dropped(self):
        cases = json.loads(FIXTURE.read_text())['cases']
        obj = invoke_case(next(c for c in cases
                               if c['name'] == 'host_condition_propagates_down_nested_include'))
        self.assertEqual([e['conditional_unresolved'] for e in obj['candidate_edges']],
                         [True, True])
        self.assertEqual([e['conditional_context_inherited'] for e in obj['candidate_edges']],
                         [False, True])

    def test_nested_inherited_match_condition_is_not_dropped(self):
        cases = json.loads(FIXTURE.read_text())['cases']
        obj = invoke_case(next(c for c in cases
                               if c['name'] == 'match_condition_propagates_down_nested_include'))
        self.assertEqual(obj['conditional_edges_not_evaluated'], 2)
        self.assertTrue(obj['candidate_edges'][1]['conditional_context_inherited'])

    def test_revisited_source_has_path_specific_condition_context(self):
        cases = json.loads(FIXTURE.read_text())['cases']
        obj = invoke_case(next(c for c in cases
                               if c['name'] == 'revisited_source_changes_conditional_context'))
        self.assertEqual([e['conditional_unresolved'] for e in obj['candidate_edges']],
                         [False, False, True, True])
        self.assertEqual([e['conditional_context_inherited'] for e in obj['candidate_edges']],
                         [False, False, False, True])

    def test_alias_is_not_evidence_of_real_symlink_resolution(self):
        cases = json.loads(FIXTURE.read_text())['cases']
        obj = invoke_case(next(c for c in cases if c['name'] == 'wildcard_alias'))
        self.assertEqual(len(obj['alias_declarations_synthetic_only']), 1)
        self.assertFalse(obj['real_include_graph_resolved'])


class RejectionTests(unittest.TestCase):
    def call(self, data=None, aliases=None):
        return r26.analyze_synthetic_sources(
            {r26.ROOT: b'Host *\n'} if data is None else data,
            aliases={} if aliases is None else aliases)

    def rejects(self, data=None, aliases=None):
        with self.assertRaises(r26.GraphError):
            self.call(data, aliases)

    def test_missing_root(self): self.rejects({r26.FRAGMENT_DIR+'/10-a.conf': b'Host *\n'})
    def test_empty_root(self): self.rejects({r26.ROOT: b''})
    def test_root_utf8(self): self.rejects({r26.ROOT: b'\xff'})
    def test_nul_in_bytes(self): self.rejects({r26.ROOT: b'X\x00Y'})
    def test_path_traversal(self): self.rejects({r26.ROOT:b'X y\n', r26.FRAGMENT_DIR+'/../secret.conf':b'x'})
    def test_host_path_as_file(self): self.rejects({r26.ROOT:b'x\n', '/tmp/random.conf':b'x'})
    def test_alias_out_of_scope(self): self.rejects(aliases={r26.ALIAS:'/etc/shadow'})
    def test_alias_missing(self): self.rejects(aliases={r26.ALIAS:r26.ALIAS_TARGET})
    def test_alias_extra(self):
        self.rejects({r26.ROOT:b'x\n',r26.ALIAS:b'x\n'},
                     {r26.ALIAS:r26.ALIAS_TARGET,'/other':'x'})
    def test_larger_than_file_limit(self): self.rejects({r26.ROOT:b'a'*(r26.MAX_FILE_BYTES+1)})
    def test_larger_than_inventory_count(self):
        s={r26.ROOT:b'x\n'}
        s.update({r26.FRAGMENT_DIR+f'/{i}.conf':b'x\n' for i in range(r26.MAX_SOURCES)})
        self.rejects(s)
    def test_line_length(self): self.rejects({r26.ROOT:b'H'+b'x'*r26.MAX_LINE_BYTES+b' y\n'})
    def test_line_count(self): self.rejects({r26.ROOT:b'#\n'*(r26.MAX_LINES+1)})
    def test_missing_include_argument(self): self.rejects({r26.ROOT:b'Include\n'})
    def test_bad_include_quote(self): self.rejects({r26.ROOT:b'Include "/etc/ssh/ssh_config.d/*.conf"\n'})
    def test_bad_include_dollar(self): self.rejects({r26.ROOT:b'Include $HOME/.ssh/a.conf\n'})
    def test_bad_include_tilde(self): self.rejects({r26.ROOT:b'Include ~/.ssh/a.conf\n'})
    def test_bad_include_backtick(self): self.rejects({r26.ROOT:b'Include `id`\n'})
    def test_bad_include_shell(self): self.rejects({r26.ROOT:b'Include /etc/ssh/ssh_config.d/a.conf;rm\n'})
    def test_bad_include_nested_glob(self): self.rejects({r26.ROOT:b'Include /etc/ssh/ssh_config.d/a*.conf\n'})
    def test_bad_include_parent(self): self.rejects({r26.ROOT:b'Include /etc/ssh/ssh_config.d/../a.conf\n'})
    def test_bad_include_root_self(self): self.rejects({r26.ROOT:(b'Include '+r26.ROOT.encode()+b'\n')})
    def test_repeated_self_cycle(self):
        p=r26.FRAGMENT_DIR+'/a.conf'
        self.rejects({r26.ROOT:f'Include {p}\n'.encode(),p:f'Include {p}\n'.encode()})
    def test_two_node_cycle(self):
        a=r26.FRAGMENT_DIR+'/a.conf'; b=r26.FRAGMENT_DIR+'/b.conf'
        self.rejects({r26.ROOT:f'Include {a}\n'.encode(),a:f'Include {b}\n'.encode(),b:f'Include {a}\n'.encode()})
    def test_expansion_depth_limit(self):
        names=[r26.FRAGMENT_DIR+f'/{i}.conf' for i in range(10)]
        data={r26.ROOT:f'Include {names[0]}\n'.encode()}
        data.update({p:f'Include {names[i+1]}\n'.encode() if i+1<len(names) else b'# end\n' for i,p in enumerate(names)})
        self.rejects(data)
    def test_match_exec_no_execution(self):
        self.rejects({r26.ROOT:b'Match exec "true"\n'})
    def test_match_negated_exec_no_execution(self):
        self.rejects({r26.ROOT:b'Match !exec true\n'})
    def test_unsupported_multitoken_relative(self):
        self.rejects({r26.ROOT:b'Include a.conf b.conf\n'})
    def test_unrecognized_full_glob_not_ignored(self):
        self.rejects({r26.ROOT:b'Include /etc/ssh/*.conf\n'})
    def test_glob_self_include_cycle(self):
        a=r26.FRAGMENT_DIR+'/a.conf'
        self.rejects({r26.ROOT:(f'Include {r26.GLOB}\n').encode(),
                      a:(f'Include {r26.GLOB}\n').encode()})
    def test_cannot_pretend_to_know_default_include_without_bytes(self):
        d=self.call()
        self.assertEqual(d['candidate_edge_count'],0)
        self.assertFalse(d['real_include_graph_resolved'])
        self.assertFalse(d['user_config_observed'])


if __name__ == '__main__':
    unittest.main()
