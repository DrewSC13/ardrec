#!/usr/bin/env python3
"""Synthetic offline adversarial tests: no QCOW2, guestfish, loader or network."""
from __future__ import annotations
from collections import Counter
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r19_graph as g
import p8_r20_samba_candidate as r20
import p8_r21_multiarch_reconcile as r21
import p8_r21_offline_collect as collect


def r19_fixture():
    def md():return {'dispatch_allowed':False,'loader_executed':False,
                     'static_candidate_only':True,'elf_type':'ET_DYN','dt_needed_direct':[]}
    base='/usr/lib/x86_64-linux-gnu/libc.so.6'
    nodes=[{'canonical_path':base,'metadata':md()}]
    nodes.extend({'canonical_path':f'/usr/lib/x86_64-linux-gnu/libhistorical{i}.so.1',
                  'metadata':md()} for i in range(67))
    edges=[{'requested_by':'/usr/bin/smbclient','soname':'libc.so.6',
            'candidate_paths':[base],'candidate_resolution_only':True,
            'runtime_selected':False} for _ in range(225)]
    missing=[]
    for i in range(67):
        name=f'libmissing{i%38}.so.0'
        edges.append({'requested_by':'/usr/bin/smbclient','soname':name,
                      'candidate_paths':[],'candidate_resolution_only':True,
                      'runtime_selected':False})
        missing.append({'requested_by':'/usr/bin/smbclient','soname':name,
                        'status':'NOT_FOUND_IN_RESTRICTED_CANDIDATE_DIRS'})
    summary={'status':'PASS_P8_R19_OFFLINE_CANDIDATE_GRAPH_NOT_LOADER_CLOSURE',
             'observed_library_nodes':68,'direct_and_transitive_candidate_edges':292,
             'unresolved_edges':67,'ambiguous_edges':0,
             'runtime_dependency_closure_verified':False,
             'loader_search_semantics_verified':False,'dispatch_allowed':False}
    return {'scope':'P8_R19_OFFLINE_STATIC_ELF_CANDIDATE_GRAPH_ONLY',
            'base_main_commit':'e1e43c621e28628d004775d888ef5b133debfb52',
            'operator_confirmed_image_idle':True,'runtime_dependency_closure_verified':False,
            'effective_loader_resolution_verified':False,'case_authority_verified':False,
            'dispatch_allowed':False,'guest_binaries_executed':False,
            'authorized_profiles':0,'authorized_cases':0,
            'result':{'nodes':nodes,'edges':edges,'unresolved':missing,
                      'ambiguous':[],'summary':summary}}


def r20_fixture(r19_doc):
    missing=list(r21.EXPECTED_MISSING)
    assert sum(r21.EXPECTED_MISSING.values())==8
    origins=[f'libmissing{i}.so.0' for i in range(38)]
    origins.extend(f'libextra{i}.so.0' for i in range(26))
    assert len(origins)==64
    bad=[]
    for n,c in r21.EXPECTED_MISSING.items():bad.extend([n]*c)
    nodes=[]
    for i,origin in enumerate(origins):
        need_count=9 if i<51 else 8
        needed=[origins[(i+j+1)%64] for j in range(need_count)]
        if i<8:needed[-1]=bad[i]
        meta={'sha256':'a'*64,'file_bytes':4096,'elf_type':'ET_DYN',
              'soname':origin,'dt_needed_direct':needed,
              'dt_rpath':'$ORIGIN' if i<53 else None,'dt_runpath':None,
              'dispatch_allowed':False,'loader_executed':False,
              'static_candidate_only':True}
        nodes.append({'canonical_path':r20.restricted_candidate(origin),
                      'origin_soname':origin,'metadata':meta})
    probes={n:r20.restricted_candidate(n) for n in origins}
    probes.update({n:None for n in missing})
    report=r20.evaluate(r19_doc['result'],nodes,probes)
    assert report['summary']['r20_new_dso_needed_edges']==563
    assert report['summary']['r20_new_unresolved_edges']==8
    assert report['summary']['r20_custom_search_path_flags']==53
    return {'scope':'P8_R20_SAMBA_STATIC_CANDIDATES_NOT_LOADER_PROOF',
            'base_main_commit':r21.R20_BASE,
            'image_sha256':r21.IMAGE_SHA,
            'r19_private_receipt_sha256':r21.R19_SHA,
            'r9_offline_status':'PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION',
            'operator_confirmed_image_idle':True,
            'effective_loader_resolution_verified':False,
            'runtime_dependency_closure_verified':False,
            'runtime_binary_identity_verified':False,
            'dispatch_allowed':False,'guest_binaries_executed':False,
            'authorized_profiles':0,'authorized_cases':0,
            'result':report}


def fixture():
    old=r19_fixture()
    return old,r20_fixture(old)


def new_dso(name,needed=('libc.so.6',)):
    return {'canonical_path':'/usr/lib/x86_64-linux-gnu/'+name,
            'origin_soname':name,
            'metadata':{'elf_type':'ET_DYN','soname':name,'file_bytes':4096,
                        'sha256':'b'*64,'dt_needed_direct':list(needed),
                        'dt_rpath':None,'dt_runpath':None,
                        'dispatch_allowed':False,'loader_executed':False,
                        'static_candidate_only':True}}


def good_probe(names):
    opts={n:['/usr/lib/x86_64-linux-gnu/'+n] for n in names}
    hits={n:[{'candidate_path':r21.candidate_paths(n)[1],
              'canonical_path':opts[n][0]}] for n in names}
    nodes=[new_dso(n) for n in names]
    return opts,hits,nodes


class CanonicalScanTests(unittest.TestCase):
    def test_seven_directories(self):
        self.assertEqual(len(r21.SEARCH_DIRS),7)
        self.assertEqual(len(r21.candidate_paths('libjansson.so.4')),7)
        self.assertIn('/usr/lib/x86_64-linux-gnu/samba/libjansson.so.4',
                      r21.candidate_paths('libjansson.so.4'))
    def test_unsafe_sonames_rejected(self):
        for bad in ('../bad','/etc/passwd','../../passwd','a/b','', 'a'*256):
            with self.subTest(bad=bad),self.assertRaises(g.GraphError):
                r21.candidate_paths(bad)
    def test_unsafe_canonical_rejected(self):
        for bad in ('/etc/shadow','/usr/share/libx.so.0',
                    '/usr/lib/x86_64-linux-gnu/../shadow',
                    '/usr/lib/x86_64-linux-gnu/samba/../../etc/passwd'):
            with self.subTest(bad=bad),self.assertRaises(g.GraphError):
                r21.canonical_guest_path(bad)
    def test_no_candidate_returns_empty(self):
        out,hits=r21.assess_multidir_scan(['liba.so.0'],['false']*7,[])
        self.assertEqual(out['liba.so.0'],[])
        self.assertEqual(hits['liba.so.0'],[])
    def test_aliases_collapsed_to_one_canonical(self):
        out,hits=r21.assess_multidir_scan(['liba.so.0'],
             ['true','true']+['false']*5,
             ['/usr/lib/x86_64-linux-gnu/liba.so.0']*2)
        self.assertEqual(out['liba.so.0'],['/usr/lib/x86_64-linux-gnu/liba.so.0'])
        self.assertEqual(len(hits['liba.so.0']),2)
    def test_distinct_canonical_is_ambiguous(self):
        out,_=r21.assess_multidir_scan(['liba.so.0'],
             ['true','true']+['false']*5,
             ['/lib/x86_64-linux-gnu/liba.so.0',
              '/usr/lib/x86_64-linux-gnu/liba.so.0'])
        self.assertEqual(len(out['liba.so.0']),2)
    def test_bad_boolean(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan(['liba.so.0'],['maybe']*7,[])
    def test_bad_cardinality(self):
        for values in ([],['false']*6,['false']*8):
            with self.subTest(values=values),self.assertRaises(g.GraphError):
                r21.assess_multidir_scan(['liba.so.0'],values,[])
    def test_missing_realpath(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan(['liba.so.0'],['true']+['false']*6,[])
    def test_extra_realpath(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan(['liba.so.0'],['false']*7,
                                     ['/usr/lib/x86_64-linux-gnu/liba.so.0'])
    def test_invalid_realpath(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan(['liba.so.0'],['true']+['false']*6,['/etc/passwd'])
    def test_duplicate_input(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan(['liba.so.0']*2,['false']*14,[])
    def test_layer_bound(self):
        with self.assertRaises(g.GraphError):
            r21.assess_multidir_scan([f'lib{i}.so.0' for i in range(97)],['false']*679,[])
    def test_mixed_exact_multiplicity(self):
        answers=['false']*7+['true']+['false']*6
        out,_=r21.assess_multidir_scan(['liba.so.0','libb.so.0'],answers,
             ['/usr/lib/x86_64-linux-gnu/libb.so.0'])
        self.assertEqual(out['liba.so.0'],[])
        self.assertEqual(len(out['libb.so.0']),1)


class ProvenanceRecheckTests(unittest.TestCase):
    def test_recomputed_valid_source(self):
        old,new=fixture();known,names=r21.validate_r20_receipts(old,new)
        self.assertEqual(names,sorted(r21.EXPECTED_MISSING))
        self.assertIn('libc.so.6',known)
        self.assertEqual(len(known),65)
    def test_recovered_count_mutations_rejected(self):
        for k in ('r20_new_library_nodes','r20_new_dso_needed_edges',
                  'r19_recovered_candidate_edges','r20_new_unresolved_edges',
                  'r20_custom_search_path_flags'):
            old,new=fixture();new['result']['summary'][k]+=1
            with self.subTest(k=k),self.assertRaises(g.GraphError):
                r21.validate_r20_receipts(old,new)
    def test_reconciled_edge_tamper_rejected(self):
        old,new=fixture();new['result']['new_dso_edges'][0]['soname']='libfake.so.0'
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_unresolved_soname_tamper_rejected(self):
        old,new=fixture();new['result']['unresolved_new_dso_edges'][0]['soname']='evil.so.0'
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_node_digest_shape_rejected(self):
        old,new=fixture();new['result']['new_nodes'][0]['metadata']['sha256']='bad'
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_r20_base_drift_rejected(self):
        old,new=fixture();new['base_main_commit']='0'*40
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_r20_r19_sha_drift_rejected(self):
        old,new=fixture();new['r19_private_receipt_sha256']='0'*64
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_r20_runtime_promotion_rejected(self):
        for k in ('dispatch_allowed','guest_binaries_executed',
                  'runtime_binary_identity_verified'):
            old,new=fixture();new[k]=True
            with self.subTest(k=k),self.assertRaises(g.GraphError):
                r21.validate_r20_receipts(old,new)
    def test_r20_authority_rejected(self):
        old,new=fixture();new['authorized_profiles']=1
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_prior_r19_status_rejected(self):
        old,new=fixture();old['result']['summary']['dispatch_allowed']=True
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)
    def test_unobserved_additional_node_rejected(self):
        old,new=fixture();new['result']['new_nodes'][0]['canonical_path']='/etc/passwd'
        with self.assertRaises(g.GraphError):r21.validate_r20_receipts(old,new)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.old,self.doc=fixture()
        self.known,self.names=r21.validate_r20_receipts(self.old,self.doc)
        self.opts,self.hits,self.nodes=good_probe(self.names)
    def test_all_eight_candidate_edges(self):
        result=r21.evaluate(self.doc,self.known,self.opts,self.nodes,self.hits)
        summary=result['summary']
        self.assertEqual(summary['r20_recovered_candidate_edges'],8)
        self.assertEqual(summary['r20_remaining_unresolved_edges'],0)
        self.assertEqual(summary['r21_new_library_nodes'],5)
        self.assertEqual(summary['r21_new_dso_needed_edges'],5)
        self.assertFalse(summary['loader_resolution_verified'])
        self.assertFalse(summary['dispatch_allowed'])
    def test_partial_resolution(self):
        names=self.names
        self.opts[names[0]]=[];self.hits[names[0]]=[]
        self.nodes=[n for n in self.nodes if n['origin_soname']!=names[0]]
        result=r21.evaluate(self.doc,self.known,self.opts,self.nodes,self.hits)
        count=r21.EXPECTED_MISSING[names[0]]
        self.assertEqual(result['summary']['r20_remaining_unresolved_edges'],count)
        self.assertEqual(result['summary']['r20_recovered_candidate_edges'],8-count)
    def test_ambiguity_is_not_auto_selected(self):
        name=self.names[0]
        other='/usr/lib/x86_64-linux-gnu/samba/'+name
        self.opts[name].append(other)
        self.hits[name].append({'candidate_path':r21.candidate_paths(name)[-1],
                                 'canonical_path':other})
        self.nodes=[n for n in self.nodes if n['origin_soname']!=name]
        result=r21.evaluate(self.doc,self.known,self.opts,self.nodes,self.hits)
        self.assertEqual(result['summary']['r20_ambiguous_edges'],
                         r21.EXPECTED_MISSING[name])
    def test_new_missing_transitive_retained(self):
        self.nodes[0]['metadata']['dt_needed_direct']=['libstillmissing.so.0']
        result=r21.evaluate(self.doc,self.known,self.opts,self.nodes,self.hits)
        self.assertEqual(result['summary']['r21_new_unresolved_edges'],1)
    def test_new_known_transitive_resolved(self):
        result=r21.evaluate(self.doc,self.known,self.opts,self.nodes,self.hits)
        self.assertEqual(result['summary']['r21_new_unresolved_edges'],0)
    def test_new_node_can_not_dispatch(self):
        self.nodes[0]['metadata']['dispatch_allowed']=True
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_reject_unsafe_new_node_path(self):
        self.nodes[0]['canonical_path']='/etc/passwd'
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_reject_unobserved_singleton(self):
        self.nodes.pop()
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_reject_rogue_probe_path(self):
        self.hits[self.names[0]][0]['candidate_path']='/tmp/rogue.so'
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_reject_hit_drift(self):
        self.hits[self.names[0]]=[]
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_reject_new_node_digest(self):
        self.nodes[0]['metadata']['sha256']='notasha'
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_node_cap(self):
        for i in range(60):self.nodes.append(new_dso(f'libadded{i}.so.1'))
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)
    def test_added_edge_cap(self):
        for n in self.nodes:
            n['metadata']['dt_needed_direct']=[f'libx{i}.so.1' for i in range(130)]
        with self.assertRaises(g.GraphError):r21.evaluate(
            self.doc,self.known,self.opts,self.nodes,self.hits)


class CollectorBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.old,self.doc=fixture()
        self.known,self.names=r21.validate_r20_receipts(self.old,self.doc)
    def test_probe_batched_no_loader(self):
        name='libjansson.so.4'
        states=['false','true']+['false']*5
        with patch.object(collect.r19,'guestfish_lines',side_effect=[states,
                ['/usr/lib/x86_64-linux-gnu/libjansson.so.4']]) as reader:
            opts,hits=collect.probe([name])
            self.assertEqual(reader.call_count,2)
            self.assertEqual(len(reader.call_args_list[0].args[0]),7)
            self.assertEqual(len(opts[name]),1)
            self.assertEqual(len(hits[name]),1)
    def test_full_synthetic_bfs(self):
        def fake_scan(names):
            o,h,_=good_probe(names)
            return o,h
        def fake_meta(data):
            name=data.decode()
            return new_dso(name)['metadata']
        with patch.object(collect,'probe',side_effect=fake_scan),\
             patch.object(collect.r19,'virt_cat',side_effect=lambda path: path.rsplit('/',1)[-1].encode()) as cat,\
             patch.object(collect.graph,'parse_elf',side_effect=fake_meta):
            result=collect.expand(self.doc,self.known,self.names)
            self.assertEqual(cat.call_count,5)
            self.assertEqual(result['summary']['r20_recovered_candidate_edges'],8)
    def test_zero_results_keep_denied(self):
        with patch.object(collect,'probe',return_value=(
                {n:[] for n in self.names},{n:[] for n in self.names})),\
             patch.object(collect.r19,'virt_cat') as cat:
            out=collect.expand(self.doc,self.known,self.names)
        cat.assert_not_called()
        self.assertEqual(out['summary']['r20_remaining_unresolved_edges'],8)
    def test_ambiguous_never_read(self):
        names=self.names
        def ambiguous(names):
            o={n:['/usr/lib/x86_64-linux-gnu/'+n,
                  '/usr/lib/x86_64-linux-gnu/samba/'+n] for n in names}
            h={n:[{'candidate_path':r21.candidate_paths(n)[1],
                   'canonical_path':o[n][0]},
                  {'candidate_path':r21.candidate_paths(n)[-1],
                   'canonical_path':o[n][1]}] for n in names}
            return o,h
        with patch.object(collect,'probe',side_effect=ambiguous),\
             patch.object(collect.r19,'virt_cat') as cat:
            out=collect.expand(self.doc,self.known,names)
        cat.assert_not_called()
        self.assertEqual(out['summary']['r20_ambiguous_edges'],8)
    def test_soname_mismatch_fails_closed(self):
        def one(names):
            o,h,_=good_probe(names);return o,h
        with patch.object(collect,'probe',side_effect=one),\
             patch.object(collect.r19,'virt_cat',return_value=b'synthetic'),\
             patch.object(collect.graph,'parse_elf',return_value=new_dso('libwrong.so.1')['metadata']),\
             self.assertRaises(g.GraphError):
            collect.expand(self.doc,self.known,self.names)
    def test_layer_bound(self):
        with patch.object(collect,'probe') as probe,self.assertRaises(g.GraphError):
            collect.expand(self.doc,self.known,['bad.so.0']*200)
        probe.assert_not_called()
    def test_bad_seeds(self):
        with patch.object(collect,'probe') as probe,self.assertRaises(g.GraphError):
            collect.expand(self.doc,self.known,[])
        probe.assert_not_called()

if __name__=='__main__':unittest.main()
