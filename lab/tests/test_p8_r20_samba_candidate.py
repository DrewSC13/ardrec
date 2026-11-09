#!/usr/bin/env python3
"""Offline synthetic regression and fail-closed adversarial cases. No libguestfs access."""
from __future__ import annotations
from collections import Counter
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r20_samba_candidate as r20
import p8_r20_offline_collect as collector
import p8_r19_graph as g


def fixture():
    base='/usr/lib/x86_64-linux-gnu/libc.so.6'
    metadata={'dispatch_allowed':False,'loader_executed':False,'static_candidate_only':True,
              'elf_type':'ET_DYN','dt_needed_direct':[]}
    nodes=[{'canonical_path':base,'metadata':copy.deepcopy(metadata)}]
    for i in range(67):
        nodes.append({'canonical_path':f'/usr/lib/x86_64-linux-gnu/liboriginal{i}.so.1',
                      'metadata':copy.deepcopy(metadata)})
    unresolved=[];edges=[]
    for i in range(225):
        edges.append({'requested_by':'/usr/bin/smbclient','soname':'libc.so.6',
                      'candidate_paths':[base],'candidate_resolution_only':True,
                      'runtime_selected':False})
    for i in range(67):
        name=f'libmissing{i%38}.so.0'
        row={'requested_by':'/usr/bin/smbclient','soname':name,
             'candidate_paths':[],'candidate_resolution_only':True,'runtime_selected':False}
        edges.append(row)
        unresolved.append({'requested_by':'/usr/bin/smbclient','soname':name,
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
            'result':{'nodes':nodes,'edges':edges,'unresolved':unresolved,
                      'ambiguous':[],'summary':summary}}


def new_node(name='libmissing0.so.0', needed=('libc.so.6',)):
    return {'canonical_path':r20.restricted_candidate(name),'origin_soname':name,
            'metadata':{'elf_type':'ET_DYN','dt_needed_direct':list(needed),
                        'soname':name,'sha256':'a'*64,'dispatch_allowed':False,
                        'loader_executed':False,'static_candidate_only':True}}


class PathConstraints(unittest.TestCase):
    def test_candidate(self):
        self.assertEqual(r20.restricted_candidate('libreplace-private-samba.so.0'),
            '/usr/lib/x86_64-linux-gnu/samba/libreplace-private-samba.so.0')
    def test_soname_traversal(self):
        for name in ('../x','a/b','../evil.so','\\etc','', 'a'*256):
            with self.subTest(name=name),self.assertRaises(g.GraphError):r20.restricted_candidate(name)
    def test_cross_directory_canonical(self):
        for p in ('/etc/passwd','/usr/lib/x86_64-linux-gnu/libc.so.6',
                  '/usr/lib/x86_64-linux-gnu/samba/../evil.so'):
            with self.subTest(path=p),self.assertRaises(g.GraphError):r20.validated_canonical(p)
    def test_boolean_and_cardinality(self):
        for present,reals in (([],[]),(['maybe'],[]),(['true'],[]),(['false'],['/usr/lib/x86_64-linux-gnu/samba/x.so'])):
            with self.subTest(present=present),self.assertRaises(g.GraphError):
                r20.assess_candidate_scan(['libx.so.1'],present,reals)
    def test_scan_success(self):
        found=r20.assess_candidate_scan(['libx.so.1','liby.so.2'],['true','false'],
             ['/usr/lib/x86_64-linux-gnu/samba/libx.so.1'])
        self.assertEqual(found,{'libx.so.1':'/usr/lib/x86_64-linux-gnu/samba/libx.so.1','liby.so.2':None})
    def test_duplicate_names(self):
        with self.assertRaises(g.GraphError):r20.assess_candidate_scan(['libx.so.1']*2,['false']*2,[])
    def test_overbound(self):
        with self.assertRaises(g.GraphError):r20.assess_candidate_scan(['libx.so.1']*129,[],[])
    def test_absolute_path_injection(self):
        with self.assertRaises(g.GraphError):r20.assess_candidate_scan(['libx.so.1'],['true'],['/tmp/untrusted.so'])


class SourceValidation(unittest.TestCase):
    def test_fixture_valid(self):
        doc=fixture();mapped,names=r20.validate_r19(doc)
        self.assertEqual(len(names),38)
        self.assertEqual(mapped['libc.so.6'],'/usr/lib/x86_64-linux-gnu/libc.so.6')
    def test_count_mutations(self):
        for field in ('observed_library_nodes','direct_and_transitive_candidate_edges','unresolved_edges','ambiguous_edges'):
            doc=fixture();doc['result']['summary'][field]+=1
            with self.subTest(field=field),self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_invalid_receipt_base(self):
        doc=fixture();doc['base_main_commit']='f'*40
        with self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_promoted_authority(self):
        for field in ('authorized_profiles','authorized_cases'):
            doc=fixture();doc[field]=1
            with self.subTest(field=field),self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_promoted_runtime(self):
        for field in ('runtime_dependency_closure_verified','effective_loader_resolution_verified','dispatch_allowed','guest_binaries_executed'):
            doc=fixture();doc[field]=True
            with self.subTest(field=field),self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_untracked_candidate(self):
        doc=fixture();doc['result']['edges'][0]['candidate_paths']=['/usr/lib/x86_64-linux-gnu/absent.so']
        with self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_missing_not_tracked_by_edge(self):
        doc=fixture();doc['result']['unresolved'][0]['soname']='another.so.4'
        with self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_mutated_node_policy(self):
        doc=fixture();doc['result']['nodes'][0]['metadata']['loader_executed']=True
        with self.assertRaises(g.GraphError):r20.validate_r19(doc)
    def test_ambiguous_candidate(self):
        doc=fixture();doc['result']['edges'][0]['candidate_paths']=['/usr/lib/x86_64-linux-gnu/libc.so.6']*2
        with self.assertRaises(g.GraphError):r20.validate_r19(doc)


class Reconciliation(unittest.TestCase):
    def test_empty_scan_no_promotion(self):
        old=fixture()['result'];names=r20.validate_r19(fixture())[1]
        report=r20.evaluate(old,[],{name:None for name in names})
        self.assertEqual(report['summary']['r19_remaining_unresolved_edges'],67)
        self.assertEqual(report['summary']['r19_recovered_candidate_edges'],0)
        self.assertFalse(report['summary']['dispatch_allowed'])
    def test_recovery_counts_repeated_soname(self):
        old=fixture()['result'];names=r20.validate_r19(fixture())[1]
        probes={name:None for name in names};probes['libmissing0.so.0']=r20.restricted_candidate('libmissing0.so.0')
        report=r20.evaluate(old,[new_node()],probes)
        actual=Counter(x['soname'] for x in old['unresolved'])['libmissing0.so.0']
        self.assertEqual(report['summary']['r19_recovered_candidate_edges'],actual)
        self.assertEqual(report['summary']['r20_new_dso_needed_edges'],1)
        self.assertEqual(report['summary']['r20_new_unresolved_edges'],0)
    def test_new_missing_dependency(self):
        old=fixture()['result'];names=r20.validate_r19(fixture())[1]
        probes={name:None for name in names};probes['libmissing0.so.0']=r20.restricted_candidate('libmissing0.so.0')
        report=r20.evaluate(old,[new_node(needed=('libnotthere.so.9',))],probes)
        self.assertEqual(report['summary']['r20_new_unresolved_edges'],1)
    def test_no_unobserved_path(self):
        old=fixture()['result'];names=r20.validate_r19(fixture())[1]
        probes={name:None for name in names};probes['libmissing0.so.0']=r20.restricted_candidate('libmissing0.so.0')
        with self.assertRaises(g.GraphError):r20.evaluate(old,[],probes)
    def test_new_node_unsafe_promotion(self):
        old=fixture()['result'];names=r20.validate_r19(fixture())[1]
        node=new_node();node['metadata']['dispatch_allowed']=True
        probes={name:None for name in names};probes['libmissing0.so.0']=node['canonical_path']
        with self.assertRaises(g.GraphError):r20.evaluate(old,[node],probes)
    def test_new_node_outside_dir(self):
        node=new_node();node['canonical_path']='/etc/ld.so.cache'
        old=fixture()['result']
        with self.assertRaises(g.GraphError):r20.evaluate(old,[node],{})


class CollectorHarness(unittest.TestCase):
    def test_batch_only_2_calls(self):
        with patch.object(collector.r19,'guestfish_lines',side_effect=[['true','false'],
                ['/usr/lib/x86_64-linux-gnu/samba/libmissing0.so.0']]) as guest:
            out=collector.probe_samba(['libmissing0.so.0','libmissing1.so.0'])
            self.assertEqual(guest.call_count,2)
            self.assertIsNone(out['libmissing1.so.0'])
    def test_recursion_bounded_and_materialized(self):
        doc=fixture();names=r20.validate_r19(doc)[1]
        first={n:None for n in names};first['libmissing0.so.0']=r20.restricted_candidate('libmissing0.so.0')
        next_map={'libnew.so.1':r20.restricted_candidate('libnew.so.1')}
        elf1=new_node(needed=('libnew.so.1','libc.so.6'))['metadata']
        elf2=new_node('libnew.so.1',needed=('libc.so.6',))['metadata']
        with patch.object(collector,'probe_samba',side_effect=[first,next_map]) as scan,\
             patch.object(collector.r19,'virt_cat',return_value=b'fake') as cat,\
             patch.object(collector.graph,'parse_elf',side_effect=[elf1,elf2]):
            report=collector.graph_from_samba(doc,names)
            self.assertEqual(report['summary']['r20_new_library_nodes'],2)
            self.assertEqual(report['summary']['r20_new_unresolved_edges'],0)
            self.assertEqual(cat.call_count,2)
            self.assertEqual(scan.call_count,2)
    def test_repeated_canonical_same_name_not_double_read(self):
        doc=fixture();names=r20.validate_r19(doc)[1]
        first={n:None for n in names};first['libmissing0.so.0']=r20.restricted_candidate('libmissing0.so.0')
        with patch.object(collector,'probe_samba',return_value=first),\
             patch.object(collector.r19,'virt_cat',return_value=b'fake') as cat,\
             patch.object(collector.graph,'parse_elf',return_value=new_node(needed=('libc.so.6',))['metadata']):
            report=collector.graph_from_samba(doc,names)
            self.assertEqual(cat.call_count,1)
            self.assertEqual(report['depths_processed'],1)
    def test_bad_canonical_fails_closed(self):
        doc=fixture();names=r20.validate_r19(doc)[1]
        first={n:None for n in names};first['libmissing0.so.0']='/tmp/evil.so'
        with patch.object(collector,'probe_samba',return_value=first),\
             patch.object(collector.r19,'virt_cat') as cat, self.assertRaises(g.GraphError):
            collector.graph_from_samba(doc,names)
        cat.assert_not_called()

if __name__=='__main__':unittest.main()
