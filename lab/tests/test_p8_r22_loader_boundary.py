#!/usr/bin/env python3
"""P8-R22 synthetic adversarial tests. No QCOW2, private data or guest access."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r22_loader_boundary as a
import p8_r22_private_audit as c
import p8_r19_graph as g

DIGEST='b'*64
BASE='/usr/lib/x86_64-linux-gnu/'
INTERP='/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'

def meta(flag=False,root=False):
    m={'sha256':DIGEST,'dt_needed_direct':['liba.so.1'],
       'dt_rpath':'$ORIGIN/../lib' if flag else None,
       'dt_runpath':None,
       'dispatch_allowed':False,'interpreter':'/lib64/ld-linux-x86-64.so.2'}
    if root:
        m.update(dynamic_loader_executed=False,runtime_identity_verified=False)
    else:
        m.update(elf_type='ET_DYN',loader_executed=False,static_candidate_only=True)
    return m

def fixture():
    roots=[{'guest_path':p,'metadata':meta(root=True)} for p in a.ROOTS]
    roots[0]['metadata']['dt_rpath']='$ORIGIN/../lib'
    roots[1]['metadata']['dt_rpath']=None
    roots[2]['metadata']['dt_rpath']=None
    groups=[]
    for prefix,count,flags in (('r19',68,8),('r20',64,53),('r21',6,4)):
        rows=[]
        for i in range(count):
            p=INTERP if prefix=='r19' and i==0 else BASE+f'{prefix}_{i}.so.0'
            m=meta(i<flags)
            rows.append({'canonical_path':p,'metadata':m,'origin_soname':f'{prefix}_{i}.so.0'})
        groups.append(rows)
    r19nodes,r20nodes,r21nodes=groups
    r19edges=[];recovered19=[]
    for i in range(225):
        r19edges.append({'requested_by':a.ROOTS[0], 'soname':f'lib_old{i}.so',
                         'candidate_paths':[r19nodes[i%68]['canonical_path']],
                         'candidate_resolution_only':True,'runtime_selected':False})
    for i in range(67):
        name=f'lib_r20_{i}.so'
        key={'requested_by':a.ROOTS[i%3], 'soname':name}
        r19edges.append({**key,'candidate_paths':[],
                         'candidate_resolution_only':True,'runtime_selected':False})
        recovered19.append({**key,'candidate_path':r20nodes[i%64]['canonical_path']})
    r20edges=[];recovered20=[]
    for i in range(555):
        r20edges.append({'requested_by':r20nodes[i%64]['canonical_path'],
                         'soname':f'lib_r19_{i}.so','candidate_path':r19nodes[i%68]['canonical_path'],
                         'runtime_selected':False})
    for i in range(8):
        key={'requested_by':r20nodes[i]['canonical_path'],'soname':f'lib_r21_{i}.so'}
        r20edges.append({**key,'candidate_path':None,'runtime_selected':False})
        recovered20.append({**key,'candidate_path':r21nodes[i%6]['canonical_path']})
    r21edges=[{'requested_by':r21nodes[i%6]['canonical_path'],
               'soname':f'lib_r19_from21_{i}.so',
               'candidate_paths':[r19nodes[i%68]['canonical_path']],
               'classification':'CANDIDATE','runtime_selected':False}
               for i in range(51)]
    r19={'nodes':r19nodes,'edges':r19edges,'unresolved':[{}]*67,'ambiguous':[],
         'search_path_uncertainties':[{'guest_path':'unknown'}]*9,
         'interpreter_candidate':{'declared':'/lib64/ld-linux-x86-64.so.2',
                                  'canonical_path':INTERP}}
    r20={'new_nodes':r20nodes,'new_dso_edges':r20edges,
         'recovered_r19_edges':recovered19,'remaining_r19_edges':[],
         'unresolved_new_dso_edges':[{}]*8,
         'summary':{'r20_custom_search_path_flags':53}}
    r21={'new_nodes':r21nodes,'new_dso_edges':r21edges,
         'recovered_r20_edges':recovered20,'remaining_r20_edges':[],
         'custom_search_path_uncertainties':[{}]*4}
    return roots,r19,r20,r21

class Lexical(unittest.TestCase):
    def test_origin(self):
        self.assertEqual(a.path_segments('$ORIGIN/lib')[0]['kind'],
                         'DYNAMIC_TOKEN_REQUIRES_RUNTIME_CONTEXT')
    def test_lib(self):
        self.assertIn('$LIB',a.path_segments('$LIB/samba')[0]['tokens'])
    def test_platform(self):
        self.assertIn('$PLATFORM',a.path_segments('$PLATFORM')[0]['tokens'])
    def test_braced(self):
        self.assertIn('${ORIGIN}',a.path_segments('${ORIGIN}/lib')[0]['tokens'])
    def test_absolute(self):
        self.assertEqual(a.path_segments('/usr/lib')[0]['kind'],
                         'ABSOLUTE_DIRECTORY_NOT_EFFECTIVE_PROOF')
    def test_relative(self):
        self.assertEqual(a.path_segments('lib')[0]['kind'],'RELATIVE_CWD_SENSITIVE')
    def test_unknown_token(self):
        self.assertEqual(a.path_segments('$EVIL/lib')[0]['kind'],'UNKNOWN_DYNAMIC_TOKEN')
    def test_unknown_embedded(self):
        self.assertEqual(a.path_segments('$ORIGIN_EXTRA')[0]['kind'],'UNKNOWN_DYNAMIC_TOKEN')
    def test_relative_parent(self):
        self.assertEqual(a.path_segments('../lib')[0]['kind'],'PARENT_TRAVERSAL_UNRESOLVED')
    def test_dynamic_parent(self):
        self.assertEqual(a.path_segments('$ORIGIN/../lib')[0]['kind'],
                         'PARENT_TRAVERSAL_UNRESOLVED')
    def test_empty_component(self):
        self.assertEqual([x['kind'] for x in a.path_segments(':/lib:')],
                         ['EMPTY_CWD_SENSITIVE','ABSOLUTE_DIRECTORY_NOT_EFFECTIVE_PROOF',
                          'EMPTY_CWD_SENSITIVE'])
    def test_reject_empty_raw(self):
        with self.assertRaises(g.GraphError):a.path_segments('')
    def test_reject_non_string(self):
        with self.assertRaises(g.GraphError):a.path_segments(None)
    def test_reject_size(self):
        with self.assertRaises(g.GraphError):a.path_segments('a'*256)
    def test_reject_newline(self):
        with self.assertRaises(g.GraphError):a.path_segments('/lib\n../etc')
    def test_reject_backslash(self):
        with self.assertRaises(g.GraphError):a.path_segments('\\tmp')
    def test_token_prefix_not_approved(self):
        self.assertEqual(a.path_segments('$LIBXY')[0]['kind'],'UNKNOWN_DYNAMIC_TOKEN')
    def test_non_modeling_claims(self):
        self.assertFalse(a.path_segments('/lib')[0].get('loader_selected',False))

class GraphAccounting(unittest.TestCase):
    def setUp(self):self.sample=fixture()
    def report(self):return a.analyze(*self.sample)
    def test_full_candidate_accounting(self):
        s=self.report()['summary']
        self.assertEqual((s['candidate_dso_nodes'],s['candidate_graph_edges']), (138,906))
        self.assertEqual(s['search_flagged_objects'],66)
        self.assertEqual(s['static_candidate_edges_without_candidate'],0)
    def test_no_authority(self):
        s=self.report()['summary']
        for key in ('dispatch_allowed','loader_search_order_verified',
                    'effective_loader_resolution_verified','glibc_cache_verified',
                    'glibc_hwcaps_verified','environment_and_preload_verified',
                    'effective_configuration_verified','transitive_runtime_closure_verified'):
            self.assertFalse(s[key])
        self.assertEqual((s['authorized_profiles'],s['authorized_cases']),(0,0))
    def test_reject_node_count(self):
        self.sample[1]['nodes'].pop()
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_edge_count(self):
        self.sample[2]['new_dso_edges'].pop()
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_duplicate_node(self):
        self.sample[3]['new_nodes'][0]['canonical_path']=self.sample[1]['nodes'][0]['canonical_path']
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_node_danger(self):
        self.sample[1]['nodes'][0]['metadata']['loader_executed']=True
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_node_bad_hash(self):
        self.sample[2]['new_nodes'][0]['metadata']['sha256']='ab'
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_bad_root(self):
        self.sample[0][0]['guest_path']='/usr/bin/danger'
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_interp(self):
        self.sample[1]['interpreter_candidate']['canonical_path']='/etc/passwd'
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_bad_r19_edge(self):
        self.sample[1]['edges'][0]['runtime_selected']=True
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_unresolved_r19_edge(self):
        self.sample[2]['recovered_r19_edges'].pop()
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_unknown_r20_edge_target(self):
        self.sample[2]['new_dso_edges'][0]['candidate_path']='/etc/passwd'
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_unknown_owner(self):
        self.sample[3]['new_dso_edges'][0]['requested_by']='/tmp/a.so'
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_ambiguous_r21(self):
        self.sample[3]['new_dso_edges'][0]['candidate_paths'].append(
            self.sample[1]['nodes'][0]['canonical_path'])
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_r21_runtime_promotion(self):
        self.sample[3]['new_dso_edges'][0]['runtime_selected']=True
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_wrong_r20_flags(self):
        self.sample[2]['summary']['r20_custom_search_path_flags']=52
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_wrong_r19_flags(self):
        self.sample[1]['search_path_uncertainties'].pop()
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_wrong_r21_flags(self):
        self.sample[3]['custom_search_path_uncertainties'].pop()
        with self.assertRaises(g.GraphError):self.report()
    def test_reject_wrong_object_flags(self):
        self.sample[2]['new_nodes'][0]['metadata']['dt_rpath']=None
        with self.assertRaises(g.GraphError):self.report()
    def test_rpath_and_runpath_both_recorded_not_interpreted(self):
        self.sample[2]['new_nodes'][0]['metadata']['dt_runpath']='$ORIGIN/lib'
        report=self.report()
        self.assertGreater(report['summary']['search_tag_occurrences'],66)
        self.assertFalse(report['summary']['loader_search_order_verified'])
    def test_private_not_in_summary(self):
        report=self.report()
        self.assertNotIn('search_path_audit',report['summary'])
    def test_sources_all_present(self):
        report=self.report()
        self.assertEqual(set(x['evidence_origin'] for x in report['candidate_edges']),
                         {'R19','R20','R21'})

class CollectorGuards(unittest.TestCase):
    def test_receipt_only_sources_four(self):self.assertEqual(len(c.SOURCES),4)
    def test_output_outside_repository(self):
        self.assertIn('/ardrec-patches/ARDREC_PRIVATE_R22',str(c.OUTPUT_DIR))
    def test_no_image_acquisition_helpers(self):
        self.assertFalse(hasattr(c,'virt_cat'))
        self.assertFalse(hasattr(c,'guestfish_lines'))
    def test_private_paths_not_public(self):
        self.assertTrue(all('/ARDREC_PRIVATE_R' in str(x[1]) for x in c.SOURCES))

if __name__=='__main__':unittest.main()
