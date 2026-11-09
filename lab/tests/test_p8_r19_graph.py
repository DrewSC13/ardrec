#!/usr/bin/env python3
"""P8-R19 synthetic ELF64 / graph tests; never access an image or run guest binaries."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r19_graph as g
import p8_r19_offline_collect as collector


def make_elf(needed=('libc.so.6',),soname='libexample.so.1',interp=None,rpath=None,runpath=None):
    b=bytearray(4096)
    b[:16]=b'\x7fELF\x02\x01\x01'+b'\x00'*9
    n=3 if interp is not None else 2
    struct.pack_into('<HHIQQQIHHHHHH',b,16,3,62,1,0,64,0,0,64,56,n,0,0,0)
    struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0x400000,0,len(b),len(b),4096)
    struct.pack_into('<IIQQQQQQ',b,120,2,4,0x300,0x400300,0,0x100,0x100,8)
    if interp is not None:
        value=interp.encode()+b'\x00'
        struct.pack_into('<IIQQQQQQ',b,176,3,4,0x200,0x400200,0,len(value),len(value),1)
        b[0x200:0x200+len(value)]=value
    s=bytearray(b'\x00')
    def add(v):
        if v is None:return None
        off=len(s);s.extend(v.encode()+b'\x00');return off
    entries=[]
    for name in needed:entries.append((1,add(name)))
    if soname is not None:entries.append((14,add(soname)))
    if rpath is not None:entries.append((15,add(rpath)))
    if runpath is not None:entries.append((29,add(runpath)))
    entries=[(5,0x400500),(10,len(s))]+entries+[(0,0)]
    for i,(a,v) in enumerate(entries):struct.pack_into('<QQ',b,0x300+i*16,a,v)
    b[0x500:0x500+len(s)]=s
    return bytes(b)


def sample_roots():
    return [dict(guest_path=n) for n in ('/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient')]


def sample_graph():
    meta=g.parse_elf(make_elf())
    nodes=[{'canonical_path':'/usr/lib/x86_64-linux-gnu/libexample.so.1','metadata':meta}]
    edges=[{'requested_by':'/usr/bin/ssh','soname':'libexample.so.1',
            'candidate_paths':[nodes[0]['canonical_path']],
            'candidate_resolution_only':True,'runtime_selected':False}]
    return nodes,edges

class Tests(unittest.TestCase):
    def test_01_shared_object_without_interp(self):
        d=g.parse_elf(make_elf())
        self.assertIsNone(d['interpreter'])
        self.assertEqual(d['dt_needed_direct'],['libc.so.6'])
        self.assertEqual(d['soname'],'libexample.so.1')
        self.assertFalse(d['loader_executed'])
    def test_02_loader_with_interp(self):
        d=g.parse_elf(make_elf(interp='/lib64/ld-linux-x86-64.so.2'))
        self.assertEqual(d['interpreter'],'/lib64/ld-linux-x86-64.so.2')
    def test_03_no_needed_allowed(self):
        self.assertEqual(g.parse_elf(make_elf(needed=()))['dt_needed_direct'],[])
    def test_04_multiple_needed(self):
        self.assertEqual(g.parse_elf(make_elf(needed=('libc.so.6','libm.so.6')))['dt_needed_direct'],
                         ['libc.so.6','libm.so.6'])
    def test_05_rpath_and_runpath_observed_not_applied(self):
        d=g.parse_elf(make_elf(rpath='$ORIGIN/lib',runpath='/lib/x86_64-linux-gnu'))
        self.assertEqual(d['dt_rpath'],'$ORIGIN/lib')
        self.assertEqual(d['dt_runpath'],'/lib/x86_64-linux-gnu')
    def test_06_hash_file_bytes(self):
        b=make_elf();self.assertEqual(g.parse_elf(b)['sha256'],hashlib.sha256(b).hexdigest())
    def test_07_path_canonical_safety(self):
        self.assertEqual(g.safe_path('/usr/lib/x86_64-linux-gnu/libc.so.6'),
                         '/usr/lib/x86_64-linux-gnu/libc.so.6')
    def test_08_candidate_paths(self):
        p=g.candidate_paths('libc.so.6')
        self.assertEqual(len(p),6)
        self.assertEqual(p[0],'/lib/x86_64-linux-gnu/libc.so.6')
    def test_09_deterministic_summary(self):
        n,e=sample_graph()
        a=g.graph_summary(sample_roots(),n,e,[],[],False)
        self.assertEqual(a,g.graph_summary(sample_roots(),n,e,[],[],False))
        self.assertFalse(a['runtime_dependency_closure_verified'])
    def test_10_unique_library_graph(self):
        n,e=sample_graph();r=g.graph_summary(sample_roots(),n,e,[],[],False)
        self.assertEqual(r['observed_library_nodes'],1)
        self.assertEqual(r['direct_and_transitive_candidate_edges'],1)
    def test_11_tool_has_no_execution_import(self):
        source=(LAB/'p8_r19_graph.py').read_text()
        self.assertNotIn('import subprocess',source)
        self.assertNotIn('os.system',source)
    def test_12_collector_only_readonly_commands(self):
        src=(LAB/'p8_r19_offline_collect.py').read_text()
        self.assertIn("'guestfish','--ro'",src)
        self.assertNotIn('shell=True',src)
        self.assertNotIn('guestmount',src)
    def test_13_resolve_single_canonical_aliases(self):
        def mock_lines(cmd):
            if cmd[0].startswith('is-file'):
                return ['true','true','false','false','false','false']
            return ['/usr/lib/x86_64-linux-gnu/libc.so.6']*2
        with patch.object(collector,'guestfish_lines',side_effect=mock_lines):
            r=collector.resolve_sonames(['libc.so.6'])
        self.assertEqual(r['libc.so.6'],['/usr/lib/x86_64-linux-gnu/libc.so.6'])
    def test_14_resolve_ambiguous(self):
        def mock_lines(cmd):
            if cmd[0].startswith('is-file'):
                return ['true','true','false','false','false','false']
            return ['/lib/x86_64-linux-gnu/libc.so.6','/usr/lib/x86_64-linux-gnu/libc.so.6']
        with patch.object(collector,'guestfish_lines',side_effect=mock_lines):
            r=collector.resolve_sonames(['libc.so.6'])
        self.assertEqual(len(r['libc.so.6']),2)
    def test_15_resolve_missing(self):
        with patch.object(collector,'guestfish_lines',return_value=['false']*6):
            r=collector.resolve_sonames(['libc.so.6'])
        self.assertEqual(r['libc.so.6'],[])
    def test_16_guestfish_cardinality_rejected(self):
        with patch.object(collector,'bounded_run',return_value=b'true\n'):
            with self.assertRaises(g.GraphError):
                collector.guestfish_lines(['is-file /lib/a','is-file /lib/b'])
    def test_17_guestfish_wrong_boolean(self):
        with patch.object(collector,'guestfish_lines',return_value=['yes']*6):
            with self.assertRaises(g.GraphError):collector.resolve_sonames(['libc.so.6'])
    def test_18_no_execution_auth_in_summary(self):
        n,e=sample_graph();x=g.graph_summary(sample_roots(),n,e,[],[],False)
        self.assertEqual(x['authorized_profiles'],0)
        self.assertEqual(x['authorized_cases'],0)
        self.assertFalse(x['dispatch_allowed'])


class GraphAcquisitionTests(unittest.TestCase):
    def fixture_roots(self):
        return [
            {'guest_path':'/usr/bin/ssh','metadata':{'interpreter':'/lib64/ld-linux-x86-64.so.2',
             'dt_needed_direct':['libx.so.1'],'dt_rpath':None,'dt_runpath':None}},
            {'guest_path':'/usr/bin/curl','metadata':{'interpreter':'/lib64/ld-linux-x86-64.so.2',
             'dt_needed_direct':['libx.so.1'],'dt_rpath':None,'dt_runpath':None}},
            {'guest_path':'/usr/bin/smbclient','metadata':{'interpreter':'/lib64/ld-linux-x86-64.so.2',
             'dt_needed_direct':['libabsent.so.9'],'dt_rpath':None,'dt_runpath':None}},
        ]
    def resolver(self,names):
        values={'libx.so.1':'/usr/lib/x86_64-linux-gnu/libx.so.1',
                'libcommon.so.0':'/usr/lib/x86_64-linux-gnu/libcommon.so.0'}
        return {n:([values[n]] if n in values else []) for n in names}
    def virt(self,path):
        if path.endswith('libx.so.1'):
            return make_elf(needed=('libcommon.so.0',),soname='libx.so.1')
        if path.endswith('libcommon.so.0'):
            return make_elf(needed=(),soname='libcommon.so.0')
        if path.endswith('ld-linux-x86-64.so.2'):
            return make_elf(needed=(),soname='ld-linux-x86-64.so.2')
        raise AssertionError(path)
    def guest(self,cmd):
        return ['true'] if cmd[0].startswith('is-file') else ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2']
    def test_01_graph_bfs_with_transitive_and_unresolved(self):
        with patch.object(collector,'resolve_sonames',side_effect=self.resolver),\
             patch.object(collector,'virt_cat',side_effect=self.virt),\
             patch.object(collector,'guestfish_lines',side_effect=self.guest):
            out=collector.acquire_graph(self.fixture_roots())
        self.assertEqual(out['summary']['observed_library_nodes'],3)
        self.assertEqual(out['summary']['direct_and_transitive_candidate_edges'],4)
        self.assertEqual(out['summary']['unresolved_edges'],1)
        self.assertFalse(out['summary']['runtime_dependency_closure_verified'])
    def test_02_ambiguous_library_never_selected(self):
        def ambiguous(names):
            result=self.resolver(names)
            if 'libx.so.1' in result:
                result['libx.so.1']=['/lib/libx.so.1','/usr/lib/libx.so.1']
            return result
        with patch.object(collector,'resolve_sonames',side_effect=ambiguous),\
             patch.object(collector,'virt_cat',side_effect=self.virt),\
             patch.object(collector,'guestfish_lines',side_effect=self.guest):
            out=collector.acquire_graph(self.fixture_roots())
        self.assertEqual(out['summary']['ambiguous_edges'],2)
        self.assertTrue(all(x['canonical_path'].endswith('ld-linux-x86-64.so.2') for x in out['nodes']))
    def test_03_graph_depth_cap_is_fail_closed(self):
        with patch.object(collector,'resolve_sonames',side_effect=self.resolver),\
             patch.object(collector,'virt_cat',side_effect=self.virt),\
             patch.object(collector,'guestfish_lines',side_effect=self.guest),\
             patch.object(g,'MAX_GRAPH_DEPTH',1):
            with self.assertRaises(g.GraphError):
                collector.acquire_graph(self.fixture_roots())
    def test_04_custom_search_paths_are_uncertainty_flags(self):
        roots=self.fixture_roots();roots[0]['metadata']['dt_runpath']='$ORIGIN/lib'
        with patch.object(collector,'resolve_sonames',side_effect=self.resolver),\
             patch.object(collector,'virt_cat',side_effect=self.virt),\
             patch.object(collector,'guestfish_lines',side_effect=self.guest):
            out=collector.acquire_graph(roots)
        self.assertEqual(len(out['search_path_uncertainties']),1)
        self.assertFalse(out['summary']['loader_search_semantics_verified'])

class H1LimitTests(unittest.TestCase):
    def test_h1_01_large_but_bounded_elf_supported(self):
        # Padded synthetic ELF > original 16 MiB limit (not guest execution).
        synthetic=make_elf()+bytes(17*1024*1024)
        self.assertLessEqual(len(synthetic),g.MAX_BYTES)
        info=g.parse_elf(synthetic)
        self.assertEqual(info['file_bytes'],len(synthetic))
        self.assertEqual(info['dt_needed_direct'],['libc.so.6'])
        self.assertFalse(info['dispatch_allowed'])

    def test_h1_02_bounded_virtcat_accepts_large_fixture(self):
        synthetic=make_elf()+bytes(17*1024*1024)
        with patch.object(collector,'bounded_run',return_value=synthetic):
            self.assertEqual(collector.virt_cat('/usr/lib/x86_64-linux-gnu/libtest.so.1'),synthetic)

    def test_h1_03_oversize_rejected_with_exact_path_and_size(self):
        with patch.object(g,'MAX_BYTES',4096), patch.object(collector,'bounded_run',return_value=bytes(4097)):
            with self.assertRaisesRegex(g.GraphError,r'guest_elf_size:.+libtest\.so\.1:bytes=4097:limit=4096'):
                collector.virt_cat('/usr/lib/x86_64-linux-gnu/libtest.so.1')

    def test_h1_04_empty_file_rejected_with_path_and_size(self):
        with patch.object(collector,'bounded_run',return_value=b''):
            with self.assertRaisesRegex(g.GraphError,r'guest_elf_size:.+bytes=0:limit=67108864'):
                collector.virt_cat('/usr/lib/x86_64-linux-gnu/libempty.so.1')

    def test_h1_05_original_size_limit_always_enforced(self):
        self.assertEqual(g.MAX_BYTES,64*1024*1024)
        with patch.object(g,'MAX_BYTES',4096):
            with self.assertRaises(g.GraphError):g.parse_elf(make_elf()+b'0')

NEGATIVES=[
 ('wrong_magic',lambda b:b.__setitem__(0,0)),
 ('wrong_endian',lambda b:b.__setitem__(5,2)),
 ('wrong_machine',lambda b:struct.pack_into('<H',b,18,3)),
 ('too_many_headers',lambda b:struct.pack_into('<H',b,56,257)),
 ('missing_dynamic',lambda b:struct.pack_into('<I',b,120,4)),
 ('missing_load',lambda b:struct.pack_into('<I',b,64,4)),
 ('bad_phoff',lambda b:struct.pack_into('<Q',b,32,999999)),
 ('bad_dynsize',lambda b:struct.pack_into('<Q',b,152,65553)),
 ('no_dynamic_null',lambda b:(struct.pack_into('<Q',b,0x300+4*16,9),struct.pack_into('<Q',b,152,5*16))),
 ('bad_strtab',lambda b:struct.pack_into('<Q',b,0x300+8,0xffffffff)),
 ('invalid_soname_string',lambda b:b.__setitem__(0x500+len('\0libc.so.6\0'),ord('/'))),
]
for idx,(label,mutate) in enumerate(NEGATIVES):
    def test(self,mutate=mutate):
        b=bytearray(make_elf());mutate(b)
        with self.assertRaises(g.GraphError):g.parse_elf(bytes(b))
    setattr(Tests,'test_negative_%02d_%s'%(idx,label),test)

OTHER_BAD=[
 ('up',lambda:g.safe_path('/usr/lib/../etc/passwd')),
 ('relative',lambda:g.safe_path('usr/lib/a')),
 ('backslash',lambda:g.safe_path('/lib/a\\b')),
 ('command',lambda:g.safe_soname('foo;cat')),
 ('slash_soname',lambda:g.safe_soname('../libc.so.6')),
 ('empty_soname',lambda:g.safe_soname('')),
 ('long_soname',lambda:g.safe_soname('a'*256)),
 ('incorrect_root_order',lambda:g.graph_summary(list(reversed(sample_roots())),*sample_graph(),[],[],False)),
 ('duplicate_nodes',lambda:g.graph_summary(sample_roots(),sample_graph()[0]*2,[],[],[],False)),
 ('promoted_edge',lambda:g.graph_summary(sample_roots(),sample_graph()[0],[{**sample_graph()[1][0],'runtime_selected':True}],[],[],False)),
 ('promoted_node',lambda:g.graph_summary(sample_roots(),[{**sample_graph()[0][0],'metadata':{**sample_graph()[0][0]['metadata'],'dispatch_allowed':True}}],[],[],[],False)),
 ('loader_claim',lambda:g.graph_summary(sample_roots(),*sample_graph(),[],[],True)),
 ('unsafe_command',lambda:collector.guestfish_lines(['rm /var/lib/data'])),
 ('unsafe_path_cmd',lambda:collector.guestfish_lines(['is-file /tmp/a\nrm /tmp/b'])),
 ('layer_too_big',lambda:collector.resolve_sonames(['libc.so.6']*129)),
]
for idx,(label,fn) in enumerate(OTHER_BAD):
    def test(self,fn=fn):
        with self.assertRaises(g.GraphError):fn()
    setattr(Tests,'test_reject_%02d_%s'%(idx,label),test)

if __name__=='__main__':unittest.main()
