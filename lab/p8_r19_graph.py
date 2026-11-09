#!/usr/bin/env python3
"""ARDREC P8-R19: pure, bounded ELF64 x86-64 graph evidence primitives.

No loading, executing, CLI renderer, network, VM, process spawn or case authority.
A static candidate graph IS NOT the effective glibc loader dependency closure.
"""
from __future__ import annotations
import hashlib
import re
import struct

MAX_BYTES=64*1024*1024
MAX_PHDRS=256
MAX_NEEDED=96
MAX_STRTAB=2*1024*1024
MAX_GRAPH_NODES=160
MAX_GRAPH_EDGES=1000
MAX_GRAPH_DEPTH=16
# Candidate lookup locations, NOT authoritative loader search order.
LIB_DIRS=('/lib/x86_64-linux-gnu','/usr/lib/x86_64-linux-gnu',
          '/lib64','/usr/lib64','/lib','/usr/lib')
GUEST_PATH=re.compile(r'/[A-Za-z0-9._+\-/]+\Z')
SONAME=re.compile(r'[A-Za-z0-9_+\.@\-]+\Z')

class GraphError(ValueError):
    pass

def need(ok,why):
    if not ok: raise GraphError('P8_R19_FAIL_CLOSED:'+why)

def safe_path(value):
    need(type(value) is str and len(value)<=300 and
         GUEST_PATH.fullmatch(value) is not None and
         '//' not in value and all(s not in ('','.', '..') for s in value[1:].split('/')),
         'unsafe_guest_path')
    return value

def safe_soname(name):
    need(type(name) is str and len(name)<=255 and SONAME.fullmatch(name) is not None and
         name not in ('.','..') and '/' not in name, 'unsafe_soname')
    return name

def candidate_paths(soname):
    name=safe_soname(soname)
    return [safe_path(directory+'/'+name) for directory in LIB_DIRS]

def parse_elf(data:bytes):
    """Read DSO or loader PT_DYNAMIC/DT_NEEDED/DT_SONAME; PT_INTERP optional.

    Does not call or consult the dynamic loader. No guest executable is launched.
    """
    need(type(data) is bytes and 64<=len(data)<=MAX_BYTES,'size')
    need(data[:4]==b'\x7fELF' and data[4:7]==b'\x02\x01\x01' and
         data[7] in (0,3) and data[8:16]==b'\x00'*8, 'elf_ident')
    kind,machine,version,_,phoff,_,_,ehsize,phentsize,phnum,_,_,_=struct.unpack_from(
        '<HHIQQQIHHHHHH',data,16)
    need(kind in (2,3) and machine==62 and version==1 and ehsize==64 and
         phentsize==56 and 1<=phnum<=MAX_PHDRS,'architecture_or_program_header')
    def span(offset,length,label):
        need(type(offset) is int and type(length) is int and offset>=0 and length>=0
             and offset<=len(data) and length<=len(data)-offset,'bounds_'+label)
        return data[offset:offset+length]
    span(phoff,phnum*56,'phdrs')
    loads=[];dynamic=[];interp=[]
    for i in range(phnum):
        typ,flags,off,vaddr,paddr,size,memsz,align=struct.unpack_from(
            '<IIQQQQQQ',data,phoff+i*56)
        span(off,size,'segment')
        if typ==1:
            need(memsz>=size,'load_memsz')
            loads.append((vaddr,size,off))
        elif typ==2: dynamic.append((off,size))
        elif typ==3: interp.append((off,size))
    need(loads and len(dynamic)==1 and len(interp)<=1,'segment_cardinality')
    interpreter=None
    if interp:
        off,size=interp[0]
        need(2<=size<=256,'interp_size')
        raw=span(off,size,'interp')
        need(raw[-1:]==b'\0' and b'\0' not in raw[:-1],'interp_null')
        try:interpreter=safe_path(raw[:-1].decode('ascii'))
        except UnicodeError as e:raise GraphError('P8_R19_FAIL_CLOSED:interp_ascii') from e
    off,size=dynamic[0]
    need(16<=size<=65536 and size%16==0,'dynamic_size')
    entries=[struct.unpack_from('<QQ',data,off+i*16) for i in range(size//16)]
    endings=[i for i,(tag,_) in enumerate(entries) if tag==0]
    need(bool(endings),'dynamic_termination')
    tags={}
    for tag,v in entries[:endings[0]]:tags.setdefault(tag,[]).append(v)
    need(len(tags.get(5,[]))==1 and len(tags.get(10,[]))==1,'dynstr_tags')
    straddr,strsize=tags[5][0],tags[10][0]
    need(1<=strsize<=MAX_STRTAB,'dynstr_size')
    offsets=[]
    for vaddr,filesz,fileoff in loads:
        if vaddr<=straddr and straddr-vaddr<=filesz and strsize<=filesz-(straddr-vaddr):
            offsets.append(fileoff+straddr-vaddr)
    need(len(offsets)==1,'dynstr_mapping')
    strings=span(offsets[0],strsize,'dynstr')
    def at(off,label,paths=False):
        need(type(off) is int and 0<=off<len(strings),'string_offset_'+label)
        end=strings.find(b'\0',off)
        need(off<end<=len(strings) and end-off<=255,'string_bounds_'+label)
        try: value=strings[off:end].decode('ascii')
        except UnicodeError as e:raise GraphError('P8_R19_FAIL_CLOSED:ascii_'+label) from e
        if paths:
            need(re.fullmatch(r'[A-Za-z0-9_+.@\-/:$]+',value) is not None,
                 'unsafe_search_string')
        else: safe_soname(value)
        return value
    needed=[at(v,'needed') for v in tags.get(1,[])]
    need(len(needed)<=MAX_NEEDED and len(needed)==len(set(needed)),'needed_count_or_duplicate')
    for tag in (14,15,29):need(len(tags.get(tag,[]))<=1,'repeated_dynamic_tag')
    soname=at(tags[14][0],'soname') if tags.get(14) else None
    rpath=at(tags[15][0],'rpath',True) if tags.get(15) else None
    runpath=at(tags[29][0],'runpath',True) if tags.get(29) else None
    return {
        'sha256':hashlib.sha256(data).hexdigest(), 'file_bytes':len(data),
        'elf_type':'ET_DYN' if kind==3 else 'ET_EXEC',
        'machine':'EM_X86_64','interpreter':interpreter,
        'soname':soname,'dt_needed_direct':needed,'dt_rpath':rpath,'dt_runpath':runpath,
        'loader_executed':False,'static_candidate_only':True,'dispatch_allowed':False,
    }

def graph_summary(roots,nodes,edges,unresolved,ambiguous,loader):
    """Minimal conservative invariant oracle, for real and synthetic graph receipts."""
    need(type(roots) is list and len(roots)==3 and
         [x['guest_path'] for x in roots]==['/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient'],
         'root_order')
    need(type(nodes) is list and len(nodes)<=MAX_GRAPH_NODES and
         type(edges) is list and len(edges)<=MAX_GRAPH_EDGES, 'graph_limits')
    need(type(unresolved) is list and type(ambiguous) is list,'graph_diagnostics')
    ids=[x['canonical_path'] for x in nodes]
    need(len(ids)==len(set(ids)),'duplicate_node')
    for x in nodes:
        safe_path(x['canonical_path'])
        need(x['metadata']['dispatch_allowed'] is False and
             x['metadata']['loader_executed'] is False and
             x['metadata']['static_candidate_only'] is True,'node_promotion')
    for x in edges:
        need(x['requested_by'] in ids or x['requested_by'] in
             [r['guest_path'] for r in roots],'edge_owner')
        safe_soname(x['soname'])
        need(x['candidate_resolution_only'] is True and
             x['runtime_selected'] is False,'edge_promotion')
    need(loader is False,'loader_promotion')
    return {
        'status':'PASS_P8_R19_OFFLINE_CANDIDATE_GRAPH_NOT_LOADER_CLOSURE',
        'candidate_root_count':3,'observed_library_nodes':len(nodes),
        'direct_and_transitive_candidate_edges':len(edges),
        'unresolved_edges':len(unresolved),'ambiguous_edges':len(ambiguous),
        'loader_execution_performed':False,'loader_search_semantics_verified':False,
        'runtime_dependency_closure_verified':False,'runtime_binary_identity_verified':False,
        'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
    }
