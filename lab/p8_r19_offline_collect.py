#!/usr/bin/env python3
"""P8-R19: operator-only, read-only Debian QCOW2 DSO candidate graph.

Uses sudo -n guestfish --ro (is-file, realpath) and sudo -n virt-cat only.
No guest process, loader, SSH/FTP/SMB, shell, socket or network dispatch.
Read-once private R18 receipt; create-once private R19 receipt outside Git.
"""
from __future__ import annotations
import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import p8_r19_graph as graph

ROOT=Path(__file__).resolve().parents[1]
IMAGE_PATH='/var/lib/libvirt/images/ardrec-dev-point4-v4/runner-base.qcow2'
BASE='e1e43c621e28628d004775d888ef5b133debfb52'
R18_PRIVATE=Path('/home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R18/ELF_DIRECT_R18_PRIVATE.json')
R18_SHA='90586b0fedd11fad28e9896f75f654fe3ff7558f2510940bd5e48d2171cbb806'
OUTPUT_DIR=Path('/home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R19')
OUTPUT_NAME='ELF_GRAPH_R19_PRIVATE.json'
ROOTS=('/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient')


def private_dir(directory):
    graph.need(directory.is_dir() and not directory.is_symlink() and
               stat.S_IMODE(directory.stat().st_mode)==0o700 and
               os.path.realpath(str(directory))==str(directory),'private_directory')

def bounded_run(command, stdin=None, timeout=180):
    result=subprocess.run(command,input=stdin,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=timeout,check=False)
    graph.need(result.returncode==0,'read_only_command_failed:'+command[2]+':'+
               result.stderr[-180:].decode('utf-8','replace'))
    graph.need(len(result.stdout)<=graph.MAX_BYTES*2,'read_only_output_limit')
    return result.stdout

def guestfish_lines(commands):
    graph.need(1<=len(commands)<=1000,'guestfish_command_bound')
    for cmd in commands:
        graph.need(type(cmd) is str and cmd.startswith(('is-file ','realpath '))
                   and '\n' not in cmd and '\r' not in cmd,'unsafe_guestfish_command')
    payload=('\n'.join(commands)+'\n').encode()
    out=bounded_run(['sudo','-n','guestfish','--ro','--format=qcow2',
                      '-a',IMAGE_PATH,'-i'],stdin=payload,timeout=240)
    try: lines=out.decode('utf-8').splitlines()
    except UnicodeError as e:raise graph.GraphError('P8_R19_FAIL_CLOSED:guestfish_encoding') from e
    graph.need(len(lines)==len(commands),'guestfish_cardinality')
    return [x.strip() for x in lines]

def resolve_sonames(names):
    """Return uniquely canonicalized *candidates*, not loader-selected paths.

    A missing or multi-canonical SONAME is left unresolved/ambiguous; never choose
    the first in search order or silently collapse different guest files.
    """
    graph.need(type(names) is list and len(names)<=128,'layer_limit')
    paths=[p for n in names for p in graph.candidate_paths(n)]
    graph.need(len(paths)<=1000,'query_limit')
    exists=guestfish_lines(['is-file '+p+' followsymlinks:true' for p in paths])
    graph.need(all(x in ('true','false') for x in exists),'guestfish_bool')
    present=[p for p,x in zip(paths,exists) if x=='true']
    real=guestfish_lines(['realpath '+p for p in present]) if present else []
    by_path={p:graph.safe_path(target) for p,target in zip(present,real)}
    answers={}
    for i,n in enumerate(names):
        options=[]
        for p in paths[i*len(graph.LIB_DIRS):(i+1)*len(graph.LIB_DIRS)]:
            if p in by_path and by_path[p] not in options:
                options.append(by_path[p])
        answers[n]=options
    return answers

def virt_cat(path):
    graph.safe_path(path)
    print('R19_READ_START='+path, file=sys.stderr, flush=True)
    data=bounded_run(['sudo','-n','virt-cat','--format=qcow2',
                      '-a',IMAGE_PATH,path],timeout=150)
    size=len(data)
    graph.need(64<=size<=graph.MAX_BYTES,
               'guest_elf_size:'+path+':bytes='+str(size)+':limit='+str(graph.MAX_BYTES))
    print('R19_READ_OK='+path+':bytes='+str(size),file=sys.stderr,flush=True)
    return data

def read_r18():
    import verify_p8_material_inventory as r9
    private_dir(R18_PRIVATE.parent)
    graph.need(R18_PRIVATE.is_file() and not R18_PRIVATE.is_symlink() and
               stat.S_IMODE(R18_PRIVATE.stat().st_mode)==0o600,'r18_receipt_mode')
    raw=R18_PRIVATE.read_bytes()
    graph.need(hashlib.sha256(raw).hexdigest()==R18_SHA,'r18_receipt_digest')
    document=json.loads(raw)
    graph.need(document['base_main_commit']=='05513b28af3ffa23ef98cef3fd4e2dcf2a71eea8' and
               document['scope']=='P8_R18_OFFLINE_DIRECT_ELF_CANDIDATE_ONLY' and
               document['image_sha256']==r9.IMAGE_SHA and
               document['r9_offline_status']=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION',
               'r18_receipt_identity')
    for field in ('dispatch_allowed','runtime_binary_identity_verified',
                  'transitive_dependency_closure_verified','guest_binaries_executed'):
        graph.need(document[field] is False,'r18_promotion_'+field)
    graph.need(document['authorized_profiles']==0 and document['authorized_cases']==0,
               'r18_authority')
    roots=document['candidates']
    graph.need(type(roots) is list and len(roots)==3 and
               [r['guest_path'] for r in roots]==list(ROOTS),'r18_roots')
    inventory=r9.read(ROOT,r9.INV_PATH)
    expected={x['absolute_path']:x['sha256'] for x in inventory['binary_observations']}
    graph.need(all(r['r9_sha256']==expected[r['guest_path']]==r['metadata']['sha256'] and
                   r['metadata']['dynamic_loader_executed'] is False and
                   r['metadata']['dispatch_allowed'] is False and
                   type(r['metadata']['dt_needed_direct']) is list and
                   len(r['metadata']['dt_needed_direct'])<=graph.MAX_NEEDED
                   for r in roots),'r18_binary_provenance')
    graph.need([len(r['metadata']['dt_needed_direct']) for r in roots]==[5,3,23],
               'r18_direct_counts')
    return roots

def acquire_graph(roots):
    graph.need([r['guest_path'] for r in roots]==list(ROOTS),'root_identity')
    frontier=deque()
    for item in roots:
        for soname in item['metadata']['dt_needed_direct']:
            frontier.append((item['guest_path'],graph.safe_soname(soname),1))
    nodes={}  # canonical path -> metadata; insertion order preserved
    edges=[];unresolved=[];ambiguous=[];search_flags=[]
    for item in roots:
        m=item['metadata']
        if m.get('dt_rpath') or m.get('dt_runpath'):
            search_flags.append({'guest_path':item['guest_path'],'status':'CUSTOM_SEARCH_PATH_NOT_MODELED'})
    depth=1
    while frontier:
        graph.need(depth<=graph.MAX_GRAPH_DEPTH,'graph_depth_limit')
        layer=[]
        while frontier and frontier[0][2]==depth:
            layer.append(frontier.popleft())
        graph.need(bool(layer),'layer_order')
        names=list(dict.fromkeys(n for _,n,_ in layer))
        print('R19_LAYER_DEPTH='+str(depth)+':edges='+str(len(layer))+
              ':names='+str(len(names))+':libraries='+str(len(nodes)),
              file=sys.stderr,flush=True)
        # A full layer with >128 distinct names is intentionally rejected.
        lookup=resolve_sonames(names)
        for owner,name,level in layer:
            options=lookup[name]
            edge={'requested_by':owner,'soname':name,'candidate_paths':options,
                  'candidate_resolution_only':True,'runtime_selected':False}
            edges.append(edge)
            graph.need(len(edges)<=graph.MAX_GRAPH_EDGES,'graph_edge_limit')
            if len(options)==0:
                unresolved.append({'requested_by':owner,'soname':name,'status':'NOT_FOUND_IN_RESTRICTED_CANDIDATE_DIRS'})
                continue
            if len(options)>1:
                ambiguous.append({'requested_by':owner,'soname':name,'candidate_paths':options,'status':'MULTIPLE_CANONICAL_CANDIDATES'})
                continue
            canonical=options[0]
            if canonical in nodes:
                continue
            graph.need(len(nodes)<graph.MAX_GRAPH_NODES,'graph_node_limit')
            meta=graph.parse_elf(virt_cat(canonical))
            graph.need(meta['elf_type']=='ET_DYN','not_shared_object')
            if meta['soname'] is not None:
                graph.need(meta['soname']==name,'soname_identity_mismatch')
            nodes[canonical]={'canonical_path':canonical,'metadata':meta}
            if meta['dt_rpath'] or meta['dt_runpath']:
                search_flags.append({'guest_path':canonical,'status':'CUSTOM_SEARCH_PATH_NOT_MODELED'})
            for downstream in meta['dt_needed_direct']:
                frontier.append((canonical,downstream,level+1))
        depth+=1
    # PT_INTERP is an independently observed guest ELF: not proof of loader selection.
    loaders={r['metadata']['interpreter'] for r in roots}
    graph.need(len(loaders)==1 and None not in loaders,'root_interpreters')
    interp=graph.safe_path(next(iter(loaders)))
    present=guestfish_lines(['is-file '+interp+' followsymlinks:true'])
    graph.need(present==['true'],'interpreter_missing')
    canonical=graph.safe_path(guestfish_lines(['realpath '+interp])[0])
    if canonical not in nodes:
        graph.need(len(nodes)<graph.MAX_GRAPH_NODES,'interpreter_node_limit')
        meta=graph.parse_elf(virt_cat(canonical))
        graph.need(meta['elf_type']=='ET_DYN','interpreter_elf_type')
        nodes[canonical]={'canonical_path':canonical,'metadata':meta}
    summary=graph.graph_summary(roots,list(nodes.values()),edges,unresolved,ambiguous,False)
    return {'summary':summary,'nodes':list(nodes.values()),'edges':edges,
            'unresolved':unresolved,'ambiguous':ambiguous,
            'search_path_uncertainties':search_flags,
            'interpreter_candidate':{'declared':interp,'canonical_path':canonical},
            'search_directories_candidate_only':list(graph.LIB_DIRS)}

def private_dest(path):
    graph.need(path==OUTPUT_DIR/OUTPUT_NAME and path.is_absolute() and
               not path.is_symlink() and not path.exists(),'destination_path')
    private_dir(path.parent)

def collect(receipt,ack_idle):
    graph.need(os.geteuid()!=0,'never_execute_python_as_root')
    graph.need(ack_idle is True,'explicit_idle_confirmation_required')
    private_dest(receipt)
    import verify_p8_material_inventory as r9
    print('R19_PHASE=VERIFY_R18_PRIVATE_RECEIPT',file=sys.stderr,flush=True)
    roots=read_r18()
    print('R19_PHASE=VERIFY_R9_SOURCE',file=sys.stderr,flush=True)
    prior=r9.verify_repository()
    graph.need(prior['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL','r9_source')
    image=r9.read(ROOT,r9.INV_PATH)
    print('R19_PHASE=VERIFY_R9_OFFLINE_IMAGE',file=sys.stderr,flush=True)
    observed=r9.verify_offline_image(image)
    graph.need(observed['status']=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION','r9_image')
    print('R19_PHASE=COLLECT_CANDIDATE_GRAPH',file=sys.stderr,flush=True)
    report=acquire_graph(roots)
    print('R19_PHASE=VERIFY_IMAGE_POST_READ',file=sys.stderr,flush=True)
    after=r9.checked_command(['sudo','-n','sha256sum',r9.IMAGE_PATH]).split()[0]
    graph.need(after==r9.IMAGE_SHA,'post_acquisition_image_hash')
    doc={'schema_version':'1.0','scope':'P8_R19_OFFLINE_STATIC_ELF_CANDIDATE_GRAPH_ONLY',
         'base_main_commit':BASE,'image_sha256':r9.IMAGE_SHA,
         'r18_private_receipt_sha256':R18_SHA,'r9_offline_status':observed['status'],
         'operator_confirmed_image_idle':True,
         'result':report,'runtime_dependency_closure_verified':False,
         'effective_loader_resolution_verified':False,'case_authority_verified':False,
         'dispatch_allowed':False,'authorized_profiles':0,'authorized_cases':0,
         'guest_binaries_executed':False,
         'limitations':['CANDIDATE_DIRECTORY_SEARCH_NOT_LD_SO_CACHE',
                        'NO_GLIBC_HWCAPS_OR_LD_SO_PRELOAD',
                        'NO_TRANSITIVE_LOADER_SEARCH_EQUIVALENCE',
                        'NO_RUNTIME_IDENTITY_NO_EFFECTIVE_CONFIGURATION',
                        'NO_CASE_AUTHORITY_NO_DISPATCH']}
    data=(json.dumps(doc,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
    fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:os.unlink(receipt)
        except OSError:pass
        raise
    dfd=os.open(receipt.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'status':report['summary']['status'],
            'private_receipt_sha256':hashlib.sha256(data).hexdigest(),
            **{k:v for k,v in report['summary'].items() if k!='status'},
            'custom_search_path_flags':len(report['search_path_uncertainties'])}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--private-receipt',type=Path,required=True)
    ap.add_argument('--confirm-image-idle',action='store_true',
                    help='Operator explicitly confirms pinned offline image is not attached to running VM')
    args=ap.parse_args()
    try: print(json.dumps(collect(args.private_receipt,args.confirm_image_idle),sort_keys=True))
    except (graph.GraphError,OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as err:
        print('P8_R19=FAIL_CLOSED:'+str(err),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
