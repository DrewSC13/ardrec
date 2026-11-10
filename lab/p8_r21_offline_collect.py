#!/usr/bin/env python3
"""ARDREC P8-R21: read-only source-pinned ELF candidate expansion.

Guest files are never executed, loaded by ld.so, connected to network services,
or used to authorize cases. One-shot operator-only receipt outside the repo.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import p8_r19_graph as graph
import p8_r19_offline_collect as r19
import p8_r20_offline_collect as r20coll
import p8_r21_multiarch_reconcile as r21

ROOT=r19.ROOT
IMAGE=r19.IMAGE_PATH
BASE=r21.R21_BASE
PRIVATE_ROOT=Path('/home/cicada/Development/GitHub/ardrec-patches')
R19_PRIVATE=PRIVATE_ROOT/'ARDREC_PRIVATE_R19/ELF_GRAPH_R19_PRIVATE.json'
R20_PRIVATE=PRIVATE_ROOT/'ARDREC_PRIVATE_R20/SAMBA_CANDIDATES_R20_PRIVATE.json'
OUTPUT_DIR=PRIVATE_ROOT/'ARDREC_PRIVATE_R21'
OUTPUT_NAME='MULTIARCH_CANDIDATES_R21_PRIVATE.json'


def private_source(path,expected_sha):
    r19.private_dir(path.parent)
    r21.need(path.is_file() and not path.is_symlink() and
             stat.S_IMODE(path.stat().st_mode)==0o600,'private_source_mode')
    r21.need(path.stat().st_size<8*1024*1024,'private_source_size')
    content=path.read_bytes()
    r21.need(hashlib.sha256(content).hexdigest()==expected_sha,'private_source_sha')
    return json.loads(content)


def read_sources():
    r19_doc=private_source(R19_PRIVATE,r21.R19_SHA)
    r20_doc=private_source(R20_PRIVATE,r21.R20_SHA)
    known,seeds=r21.validate_r20_receipts(r19_doc,r20_doc)
    return r20_doc,known,seeds


def probe(names):
    """Batched canonical lookup only; no guest process, shell or loader."""
    r21.need(type(names) is list and 1<=len(names)<=r21.MAX_NAMES_PER_LAYER,'probe_batch')
    paths=[path for name in names for path in r21.candidate_paths(name)]
    results=r19.guestfish_lines(['is-file '+p+' followsymlinks:true' for p in paths])
    present=[p for p,state in zip(paths,results) if state=='true']
    canonical=(r19.guestfish_lines(['realpath '+p for p in present]) if present else [])
    return r21.assess_multidir_scan(names,results,canonical)


def expand(r20_doc,known,seeds):
    """Read each new singleton DSO at most once, and fail closed at bounds."""
    r21.need(seeds==sorted(r21.EXPECTED_MISSING),'source_seed_drift')
    visited={};hits={};new_nodes={};queue=seeds
    for depth in range(1,r21.MAX_LAYERS+1):
        if not queue:break
        r21.need(len(queue)<=r21.MAX_NAMES_PER_LAYER,'layer_bound')
        print(f'R21_LAYER={depth}:names={len(queue)}:new_nodes={len(new_nodes)}',
              file=sys.stderr,flush=True)
        opts,observations=probe(queue)
        r21.need(set(opts)==set(queue) and set(observations)==set(queue),'probe_cardinality')
        future=set()
        for name in queue:
            r21.need(name not in known and name not in visited,'duplicate_or_known_name')
            choices=opts[name]
            visited[name]=choices
            hits[name]=observations[name]
            if len(choices)!=1:
                continue
            path=r21.canonical_guest_path(choices[0])
            if path in new_nodes:
                meta=new_nodes[path]['metadata']
                r21.need(meta['soname'] in (None,name),'alias_soname_mismatch')
                continue
            r21.need(len(new_nodes)<r21.MAX_NEW_NODES,'new_node_bound')
            print('R21_READ_START='+path,file=sys.stderr,flush=True)
            meta=graph.parse_elf(r19.virt_cat(path))
            r21.need(meta['elf_type']=='ET_DYN' and meta['soname'] in (None,name),
                     'candidate_elf_soname')
            new_nodes[path]={'canonical_path':path,'origin_soname':name,'metadata':meta}
            print('R21_READ_OK='+path+':bytes='+str(meta['file_bytes'])+
                  ':sha256='+meta['sha256'][:16],file=sys.stderr,flush=True)
        for item in new_nodes.values():
            for soname in item['metadata']['dt_needed_direct']:
                graph.safe_soname(soname)
                if soname not in known and soname not in visited:
                    future.add(soname)
        queue=sorted(future)
        r21.need(len(queue)<=r21.MAX_NAMES_PER_LAYER,'next_layer_bound')
    else:
        r21.need(not queue,'max_layers_exceeded')
    return r21.evaluate(r20_doc,known,visited,list(new_nodes.values()),hits)


def collect(receipt,confirmed_idle):
    r21.need(os.geteuid()!=0,'never_execute_python_as_root')
    r21.need(confirmed_idle is True,'explicit_image_idle_confirmation_required')
    r21.need(receipt.is_absolute() and receipt==OUTPUT_DIR/OUTPUT_NAME and
             not receipt.exists() and not receipt.is_symlink(),'receipt_destination')
    r19.private_dir(OUTPUT_DIR)
    print('R21_PHASE=VERIFY_PRIVATE_R19_R20_RECEIPTS',file=sys.stderr,flush=True)
    r20_doc,known,seeds=read_sources()
    import verify_p8_material_inventory as r9
    print('R21_PHASE=VERIFY_R9_STATIC_SOURCE',file=sys.stderr,flush=True)
    r21.need(r9.verify_repository()['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
             'r9_source')
    inv=r9.read(ROOT,r9.INV_PATH)
    r21.need(r9.IMAGE_SHA==r21.IMAGE_SHA and r20_doc['image_sha256']==r9.IMAGE_SHA,
             'image_pin')
    print('R21_PHASE=VERIFY_R9_OFFLINE_IMAGE',file=sys.stderr,flush=True)
    image=r9.verify_offline_image(inv)
    r21.need(image['status']=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION',
             'r9_image')
    print('R21_PHASE=PROBE_MULTIARCH_AND_SAMBA_CANDIDATES',file=sys.stderr,flush=True)
    report=expand(r20_doc,known,seeds)
    print('R21_PHASE=VERIFY_IMAGE_POST_READ',file=sys.stderr,flush=True)
    post=r9.checked_command(['sudo','-n','sha256sum',r9.IMAGE_PATH]).split()[0]
    r21.need(post==r21.IMAGE_SHA,'image_changed_after_acquisition')
    doc={'schema_version':'1.0','scope':'P8_R21_READ_ONLY_MULTIARCH_CANDIDATES_NO_LOADER_PROOF',
         'base_main_commit':BASE,'image_sha256':r21.IMAGE_SHA,
         'r19_private_receipt_sha256':r21.R19_SHA,'r20_private_receipt_sha256':r21.R20_SHA,
         'r9_offline_status':image['status'],'operator_confirmed_image_idle':True,
         'result':report,'runtime_dependency_closure_verified':False,
         'loader_search_semantics_verified':False,'runtime_binary_identity_verified':False,
         'effective_configuration_verified':False,'guest_binaries_executed':False,
         'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
         'limitations':['SEVEN_RESTRICTED_SEARCH_DIRS_ARE_CANDIDATES_ONLY',
                        'NO_LD_SO_CACHE_HWCAPS_PRELOAD_RPATH_EFFECTIVE_SEMANTICS',
                        'NO_RUNTIME_BINARY_IDENTITY_OR_VERSION_CAPABILITY',
                        'NO_PER_CASE_AUTHORITY_OR_DISPATCH']}
    raw=(json.dumps(doc,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
    r21.need(len(raw)<8*1024*1024,'receipt_size_bound')
    fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:receipt.unlink()
        except OSError:pass
        raise
    dfd=os.open(receipt.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'status':'PASS_P8_R21_MULTIARCH_CANDIDATE_OBSERVATION_DENY_ONLY',
            'private_receipt_sha256':hashlib.sha256(raw).hexdigest(),
            **report['summary']}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--private-receipt',type=Path,required=True)
    ap.add_argument('--confirm-image-idle',action='store_true')
    args=ap.parse_args()
    try:print(json.dumps(collect(args.private_receipt,args.confirm_image_idle),sort_keys=True))
    except (graph.GraphError,ValueError,KeyError,TypeError,OSError,subprocess.TimeoutExpired) as err:
        print('P8_R21=FAIL_CLOSED:'+str(err),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
