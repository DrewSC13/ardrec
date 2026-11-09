#!/usr/bin/env python3
"""P8-R20 operator-only Samba DSO candidate supplementation from pinned, idle QCOW2.

Never execute guest files, dynamic loader, clients, laboratory VM, or network services.
Use read-only libguestfs with bounded query batches; keep receipts private and write-once.
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
import p8_r20_samba_candidate as r20
import p8_r19_graph as graph
import p8_r19_offline_collect as r19

BASE='4d0907a982183a33b18eb2decba20fc02f37b822'
R19_PRIVATE=Path('/home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R19/ELF_GRAPH_R19_PRIVATE.json')
R19_SHA='785a85192e42588042467017f4ec65bafed96f4711bb1d42c6f846ede0e1a1cf'
OUTPUT_DIR=Path('/home/cicada/Development/GitHub/ardrec-patches/ARDREC_PRIVATE_R20')
OUTPUT_NAME='SAMBA_CANDIDATES_R20_PRIVATE.json'


def read_source():
    r19.private_dir(R19_PRIVATE.parent)
    graph.need(R19_PRIVATE.is_file() and not R19_PRIVATE.is_symlink() and
               stat.S_IMODE(R19_PRIVATE.stat().st_mode)==0o600,'r20_source_mode')
    graph.need(R19_PRIVATE.stat().st_size<8*1024*1024,'r20_source_size')
    raw=R19_PRIVATE.read_bytes()
    graph.need(hashlib.sha256(raw).hexdigest()==R19_SHA,'r20_source_digest')
    doc=json.loads(raw)
    names=r20.validate_r19(doc)[1]
    return doc,names


def probe_samba(names):
    r20.need(type(names) is list and 1<=len(names)<=r20.MAX_PROBE_NAMES,'probe_names')
    commands=['is-file '+r20.restricted_candidate(n)+' followsymlinks:true' for n in names]
    exist=r19.guestfish_lines(commands)
    found=[n for n,status in zip(names,exist) if status=='true']
    canonical=r19.guestfish_lines(['realpath '+r20.restricted_candidate(n) for n in found]) if found else []
    return r20.assess_candidate_scan(names,exist,canonical)


def graph_from_samba(old,names):
    known,expected_names=r20.validate_r19(old)
    r20.need(names==expected_names,'seed_drift')
    visited={};new_nodes={};rechecked=set()
    frontier=names
    processed_depth=0
    for depth in range(1,r20.MAX_LAYERS+1):
        if not frontier:break
        processed_depth=depth
        r20.need(len(frontier)<=r20.MAX_PROBE_NAMES,'frontier_bound')
        print(f'R20_SAMBA_LAYER={depth}:names={len(frontier)}:new_nodes={len(new_nodes)}',file=sys.stderr,flush=True)
        batch=probe_samba(frontier)
        for name,path in batch.items():
            r20.need(name not in visited,'duplicate_probe')
            visited[name]=path
        next_names=set()
        for name in frontier:
            path=batch[name]
            if path is None:continue
            path=r20.validated_canonical(path)
            if path in new_nodes:
                prior=new_nodes[path]['metadata']['soname']
                r20.need(prior in (None,name),'alias_soname_mismatch')
                continue
            r20.need(len(new_nodes)<r20.MAX_NEW_LIBRARIES,'new_library_bound')
            print('R20_READ_START='+path,file=sys.stderr,flush=True)
            meta=graph.parse_elf(r19.virt_cat(path))
            r20.need(meta['elf_type']=='ET_DYN','not_dso')
            r20.need(meta['soname'] in (None,name),'soname_mismatch')
            new_nodes[path]={'canonical_path':path,'metadata':meta,'origin_soname':name}
            print('R20_READ_OK='+path+':sha256='+meta['sha256'][:16],file=sys.stderr,flush=True)
        for node in new_nodes.values():
            if node['canonical_path'] in rechecked:continue
            rechecked.add(node['canonical_path'])
            for name in node['metadata']['dt_needed_direct']:
                graph.safe_soname(name)
                if name not in known and name not in visited:
                    next_names.add(name)
        frontier=sorted(next_names)
    else:
        r20.need(not frontier,'max_layers_exceeded')
    report=r20.evaluate(old['result'],list(new_nodes.values()),visited)
    report['depths_processed']=processed_depth
    return report


def collect(path,ack_idle):
    graph.need(os.geteuid()!=0,'never_root_python')
    graph.need(ack_idle is True,'explicit_idle_confirmation_required')
    r20.need(path==OUTPUT_DIR/OUTPUT_NAME and path.is_absolute()
             and not path.exists() and not path.is_symlink(),'destination')
    r19.private_dir(OUTPUT_DIR)
    print('R20_PHASE=CHECK_R19_RECEIPT',file=sys.stderr,flush=True)
    old,names=read_source()
    import verify_p8_material_inventory as r9
    print('R20_PHASE=VERIFY_R9_SOURCE',file=sys.stderr,flush=True)
    upstream=r9.verify_repository()
    r20.need(upstream['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL','r9_source')
    inv=r9.read(r19.ROOT,r9.INV_PATH)
    r20.need(old['image_sha256']==r9.IMAGE_SHA,'image_identity')
    print('R20_PHASE=VERIFY_R9_OFFLINE_IMAGE',file=sys.stderr,flush=True)
    witnessed=r9.verify_offline_image(inv)
    r20.need(witnessed['status']=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION','r9_offline_image')
    print('R20_PHASE=SAMBA_PRIVATE_DSO_CANDIDATES',file=sys.stderr,flush=True)
    report=graph_from_samba(old,names)
    print('R20_PHASE=VERIFY_IMAGE_POST_READ',file=sys.stderr,flush=True)
    post=r9.checked_command(['sudo','-n','sha256sum',r9.IMAGE_PATH]).split()[0]
    r20.need(post==r9.IMAGE_SHA,'qcow2_drift_after_read')
    receipt={'schema_version':'1.0','scope':'P8_R20_SAMBA_STATIC_CANDIDATES_NOT_LOADER_PROOF',
             'base_main_commit':BASE,'image_sha256':r9.IMAGE_SHA,
             'r19_private_receipt_sha256':R19_SHA,'r9_offline_status':witnessed['status'],
             'operator_confirmed_image_idle':True,'result':report,
             'effective_loader_resolution_verified':False,'runtime_dependency_closure_verified':False,
             'runtime_binary_identity_verified':False,'authorized_profiles':0,
             'authorized_cases':0,'dispatch_allowed':False,'guest_binaries_executed':False,
             'limitations':['SAMBA_CANDIDATE_DIRECTORY_ONLY','NOT_GLIBC_SEARCH_ORDER',
                            'NOT_LD_SO_CACHE_OR_HWCAPS_OR_PRELOAD','NOT_RUNTIME_IDENTITY',
                            'NOT_EFFECTIVE_CONFIG_OR_CLI_APPROVAL','NOT_CASE_AUTHORITY_OR_P9']}
    payload=(json.dumps(receipt,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
    r20.need(len(payload)<8*1024*1024,'receipt_bytes_limit')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(payload);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:path.unlink()
        except OSError:pass
        raise
    dfd=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'status':'PASS_P8_R20_SAMBA_CANDIDATE_OBSERVATION_DENY_ONLY',
            'private_receipt_sha256':hashlib.sha256(payload).hexdigest(),
            **report['summary']}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--private-receipt',type=Path,required=True)
    ap.add_argument('--confirm-image-idle',action='store_true')
    args=ap.parse_args()
    try:print(json.dumps(collect(args.private_receipt,args.confirm_image_idle),sort_keys=True))
    except (graph.GraphError,OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired) as exc:
        print('P8_R20=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
