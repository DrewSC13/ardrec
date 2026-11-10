#!/usr/bin/env python3
"""P8-R22: authenticated receipt-only, no-QCOW2 static loader-boundary audit.

Only read four pre-existing private receipts. Never access sudo, guestfish,
virt-cat, host/guest loaders, services, case credentials, networks or dispatch.
Creates a new receipt once, with private permissions, outside the repository.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import p8_r19_graph as graph
import p8_r19_offline_collect as r19
import p8_r22_loader_boundary as audit

PRIVATE=Path('/home/cicada/Development/GitHub/ardrec-patches')
SOURCES=(
    ('R18',PRIVATE/'ARDREC_PRIVATE_R18/ELF_DIRECT_R18_PRIVATE.json',audit.R18_SHA),
    ('R19',PRIVATE/'ARDREC_PRIVATE_R19/ELF_GRAPH_R19_PRIVATE.json',audit.R19_SHA),
    ('R20',PRIVATE/'ARDREC_PRIVATE_R20/SAMBA_CANDIDATES_R20_PRIVATE.json',audit.R20_SHA),
    ('R21',PRIVATE/'ARDREC_PRIVATE_R21/MULTIARCH_CANDIDATES_R21_PRIVATE.json',audit.R21_SHA),
)
OUTPUT_DIR=PRIVATE/'ARDREC_PRIVATE_R22'
OUTPUT_NAME='LOADER_BOUNDARY_R22_PRIVATE.json'


def private_doc(label,path,expected):
    r19.private_dir(path.parent)
    audit.need(path.is_file() and not path.is_symlink() and
               stat.S_IMODE(path.stat().st_mode)==0o600 and
               path.stat().st_size<8*1024*1024, label+'_receipt_access')
    raw=path.read_bytes()
    audit.need(hashlib.sha256(raw).hexdigest()==expected,label+'_sha256')
    return json.loads(raw)


def collect(output):
    audit.need(os.geteuid()!=0,'never_root_python')
    audit.need(output==OUTPUT_DIR/OUTPUT_NAME and output.is_absolute() and
               not output.is_symlink() and not output.exists(),'output_destination')
    r19.private_dir(OUTPUT_DIR)
    docs={}
    for label,path,expected in SOURCES:
        print('R22_PHASE=VERIFY_PRIVATE_'+label,file=sys.stderr,flush=True)
        docs[label]=private_doc(label,path,expected)
    print('R22_PHASE=REPLAY_R20_R21',file=sys.stderr,flush=True)
    roots,known=audit.source_ledger(docs['R18'],docs['R19'],docs['R20'],docs['R21'])
    # Public R9 inventory is checked without accessing the QCOW2 image.
    import verify_p8_material_inventory as r9
    observed=r9.verify_repository()
    audit.need(observed['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
               'r9_static_source')
    audit.need(r9.IMAGE_SHA==audit.IMAGE_SHA,'image_pin')
    print('R22_PHASE=RECONCILE_STATIC_CANDIDATE_GRAPH',file=sys.stderr,flush=True)
    report=audit.analyze(roots,docs['R19']['result'],docs['R20']['result'],docs['R21']['result'])
    data={'schema_version':'1.0',
          'scope':'P8_R22_OFFLINE_RECEIPT_ONLY_LOADER_SEARCH_BOUNDARY_NOT_LOADER_PROOF',
          'base_main_commit':audit.BASE,'image_sha256':audit.IMAGE_SHA,
          'source_receipt_sha256':{label:sha for label,_,sha in SOURCES},
          'private_receipts_replayed':True,'qcow2_accessed':False,
          'guest_binaries_executed':False,'loader_executed':False,
          'effective_loader_resolution_verified':False,
          'effective_configuration_verified':False,
          'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
          'result':report,
          'limitations':['LEXICAL_RPATH_RUNPATH_AUDIT_NOT_LOADER_SEARCH_ORDER',
                         'NO_LD_SO_CACHE_HWCAPS_PRELOAD_ENVIRONMENT',
                         'NO_RPATH_INHERITANCE_OR_RUNPATH_DIRECT_ONLY_SIMULATION',
                         'NO_EFFECTIVE_RUNTIME_IDENTITY_OR_CONFIG',
                         'NO_PROFILE_AUTHORITY_OR_DISPATCH']}
    payload=(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    audit.need(len(payload)<4*1024*1024,'output_size')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(payload);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:output.unlink()
        except OSError:pass
        raise
    dfd=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'status':'PASS_P8_R22_RECEIPT_ONLY_LOADER_BOUNDARY_DENY_ONLY',
            'private_receipt_sha256':hashlib.sha256(payload).hexdigest(),
            'qcow2_accessed':False,'authorized_profiles':0,
            'authorized_cases':0,'dispatch_allowed':False,
            **report['summary']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-receipt',required=True,type=Path)
    args=parser.parse_args()
    try:print(json.dumps(collect(args.private_receipt),sort_keys=True))
    except (graph.GraphError,ValueError,OSError,KeyError,TypeError) as exc:
        print('P8_R22=FAIL_CLOSED:'+str(exc),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
