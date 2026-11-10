#!/usr/bin/env python3
"""Operator-only private R24 crosswalk: authenticates R23 receipt; never runs guest.

Does not access QCOW2, sudo, network, shells, secrets, client argv or live service.
Refuses overwrite, symlinks and unexpected permissions. CI never runs this.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import p8_r24_capability_proof_boundary as p24
import verify_p8_r24_capability_proof_boundary as v24

PATCHES=Path('/home/cicada/Development/GitHub/ardrec-patches')
PRIVATE_R23=PATCHES/'ARDREC_PRIVATE_R23/PROFILE_OBLIGATIONS_R23_PRIVATE.json'
OUT_DIR=PATCHES/'ARDREC_PRIVATE_R24'
OUT_FILE=OUT_DIR/'PROOF_SUFFICIENCY_R24_PRIVATE.json'


def private_input(path,sha):
    p24.require(path.is_file() and not path.is_symlink() and
                path.parent.is_dir() and not path.parent.is_symlink() and
                stat.S_IMODE(path.parent.stat().st_mode)==0o700 and
                stat.S_IMODE(path.stat().st_mode)==0o600,'r23_private_permissions')
    p24.require(path.stat().st_size<=1024*1024,'r23_private_size')
    raw=path.read_bytes()
    p24.require(hashlib.sha256(raw).hexdigest()==sha,'r23_private_sha')
    return json.loads(raw)


def audit(path):
    p24.require(os.geteuid()!=0,'no_root')
    p24.require(path.is_absolute() and path==OUT_FILE and
                not path.exists() and not path.is_symlink(),'exact_new_private_output')
    p24.require(PATCHES.is_dir() and not PATCHES.is_symlink(),'private_parent')
    print('R24_PHASE=VERIFY_PUBLIC_CONTRACT',file=sys.stderr,flush=True)
    public=v24.verify()
    p24.require(public['status']=='PASS_P8_R24_PROOF_SUFFICIENCY_BOUNDARY_DENY_ONLY',
                'r24_public')
    print('R24_PHASE=AUTHENTICATE_R23_PRIVATE_RECEIPT',file=sys.stderr,flush=True)
    old=private_input(PRIVATE_R23,p24.R23_RECEIPT_SHA)
    provenance=p24.authenticate_r23_receipt(old)
    rows=old['profile_ledger']
    print('R24_PHASE=BUILD_STATIC_PROOF_SUFFICIENCY_MATRIX',file=sys.stderr,flush=True)
    matrix=p24.proof_matrix(rows,p24.R23_LEDGER_SHA)
    summary=p24.summarize(matrix)
    p24.require(summary['matrix_sha256']==public['matrix_sha256'],
                'public_private_crosswalk_drift')
    for row in matrix:
        pid=row['profile_id']
        p24.require(p24.deny_profile(matrix,pid,{'all_gates_passed':True})['decision']=='DENY',
                    'unsafe_promotion')
        for gate in p24.SOURCE_ONLY:
            claim={'profile_id':pid,'gate_id':gate,'claim_kind':'PINNED_SOURCE_REFERENCE',
                   'origin':p24.ORIGINS[gate],
                   'source_sha256':(row['candidate_image_sha256'] if gate=='actual_binary_identity'
                                    else p24.R22_RECEIPT_SHA),
                   'asserted_status':'CANDIDATE_ONLY'}
            p24.require(p24.inspect_claim(matrix,claim)['decision']=='DENY',
                        'static_claim_promoted')
    doc={'schema_version':'1.0',
         'scope':'P8_R24_PRIVATE_STATIC_PROOF_REQUIREMENTS_NOT_OPERATIONAL_PROOF',
         'base_main_commit':p24.BASE,'r23_private_receipt_sha256':p24.R23_RECEIPT_SHA,
         'r23_public_ledger_sha256':p24.R23_LEDGER_SHA,'r23_provenance':provenance,
         'proof_matrix':matrix,'summary':summary,
         'offline_reference_only':True,'runtime_identity_verified':False,
         'effective_loader_resolution_verified':False,
         'client_capability_verified':False,'effective_configuration_verified':False,
         'case_authority_verified':False,'independent_cleanup_verified':False,
         'qcow2_accessed':False,'guest_binaries_executed':False,
         'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
         'limitations':['STATIC_REFERENCE_IS_NOT_BINARY_RUNTIME_IDENTITY',
                        'STATIC_GRAPH_IS_NOT_EFFECTIVE_LOADER_RESOLUTION',
                        'NO_OPERATION_SPECIFIC_CLI_OR_SERVICE_CAPABILITY_TESTED',
                        'NO_CASE_SCOPE_OR_TARGET_AUTHORIZATION',
                        'NO_TYPED_ARGV_OR_FIXED_BUDGET_OR_CASE_CAPTURE',
                        'FIVE_MUTATING_VARIANTS_NEED_INDEPENDENT_CLEANUP',
                        'NO_P9_OR_A1_TO_A10_EXECUTION']}
    data=(json.dumps(doc,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    p24.require(len(data)<1024*1024,'out_size')
    OUT_DIR.mkdir(mode=0o700,exist_ok=True)
    p24.require(not OUT_DIR.is_symlink() and
                stat.S_IMODE(OUT_DIR.stat().st_mode)==0o700,'out_dir_permissions')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException:
        try:path.unlink()
        except OSError:pass
        raise
    dfd=os.open(OUT_DIR,os.O_DIRECTORY|os.O_RDONLY)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    return {'private_receipt_sha256':hashlib.sha256(data).hexdigest(),
            'r23_private_receipt_authenticated':True,
            'r23_public_ledger_sha_authenticated':True,
            **summary}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-receipt',required=True,type=Path)
    args=parser.parse_args()
    try:print(json.dumps(audit(args.private_receipt),sort_keys=True))
    except (p24.BoundaryError,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R24=FAIL_CLOSED:'+str(exc),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
