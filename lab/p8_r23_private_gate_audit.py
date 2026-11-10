#!/usr/bin/env python3
"""P8-R23 operator-only receipt: R22 SHA + public profile gate crosswalk.

No QCOW2, sudo, network, guest binary, runtime loader, CLI or secrets.
One-shot private 0600 receipt; no authentication or authority promotion.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import p8_r23_profile_obligations as gate
import verify_p8_r23_profile_obligations as v23
import verify_p8_material_inventory as r9

PRIVATE=Path('/home/cicada/Development/GitHub/ardrec-patches')
R22_RECEIPT=PRIVATE/'ARDREC_PRIVATE_R22/LOADER_BOUNDARY_R22_PRIVATE.json'
OUT_DIR=PRIVATE/'ARDREC_PRIVATE_R23'
OUT_FILE=OUT_DIR/'PROFILE_OBLIGATIONS_R23_PRIVATE.json'


def private_source(path,sha):
    gate.need(path.is_file() and not path.is_symlink() and
              path.parent.is_dir() and not path.parent.is_symlink() and
              stat.S_IMODE(path.parent.stat().st_mode)==0o700 and
              stat.S_IMODE(path.stat().st_mode)==0o600,'r22_private_permissions')
    gate.need(path.stat().st_size<4*1024*1024,'r22_size_bound')
    payload=path.read_bytes()
    gate.need(hashlib.sha256(payload).hexdigest()==sha,'r22_sha256')
    return json.loads(payload)


def audit(output):
    gate.need(os.geteuid()!=0,'no_root_python')
    gate.need(output.is_absolute() and output==OUT_FILE and not output.is_symlink()
              and not output.exists(),'output_must_be_new_exact_private_path')
    gate.need(OUT_DIR.parent.is_dir() and not OUT_DIR.parent.is_symlink(),
              'private_parent')
    print('R23_PHASE=VERIFY_PUBLIC_CONTRACT',file=sys.stderr,flush=True)
    public=v23.verify()
    gate.need(public['status']=='PASS_P8_R23_PROFILE_OBLIGATION_LEDGER_DENY_ONLY',
              'public_preflight')
    print('R23_PHASE=AUTHENTICATE_R22_RECEIPT',file=sys.stderr,flush=True)
    legacy=private_source(R22_RECEIPT,gate.R22_SHA)
    proof=gate.authenticate_r22_receipt(legacy)
    print('R23_PHASE=BUILD_PROFILE_OBLIGATION_CROSSWALK',file=sys.stderr,flush=True)
    root=v23.ROOT
    rows=gate.profile_rows(r9.read(root,r9.P8_PATH,digest=r9.P8_SHA),
                           r9.read(root,r9.CMP_PATH),r9.read(root,r9.INV_PATH),
                           r9.read(root,r9.P7_PATH,digest=r9.P7_SHA))
    summary=gate.summarize(rows)
    gate.need(summary['profile_obligation_ledger_sha256']==
              public['profile_obligation_ledger_sha256'],'public_private_drift')
    # No runtime or external assertions can turn a candidate into an authority.
    for row in rows:
        gate.need(gate.deny_request(rows,row['profile_id'],{'claimed_approved':True})
                  ['decision']=='DENY','unsafe_deny_override')
    doc={'schema_version':'1.0','scope':'P8_R23_PUBLISHED_OBLIGATIONS_PRIVATE_NOT_AUTHORITY',
         'base_main_commit':gate.BASE,'image_sha256':gate.IMAGE_SHA,
         'r22_private_receipt_sha256':gate.R22_SHA,'r22_boundary':proof,
         'source':'R9_PUBLIC_CANDIDATE_BINARY_P8_UNBOUND_PROFILE_MATRIX',
         'profile_ledger':rows,'summary':summary,
         'qcow2_accessed':False,'guest_binaries_executed':False,
         'runtime_loader_executed':False,'capability_tested':False,
         'effective_configuration_verified':False,
         'runtime_binary_identity_verified':False,
         'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
         'limitations':['PUBLIC_SOURCE_OBLIGATIONS_ONLY_NOT_OPERATIONAL_MATERIAL',
                        'SOURCE_IMAGE_CANDIDATE_SHA_NOT_RUNTIME_IDENTITY',
                        'R22_LOADER_BOUNDARY_NOT_EFFECTIVE_RESOLUTION',
                        'FIVE_WRITE_VARIANTS_REQUIRE_INDEPENDENT_CLEANUP',
                        'NO_CASE_AUTHORITY_OR_CAPTURE_BUDGET_OR_TYPED_ARGV',
                        'NO_P9_A1_TO_A10_EXECUTION']}
    data=(json.dumps(doc,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    gate.need(len(data)<1024*1024,'output_max_size')
    OUT_DIR.mkdir(mode=0o700,exist_ok=True)
    gate.need(not OUT_DIR.is_symlink() and
              stat.S_IMODE(OUT_DIR.stat().st_mode)==0o700,'out_dir_permissions')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as fh:
            fh.write(data);fh.flush();os.fsync(fh.fileno())
    except BaseException:
        try:output.unlink()
        except OSError:pass
        raise
    dirfd=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(dirfd)
    finally:os.close(dirfd)
    return {'private_receipt_sha256':hashlib.sha256(data).hexdigest(),
            'r22_receipt_sha256_verified':True,'qcow2_accessed':False,
            **proof,**summary}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--private-receipt',required=True,type=Path)
    args=ap.parse_args()
    try:print(json.dumps(audit(args.private_receipt),sort_keys=True))
    except (gate.GateError,ValueError,KeyError,TypeError,OSError) as exc:
        print('P8_R23=FAIL_CLOSED:'+str(exc),file=sys.stderr);return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
