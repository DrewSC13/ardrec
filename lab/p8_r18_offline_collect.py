#!/usr/bin/env python3
"""P8-R18 operator-only offline QCOW2 ELF metadata acquisition.

Never run as root: calls the existing R9 read-only offline-image verifier,
then uses ONLY sudo -n virt-cat to read pinned guest file bytes in memory.
No guest ELF or process is executed. Write-once PRIVATE receipt outside Git.
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

import p8_r18_elf_metadata as elf

ROOT=Path(__file__).resolve().parents[1]
PINNED_MAIN='05513b28af3ffa23ef98cef3fd4e2dcf2a71eea8'
BINARIES=('/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient')


def private_destination(path: Path):
    elf.need(path.is_absolute() and path.name.endswith('.json') and
             not path.is_symlink() and not path.exists(), 'receipt_path')
    p=path.parent
    elf.need(p.is_dir() and not p.is_symlink() and
             stat.S_IMODE(p.stat().st_mode)==0o700 and
             os.path.realpath(str(p))==str(p), 'private_directory_mode')
    elf.need(not str(p).startswith(str(ROOT)) and
             '/ardrec-patches/' in str(p) and
             str(p).startswith('/home/'), 'private_receipt_location')


def virt_cat_read(path):
    elf.need(path in BINARIES, 'not_pinned_guest_path')
    import verify_p8_material_inventory as r9
    cmd=['sudo','-n','virt-cat','--format=qcow2','-a',r9.IMAGE_PATH,path]
    output=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          check=False,timeout=100)
    elf.need(output.returncode==0 and 64<=len(output.stdout)<=elf.MAX_ELF_BYTES,
             'virt_cat_failed_or_size_exceeded')
    return output.stdout


def collect(path):
    import verify_p8_material_inventory as r9
    elf.need(os.geteuid()!=0,'run_as_non_root')
    private_destination(path)
    upstream=r9.verify_repository()
    elf.need(upstream['status']=='PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL',
             'r9_source_identity')
    inventory=r9.read(ROOT,r9.INV_PATH)
    witnessed=r9.verify_offline_image(inventory)
    elf.need(witnessed['status']=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION',
             'r9_offline_image')
    by_path={row['absolute_path']:row for row in inventory['binary_observations']}
    records=[]
    for name in BINARIES:
        raw=virt_cat_read(name)
        candidate=by_path[name]
        elf.need(hashlib.sha256(raw).hexdigest()==candidate['sha256'],
                 'r9_binary_hash:'+name)
        observed=elf.inspect_elf(raw)
        records.append({'guest_path':name,'r9_sha256':candidate['sha256'],
                        'metadata':observed,
                        'status':'OFFLINE_DIRECT_ELF_OBSERVATION_NOT_RUNTIME_PROOF'})
    # Reject media changes between read-only R9 attestation and ELF observation.
    post=r9.checked_command(['sudo','-n','sha256sum',r9.IMAGE_PATH]).split()[0]
    elf.need(post==r9.IMAGE_SHA,'qcow2_changed_after_read')
    report={'schema_version':'1.0','scope':'P8_R18_OFFLINE_DIRECT_ELF_CANDIDATE_ONLY',
            'base_main_commit':PINNED_MAIN,'image_sha256':r9.IMAGE_SHA,
            'r9_offline_status':witnessed['status'],'candidates':records,
            'transitive_dependency_closure_verified':False,
            'runtime_binary_identity_verified':False,
            'configuration_effective_verified':False,
            'authorized_profiles':0,'authorized_cases':0,
            'dispatch_allowed':False,'guest_binaries_executed':False,
            'limitation':'Observed PT_INTERP/DT_NEEDED from read-only pinned QCOW2. Loader resolution, dependencies, environment, effective CLI configuration, authority, runtime identity and P9 remain unproven.'}
    data=(json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
               getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
    except BaseException:
        try: os.unlink(path)
        except OSError: pass
        raise
    fd2=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
    try:os.fsync(fd2)
    finally:os.close(fd2)
    return {'status':'PASS_P8_R18_OFFLINE_DIRECT_ELF_OBSERVED_DENY_ONLY',
            'private_receipt_sha256':hashlib.sha256(data).hexdigest(),
            'binary_count':len(records),'direct_needed_counts':{
                row['guest_path']:len(row['metadata']['dt_needed_direct']) for row in records},
            'transitive_closure_verified':False,'runtime_identity_verified':False,
            'dispatch_allowed':False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--private-receipt',required=True,type=Path)
    args=ap.parse_args()
    try: print(json.dumps(collect(args.private_receipt),sort_keys=True))
    except (elf.ElfEvidenceError,OSError,ValueError,
            subprocess.TimeoutExpired) as exc:
        print('P8_R18=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
