#!/usr/bin/env python3
"""Operator-only R31: reuse *existing* R14 private manpage capture, no QCOW2 read.

inspect: read, authenticate and validate R14 report, without writing.
extract: do that again and create a NEW exclusive private 0600 evidence file.

No ssh/curl/smbclient invocation, network, credentials, shell or execution authority.
Never put the private R14/R31 report, roff excerpts, or paths into Git.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

import p8_r31_manual_windows as r31
import verify_p8_cli_full_sources as r14
import verify_p8_r31_manual_windows as v31

PATCHES=Path('/home/cicada/Development/GitHub/ardrec-patches')
R14_BASENAME='ARDREC_P8_R14_FULL_MANPAGES_20261109.json'
DEST_DIR=PATCHES/'ARDREC_PRIVATE_R31'
DEST_FILE=DEST_DIR/'FTP_SMB_ROFF_WINDOWS_R31_PRIVATE.json'


def require(test,reason):
    if not test: raise r31.Blocked('R31_PRIVATE_FAIL_CLOSED:'+reason)


def read_source():
    require(os.getuid()==1000 and os.geteuid()!=0,'nonroot_expected')
    require(PATCHES.is_dir() and not PATCHES.is_symlink(),'patches_root')
    # Bounded, exact basename discovery only; do not recurse outside patch storage.
    candidates=[]
    for p in PATCHES.glob('**/'+R14_BASENAME):
        try: rel=p.relative_to(PATCHES)
        except ValueError:continue
        if len(rel.parts)>4:continue
        ancestor=PATCHES
        safe=True
        for name in rel.parts[:-1]:
            ancestor=ancestor/name
            if ancestor.is_symlink() or not ancestor.is_dir():safe=False;break
        if not safe or p.is_symlink() or not p.is_file():continue
        candidates.append(p)
    require(len(candidates)==1,'expected_exactly_one_r14_report_found_'+str(len(candidates)))
    path=candidates[0]
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
            stat.S_IMODE(info.st_mode)==0o600 and 0<info.st_size<=1048576,
            'r14_private_report_permissions_and_size')
    raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==r31.R14_FULL_SHA,'r14_private_sha256')
    return raw


def inspect_private():
    need=v31.verify()
    require(need['status']=='PASS_P8_R31_39_REAL_SOURCE_ANCHORS_READY_FOR_PRIVATE_EXTRACTION',
            'public_contract')
    raw=read_source()
    a=r14.safe_read(v31.ROOT,r14.SOURCE,r14.SOURCE_SHA)
    report=r31.from_authenticated_report(raw,a,r14.private_reconcile)
    require(len(report['source_windows'])==39 and
            report['dispatch_allowed'] is False and
            report['complete_semantic_reviews']==0,'private_evidence_scope')
    print('PASS:authenticated_existing_R14_seven_manuals_91_entry_anchors',flush=True)
    print('PASS:R31_39_bounded_private_windows_21_ftp_smb_profiles',flush=True)
    print('R31_MANUAL_CONTEXT=ACTUAL_PREVIOUSLY_CAPTURED_ROFF_SOURCE_NOT_SEMANTIC_APPROVAL',flush=True)
    print('QCOW2_READ=False CLI_EXECUTED=False DISPATCH=False',flush=True)
    return report


def exclusive_write(report):
    require(not DEST_DIR.is_symlink() and not DEST_DIR.exists() and
            not DEST_FILE.exists() and not DEST_FILE.is_symlink(),
            'private_r31_report_already_exists_do_not_retry')
    raw=(json.dumps(report,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    require(0 < len(raw) < 450000,'r31_receipt_size_limit')
    DEST_DIR.mkdir(mode=0o700)
    require(stat.S_IMODE(DEST_DIR.stat().st_mode)==0o700,'private_dir_mode')
    fd=os.open(DEST_FILE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    d=os.open(DEST_DIR,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(d)
    finally:os.close(d)
    require(stat.S_IMODE(DEST_FILE.lstat().st_mode)==0o600,'private_file_mode')
    return hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('inspect','extract'))
    args=parser.parse_args()
    print('========== ARDREC / P8-R31 / MATERIAL MANUAL REVIEW INPUT ==========',flush=True)
    result=inspect_private()
    if args.mode=='inspect':
        print('P8_R31_PRIVATE_INSPECT=PASS_NO_MUTATION',flush=True)
    else:
        receipt=exclusive_write(result)
        print('R31_PRIVATE_RECEIPT_SHA256='+receipt,flush=True)
        print('P8_R31_PRIVATE_EXTRACTION=PASS_SINGLE_PRIVATE_REPORT',flush=True)
    print('P8_OPEN=True APPROVED_CLI_OPTIONS=0 APPROVED_PROFILES=0',flush=True)
    print('P9_STARTED=False AL06_AL07_OPEN=True',flush=True)
    print('========== FIN / TERMINAL DISPONIBLE ==========',flush=True)


if __name__=='__main__':
    try:main()
    except (r31.Blocked,r14.FullSourceError,ValueError,TypeError,KeyError,
            OSError,json.JSONDecodeError) as err:
        print('P8_R31_PRIVATE=BLOCKED_'+type(err).__name__,flush=True)
        print('DETAIL='+str(err)[:300],flush=True)
        print('NO_AUTOMATIC_RETRY=True QCOW2_READ=False',flush=True)
        raise SystemExit(1)
