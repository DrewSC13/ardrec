#!/usr/bin/env python3
"""R59-D: offline A5 candidate intake, verify and private replay; NEVER executes A5.

Supported operations:
  --demo-no-start --store-root EXISTING_PRIVATE_DIRECTORY
  --import-intent FILE --import-receipt FILE --import-support FILE --store-root ...
  --verify-sha HEX --store-root ...
No VM, sudo, socket, process launch, state transitions, A7 or A9 publication.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r59d_a5_result_intake as m


def json_file(path: Path, max_bytes: int) -> dict:
    raw = external_file(path, max_bytes)
    try:
        obj=json.loads(raw, object_pairs_hook=m._pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise m.IntakeError('INPUT_INVALID_JSON') from exc
    m.need(type(obj) is dict, 'INPUT_OBJECT_REQUIRED')
    return obj


def external_file(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    m.need(path.is_absolute() and path.is_file() and not path.is_symlink(),
           'EXTERNAL_INPUT_PATH_INVALID')
    fd=os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd)
        m.need(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and
               before.st_nlink == 1 and (stat.S_IMODE(before.st_mode)&0o077)==0 and
               (0 if allow_empty else 1) <= before.st_size <= maximum,
               'EXTERNAL_INPUT_MODE_OR_SIZE')
        raw = b''
        while len(raw) <= maximum:
            chunk=os.read(fd, min(65536, maximum+1-len(raw)))
            if not chunk:
                break
            raw += chunk
        after=os.fstat(fd)
        m.need(len(raw)==before.st_size and (before.st_dev,before.st_ino,before.st_mtime_ns,
               before.st_ctime_ns,before.st_size)==(after.st_dev,after.st_ino,after.st_mtime_ns,
               after.st_ctime_ns,after.st_size), 'EXTERNAL_SOURCE_CHANGED')
        return raw
    finally:
        os.close(fd)


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--demo-no-start',action='store_true')
    group.add_argument('--import-intent',type=Path)
    group.add_argument('--verify-sha',type=str)
    ap.add_argument('--import-receipt',type=Path)
    ap.add_argument('--import-support',type=Path)
    ap.add_argument('--store-root',type=Path,required=True)
    args=ap.parse_args()
    try:
        store=m._private_root(args.store_root)
        if args.verify_sha is not None:
            m.need(args.import_receipt is None and args.import_support is None,
                   'EXTRA_INPUTS_NOT_ALLOWED_FOR_VERIFY')
            doc=m.verify_stored_candidate(store,args.verify_sha)
            status='VERIFIED_REOPENED'
        elif args.demo_no_start:
            m.need(args.import_receipt is None and args.import_support is None,
                   'EXTRA_INPUTS_NOT_ALLOWED_FOR_DEMO')
            intent=m.build_intent(service_id='SSH_DEV',session_id='DEV_R59D_DEMO',
                                  family_id='SSH-T01',derived_case_id='SSH-T01-S01-01',
                                  assessment_index=0,attempt_id='ATT_R59D_NO_START',
                                  configuration_sha256='0'*64,
                                  method_id='SSH_EFFECTIVE_CONFIG_READONLY')
            receipt=m.make_receipt(intent)
            saved=m.persist_candidate(store,intent,receipt,b'')
            doc=m.verify_stored_candidate(store,saved['report_sha256'])
            status=saved['status']
        else:
            m.need(args.import_receipt is not None and args.import_support is not None,
                   'IMPORT_THREE_FILES_REQUIRED')
            intent=json_file(args.import_intent, 8192)
            receipt=json_file(args.import_receipt,8192)
            support=external_file(args.import_support,m.MAX_SUPPORT,allow_empty=True)
            saved=m.persist_candidate(store,intent,receipt,support)
            doc=m.verify_stored_candidate(store,saved['report_sha256'])
            status=saved['status']
        summary={'r59d':'PASS','mode':'OFFLINE_SOURCE_ONLY','status':status,
                 'candidate_sha256':doc['sha256'],
                 'case_id':doc['intent']['derived_case_id'],
                 'attempt_id':doc['intent']['attempt_id'],
                 'source_kind':doc['receipt']['source_kind'],
                 'a5_physical_start_accredited':False,
                 'a6_classification':'ND','a7_confirmed_rf':None,
                 'a9_published_generation':None,'p8_operational':'NO-GO',
                 'host_mutations':0}
        print(json.dumps(summary,sort_keys=True,ensure_ascii=True))
        return 0
    except (m.IntakeError,OSError,TypeError,KeyError,ValueError) as exc:
        print('R59D=BLOCKED:'+type(exc).__name__+':'+str(exc)[:140],file=sys.stderr)
        print('R59D_P8=NO-GO; HOST_MUTATIONS=0',file=sys.stderr)
        return 23


if __name__=='__main__':
    raise SystemExit(main())
