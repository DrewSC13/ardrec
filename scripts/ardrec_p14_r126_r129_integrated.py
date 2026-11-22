#!/usr/bin/env python3
"""R126–R129: source-bound FTP pilot acceptance and independent DENY evidence.

Read-only inspection / externally signed closure verification. Physical
arming, booting, connecting, risk promotion and publication are NOT triggered.
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r122_operational_boundary as r122
from ardrec.coordination import r123_guarded_window as r123
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125
from ardrec.coordination import r126_operational_controller as r126
from ardrec.coordination import r126_scope_v2 as scope_v2
from ardrec.coordination import r126_window_v2 as window_v2
from ardrec.coordination import r127_closure_witness as r127
from ardrec.coordination import r128_ftp_pilot as r128
from ardrec.coordination import r129_a6_a10_recovery as r129

REPO=Path('/home/cicada/Development/GitHub/ardrec')
CATALOG=Path('lab/operational-catalog-v1/catalog.json')


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--capabilities',action='store_true')
    modes.add_argument('--inspect',action='store_true')
    modes.add_argument('--verify-closure',action='store_true')
    modes.add_argument('--authority-metadata',action='store_true')
    modes.add_argument('--scope-v2-plan',action='store_true')
    modes.add_argument('--window-v2-capabilities',action='store_true')
    modes.add_argument('--root-deny-controller-capabilities',action='store_true')
    modes.add_argument('--window-v2-review',action='store_true')
    modes.add_argument('--unsigned-pilot-request',action='store_true')
    modes.add_argument('--verify-audit',type=Path)
    parser.add_argument('--head')
    parser.add_argument('--contract',type=Path)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--pilot-permit',type=Path)
    parser.add_argument('--traffic-window',type=Path)
    parser.add_argument('--request-output',type=Path)
    parser.add_argument('--capture',type=Path)
    parser.add_argument('--journal',type=Path)
    parser.add_argument('--unit-file',type=Path)
    parser.add_argument('--pre-readback',type=Path)
    parser.add_argument('--post-readback',type=Path)
    parser.add_argument('--witness',type=Path)
    parser.add_argument('--save-audit',action='store_true')
    args=parser.parse_args(argv)
    if args.capabilities:
        if any(x is not None for x in (args.head,args.capture,args.journal,
                args.unit_file,args.pre_readback,args.post_readback,args.witness,
                args.contract,args.authorization,args.pilot_permit,
                args.traffic_window,args.request_output,args.verify_audit)) or args.save_audit:
            parser.error('capabilities rejects additional inputs')
        print(f1.canonical({'r126':r126.capabilities(),
                            'r127':r127.capabilities(),
                            'r128':r128.capabilities(),
                            'r129':r129.capabilities()}).decode().strip())
        return 0
    try:
        r126.need(Path.cwd().resolve()==REPO, 'WRONG_REPOSITORY')
        now=datetime.now(timezone.utc).replace(microsecond=0)
        catalog=CATALOG.read_bytes()
        f14.catalog_check(catalog)
        supplied=(args.contract,args.authorization,args.pilot_permit)
        if args.root_deny_controller_capabilities:
            r126.need(args.head is None and not any(x is not None for x in
                (args.contract,args.authorization,args.pilot_permit,
                 args.traffic_window,args.request_output,args.capture,
                 args.journal,args.unit_file,args.verify_audit)) and
                 not args.save_audit,
                 'ROOT_CAPABILITIES_FORBIDS_OPERATIONAL_INPUTS')
            import ardrec_p14_r126_root_session_guard as root_guard_b4
            print(f1.canonical(root_guard_b4.capabilities()).decode().strip())
            return 0
        if args.window_v2_capabilities:
            r126.need(args.head is None and args.traffic_window is None and
                      not any(x is not None for x in supplied) and
                      args.request_output is None,
                      'WINDOW_CAPABILITIES_FORBIDS_INPUTS')
            print(f1.canonical(window_v2.capabilities()).decode().strip())
            return 0
        if args.window_v2_review:
            r126.need(args.head is not None and
                      all(x is not None for x in supplied) and
                      args.traffic_window is not None and
                      args.request_output is None and not args.save_audit,
                      'CURRENT_WINDOW_FOUR_DOCUMENTS_REQUIRED')
            cmd=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],
                stdin=subprocess.DEVNULL,capture_output=True,timeout=6,check=False)
            r126.need(cmd.returncode == 0 and
                      cmd.stdout.decode('ascii').strip() == args.head,
                      'CURRENT_GIT_HEAD_CHANGED')
            # Documentation-only review still rejects a dirty/unapproved source
            # to prevent a draft tree being mistaken for an executable permit.
            clean=subprocess.run(['/usr/bin/git','status','--porcelain=v1'],
                stdin=subprocess.DEVNULL,capture_output=True,timeout=6,check=False)
            r126.need(clean.returncode == 0 and clean.stdout == b'',
                      'CURRENT_SOURCE_NOT_FROZEN_OR_SIGNED')
            c,a,p,w=(f2.private_read(path) for path in
                       (*supplied,args.traffic_window))
            x=window_v2.review_current(contract_raw=c,authorization_raw=a,
                pilot_raw=p,window_raw=w,catalog_raw=catalog,
                expected_head=args.head,now=now)
            print('R126_WINDOW_DOCUMENT='+x['document_status'])
            print('R126_WINDOW_SHA256='+x['sha256'])
            print('R126_WINDOW_ROOT_GRANT=FALSE')
            print('R126_WINDOW_DISPATCH=BLOCKED')
            print('R126_WINDOW_P8=NO-GO')
            return 0
        any_docs=any(p is not None for p in supplied)
        all_docs=all(p is not None for p in supplied)
        r126.need(args.traffic_window is None,
                  'TRAFFIC_WINDOW_ONLY_WITH_WINDOW_REVIEW')
        if args.scope_v2_plan:
            r126.need(args.head is not None and not any_docs and
                      args.request_output is None,
                      'SCOPE_V2_PLAN_ONLY_HEAD_ALLOWED')
            print(f1.canonical(scope_v2.enrollment_plan(expected_head=args.head)).decode().strip())
            return 0
        if args.authority_metadata:
            r126.need(not any_docs and args.request_output is None,
                      'AUTHORITY_METADATA_FORBIDS_DOCUMENT_INPUTS')
            print(f1.canonical(r126.root_document_metadata()).decode().strip())
            return 0
        if args.unsigned_pilot_request:
            r126.need(args.contract is not None and
                      args.authorization is None and args.pilot_permit is None and
                      args.request_output is not None and args.head is not None,
                      'UNSIGNED_REQUEST_CONTRACT_HEAD_OUTPUT_REQUIRED')
            r126.need(args.request_output.is_absolute() and
                      args.request_output.parent.is_dir() and
                      not any(part.is_symlink() for part in
                              (args.request_output.parent, *args.request_output.parent.parents)) and
                      not args.request_output.exists() and
                      not args.request_output.is_symlink(),
                      'UNSIGNED_REQUEST_OUTPUT_PATH_UNSAFE')
            parent=args.request_output.parent.stat()
            r126.need(parent.st_uid==os.geteuid() and
                      parent.st_mode & 0o077 == 0,
                      'UNSIGNED_REQUEST_PARENT_NOT_PRIVATE')
            cmd=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],
                               stdin=subprocess.DEVNULL,capture_output=True,
                               timeout=6,check=False)
            r126.need(cmd.returncode==0 and
                      cmd.stdout.decode('ascii').strip()==args.head,
                      'CURRENT_GIT_HEAD_CHANGED')
            contract=f2.private_read(args.contract)
            request=r126.unsigned_pilot_request(head=args.head,catalog_raw=catalog,
                                                 contract_raw=contract)
            body=f1.canonical(request)
            f2.exclusive(args.request_output,body)
            folder_fd=os.open(args.request_output.parent,
                              os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
            try:
                os.fsync(folder_fd)
            finally:
                os.close(folder_fd)
            print('R126_UNSIGNED_REQUEST='+str(args.request_output))
            print('R126_UNSIGNED_REQUEST_SHA256='+f1.digest(body))
            print('R126_UNSIGNED_REQUEST_STATUS=UNSIGNED_NOT_VALID_FOR_EXECUTION')
            print('R126_P8=NO-GO')
            return 0
        r126.need(args.request_output is None,'REQUEST_OUTPUT_ONLY_WITH_REQUEST_MODE')
        r126.need(not any_docs or (args.inspect and all_docs),
                  'PARTIAL_OR_NON_INSPECT_DOCUMENTS')
        if args.verify_audit is not None:
            report=r129.verify_private(args.verify_audit,catalog)
            print('R129_A10=REPLAY_VALID')
            print('R129_SHA256='+report['sha256'])
            print('R129_P8=NO-GO')
            return 0
        if args.verify_closure:
            r126.need(all(x is not None for x in
                     (args.pre_readback,args.post_readback,args.witness)),
                     'PHYSICAL_WITNESS_INPUTS_REQUIRED')
            files=(args.pre_readback,args.post_readback,args.witness)
            r126.need(all(x.is_absolute() and x.is_file() for x in files),
                     'WITNESS_SOURCE_FILE_MISSING')
            pre=f1.load(files[0].read_bytes())
            post=f1.load(files[1].read_bytes())
            envelope=f1.load(files[2].read_bytes())
            receipt=r127.verify_root_anchored(envelope=envelope,pre=pre,
                                               post=post,now=now)
            print('R127_ROOT_TRUST=ANCHORED')
            print('R127_INDEPENDENT_CLOSURE_SHA256='+receipt['sha256'])
            print('R127_MAX_60S_MET='+str(receipt['max_60s_met']))
            print('R127_P8=NO-GO')
            return 0
        r126.need(args.inspect and args.capture is not None and args.head is not None,
                  'INSPECTION_SOURCE_REQUIRED')
        r126.need(args.capture.is_absolute(), 'CAPTURE_NOT_ABSOLUTE')
        cmd=subprocess.run(['/usr/bin/git','rev-parse','HEAD'],
                           stdin=subprocess.DEVNULL,capture_output=True,
                           timeout=6,check=False)
        r126.need(cmd.returncode==0 and
                  cmd.stdout.decode('ascii').strip()==args.head,
                  'CURRENT_GIT_HEAD_CHANGED')
        need_case = args.journal is not None or args.unit_file is not None
        r126.need(not need_case or
                  (args.journal is not None and args.unit_file is not None and
                   args.journal.is_absolute() and args.unit_file.is_absolute()),
                  'PARTIAL_CASE_ARGUMENTS')
        unit=f1.load(args.unit_file.read_bytes()) if need_case else None
        boundary=r122.build(capture_folder=args.capture,catalog_raw=catalog,
                            head=args.head,now=now,
                            journal_folder=args.journal,unit=unit)
        plan=r123.plan(boundary=boundary,catalog_raw=catalog,now=now)
        readback=r124.inspect(head=args.head,now=now)
        unified=r125.build(head=args.head,catalog_raw=catalog,now=now,
                           boundary=boundary,plan=plan,root_report=readback)
        documentary=None
        if all_docs:
            contract_raw,authorization_raw,pilot_raw=(f2.private_read(p) for p in supplied)
            documentary=r126.signed_documents(
                contract_raw=contract_raw,authorization_raw=authorization_raw,
                pilot_raw=pilot_raw,catalog_raw=catalog,head=args.head,now=now)
        review=r126.review(head=args.head,now=now,root_report=readback,
                           integrated_report=unified,documentary_review=documentary)
        r126.verify(review,root_report=readback,integrated_report=unified,
                    documentary_review=documentary)
        print('R126_HEAD='+review['head'])
        print('R126_ROOT_DENY='+review['root_deny_state'])
        print('R126_INPUT_DOCUMENTS_SUPPLIED='+str(all_docs).upper())
        print('R126_SIGNED_PILOT_DOCUMENTS='+review['document_status'])
        print('R126_ROOT_GRANT='+str(review['root_enforced_grant_verified']))
        print('R126_SESSION_TIMER='+str(review['root_session_timer']))
        print('R126_DISPATCH=BLOCKED')
        print('R126_SHA256='+review['sha256'])
        if need_case:
            reservation=f13._read_json(args.journal,'reservation.json')
            preparation=r128.prepare(handoff=review,
                                     intent=reservation['intent'],
                                     profile=reservation['profile'])
            intake=r128.reconcile(preparation=preparation,journal=args.journal,
                                  catalog_raw=catalog)
            case=r121.build(args.journal,catalog,unit)
            result=r129.reconcile(intake=intake,case=case,catalog_raw=catalog)
            print('R128_A5='+intake['a5'])
            print('R128_A6='+intake['a6'])
            print('R129_A7_INTERVAL='+str(result['a7_mathematical_interval']))
            print('R129_RF='+str(result['a7_confirmed_rf']))
            print('R129_A8='+str(result['a8_authoritative_transition']))
            print('R129_A9='+str(result['a9_global_generation']))
            if args.save_audit:
                folder=r129.store_private(result,intake=intake,case=case,
                                          catalog_raw=catalog)
                r129.verify_private(folder,catalog)
                print('R129_PRIVATE_A10='+str(folder))
                print('R129_PRIVATE_A10=REPLAY_PASS')
        print('R126_R129_PHYSICAL_ACTIONS=0')
        print('R126_R129_P8=NO-GO')
        return 0
    except (r126.Stop,r127.Stop,r128.Stop,r129.Stop,r121.Stop,r122.Stop,f2.Stop,
            r123.Stop,r124.Stop,r125.Stop,window_v2.Stop,f13.Stop,f14.Stop,
            ValueError,KeyError,OSError,TypeError,UnicodeError,
            subprocess.TimeoutExpired) as exc:
        print('R126_R129_STOP='+type(exc).__name__+':'+str(exc)[:180])
        print('R126_R129_P8=NO-GO')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
