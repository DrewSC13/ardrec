#!/usr/bin/env python3
"""R59-G: offline A5-v2 signature intake/reopen, strictly documentary P8 NO-GO."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59f_variant_origin as v2
from ardrec.coordination import r59g_signed_a5_review as g

BUNDLE_SCHEMA = 'ardrec-r59g-a5-v2-signatures-input-v1'


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    actions=p.add_mutually_exclusive_group(required=True)
    actions.add_argument('--inspect-v2',action='store_true')
    actions.add_argument('--submit-signed',action='store_true')
    actions.add_argument('--verify-signed',action='store_true')
    for name in ('v2-root','a5-root','a6-root','attempt-id'):
        p.add_argument('--'+name,required=True,type=Path if name.endswith('root') else str)
    p.add_argument('--output-root',type=Path)
    p.add_argument('--registry-path',type=Path)
    p.add_argument('--registry-pin-sha256')
    p.add_argument('--signatures-path',type=Path)
    p.add_argument('--review-at-utc')
    args=p.parse_args()
    try:
        if args.inspect_v2:
            if any(value is not None for value in (
                args.output_root,args.registry_path,args.registry_pin_sha256,
                args.signatures_path,args.review_at_utc)):
                raise g.SignedA5Error('INSPECT_V2_CANNOT_SUBMIT_SIGNATURES')
            doc=v2.verify_stored(args.v2_root,args.a5_root,args.a6_root,args.attempt_id)
            out={'r59g':'VERIFIED_A5_V2_DOCUMENTARY_ONLY',
                 'attempt_id':doc['intent']['attempt_id'],
                 'variant':doc['intent']['variant'],
                 'declared_outcome':doc['receipt']['declared_outcome'],
                 'v2_report_sha256':doc['sha256'],
                 'signed_review_present':False,
                 'cryptographic_attribution_verified':False,
                 'a5_physical_start_accredited':False,
                 'a6_classification':'ND','p8_operational':'NO-GO'}
        else:
            if not all((args.output_root,args.registry_path,args.registry_pin_sha256)):
                raise g.SignedA5Error('SIGNATURE_MODE_REQUIRES_PINNED_EXTERNAL_REGISTRY')
            if args.submit_signed:
                if args.signatures_path is None or args.review_at_utc is None:
                    raise g.SignedA5Error('SIGNATURE_BUNDLE_AND_REVIEW_TIME_REQUIRED')
                raw=d._read_private(args.signatures_path,16384)
                bundle=json.loads(raw,object_pairs_hook=d._pairs)
                if type(bundle) is not dict or set(bundle)!={'schema','signatures'} or bundle['schema']!=BUNDLE_SCHEMA or raw!=d.canonical(bundle)+b'\n':
                    raise g.SignedA5Error('SIGNATURE_BUNDLE_NOT_CANONICAL')
                result=g.persist(args.output_root,args.v2_root,args.a5_root,args.a6_root,args.attempt_id,
                                 signatures=bundle['signatures'],registry_path=args.registry_path,
                                 registry_pin_sha256=args.registry_pin_sha256,
                                 review_at_utc=args.review_at_utc)
                mode=result['status']
                doc=g.verify_stored(args.output_root,args.v2_root,args.a5_root,args.a6_root,
                                    args.attempt_id,registry_path=args.registry_path,
                                    registry_pin_sha256=args.registry_pin_sha256)
            else:
                if args.signatures_path is not None or args.review_at_utc is not None:
                    raise g.SignedA5Error('VERIFY_ONLY_TAKES_EXTERNAL_REGISTRY')
                doc=g.verify_stored(args.output_root,args.v2_root,args.a5_root,args.a6_root,
                                    args.attempt_id,registry_path=args.registry_path,
                                    registry_pin_sha256=args.registry_pin_sha256)
                mode='VERIFIED_REOPENED'
            out={'r59g':'PASS_SIGNED_DECLARATION_NO_PHYSICAL_ATTESTATION',
                 'mode':mode,'attempt_id':args.attempt_id,
                 'signed_review_sha256':doc['sha256'],
                 'v2_report_sha256':doc['statement']['v2_report_sha256'],
                 'cryptographic_attribution_verified':True,
                 'a5_physical_start_accredited':False,
                 'a6_classification':'ND','p8_operational':'NO-GO'}
    except (ValueError,TypeError,KeyError,AttributeError,OSError,RuntimeError) as exc:
        print('R59G=BLOCKED:'+type(exc).__name__+':'+str(exc)[:200])
        print('R59G_A5_PHYSICAL=NOT_ATTESTED; R59G_A6=ND; P8=NO-GO')
        return 23
    print(json.dumps(out,ensure_ascii=True,sort_keys=True))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
