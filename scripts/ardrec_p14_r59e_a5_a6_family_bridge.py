#!/usr/bin/env python3
"""R59-E: read a persisted R59-D case; run R58H/I/J family previews offline.

No execution, VM, host commands, network, F11 transitions, A6 accreditation,
A7 risk confirmation, or A9 publication.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59e_a5_a6_family_bridge as b


def main() -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-root',type=Path,required=True)
    ap.add_argument('--output-root',type=Path,required=True)
    identity=ap.add_mutually_exclusive_group(required=True)
    identity.add_argument('--candidate-sha')
    identity.add_argument('--from-r59d-demo-summary',type=Path)
    ap.add_argument('--variant',choices=sorted({v for vs in b.VARIANT_OPTIONS.values() for v in vs}))
    ap.add_argument('--review-json',type=Path)
    ap.add_argument('--verify',action='store_true')
    args=ap.parse_args()
    try:
        d._private_root(args.source_root)
        d._private_root(args.output_root)
        if args.from_r59d_demo_summary is not None:
            raw=d._read_private(args.from_r59d_demo_summary,16_384)
            item=json.loads(raw,object_pairs_hook=d._pairs)
            d.need(type(item) is dict and item.get('r59d')=='PASS' and
                   item.get('a5_physical_start_accredited') is False and
                   item.get('a6_classification')=='ND' and
                   item.get('p8_operational')=='NO-GO',
                   'R59D_SUMMARY_UNSUPPORTED_AUTHORITY')
            candidate=item.get('candidate_sha256')
        else:
            candidate=args.candidate_sha
        d.need(d._hex(candidate),'CANDIDATE_SHA_NOT_HEX')
        if args.verify:
            d.need(args.review_json is None and args.variant is None,
                   'VERIFY_MODE_NOT_RECONFIGURABLE')
            doc=b.verify_stored_bridge(args.output_root,args.source_root,candidate)
            mode='VERIFIED_REOPENED'
        else:
            review=None
            if args.review_json is not None:
                raw=d._read_private(args.review_json,b.MAX_REVIEW)
                review=json.loads(raw,object_pairs_hook=d._pairs)
            saved=b.persist_bridge(args.output_root,args.source_root,candidate,
                                   variant=args.variant,review=review)
            doc=b.verify_stored_bridge(args.output_root,args.source_root,candidate)
            mode=saved['status']
        summary={
            'r59e':'PASS_SOURCE_BOUND_A5_A6_FAMILY_REVIEW',
            'mode':mode,'source_candidate_sha256':candidate,
            'bridge_sha256':doc['sha256'],
            'service_id':doc['identity']['service_id'],
            'family_id':doc['identity']['family_id'],
            'attempt_id':doc['identity']['attempt_id'],
            'declared_outcome':doc['declared_outcome'],
            'model_family_class':doc['hypothetical_family_class'],
            'unresolved_preconditions':len(doc['unresolved_preconditions']),
            'unresolved_supports':len(doc['unresolved_supports']),
            'variant_in_original_a5_intent':False,
            'a5_physical_start_accredited':False,
            'a6_classification':'ND','confirmed_rf':None,
            'published_generation':None,'host_mutations':0,
            'p8_operational':'NO-GO',
        }
        print(json.dumps(summary,sort_keys=True,ensure_ascii=True))
        return 0
    except (d.IntakeError,b.FamilyBridgeError,ValueError,TypeError,KeyError,
            AttributeError,OSError,UnicodeError) as exc:
        print('R59E=BLOCKED:'+type(exc).__name__+':'+str(exc)[:170],file=sys.stderr)
        print('R59E_HOST_MUTATIONS=0; R59E_A6=ND; P8=NO-GO',file=sys.stderr)
        return 23


if __name__=='__main__':raise SystemExit(main())
