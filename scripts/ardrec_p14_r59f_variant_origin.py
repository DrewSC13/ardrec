#!/usr/bin/env python3
"""R59-F: v2 variant-bound A5 identity and private no-start replay, no execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59e_a5_a6_family_bridge as e
from ardrec.coordination import r59f_variant_origin as f

IDENT = ('service_id','session_id','family_id','derived_case_id',
         'assessment_index','attempt_id','configuration_sha256','method_id')


def example(service: str, family: str, variant: str | None) -> dict:
    tag = (variant if variant is not None else 'BASE')
    attempt = 'ATT_R59F_'+family.replace('-','_')+'_'+tag
    return f.build_intent(
        service_id=service,session_id='DEV_TUTOR_001',family_id=family,
        derived_case_id=family+'-S01-01',assessment_index=0,
        attempt_id=attempt,configuration_sha256='0'*64,
        method_id=d.SERVICES[service][2],variant=variant)


def all_families():
    sha, engines=e._sources()
    count=0
    options=0
    for service,(_,specs,_,_) in sorted(engines.items()):
        for row in specs:
            family=row['id']
            variants=e.VARIANT_OPTIONS.get(family,(None,))
            for variant in variants:
                intent=example(service,family,variant)
                f.verify_intent(intent)
                f.make_receipt(intent)
                options+=1
            count+=1
    if count != 25 or options != 29:
        raise f.VariantOriginError('PINNED_25_FAMILY_29_VARIANT_CASES_NOT_MET')
    return {'r59f':'PASS_PINNED_P7_V2_ORIGIN','families':count,
            'variant_cases':options,'catalogue_sha256':sha,
            'p8_operational':'NO-GO', 'physical_attempts':0}


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--catalogue-check',action='store_true')
    g.add_argument('--demo-no-start',action='store_true')
    g.add_argument('--verify',action='store_true')
    p.add_argument('--v2-root',type=Path)
    p.add_argument('--a5-root',type=Path)
    p.add_argument('--a6-root',type=Path)
    p.add_argument('--service',choices=list(d.SERVICES),default='FTP_DEV')
    p.add_argument('--family',default='FTP-T02')
    p.add_argument('--variant',default='DATA')
    args=p.parse_args()
    try:
        if args.catalogue_check:
            if any(v is not None for v in (args.v2_root,args.a5_root,args.a6_root)):
                raise f.VariantOriginError('CATALOGUE_READONLY_NO_ROOT_ARGUMENTS')
            out=all_families()
        else:
            if not all(isinstance(v,Path) for v in (args.v2_root,args.a5_root,args.a6_root)):
                raise f.VariantOriginError('THREE_PRIVATE_ROOTS_REQUIRED')
            variant=None if args.variant=='NONE' else args.variant
            intent=example(args.service,args.family,variant)
            if args.demo_no_start:
                receipt=f.make_receipt(intent)
                result=f.persist(args.v2_root,args.a5_root,args.a6_root,intent,receipt,b'')
                doc=f.verify_stored(args.v2_root,args.a5_root,args.a6_root,intent['attempt_id'])
                action=result['status']
            else:
                doc=f.verify_stored(args.v2_root,args.a5_root,args.a6_root,intent['attempt_id'])
                action='VERIFIED_REOPENED'
            if doc['intent']!=intent:
                raise f.VariantOriginError('DEMO_V2_INTENT_NOT_IDENTICAL')
            out={'r59f':'PASS_V2_ORIGIN_LEGACY_A5_A6_NO_START','mode':action,
                 'v2_report_sha256':doc['sha256'],
                 'legacy_candidate_sha256':doc['legacy_candidate_sha256'],
                 'bridge_sha256':doc['source_bridge_sha256'],
                 'family_id':doc['intent']['family_id'],
                 'variant':doc['intent']['variant'],
                 'variant_bound_at_origin':doc['variant_bound_at_origin'],
                 'a5_physical_start_accredited':False,
                 'a6_classification':doc['a6_classification'],
                 'p8_operational':doc['p8_operational'],
                 'host_mutations':0}
    except (ValueError,TypeError,KeyError,OSError,RuntimeError) as exc:
        print('R59F=BLOCKED:'+type(exc).__name__+':'+str(exc)[:150])
        print('R59F_A6=ND; P8=NO-GO')
        return 23
    print(json.dumps(out,sort_keys=True,ensure_ascii=True))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
