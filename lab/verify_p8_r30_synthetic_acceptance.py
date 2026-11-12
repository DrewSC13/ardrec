#!/usr/bin/env python3
"""Public source-only R30 verifier: derives 21 bounded synthetic acceptance vectors."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r30_synthetic_acceptance as r30
import p8_r29_typed_declaration as r29
import verify_p8_r29_typed_declaration as v29

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'lab/p8-r30-synthetic-acceptance-v1/spec.json'
SPEC_SHA = '7153e5aeb8bc95f24d03211be39c059de83e42126e70128e38581b637c457e7c'
MODEL_SHA = '8bca827a9cc0cdc6ae526c5eb991b8723d58c6fef4b987968c9b9f7b39ae5ec6'


def verify():
    r30.need(hashlib.sha256(SPEC.read_bytes()).hexdigest() == SPEC_SHA, 'spec_digest')
    r30.need(hashlib.sha256((ROOT / 'lab/p8_r30_synthetic_acceptance.py').read_bytes()).hexdigest() == MODEL_SHA, 'model_digest')
    r30.need(hashlib.sha256((ROOT / 'lab/p8_r29_typed_declaration.py').read_bytes()).hexdigest() ==
             '564a5dbedf60cd9d1d9ffb5186a08d09067089d1d034701d5e69cb7d40a921cc',
             'r29_model_pin')
    r30.need(v29.verify()['status'] == 'PASS_P8_R29_29_TYPED_SYMBOLIC_DESIGNS_DENY_ONLY', 'r29_upstream_verify')
    spec=json.loads(SPEC.read_bytes())
    r30.need(spec['r29_model_module_sha256'] == '564a5dbedf60cd9d1d9ffb5186a08d09067089d1d034701d5e69cb7d40a921cc'
             and spec['r29_spec_git_blob'] == '9f8c4c60a4fe9bc6f56e3f15756024c2ea95323c', 'r29_source_anchor')
    rows, _ = r29.verify_repository(ROOT)
    result=r30.build_catalog(rows,spec)
    summary=r30.summarize(result)
    r30.need(summary['profile_count'] == 21 and summary['write_variants'] == 4 and
             summary['material_bindings_unbound']==348 and summary['unverified_proof_gates']==261,
             'summary')
    for row in result:
        vector={'schema_version':'1.0', 'profile_id':row['profile_id'],
          'origin':r30.SYNTHETIC_ORIGIN,'observations':[
          {'support_id':s,'outcome':'PASS_SYNTHETIC'} for s in row['acceptance_supports']],
          'runtime_capability_asserted':False, 'case_authorization_asserted':False,
          'dispatch_asserted':False}
        assessment = r30.evaluate_synthetic(result, vector)
        r30.need(assessment['decision']=='DENY' and assessment['argv'] is None and
                 assessment['proof_gates_closed']==0 and assessment['dispatch_allowed'] is False,
                 'oracle_must_deny:' + row['profile_id'])
    return summary

if __name__ == '__main__':
    try:
        print(json.dumps(verify(),sort_keys=True))
        print('P8_R30_PUBLIC_VERIFY=PASS_21_SYNTHETIC_ONLY_DENY_ALL')
    except (r30.Rejected, ValueError, KeyError, TypeError, OSError) as exc:
        print('P8_R30_PUBLIC_VERIFY=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        raise SystemExit(1)
