#!/usr/bin/env python3
"""P8-R16-R6 CI: verify frozen SSH synthetic model against R15, fail-closed.

This does NOT verify an actual SSH client's effective configuration, provide a
trusted operational receipt, approve any CLI option, render argv, or dispatch.
The private R4/R5 evidence is deliberately absent from the repository.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r16_ssh_precedence as model
import verify_p8_cli_review_gates as r15

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'lab/p8-r16-ssh-precedence-v1/cases.json'
R15_SOURCE=ROOT/'lab/p8-cli-review-gates-v1/gates.json'
R15_SHA='90fe31e92366493e97818e2c706c142f91a47eff84446413374fa421169ca716'
R5_SOURCE_SHA='530cc38146f5bbbb2a1a7f996c1f34c885e1e031fcf48520e1ace8e75bf8d343'
R5_PRIVATE_RECEIPT_SHA='54e73fb46fd834d947de5deb8663910f049d0140251c10d70c633061e4741844'

class VerificationError(ValueError):pass

def need(v,why):
    if not v:raise VerificationError('P8_R16_R6_FAIL_CLOSED:'+why)

def verify(root=ROOT,check_r15=True):
    root=Path(root)
    raw= (root/'lab/p8-r16-ssh-precedence-v1/cases.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest()==model.RULES_SHA,'r5_fixture_sha')
    fixture=model.read_json(raw)
    model.validate_fixture(fixture)
    need(hashlib.sha256((root/'lab/p8-cli-review-gates-v1/gates.json').read_bytes()).hexdigest()==R15_SHA,'r15_matrix_sha')
    if check_r15:
        need(root.resolve()==ROOT.resolve(),'r15_root')
        outcome=r15.verify_repository()
        need(outcome['status']=='PASS_P8_R15_29_PROFILES_25_RISKS_238_LINKS_DENY_ALL','r15_chain')
    results=model.test_oracles(fixture)
    need(len(results)==10,'case_count')
    for result in results:
        need(result['status']=='BLOCKED_MODEL_ONLY' and
             result['configuration_effective_verified'] is False and
             result['dispatch_allowed'] is False and result['runnable_argv'] is None and
             'AUTHENTICATED_EFFECTIVE_CONFIG_FROM_PINNED_GUEST_BINARY' in result['missing_operational_proofs'],
             'semantic_promotion')
    model.deny(fixture,'fixture')
    return {'status':'PASS_P8_R16_R6_10_SYNTHETIC_ORACLES_DENY_ONLY',
            'model_source':'R5_PREVIOUSLY_VERIFIED_EXTERNAL_PROVENANCE',
            'private_r4_r5_rechecked_in_ci':False,
            'r5_private_receipt_sha256_declared_only':R5_PRIVATE_RECEIPT_SHA,
            'r5_model_source_sha256_declared_only':R5_SOURCE_SHA,
            'synthetic_cases':len(results),'complete_semantic_reviews':0,
            'approved_cli_options':0,'dispatch_allowed':False,
            'real_effective_config_verified':False,
            'algorithms_started':False,'vm_contact':False,'ssh_executed':False}

def main():
    try:
        print(json.dumps(verify(),sort_keys=True))
    except (VerificationError,model.ModelError,r15.ReviewGateError,
            OSError,UnicodeError,ValueError,KeyError,TypeError) as exc:
        print('P8_R16_R6=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
