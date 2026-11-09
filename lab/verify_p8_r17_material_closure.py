#!/usr/bin/env python3
"""P8-R17: 29-profile material gap gate; never authorizes dispatch."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys
import p8_r17_material_closure as m

ROOT=Path(__file__).resolve().parents[1]
SPEC='lab/p8-r17-material-closure-v1/spec.json'
SPEC_SHA='45a7ff0dc66329466b8664ecb0abb90974c4d6c8fbdf541b86082c756da3e14a'

def verify(root=ROOT,deep=True):
    root=Path(root)
    if deep:
        import verify_p8_profile_contracts as r10
        import verify_p8_cli_review_gates as r15
        # Full inherited checks against P6/P7/R9/R10/R13/R14/R15.
        a=r10.verify_repository(root)
        b=r15.verify_repository(root)
        m.need(a['status']=='PASS_P8_R10_29_STRUCTURED_INTENTS_DENY_ALL', 'r10_chain')
        m.need(b['status']=='PASS_P8_R15_29_PROFILES_25_RISKS_238_LINKS_DENY_ALL','r15_chain')
    src=(root/SPEC).read_bytes()
    m.need(hashlib.sha256(src).hexdigest()==SPEC_SHA,'frozen_spec_sha')
    spec=m.decode(src)
    m.need(type(spec) is dict and set(spec)=={
        'schema_version','scope','base_main_commit','source_sha256',
        'profile_ids','binding_fields','write_profile_ids','expected'},'spec_fields')
    m.need(spec['schema_version']=='1.0' and spec['scope']=='P8_R17_MATERIAL_CLOSURE_AUDIT_ONLY'
         and spec['base_main_commit']==m.BASE and spec['source_sha256']==m.PINS
         and spec['binding_fields']==list(m.BINDING_FIELDS)
         and set(spec['write_profile_ids'])==m.WRITER_IDS, 'spec_identity')
    result=m.verify_repository(root)
    m.need([row['profile_id'] for row in result['profiles']]==spec['profile_ids'],'profile_registry')
    for k,expected in spec['expected'].items():
        # Alias only in the frozen spec; no authorizing fields.
        key={'authorized_profiles':'approved_profiles','profiles':'profiles_reviewed'}.get(k,k)
        m.need(result[key]==expected,'expected_count:'+k)
    return result

def main():
    try:
        r=verify()
        print(json.dumps({k:v for k,v in r.items() if k!='profiles'},sort_keys=True))
        print('RESULT=PASS_29_PROFILES_348_BINDINGS_PENDING_NO_DISPATCH')
    except (m.MaterialError,ValueError,OSError,TypeError,KeyError) as exc:
        print('RESULT=FAIL_CLOSED:'+str(exc),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
