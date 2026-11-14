#!/usr/bin/env python3
"""R25: 54 servicios ficticios, soportes de declaración sintética no acreditada."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.scheduling.observation_preview import (
    FORMAT, DOCUMENT_FORMAT, reconcile_documentary_observations)
from ardrec.scheduling.readiness_preview import preview_hypothetical_readiness
from demo_p14_r24_a3_readiness_preview import example


def _raw(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True).encode('ascii')


def sample(n: int = 54):
    sources, candidates, scenario = example(n)
    readiness = preview_hypothetical_readiness(*sources, candidates, scenario)
    services = []
    blobs: dict[str, bytes] = {}
    for s in scenario['services']:
        sid = s['id']
        number = int(sid.rsplit('_',1)[1])
        guard_true = number % 3 == 1
        scenario_true = guard_true and number in (1,4,7)
        rows = {}
        for category, key in (('case','cases'),('control','controls')):
            records=[]
            for item in s[key]:
                name=item['id']
                state='ND'
                if scenario_true and name in ('CHECK_A','CONTROL_A'):
                    state='VERDADERO'
                elif guard_true and name=='CHECK_B':
                    state='FALSO'
                ref=None;digest=None
                if state!='ND':
                    ref='SYN_'+sid+'_'+name
                    body=_raw({'format':DOCUMENT_FORMAT,
                               'source':'SYNTHETIC_DECLARATION_ONLY',
                               'service_id':sid,'category':category,
                               'item_id':name,'declaration':state})
                    blobs[ref]=body
                    digest=hashlib.sha256(body).hexdigest()
                records.append({'id':name,'declared':state,
                                'support_reference':ref,'support_sha256':digest})
            rows[key]=records
        services.append({'id':sid,**rows})
    batch={'format':FORMAT,'candidate_sha256':candidates.sha256,
           'readiness_sha256':readiness.sha256,'services':services}
    return sources, candidates, scenario, readiness, batch, blobs


def main() -> int:
    sources,candidates,scenario,readiness,batch,blobs=sample()
    view = reconcile_documentary_observations(*sources, candidates, scenario,
                                              readiness, batch, blobs)
    assert view.verify(*sources, candidates, scenario, readiness, batch, blobs)
    counts={c:sum(x.comparison==c for u in view.units for x in u.items)
            for c in ('SIN_DECLARACION','COINCIDE_SUPUESTO','DIFIERE_SUPUESTO')}
    assert counts=={'SIN_DECLARACION':180,'COINCIDE_SUPUESTO':18,'DIFIERE_SUPUESTO':18}
    output={
        'schema':'ardrec-p14-r25-a3-documentary-demo-v1',
        'scope':'SYNTHETIC_DOCUMENT_INTEGRITY_ONLY_NO_FACT_AUTHORITY',
        'service_count':len(view.units),
        'protocol_counts':{p:sum(u.protocol==p for u in view.units)
                           for p in ('SSH','FTP','SMB')},
        'observation_count':sum(len(u.items) for u in view.units),
        'support_count':len(blobs), 'comparison_counts':counts,
        'candidate_sha256':candidates.sha256,
        'readiness_sha256':readiness.sha256,
        'batch_sha256':view.batch_sha256,
        'documentary_sha256':view.sha256,
        'support_integrity_verified':True,
        'technical_truth_accredited':False,
        'external_custody_verified':False,
        'all_unexecutable':all(not x.executable and not x.accredited
                               for u in view.units for x in u.items),
        'generation_published':view.published_generation is not None,
        'executable_agenda':view.executable_agenda,
        'operational_dispatch':view.operational_dispatch_allowed,
        'p8_operational':'NO-GO', 'a1_full':False,'a2_full':False,'a3_full':False,
    }
    print(json.dumps(output,sort_keys=True,separators=(',',':')))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
