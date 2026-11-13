#!/usr/bin/env python3
"""R18: demostrar inicialización sintética vinculada a reglas, sin despacho P8."""
from __future__ import annotations

import json
from pathlib import Path
import sys

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
from ardrec.initialization.rule_preflight import FORMAT as R17_FORMAT, preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT, prepare_initial_preview
from ardrec.state import Truth


def main()->int:
    rule_config={'format':R17_FORMAT, 'fields': {'permiso':'LOGICO'},
       'services':[{'id':'SSH_LAB','initial_state':'PREPARADO',
                    'rules':[{'id':'R1','condicion':{'op':'CAMPO','nombre':'permiso'}}]},
                   {'id':'SMB_LAB','initial_state':'PREPARADO',
                    'rules':[{'id':'R2','condicion':{'op':'CONSTANTE','tipo':'LOGICO',
                                                  'valor':'VERDADERO'}}]}]}
    rules=preflight_rule_configuration(rule_config)
    initial={'format':FORMAT,'rule_source_sha256':rules.sha256,
             'services':[{'id':'SSH_LAB','initial_risk':'1/4',
                          'normalized_criticality':'1/2',
                          'cases':[{'id':'CHECK1','max_repetitions':0},
                                   {'id':'CHECK2','max_repetitions':1}]},
                         {'id':'SMB_LAB','initial_risk':'3/4',
                          'normalized_criticality':'1/4',
                          'cases':[{'id':'CHECK3','max_repetitions':0}]}]}
    view=prepare_initial_preview(rules,initial)
    assert view.verify(rules)
    cases=[]
    for name,env in [('ND',{}),('FALSO',{'permiso':Truth.FALSO}),
                     ('VERDADERO',{'permiso':Truth.VERDADERO})]:
        seen=view.evaluate_guard(rules,'SSH_LAB',env)
        cases.append({'expected':name,'observed':seen.status.value,
                      'logical_guard_satisfied':seen.logical_guard_satisfied,
                      'operationally_authorized':seen.operationally_authorized})
    result={'schema':'ardrec-p14-r18-a2-initial-preview-demo-v1',
            'scope':'SYNTHETIC_INITIAL_STATE_ONLY',
            'rule_source_sha256':view.rule_source_sha256,
            'initial_snapshot_sha256':view.sha256,
            'units':[{'id':u.id,'phase':u.phase.value,
                      'initial_risk':str(u.initial_risk),
                      'recalibrated_risk':str(u.recalibrated_risk),
                      'accumulated_evidence':str(u.accumulated_evidence),
                      'normalized_criticality':str(u.normalized_criticality),
                      'priority':u.priority,
                      'case_attempt_limits':{c.id:c.permitted_attempts_ceiling for c in u.cases},
                      'case_start_counts':{c.id:c.starts_confirmed for c in u.cases}}
                     for u in view.units],
            'guard_cases':cases,'generation_published':False,
            'p8_operational':'NO-GO','operational_dispatch':False,
            'a1_full':False,'a2_full':False}
    assert not view.operational_dispatch_allowed and view.published_generation is None
    print(json.dumps(result,sort_keys=True,ensure_ascii=True,separators=(',',':')))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
