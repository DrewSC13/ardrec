#!/usr/bin/env python3
"""R19: 54 servicios sintéticos, grafo local, sin comandos ni autoridad P8."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.initialization.rule_preflight import FORMAT as RULE_FORMAT,preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as INITIAL_FORMAT,prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT,prepare_dependency_preview


def main() -> int:
    names=[f'{p}_{i:02d}' for p in ('SSH','FTP','SMB') for i in range(1,19)]
    rule_cfg={'format':RULE_FORMAT,'fields':{},'services':[
        {'id':sid,'initial_state':'PREPARADO','rules':[
            {'id':'RULE','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}}]}
        for sid in names]}
    rules=preflight_rule_configuration(rule_cfg)
    initial=prepare_initial_preview(rules,{'format':INITIAL_FORMAT,
        'rule_source_sha256':rules.sha256,'services':[
            {'id':sid,'initial_risk':'1/4','normalized_criticality':'1/2',
             'cases':[{'id':'CHECK_A','max_repetitions':0},
                      {'id':'CHECK_B','max_repetitions':1}]} for sid in names]})
    deps=prepare_dependency_preview(rules,initial,{
        'format':FORMAT,'rule_source_sha256':rules.sha256,
        'initial_snapshot_sha256':initial.sha256,'services':[
            {'id':sid,'protocol':sid.split('_')[0],
             'cases':[{'id':'CHECK_A','requires':[]},
                      {'id':'CHECK_B','requires':['CHECK_A']}]} for sid in names]})
    assert deps.verify(rules,initial)
    result={'schema':'ardrec-p14-r19-a2-dependency-preview-demo-v1',
        'scope':'SYNTHETIC_REFERENCE_ONLY',
        'count':len(deps.units),'protocol_counts':{
            p:sum(u.protocol==p for u in deps.units) for p in ('SSH','FTP','SMB')},
        'rule_source_sha256':rules.sha256,
        'initial_snapshot_sha256':initial.sha256,
        'dependency_snapshot_sha256':deps.sha256,
        'ordered_cases_per_unit':2,
        'first_case_order':list(deps.units[0].topological_order),
        'all_services_prepared':all(u.phase.value=='PREPARADO' for u in initial.units),
        'all_initial_evidence_zero':all(u.accumulated_evidence==0 for u in initial.units),
        'all_initial_risk_unchanged':all(u.initial_risk==u.recalibrated_risk for u in initial.units),
        'operational_dispatch':False,'p8_operational':'NO-GO',
        'a1_full':False,'a2_full':False,'generation_published':False}
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
