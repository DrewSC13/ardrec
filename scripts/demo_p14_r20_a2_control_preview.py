#!/usr/bin/env python3
"""R20: 54 unidades y controles simbólicos; no concede permiso P8."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.initialization.rule_preflight import FORMAT as RF,preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as IF,prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DF,prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CF,prepare_control_preview


def main() -> int:
    names=[f'{p}_{i:02d}' for p in ('SSH','FTP','SMB') for i in range(1,19)]
    rules=preflight_rule_configuration({'format':RF,'fields':{},'services':[
        {'id':sid,'initial_state':'PREPARADO','rules':[
            {'id':'GUARD','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}}
        ]} for sid in names]})
    initial=prepare_initial_preview(rules,{'format':IF,
        'rule_source_sha256':rules.sha256,'services':[
            {'id':sid,'initial_risk':'1/4','normalized_criticality':'1/2',
             'cases':[{'id':'CHECK_A','max_repetitions':0},
                      {'id':'CHECK_B','max_repetitions':1}]} for sid in names]})
    deps=prepare_dependency_preview(rules,initial,{'format':DF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'services':[{'id':sid,'protocol':sid.split('_')[0],
             'cases':[{'id':'CHECK_A','requires':[]},
                      {'id':'CHECK_B','requires':['CHECK_A']}]} for sid in names]})
    controls=prepare_control_preview(rules,initial,deps,{'format':CF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'dependency_snapshot_sha256':deps.sha256,
        'services':[{'id':sid,'controls':[
            {'id':'CONTROL_A','guard_rule_id':'GUARD','target_case_id':'CHECK_A',
             'precedence':20,'requires':[]},
            {'id':'CONTROL_B','guard_rule_id':'GUARD','target_case_id':'CHECK_B',
             'precedence':10,'requires':['CONTROL_A']}
        ]} for sid in names]})
    assert controls.verify(rules,initial,deps)
    assert len(controls.units)==54
    assert all(u.topological_order==('CONTROL_A','CONTROL_B') for u in controls.units)
    out={
        'schema':'ardrec-p14-r20-a2-control-preview-demo-v1',
        'scope':'SYNTHETIC_CONTROL_REFERENCES_ONLY',
        'unit_count':len(controls.units),
        'protocol_counts':{p:sum(1 for u in deps.units if u.protocol==p)
                           for p in ('SSH','FTP','SMB')},
        'control_count':sum(len(u.controls) for u in controls.units),
        'first_control_order':list(controls.units[0].topological_order),
        'rules_sha256':rules.sha256,
        'initial_sha256':initial.sha256,
        'dependencies_sha256':deps.sha256,
        'controls_sha256':controls.sha256,
        'all_prepared':all(u.phase.value=='PREPARADO' for u in initial.units),
        'all_initial_evidence_zero':all(u.accumulated_evidence==0 for u in initial.units),
        'all_initial_risk_unchanged':all(u.initial_risk==u.recalibrated_risk for u in initial.units),
        'generation_published':False,
        'controls_applied':False,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'a1_full':False,'a2_full':False,'a3_full':False,
    }
    print(json.dumps(out,sort_keys=True,separators=(',',':')))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
