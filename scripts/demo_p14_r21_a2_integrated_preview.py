#!/usr/bin/env python3
"""R21: síntesis A1/A2, 54 unidades ficticias; no publicación ni P8."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.initialization.rule_preflight import FORMAT as RF, preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as IF, prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DF, prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CF, prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview


def main() -> int:
    ids = [f'{protocol}_{i:02d}' for protocol in ('SSH','FTP','SMB') for i in range(1,19)]
    rules = preflight_rule_configuration({'format':RF,'fields':{},'services':[
        {'id':sid,'initial_state':'PREPARADO','rules':[
            {'id':'GUARD','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}}]}
        for sid in ids]})
    initial = prepare_initial_preview(rules,{'format':IF,'rule_source_sha256':rules.sha256,
        'services':[{'id':sid,'initial_risk':'1/4','normalized_criticality':'1/2',
                     'cases':[{'id':'CHECK_A','max_repetitions':0},
                              {'id':'CHECK_B','max_repetitions':1}]}
                    for sid in ids]})
    deps = prepare_dependency_preview(rules,initial,{'format':DF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'services':[{'id':sid,'protocol':sid.split('_')[0],
                     'cases':[{'id':'CHECK_A','requires':[]},
                              {'id':'CHECK_B','requires':['CHECK_A']}]}
                    for sid in ids]})
    controls = prepare_control_preview(rules,initial,deps,{'format':CF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'dependency_snapshot_sha256':deps.sha256,
        'services':[{'id':sid,'controls':[
            {'id':'CONTROL_A','guard_rule_id':'GUARD','target_case_id':'CHECK_A',
             'precedence':20,'requires':[]},
            {'id':'CONTROL_B','guard_rule_id':'GUARD','target_case_id':'CHECK_B',
             'precedence':10,'requires':['CONTROL_A']}]} for sid in ids]})
    view = assemble_integrated_preview(rules,initial,deps,controls)
    assert view.verify(rules,initial,deps,controls)
    result = {
        'schema':'ardrec-p14-r21-a2-integrated-contract-preview-demo-v1',
        'scope':'SYNTHETIC_READ_ONLY_INTEGRATED_A2',
        'service_count':len(view.units),
        'protocol_counts':{p:sum(u.protocol==p for u in view.units) for p in ('SSH','FTP','SMB')},
        'case_count':sum(len(u.cases) for u in view.units),
        'control_count':sum(len(u.controls) for u in view.units),
        'initial_all_prepared':all(x.phase.value=='PREPARADO' for x in initial.units),
        'initial_all_evidence_zero':all(x.accumulated_evidence==0 for x in initial.units),
        'initial_all_rf_equals_r0':all(x.recalibrated_risk==x.initial_risk for x in initial.units),
        'first_case_order':list(view.units[0].case_order),
        'first_control_order':list(view.units[0].control_order),
        'rule_sha256':rules.sha256,
        'initial_sha256':initial.sha256,
        'dependencies_sha256':deps.sha256,
        'controls_sha256':controls.sha256,
        'integrated_sha256':view.sha256,
        'generation_published':view.published_generation is not None,
        'operational_dispatch':view.operational_dispatch_allowed,
        'controls_applied':False,
        'p8_operational':'NO-GO',
        'a1_full':False,'a2_full':False,'a3_full':False,
    }
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
