#!/usr/bin/env python3
"""R22: diagnóstico A3 sintético trivalente de 54 servicios, sin despacho."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.state import Truth
from ardrec.initialization.rule_preflight import FORMAT as RF,preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as IF,prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DF,prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CF,prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards


def main() -> int:
    ids=[f'{p}_{i:02d}' for p in ('SSH','FTP','SMB') for i in range(1,19)]
    rules=preflight_rule_configuration({'format':RF,'fields':{'FACT':'LOGICO'},
        'services':[{'id':sid,'initial_state':'PREPARADO',
            'rules':[{'id':'ALLOW','condicion':{'op':'CAMPO','nombre':'FACT'}},
                     {'id':'NEVER','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'FALSO'}}]}
            for sid in ids]})
    initial=prepare_initial_preview(rules,{'format':IF,'rule_source_sha256':rules.sha256,
        'services':[{'id':sid,'initial_risk':'1/4','normalized_criticality':'1/2',
             'cases':[{'id':'CHECK_A','max_repetitions':0},
                      {'id':'CHECK_B','max_repetitions':1}]} for sid in ids]})
    deps=prepare_dependency_preview(rules,initial,{'format':DF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'services':[{'id':sid,'protocol':sid.split('_')[0],
             'cases':[{'id':'CHECK_A','requires':[]},
                      {'id':'CHECK_B','requires':['CHECK_A']}]} for sid in ids]})
    controls=prepare_control_preview(rules,initial,deps,{'format':CF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'dependency_snapshot_sha256':deps.sha256,
        'services':[{'id':sid,'controls':[
            {'id':'CONTROL_A','guard_rule_id':'ALLOW','target_case_id':'CHECK_A',
             'precedence':20,'requires':[]},
            {'id':'CONTROL_B','guard_rule_id':'ALLOW','target_case_id':'CHECK_B',
             'precedence':10,'requires':['CONTROL_A']}]} for sid in ids]})
    integrated=assemble_integrated_preview(rules,initial,deps,controls)
    environment={}
    for sid in ids:
        case=int(sid.rsplit('_',1)[1])%3
        environment[sid]={} if case==0 else {
            'FACT':Truth.VERDADERO if case==1 else Truth.FALSO}
    view=diagnose_guards(rules,initial,deps,controls,integrated,environment)
    assert view.verify(rules,initial,deps,controls,integrated,environment)
    counts={t.name:sum(u.table_status is t for u in view.units) for t in Truth}
    assert counts=={'VERDADERO':18,'FALSO':18,'ND':18}
    result={
        'schema':'ardrec-p14-r22-a3-guard-diagnostic-demo-v1',
        'scope':'SYNTHETIC_TRIVALENT_DIAGNOSTICS_ONLY',
        'service_count':len(view.units),
        'protocol_counts':{p:sum(u.protocol==p for u in view.units)
                           for p in ('SSH','FTP','SMB')},
        'case_count':sum(len(u.cases) for u in view.units),
        'control_count':sum(len(u.controls) for u in view.units),
        'trivalent_table_counts':counts,
        'all_controls_unapproved':all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c.blockers
                                     for u in view.units for c in u.controls),
        'all_initial_prepared':all(x.phase.value=='PREPARADO' for x in initial.units),
        'all_initial_evidence_zero':all(x.accumulated_evidence==0 for x in initial.units),
        'integrated_sha256':integrated.sha256,
        'guard_diagnostic_sha256':view.sha256,
        'executable_agenda':view.executable_agenda,
        'generation_published':view.published_generation is not None,
        'operational_dispatch':view.operational_dispatch_allowed,
        'p8_operational':'NO-GO',
        'a1_full':False,'a2_full':False,'a3_full':False,
    }
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
