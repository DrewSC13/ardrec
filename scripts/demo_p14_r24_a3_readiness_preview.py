#!/usr/bin/env python3
"""R24: 54 escenarios hipotéticos, ningún control ni caso realmente ejecutado."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.scheduling.agenda_preview import plan_candidate_order
from ardrec.scheduling.readiness_preview import FORMAT, preview_hypothetical_readiness
from demo_p14_r23_a3_candidate_order import sample


def example(n: int = 54):
    sources = sample(n)
    candidates = plan_candidate_order(*sources)
    assumptions = []
    for unit in sources[4].units:
        number = int(unit.service_id.rsplit('_', 1)[1])
        group = number % 3
        # Nueve de los 18 servicios con guarda verdadera simulan A cumplido.
        assumed = group == 1 and number in (1, 4, 7)
        assumptions.append({
            'id': unit.service_id,
            'cases': [
                {'id': 'CHECK_A', 'assumed': 'VERDADERO' if assumed else 'ND'},
                {'id': 'CHECK_B', 'assumed': 'ND'},
            ],
            'controls': [
                {'id': 'CONTROL_A', 'assumed': 'VERDADERO' if assumed else 'ND'},
                {'id': 'CONTROL_B', 'assumed': 'ND'},
            ],
        })
    scenario = {'format': FORMAT, 'candidate_sha256': candidates.sha256,
                'services': assumptions}
    return sources, candidates, scenario


def main() -> int:
    sources, candidates, scenario = example()
    result = preview_hypothetical_readiness(*sources, candidates, scenario)
    assert result.verify(*sources, candidates, scenario)
    counts = {state: sum(r.state == state for u in result.units for r in u.controls)
              for state in ('LISTO_CONDICIONAL', 'BLOQUEADO', 'OMITIDO_SUPUESTO')}
    assert counts == {'LISTO_CONDICIONAL': 18, 'BLOQUEADO': 9, 'OMITIDO_SUPUESTO': 9}
    out = {
        'schema': 'ardrec-p14-r24-a3-readiness-demo-v1',
        'scope': 'HYPOTHETICAL_READ_ONLY_NO_AUTHORITY',
        'service_count': len(result.units),
        'protocol_counts': {p: sum(u.protocol == p for u in result.units)
                            for p in ('SSH', 'FTP', 'SMB')},
        'base_candidate_count': sum(len(u.candidates) for u in candidates.units),
        'inherited_excluded_count': sum(len(u.inherited_exclusions) for u in result.units),
        'hypothetical_state_counts': counts,
        'all_unexecutable': all(not c.executable for u in result.units for c in u.controls),
        'all_authority_blocked': all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c.reasons
                                     for u in result.units for c in u.controls),
        'candidate_sha256': candidates.sha256,
        'scenario_sha256': result.scenario_sha256,
        'readiness_sha256': result.sha256,
        'executable_agenda': result.executable_agenda,
        'operational_dispatch': result.operational_dispatch_allowed,
        'generation_published': result.published_generation is not None,
        'assumptions_are_evidence': False,
        'controls_applied': False,
        'p8_operational': 'NO-GO',
        'a1_full': False, 'a2_full': False, 'a3_full': False,
    }
    print(json.dumps(out, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
