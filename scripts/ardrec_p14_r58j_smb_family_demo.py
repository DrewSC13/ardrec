"""R58-J offline synthetic SMB family demonstration; never probes a service."""
from __future__ import annotations

import argparse
import json

from ardrec.evidence.r58j_smb_family_logic import (
    build_smb_simulation, load_pinned_smb_catalog, _requirements, verify_smb_simulation,
)


def synthetic_smb_cases(families: list[dict]) -> list[dict]:
    entries = []
    n = 0
    for family in families:
        fid = family['id']
        options = list(family['precedence_by_variant'])
        for variant in options:
            n += 1
            pc, supports, _, _, cleanup_required = _requirements(family, variant)
            entries.append({
                'family_id': fid,
                'derived_case_id': f'{fid}-S01-{n:02d}',
                'assessment_index': 0,
                'session_id': 'DEV_TUTOR_001',
                'phase': 'PENDIENTE',
                'variant': variant,
                'preconditions': {k: 'VERDADERO' for k in pc},
                'supports': {k: 'VERDADERO' for k in supports},
                'integrity': 'VERDADERO',
                'provenance': 'VERDADERO',
                'cleanup': 'VERDADERO' if cleanup_required else 'NO_APLICA',
                'outcome': ('INCONCLUSO' if n % 3 == 0 else
                            'OBSERVADO_NEGATIVO' if n % 3 == 1 else 'OBSERVADO_POSITIVO'),
            })
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description='ARDREC R58-J synthetic SMB rule demonstration')
    parser.add_argument('--synthetic-offline', action='store_true', required=True)
    args = parser.parse_args()
    if not args.synthetic_offline:
        return 2
    cases = synthetic_smb_cases(load_pinned_smb_catalog())
    result = build_smb_simulation(cases)
    verify_smb_simulation(result)
    assert result['unit_count'] == 11
    assert result['a6_classification'] == 'ND' and result['p8_operational'] == 'NO-GO'
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
