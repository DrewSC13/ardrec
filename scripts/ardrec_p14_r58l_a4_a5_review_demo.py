#!/usr/bin/env python3
"""R58-L: synthetic A4 rank -> A5 review -> conservative A6-A8, no execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))  # allow direct CLI imports from scripts
from ardrec.coordination.r58l_a4_a5_family_review import (
    build_a4_a5_review, verify_a4_a5_review,
)
from scripts.ardrec_p14_r58k_unified_family_demo import synthetic_unified_inputs


def synthetic_entries() -> list[dict]:
    return [{**e, 'applicable': True} for e in synthetic_unified_inputs()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58L=BLOCKED:EXPLICIT_OFFLINE_MODE_AND_REPO_REQUIRED', file=sys.stderr)
        print('R58L_P8=NO-GO', file=sys.stderr)
        return 23
    try:
        entries = synthetic_entries()
        preliminary = build_a4_a5_review(entries)
        selected = preliminary['a4_selected_identity']
        if selected is None:
            raise ValueError('SYNTHETIC_DEMO_HAS_NO_A4_WINNER')
        intent = {**selected, 'attempt_id':'ATT_R58L_DEMO_001',
                  'action':'SYNTHETIC_REVIEW_ONLY'}
        report = build_a4_a5_review(entries, attempt_intent=intent)
        verify_a4_a5_review(report)
        assert report['unit_count'] == 29 and report['covered_family_count'] == 25
        assert report['a5']['disposition'] == 'SYNTHETIC_INTENT_REVIEWED_NO_RESERVATION'
        assert report['a5']['actual_attempts_started'] == 0
        assert report['a6_classification'] == 'ND' and report['p8_operational'] == 'NO-GO'
        assert report['confirmed_final_risk'] is None and report['published_generation'] is None
        summary = {
            'schema': report['schema'], 'sha256': report['sha256'],
            'unit_count': report['unit_count'],
            'covered_family_count': report['covered_family_count'],
            'count_by_service': report['count_by_service'],
            'a4_selected_synthetic': report['a4_selected_identity'],
            'a4_eligible_count': report['a4']['eligible_count'],
            'a5_disposition': report['a5']['disposition'],
            'a5_actual_starts': report['a5']['actual_attempts_started'],
            'a6_classification': report['a6_classification'],
            'a8_recommendations': sorted({d['a8_recommendation']
                                           for d in report['decisions']}),
            'confirmed_final_risk': report['confirmed_final_risk'],
            'published_generation': report['published_generation'],
            'operational_dispatch': report['operational_dispatch'],
            'p8_operational': report['p8_operational'],
        }
        print(json.dumps(summary, sort_keys=True, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, TypeError, KeyError, OSError, AssertionError, RecursionError) as exc:
        print('R58L=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58L_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
