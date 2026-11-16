#!/usr/bin/env python3
"""R58-P: verify 29 REAL R17-R22 synthetic case diagnostics, never run A5/P8."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))

from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58p_a3_family_controls import (
    build_family_a3_projection, verify_family_a3_projection,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58P=BLOCKED:OFFLINE_AND_REPOSITORY_ROOT_REQUIRED', file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO / 'lab/p14-r26-session-v1/scenario.json')
        review = build_a4_a5_review(synthetic_entries())  # no A5 intent or execution
        report = build_family_a3_projection(scenario, review)
        verify_family_a3_projection(report, scenario, review)
        assert report['control_reference_count'] == 29
        assert report['family_count'] == 25
        assert report['a3_typed_case_references_constructed'] is True
        assert report['a3_case_guard_is_operational_authority'] is False
        assert report['a1_a3_to_family_case_authority_attested'] is False
        assert report['p8_operational'] == 'NO-GO'
        summary = {
            'schema': report['schema'],
            'sha256': report['sha256'],
            'control_reference_count': report['control_reference_count'],
            'family_count': report['family_count'],
            'case_count_by_service': report['case_count_by_service'],
            'a3_guard_truth_counts': report['a3_guard_truth_counts'],
            'a3_a4_guard_mismatch_count': report['a3_a4_guard_mismatch_count'],
            'a3_typed_case_references_constructed': report['a3_typed_case_references_constructed'],
            'a3_case_guard_is_operational_authority': report['a3_case_guard_is_operational_authority'],
            'a1_a3_to_family_case_authority_attested': report['a1_a3_to_family_case_authority_attested'],
            'a1_a10_implementation_complete': report['a1_a10_implementation_complete'],
            'a6_classification': report['a6_classification'],
            'confirmed_final_risk': report['confirmed_final_risk'],
            'published_generation': report['published_generation'],
            'operational_dispatch': report['operational_dispatch'],
            'p8_operational': report['p8_operational'],
        }
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, OSError, AssertionError,
            RuntimeError, RecursionError) as exc:
        print('R58P=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58P_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
