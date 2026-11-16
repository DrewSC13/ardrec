#!/usr/bin/env python3
"""R58-K 29-case synthetic SSH/FTP/SMB A6->A7->A8 demonstration; no VM I/O."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))
from ardrec.coordination.r58k_unified_family_bridge import (
    build_unified_preview, verify_unified_preview,
)
from ardrec.evidence.r58h_ssh_family_logic import load_pinned_catalog
from ardrec.evidence.r58i_ftp_family_logic import load_pinned_ftp_catalog
from ardrec.evidence.r58j_smb_family_logic import load_pinned_smb_catalog
from ardrec_p14_r58h_ssh_family_demo import synthetic_ssh_cases
from ardrec_p14_r58i_ftp_family_demo import synthetic_ftp_cases
from ardrec_p14_r58j_smb_family_demo import synthetic_smb_cases


def synthetic_unified_inputs() -> list[dict]:
    datasets = (
        ('SSH_DEV', synthetic_ssh_cases(load_pinned_catalog())),
        ('FTP_DEV', synthetic_ftp_cases(load_pinned_ftp_catalog())),
        ('SMB_DEV', synthetic_smb_cases(load_pinned_smb_catalog())),
    )
    risk = {'initial_risk': '1/4',
            'normalized_criticality': '1/2',
            'replacement_risk': '1/4'}
    return [{'service_id': service, 'unit': unit, 'risk': dict(risk)}
            for service, units in datasets for unit in units]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58K=BLOCKED:EXPLICIT_SYNTHETIC_MODE_AND_REPO_REQUIRED', file=sys.stderr)
        print('R58K_P8=NO-GO', file=sys.stderr)
        return 23
    try:
        report = build_unified_preview(synthetic_unified_inputs())
        verify_unified_preview(report)
        if (report['unit_count'] != 29 or report['covered_family_count_in_batch'] != 25 or
                report['count_by_service'] != {'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11} or
                report['a6_classification'] != 'ND' or
                report['p8_operational'] != 'NO-GO' or
                report['confirmed_final_risk'] is not None or
                report['published_generation'] is not None):
            raise ValueError('DEMO_ASSERTION_FAILED')
        concise = {
            'schema': report['schema'], 'sha256': report['sha256'],
            'catalog_sha256': report['source_catalog_sha256'],
            'source_kind': report['source_kind'],
            'unit_count': report['unit_count'],
            'covered_family_count': report['covered_family_count_in_batch'],
            'count_by_service': report['count_by_service'],
            'hypothetical_class_counts': report['hypothetical_class_counts'],
            'a6_classification': report['a6_classification'],
            'confirmed_final_risk': report['confirmed_final_risk'],
            'published_generation': report['published_generation'],
            'a8_applied_transition': report['applied_state_transition'],
            'technical_truth_accredited': report['technical_truth_accredited'],
            'p8_operational': report['p8_operational'],
            'a6_a7_a8_bridge_sha256': report['a6_a7_a8_bridge']['sha256'],
            'decisions': [{'service_id': d['service_id'],
                           'derived_case_id': d['derived_case_id'],
                           'variant': d['variant'],
                           'hypothetical_result_class': d['hypothetical_result_class'],
                           'a6_classification': d['a6_classification'],
                           'a7_rf_lower': d['a7_rf_lower'],
                           'a7_rf_upper': d['a7_rf_upper'],
                           'a8_recommendation': d['a8_recommendation']}
                          for d in report['decisions']],
        }
        print(json.dumps(concise, sort_keys=True, indent=2))
        return 0
    except (ValueError, TypeError, OSError, KeyError, RecursionError) as exc:
        print('R58K=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58K_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
