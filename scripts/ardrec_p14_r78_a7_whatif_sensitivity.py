#!/usr/bin/env python3
"""R78: 25-family counterfactual A7 envelope using the existing exact R58-D kernel.

This is a pedagogical mathematical *what-if*, NEVER evidence accreditation.
The authenticated R75/R76 inputs remain unchanged; R77 has no external trust pin.
No A5 execution, guest interaction, transition, A9 publication or operational action.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import os
from pathlib import Path
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))

from ardrec.analytics.exact_preview import canonical, digest, rational
from ardrec.analytics.r58d_interval_kernel import build_intervals, verify_intervals
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r77_signed_a5_a8_bridge as r77

SCHEMA = 'ardrec-p14-r78-a7-25-family-counterfactual-mathematical-v1'
SOURCE = 'SYNTHETIC_MATHEMATICAL_WHAT_IF_NOT_TECHNICAL_EVIDENCE'
POINTS = (('E_0', '0'), ('E_HALF', '1/2'), ('E_1', '1'))
MAX_REPORT_BYTES = 160_000

class R78Error(ValueError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise R78Error(code)


def key(row: dict[str, Any]) -> tuple[str, str, int]:
    return row['service_id'], row['case_id'], row['assessment_index']


def build(receipt_dir: Path, r76_doc: dict[str, Any]) -> dict[str, Any]:
    need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
         'NONROOT_CANONICAL_REPO_REQUIRED')
    need(type(r76_doc) is dict and r76.verify(r76_doc, receipt_dir),
         'AUTHENTICATED_R76_REQUIRED')
    r75_manifest = r75.verify(receipt_dir)
    need(r75_manifest['a6'] == 'ND' and r75_manifest['confirmed_rf'] is None,
         'R75_AUTHORITY_MISMATCH')
    original = r76_doc['conservative_bridge']
    need(original['unit_count'] == 25 and original['all_a6_nd'] is True and
         original['technical_truth_accredited'] is False and
         original['confirmed_final_risk'] is None and
         original['applied_state_transition'] is None and
         original['published_generation'] is None and
         original['p8_operational'] == 'NO-GO', 'R76_UNACCREDITED_BOUNDARY_REQUIRED')
    units = original['inputs']
    need(type(units) is list and len(units) == 25 and
         all(type(x) is dict and x['evidence'] == [] for x in units),
         'R76_INPUT_UNSAFE')
    weights = tuple(original['weights'])
    unresolved = original['a7']
    verify_intervals(unresolved)
    need(all(row['point_identified'] is False and
             row['confirmed_rf'] is None for row in unresolved['results']),
         'R76_UNRESOLVED_EXPECTED')
    unresolved_by_key = {key(x): x for x in unresolved['results']}
    need(len(unresolved_by_key) == 25, 'R76_CASE_DUPLICATION')
    generated: dict[str, dict[tuple[str, str, int], dict[str, Any]]] = {}
    scenario_heads: dict[str, str] = {}
    for label, value in POINTS:
        synthetic = [{**row, 'evidence': [{
            'evidence_id': 'E_R78_WHATIF_' + label,
            'kind': 'SYNTHETIC_FIXED', 'lower': value, 'upper': value,
        }]} for row in units]
        result = build_intervals(synthetic, weights=weights)
        verify_intervals(result)
        need(result['unit_count'] == 25 and
             result['technical_truth_accredited'] is False and
             result['confirmed_final_risk'] is None and
             result['published_generation'] is None and
             result['p8_operational'] == 'NO-GO',
             'R58D_SIMULATED_RESULT_ESCALATED')
        mapped = {key(x): x for x in result['results']}
        need(set(mapped) == set(unresolved_by_key) and
             all(x['point_identified'] is True and
                 x['rf_lower'] == x['rf_upper'] and
                 x['confirmed_rf'] is None for x in mapped.values()),
             'SYNTHETIC_POINT_RISK_INVALID')
        generated[label] = mapped
        scenario_heads[label] = result['sha256']
    candidate_keys = {(x['service_id'], x['a7_case_id'], 0)
                      for x in r76_doc['candidates']}
    need(candidate_keys == set(unresolved_by_key), 'R76_25_FAMILY_BINDING')
    cases = []
    for candidate in sorted(r76_doc['candidates'], key=lambda x:
                            (x['service_id'], x['a7_case_id'])):
        k = candidate['service_id'], candidate['a7_case_id'], 0
        bounds = unresolved_by_key[k]
        values = {label: generated[label][k]['rf_lower'] for label, _ in POINTS}
        lo, mid, hi = (rational(values[label]) for label, _ in POINTS)
        need(lo <= mid <= hi and
             bounds['rf_lower'] == values['E_0'] and
             bounds['rf_upper'] == values['E_1'],
             'R58D_INTERVAL_AND_SYNTHETIC_ENDPOINTS_DISAGREE')
        need(candidate['a6_classification'] == 'ND' and
             candidate['physical_start_accredited'] is False,
             'R76_CANDIDATE_FALSE_PROMOTION')
        cases.append({
            'service_id': k[0], 'case_id': k[1], 'assessment_index': 0,
            'family_id': candidate['family_id'],
            'r76_claim_source': candidate['claim_source'],
            'r76_declared_outcome': candidate['declared_outcome'],
            'a6': 'ND', 'technical_truth_accredited': False,
            'rf_unresolved_lower': bounds['rf_lower'],
            'rf_unresolved_upper': bounds['rf_upper'],
            'whatif_E_0_rf': values['E_0'],
            'whatif_E_half_rf': values['E_HALF'],
            'whatif_E_1_rf': values['E_1'],
            'whatif_point_is_technical_evidence': False,
            'a7_confirmed_rf': None,
            'a8_applied_transition': None,
        })
    need(len(cases) == 25 and len({x['family_id'] for x in cases}) == 25,
         'R78_FAMILY_COUNT')
    report: dict[str, Any] = {
        'schema': SCHEMA, 'source_kind': SOURCE,
        'r75_manifest_sha256': r76_doc['r75_manifest_sha256'],
        'r76_sha256': r76_doc['sha256'],
        'r77_external_pin_provided': False,
        'r77_technical_truth_accredited': False,
        'r58d_unresolved_sha256': unresolved['sha256'],
        'r58d_synthetic_scenario_sha256': scenario_heads,
        'counterfactual_evidence_levels': ['0','1/2','1'],
        'scenario_evidence_source': 'SYNTHETIC_FIXED_MATHEMATICAL_ONLY',
        'family_count': 25,
        'service_family_counts': r76_doc['service_family_counts'],
        'cases': cases,
        'a6_classification': 'ND',
        'a7_confirmed_rf': None,
        'a8_applied_transitions': 0,
        'a9_new_generations': 0,
        'physical_executions': 0,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    need(len(canonical(report)) < MAX_REPORT_BYTES, 'REPORT_TOO_LARGE')
    report['sha256'] = digest(report)
    return report


def verify(report: dict[str, Any], receipt_dir: Path,
           r76_doc: dict[str, Any]) -> bool:
    expected = build(receipt_dir, r76_doc)
    need(type(report) is dict and canonical(report) == canonical(expected),
         'COUNTERFACTUAL_REPORT_NOT_REPRODUCIBLE')
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt-dir', type=Path, required=True)
    ap.add_argument('--r76-report', type=Path, required=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--json', action='store_true')
    mode.add_argument('--texto', action='store_true')
    mode.add_argument('--verify-json', type=Path)
    opt = ap.parse_args(argv)
    try:
        source = r77.read_canonical(opt.r76_report)
        if opt.verify_json:
            target = r77.read_canonical(opt.verify_json)
            verify(target, opt.receipt_dir, source)
            print('R78=PASS_VERIFIED_NO_EXECUTION')
            print('R78_SHA256=' + target['sha256'])
        else:
            result = build(opt.receipt_dir, source)
            if opt.json:
                sys.stdout.buffer.write(canonical(result) + b'\n')
            else:
                print('R78=PASS_EXACT_MATHEMATICAL_WHAT_IF')
                print('R78_CASES=25_FAMILIES')
                print('R78_HYPOTHETICAL_LEVELS=0,1/2,1')
                print('R78_INTERVAL_CONSISTENCY=25_OF_25_PASS')
                for x in result['cases'][:3]:
                    print('R78_SAMPLE=' + x['family_id'] +
                          ':unresolved=[' + x['rf_unresolved_lower'] + ',' +
                          x['rf_unresolved_upper'] + '];E0=' + x['whatif_E_0_rf'] +
                          ';Ehalf=' + x['whatif_E_half_rf'] + ';E1=' + x['whatif_E_1_rf'])
                print('R78_SHA256=' + result['sha256'])
        print('R78_A6=ND', file=sys.stderr)
        print('R78_RF_CONFIRMED=NULL', file=sys.stderr)
        print('R78_PHYSICAL_EXECUTIONS=0', file=sys.stderr)
        print('R78_P8=NO-GO', file=sys.stderr)
    except (R78Error, ValueError, OSError, TypeError, KeyError, RuntimeError) as exc:
        print('R78=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:160], file=sys.stderr)
        print('R78_P8=NO-GO', file=sys.stderr)
        return 23
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
