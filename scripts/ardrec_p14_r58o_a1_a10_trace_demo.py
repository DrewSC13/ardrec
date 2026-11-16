#!/usr/bin/env python3
"""R58-O offline 10-stage audit. Only a temporary benign ACCEPTED journal is created."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))

from ardrec.benign_pipeline import BenignPipeline
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58n_durable_case_binding import persist_binding
from ardrec.coordination.r58o_a1_a10_cross_contract_trace import (
    build_cross_contract_trace, verify_cross_contract_trace,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58O=BLOCKED:EXPLICIT_SYNTHETIC_MODE_AND_REPO_REQUIRED', file=sys.stderr)
        print('R58O_P8=NO-GO', file=sys.stderr)
        return 23
    try:
        scenario = read_fixed_scenario(REPO / 'lab/p14-r26-session-v1/scenario.json')
        entries = synthetic_entries()
        preview = build_a4_a5_review(entries)
        selected = preview['a4_selected_identity']
        if selected is None:
            raise ValueError('NO_SYNTHETIC_A4_WINNER')
        rid = 'ATT_R58O_DEMO_001'
        review = build_a4_a5_review(entries, attempt_intent={
            **selected, 'attempt_id': rid, 'action': 'SYNTHETIC_REVIEW_ONLY',
        })
        with tempfile.TemporaryDirectory(prefix='ardrec-r58o-offline-') as td:
            root = Path(td)
            journal_root = root / 'journal'
            receipt_root = root / 'receipts'
            receipt_root.mkdir(mode=0o700)
            benign = BenignPipeline(journal_root)
            benign.submit(rid, 'ok', deadline_ms=1000, output_cap=4096)
            benign.accept(rid)  # Never call execute(), recover(), or a VM runner.
            persisted = persist_binding(receipt_root, review, journal_root, rid)
            if persisted['persist_status'] != 'CREATED':
                raise ValueError('FIRST_DECLARED_RECEIPT_NOT_CREATED')
            report = build_cross_contract_trace(scenario, review, journal_root,
                                                receipt_root, rid)
            verify_cross_contract_trace(report, scenario, review, journal_root,
                                        receipt_root, rid)
            assert benign.read(rid)['start_count'] == 0
            summary = {
                'schema': report['schema'],
                'sha256': report['sha256'],
                'stage_count': report['a10_stage_count'],
                'stages': [x['algorithm'] for x in report['stage_ledger']],
                'stage_ledger_head_sha256': report['ledger_head_sha256'],
                'a1_a3_service_count': report['a1_a3_service_count'],
                'a1_a3_event_count': report['a1_a3_event_count'],
                'a4_a8_case_count': report['a4_a8_case_count'],
                'a4_a8_family_count': report['a4_a8_family_count'],
                'a5_local_fixture_state': report['a5_local_fixture_state'],
                'a5_local_fixture_start_intent_count': report['a5_local_fixture_start_intent_count'],
                'a1_a3_to_family_case_binding_attested': report['a1_a3_to_family_case_binding_attested'],
                'independent_physical_case_binding_attested': report['independent_physical_case_binding_attested'],
                'a1_a10_implementation_complete': report['a1_a10_implementation_complete'],
                'experimental_hypothesis_validated': report['experimental_hypothesis_validated'],
                'a6_classification': report['a6_classification'],
                'a8_recommendation': report['a8_recommendation'],
                'a9_local_declared_receipt_verified': report['a9_local_declared_receipt_verified'],
                'confirmed_final_risk': report['confirmed_final_risk'],
                'applied_state_transition': report['applied_state_transition'],
                'published_generation': report['published_generation'],
                'operational_dispatch': report['operational_dispatch'],
                'p8_operational': report['p8_operational'],
            }
        print(json.dumps(summary, sort_keys=True, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AssertionError, RecursionError) as exc:
        print('R58O=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58O_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
