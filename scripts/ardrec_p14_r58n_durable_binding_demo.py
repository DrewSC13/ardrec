#!/usr/bin/env python3
"""R58-N deterministic declared A4/A5 receipt; no execution, no P8 dispatch."""
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
from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
from ardrec.coordination.r58n_durable_case_binding import (
    persist_binding, verify_persisted,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58N=BLOCKED:OFFLINE_AND_REPO_REQUIRED',file=sys.stderr)
        return 23
    try:
        entries = synthetic_entries()
        initial = build_a4_a5_review(entries)
        selected = initial['a4_selected_identity']
        assert selected is not None
        rid = 'ATT_R58N_DEMO_001'
        review = build_a4_a5_review(
            entries, attempt_intent={**selected,'attempt_id':rid,
                                     'action':'SYNTHETIC_REVIEW_ONLY'})
        with tempfile.TemporaryDirectory(prefix='ardrec-r58n-source-only-') as td:
            root = Path(td)
            journal_root = root / 'journal'
            receipts = root / 'receipts'
            receipts.mkdir(mode=0o700)
            local = BenignPipeline(journal_root)
            local.submit(rid,'ok',deadline_ms=1000,output_cap=4096)
            local.accept(rid)  # no execute, no recover, no process launch
            first = persist_binding(receipts,review,journal_root,rid)
            replay = persist_binding(receipts,review,journal_root,rid)
            checked = verify_persisted(receipts,review,journal_root,rid)
            assert first['persist_status'] == 'CREATED'
            assert replay['persist_status'] == 'REPLAY_IDENTICAL'
            assert first['receipt']['sha256'] == replay['receipt']['sha256']
            assert checked['receipt_sha256'] == first['receipt']['sha256']
            report = first['receipt']
            summary = {
                'schema':report['schema'],
                'sha256':report['sha256'],
                'unit_count':review['unit_count'],
                'covered_family_count':review['covered_family_count'],
                'a4_selected_identity':report['a4_selected_identity'],
                'journal_state':report['a5_fixture_state'],
                'journal_event_count':report['a5_fixture_event_count'],
                'local_fixture_start_intent_count':report['a5_fixture_start_intent_count'],
                'first_persist_status':first['persist_status'],
                'replay_persist_status':replay['persist_status'],
                'verify_status':checked['persisted_verification'],
                'physical_case_binding_accredited':report['physical_case_binding_accredited'],
                'technical_truth_accredited':report['technical_truth_accredited'],
                'a6_classification':report['a6_classification'],
                'confirmed_final_risk':report['confirmed_final_risk'],
                'published_generation':report['published_generation'],
                'operational_dispatch':report['operational_dispatch'],
                'p8_operational':report['p8_operational'],
            }
        print(json.dumps(summary,sort_keys=True,indent=2,ensure_ascii=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, AssertionError, RecursionError) as exc:
        print('R58N=BLOCKED:'+type(exc).__name__+':'+str(exc)[:180],file=sys.stderr)
        print('R58N_P8=NO-GO',file=sys.stderr)
        return 23

if __name__ == '__main__':
    raise SystemExit(main())
