#!/usr/bin/env python3
"""R58-M: offline temporary benign journal audit with no process execution."""
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
from ardrec.coordination.r58l_a4_a5_family_review import (
    build_a4_a5_review, verify_a4_a5_review,
)
from ardrec.coordination.r58m_durable_a5_audit import (
    build_durable_a5_link, verify_durable_a5_link,
)
from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true')
    args = parser.parse_args()
    if not args.synthetic_offline or Path.cwd().resolve() != REPO:
        print('R58M=BLOCKED:OFFLINE_MODE_AND_REPO_REQUIRED', file=sys.stderr)
        return 23
    try:
        entries = synthetic_entries()
        initial = build_a4_a5_review(entries)
        selected = initial['a4_selected_identity']
        if selected is None:
            raise ValueError('NO_A4_SYNTHETIC_SELECTION')
        rid = 'ATT_R58M_DEMO_001'
        intent = {**selected, 'attempt_id': rid, 'action':'SYNTHETIC_REVIEW_ONLY'}
        reviewed = build_a4_a5_review(entries, attempt_intent=intent)
        verify_a4_a5_review(reviewed)
        with tempfile.TemporaryDirectory(prefix='ardrec-r58m-benign-only-') as td:
            root = Path(td) / 'journal'
            journal = BenignPipeline(root)
            journal.submit(rid, 'ok', deadline_ms=1000, output_cap=4096)
            journal.accept(rid)
            # No execute(), no recover(): both belong to the existing engine.
            assert journal.read(rid)['state'] == 'ACCEPTED'
            assert journal.verify(rid)['p8_operational'] == 'NO-GO'
            doc = build_durable_a5_link(reviewed, root, rid)
            verify_durable_a5_link(doc, reviewed, root, rid)
        assert doc['durable_a5']['journal_state'] == 'ACCEPTED'
        assert doc['durable_a5']['local_fixture_start_intent_count'] == 0
        assert doc['actual_operational_attempts_started'] == 0
        assert doc['a6_classification'] == 'ND'
        assert doc['case_identity_binding_accredited'] is False
        assert doc['p8_operational'] == 'NO-GO'
        print(json.dumps({
            'schema': doc['schema'], 'sha256':doc['sha256'],
            'r58l_review_sha256':doc['r58l_review_sha256'],
            'unit_count':reviewed['unit_count'],
            'covered_family_count':reviewed['covered_family_count'],
            'source':'EPHEMERAL_LOCAL_BENIGN_SQLITE',
            'journal_state':doc['durable_a5']['journal_state'],
            'journal_event_count':doc['durable_a5']['event_count'],
            'local_fixture_start_intent_count':doc['durable_a5']['local_fixture_start_intent_count'],
            'case_binding_accredited':doc['case_identity_binding_accredited'],
            'real_operational_attempt_starts':doc['actual_operational_attempts_started'],
            'a6_classification':doc['a6_classification'],
            'a5_disposition':doc['a5_disposition'],
            'p8_operational':doc['p8_operational'],
            'published_generation':doc['published_generation'],
        }, sort_keys=True, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, KeyError, AssertionError, OSError, TypeError, RecursionError) as exc:
        print('R58M=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180], file=sys.stderr)
        print('R58M_P8=NO-GO', file=sys.stderr)
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
