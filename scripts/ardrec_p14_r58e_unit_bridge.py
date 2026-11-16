#!/usr/bin/env python3
"""R58-E strictly synthetic A6/A7/A8 per-unit integration; no host operations."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))

from ardrec.analytics.exact_preview import canonical
from ardrec.coordination.r58e_evidence_risk_bridge import build_unit_bridge, verify_unit_bridge
from ardrec.evidence.defensive_import import (
    read_observation, admit_defensive_observation,
)

RECEIPT = ROOT/'lab/p14-r37-a6-defensive-import-v1/synthetic-receipt.json'
SUPPORT = ROOT/'lab/p14-r37-a6-defensive-import-v1/synthetic-support.txt'
AS_OF = '2026-11-14T20:00:00Z'


def synthetic_units():
    return [{'service_id': sid, 'case_id': 'CASE_REFERENCE',
             'assessment_index': 0, 'initial_risk': '1/4',
             'normalized_criticality': '1/2', 'replacement_risk': '1/4',
             'evidence': []}
            for sid in ('SSH_DEV', 'FTP_DEV', 'SMB_DEV')]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--synthetic-offline', action='store_true', required=True)
    args = parser.parse_args()
    try:
        if Path.cwd().resolve() != ROOT:
            raise ValueError('MUST_RUN_FROM_PROJECT_ROOT')
        receipt, raw = read_observation(RECEIPT)
        admission = admit_defensive_observation(receipt, raw, SUPPORT, as_of_utc=AS_OF)
        report = build_unit_bridge(synthetic_units(), [admission])
        verify_unit_bridge(report)
        print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True))
    except (ValueError, TypeError, KeyError, OSError, UnicodeError) as exc:
        print('R58E=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:160])
        print('R58E_HOST_MUTATIONS=0')
        print('R58E_P8=NO-GO')
        return 23
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
