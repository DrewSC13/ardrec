"""Read-only A1-R9 finite corpus self-check: no operational side effects."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.rules import RuleError, decide


def verify():
    corpus = json.loads((ROOT / 'tests/fixtures/a1-rules-v1.json').read_text())
    if corpus['schema_version'] != '1.0' or corpus['contract'] != 'A1-R9-PURE-RULES':
        raise ValueError('corpus identity mismatch')
    cases = corpus['cases']
    if len(cases) != 14 or len({c['name'] for c in cases}) != 14:
        raise ValueError('case identity drift')
    for case in cases:
        fx = deepcopy(corpus['base'])
        fx['env'].update(case.get('env_overrides', {}))
        for missing in case.get('missing_fields', []):
            fx['env'].pop(missing, None)
        if 'additional_rule' in case:
            fx['table'].append(case['additional_rule'])
        try:
            result = decide(fx['table'], fx['env'], fx['schema'], fx['context'])
        except RuleError as exc:
            if exc.code != case.get('error'):
                raise ValueError(f"mismatch {case['name']}: unexpected error {exc.code}") from exc
        else:
            if 'error' in case or result.status != case['status'] or result.rule_id != case['rule_id']:
                raise ValueError(f"mismatch {case['name']}: {result}")
            if result.authorized or result.dispatch_allowed:
                raise ValueError('operational permission invented')
    return {'status': 'PASS_A1_R9_PURE_RULES_SYNTHETIC',
            'cases': len(cases), 'real_cases': 0, 'dispatch_allowed': False,
            'algorithms_complete': False, 'experimental_validation': 'NOT_RUN'}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (KeyError, ValueError, TypeError, OSError) as exc:
        print('ARDREC_A1_R9=FAIL_CLOSED: ' + str(exc), file=sys.stderr)
        raise SystemExit(2)
