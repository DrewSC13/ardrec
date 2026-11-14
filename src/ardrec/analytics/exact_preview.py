"""P14-R28 / A7: oráculo matemático exacto, sin evidencia acreditada.

Reproduce las cotas de tesis §3.2.8 mediante Fraction. NO produce un
riesgo final operacional ni autoriza publicar una generación.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import re
from typing import Any

FORMAT = 'ardrec-p14-r28-a7-exact-mathematical-oracle-v1'
RATIONAL = re.compile(r'(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?\Z', re.ASCII)


class ExactPreviewError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def rational(value: Any) -> Fraction:
    if type(value) is not str or len(value) > 80 or RATIONAL.fullmatch(value) is None:
        raise ExactPreviewError('noncanonical_fraction')
    try:
        result = Fraction(value)
    except (ValueError, ZeroDivisionError, OverflowError) as exc:
        raise ExactPreviewError('invalid_fraction') from exc
    if str(result) != value or not 0 <= result <= 1:
        raise ExactPreviewError('fraction_outside_domain')
    return result


def preview_bounds(initial_risk: str, criticality: str,
                   contributions: list[str], replacement_risk: str,
                   weights: tuple[str, str, str] = ('1/3','1/3','1/3')) -> dict[str, Any]:
    """Oráculo por valores proporcionados; NO acredita su procedencia.

    E_t=max({0} U contribuciones). U=R0 si E_t=0, en otro caso
    U=max(R0, K+). D=max(R0minus, min(R0,K-)). Rf=U+D-R0.
    """
    if type(contributions) is not list or len(contributions) > 64:
        raise ExactPreviewError('contributions_invalid')
    if type(weights) is not tuple or len(weights) != 3:
        raise ExactPreviewError('weights_invalid')
    r0, c, r0minus = map(rational, (initial_risk, criticality, replacement_risk))
    if r0minus > r0:
        raise ExactPreviewError('replacement_increases_baseline')
    ww = tuple(rational(w) for w in weights)
    if not all(w > 0 for w in ww) or sum(ww) != 1:
        raise ExactPreviewError('weights_not_positive_simplex')
    values = [rational(e) for e in contributions]
    evidence = max([Fraction(0), *values])
    kp = ww[0]*r0 + ww[1]*evidence + ww[2]*c
    km = ww[0]*r0 + ww[1]*r0minus + ww[2]*c
    upper = r0 if evidence == 0 else max(r0, kp)
    lower = max(r0minus, min(r0, km))
    recalibrated = upper + lower - r0
    if not (r0minus <= lower <= recalibrated <= upper <= 1):
        raise ExactPreviewError('bound_invariant_failed')
    doc = {
        'schema': FORMAT, 'authority': 'MATHEMATICAL_ORACLE_ONLY',
        'initial_risk': str(r0), 'criticality': str(c),
        'contributions': [str(v) for v in values], 'weights': list(weights),
        'replacement_risk': str(r0minus), 'evidence_max': str(evidence),
        'k_plus': str(kp), 'k_minus': str(km), 'upper': str(upper),
        'lower': str(lower), 'hypothetical_rf': str(recalibrated),
        'technical_truth_accredited': False, 'confirmed_rf': None,
        'published_generation': None, 'p8_operational': 'NO-GO',
    }
    doc['sha256'] = digest(doc)
    return doc


def verify_bounds(document: dict[str, Any]) -> bool:
    if type(document) is not dict or type(document.get('sha256')) is not str:
        raise ExactPreviewError('report_invalid')
    actual = digest({k: v for k, v in document.items() if k != 'sha256'})
    if actual != document['sha256']:
        raise ExactPreviewError('report_digest_changed')
    expected = preview_bounds(document['initial_risk'], document['criticality'],
                              document['contributions'], document['replacement_risk'],
                              tuple(document['weights']))
    if canonical(expected) != canonical(document):
        raise ExactPreviewError('report_not_reproducible')
    return True
