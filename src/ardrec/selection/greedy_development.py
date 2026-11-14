"""P14-R27: A4 en proyeccion sintetica; eleccion exacta, NUNCA despacho.

A4 de la tesis: cand = estado PENDIENTE y guardia VERDADERO y
aplicable, clave (-PA, precedencia, servicio, caso). Este contrato no publica
un estado A9: el valor escogido es solo una prueba de logica de seleccion.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
import re
from typing import Any

FORMAT = 'ardrec-p14-r27-a4-development-selection-v1'
SOURCE = 'SYNTHETIC_PROJECTION_ONLY'
CANON_RAT = re.compile(r'(?:0|[1-9][0-9]*)(?:/[1-9][0-9]*)?\Z', re.ASCII)
IDENT = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z', re.ASCII)
MAX_BYTES = 65536


class SelectionError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def need(ok: bool, code: str) -> None:
    if not ok:
        raise SelectionError(code)


def canon(obj: Any) -> bytes:
    try:
        b = json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as e:
        raise SelectionError('serialization') from e
    need(len(b) <= MAX_BYTES, 'too_large')
    return b


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rational(value: Any) -> Fraction:
    need(type(value) is str and len(value) < 81 and CANON_RAT.fullmatch(value) is not None,
         'rational_not_canonical')
    try:
        p = Fraction(value)
    except (ZeroDivisionError, ValueError) as e:
        raise SelectionError('rational_invalid') from e
    need(Fraction(0) <= p <= Fraction(1) and str(p) == value,
         'rational_out_of_range_or_noncanonical')
    return p


def select_development(candidates: list[dict[str, Any]],
                       session_sha256: str, *, weights: tuple[str, str, str] =
                       ('1/3', '1/3', '1/3')) -> dict[str, Any]:
    """No ejecuta comandos. Independiente del orden de entrada."""
    need(type(candidates) is list and len(candidates) <= 64, 'candidates_invalid')
    need(type(session_sha256) is str and re.fullmatch(r'[a-f0-9]{64}', session_sha256) is not None,
         'session_binding_invalid')
    need(type(weights) is tuple and len(weights) == 3, 'weights_invalid')
    ww = tuple(rational(w) for w in weights)
    need(all(w > 0 for w in ww) and sum(ww) == 1, 'weights_not_positive_simplex')
    keys: set[tuple[str, str]] = set()
    rows = []
    eligible = []
    expected = {'service_id', 'case_id', 'phase', 'guard', 'applicable',
                'precedence', 'initial_risk', 'evidence', 'criticality'}
    for item in candidates:
        need(type(item) is dict and set(item) == expected, 'candidate_schema')
        sid, cid = item['service_id'], item['case_id']
        need(type(sid) is str and IDENT.fullmatch(sid) is not None and
             type(cid) is str and IDENT.fullmatch(cid) is not None, 'candidate_id')
        key = sid, cid
        need(key not in keys, 'duplicate_candidate')
        keys.add(key)
        need(item['phase'] in ('PREPARADO', 'PENDIENTE', 'ACTIVO', 'VALIDACION',
                               'ACTUALIZADO', 'PAUSADO', 'CERRADO', 'DETENIDO') and
             type(item['phase']) is str, 'phase_invalid')
        need(type(item['guard']) is str and item['guard'] in ('VERDADERO','FALSO','ND'),
             'guard_invalid')
        need(type(item['applicable']) is bool, 'applicable_invalid')
        need(type(item['precedence']) is int and 0 <= item['precedence'] <= 1023,
             'precedence_invalid')
        r0, e, cn = (rational(item[k]) for k in
                     ('initial_risk', 'evidence', 'criticality'))
        priority = ww[0]*r0 + ww[1]*e + ww[2]*cn
        reason = ('STATE_NOT_PENDING' if item['phase'] != 'PENDIENTE' else
                  'GUARD_NOT_TRUE' if item['guard'] != 'VERDADERO' else
                  'CASE_NOT_APPLICABLE' if not item['applicable'] else None)
        row = {'service_id':sid, 'case_id':cid, 'priority':str(priority),
               'precedence':item['precedence'], 'eligible':reason is None,
               'blocker':reason}
        rows.append(row)
        if reason is None:
            eligible.append(((-priority, item['precedence'], sid, cid), row))
    rows.sort(key=lambda x:(x['service_id'],x['case_id']))
    eligible.sort(key=lambda pair: pair[0])
    winner = eligible[0][1] if eligible else None
    maxp = Fraction(winner['priority']) if winner is not None else None
    tie = sum(Fraction(c['priority']) == maxp for _,c in eligible) if winner else 0
    doc: dict[str,Any] = {
        'schema':FORMAT, 'source_kind':SOURCE,
        'session_sha256':session_sha256, 'weights':list(weights),
        'candidates':rows, 'eligible_count':len(eligible),
        'selected':None if winner is None else {
            'service_id':winner['service_id'], 'case_id':winner['case_id'],
            'priority':winner['priority'], 'precedence':winner['precedence']},
        'maximum_priority_ties':tie, 'selection_is_operational':False,
        'operational_dispatch':False, 'p8_operational':'NO-GO',
        'published_generation':None,
    }
    doc['sha256'] = sha(canon(doc))
    return doc


def verify_selection(doc: dict[str, Any], candidates: list[dict[str, Any]]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str, 'report_invalid')
    claimed = doc['sha256']
    need(sha(canon({k:v for k,v in doc.items() if k!='sha256'})) == claimed,
         'report_digest_invalid')
    expected = select_development(candidates, doc['session_sha256'],
                                  weights=tuple(doc['weights']))
    need(canon(doc)==canon(expected), 'report_not_reproducible')
    return True
