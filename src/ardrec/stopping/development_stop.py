"""P14-R28 / A8: dictamen conservador de parada, SIN transición autorizada."""
from __future__ import annotations

from typing import Any
from ardrec.analytics.exact_preview import digest, canonical

FORMAT='ardrec-p14-r28-a8-stop-preview-v1'


class StopPreviewError(ValueError):
    pass


def preview_stop(*, a6_classification: str, accredited: bool,
                 vm_checked: bool, operational_dispatch: bool,
                 source_sha256: str) -> dict[str, Any]:
    if a6_classification != 'ND' or accredited is not False or vm_checked is not False or operational_dispatch is not False:
        raise StopPreviewError('unsupported_operational_state')
    if type(source_sha256) is not str or len(source_sha256) != 64 or any(c not in '0123456789abcdef' for c in source_sha256):
        raise StopPreviewError('source_identity_invalid')
    doc: dict[str, Any]={
        'schema':FORMAT, 'source_sha256':source_sha256,
        'a6_classification':'ND', 'criteria_es_sa_cv_le':[],
        'recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA',
        'applied_transition':None, 'terminal_state':None,
        'confirmed_phase':None, 'safety_gate':'NO-GO',
        'technical_truth_accredited':False,
    }
    doc['sha256']=digest(doc)
    return doc


def verify_stop(doc: dict[str, Any]) -> bool:
    if type(doc) is not dict or type(doc.get('sha256')) is not str:
        raise StopPreviewError('report_invalid')
    expected=preview_stop(a6_classification='ND',accredited=False,vm_checked=False,
                          operational_dispatch=False,source_sha256=doc['source_sha256'])
    if canonical(doc)!=canonical(expected):
        raise StopPreviewError('report_tampered')
    return True
