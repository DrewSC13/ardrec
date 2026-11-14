"""P14-R28 / A9: recibo de desarrollo durable e idempotente.

No es publicación de generación de ARDREC. Nunca sobrescribe un recibo
existente, verifica bytes y rechaza enlaces simbólicos.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any
from ardrec.analytics.exact_preview import canonical, digest

FORMAT='ardrec-p14-r28-development-receipt-v1'
FILE_NAME='r28_development_receipt.json'
MAX_BYTES=65536


class ReceiptError(ValueError):
    pass


def build_receipt(*, session_sha: str, r27_sha: str,
                  a7_sha: str, a8_sha: str) -> dict[str, Any]:
    for value in (session_sha,r27_sha,a7_sha,a8_sha):
        if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
            raise ReceiptError('invalid_sha')
    doc={
        'schema':FORMAT,'scope':'DEVELOPMENT_LOCAL_RECEIPT_ONLY',
        'sources':{'r26_session':session_sha,'r27_review':r27_sha,
                   'a7_oracle':a7_sha,'a8_stop_preview':a8_sha},
        'technical_generation_published':False,'published_generation':None,
        'operational_dispatch':False,'p8_operational':'NO-GO',
    }
    doc['sha256']=digest(doc)
    if len(canonical(doc)) > MAX_BYTES:
        raise ReceiptError('receipt_too_large')
    return doc


def verify_receipt(document: dict[str, Any]) -> bool:
    if type(document) is not dict or type(document.get('sources')) is not dict or type(document.get('sha256')) is not str:
        raise ReceiptError('receipt_invalid')
    sources=document['sources']
    if set(sources)!={'r26_session','r27_review','a7_oracle','a8_stop_preview'}:
        raise ReceiptError('source_keys_invalid')
    expected=build_receipt(session_sha=sources['r26_session'],r27_sha=sources['r27_review'],
                           a7_sha=sources['a7_oracle'],a8_sha=sources['a8_stop_preview'])
    if canonical(document)!=canonical(expected):
        raise ReceiptError('receipt_tampered')
    return True


def persist_receipt(root: Path, document: dict[str, Any]) -> Path:
    if type(root) is not Path and not isinstance(root, Path):
        raise ReceiptError('root_invalid')
    verify_receipt(document)
    if root.is_symlink() or not root.is_dir():
        raise ReceiptError('root_invalid_or_symlink')
    if root.stat().st_mode & 0o022:
        raise ReceiptError('root_writable_by_others')
    target=root/FILE_NAME
    data=canonical(document)+b'\n'
    if target.is_symlink():
        raise ReceiptError('receipt_symlink')
    if target.exists():
        if not target.is_file() or target.read_bytes()!=data:
            raise ReceiptError('receipt_conflict_or_tamper')
        return target
    fd,tmp=tempfile.mkstemp(prefix='.r28-',dir=root)
    try:
        with os.fdopen(fd,'wb') as output:
            os.fchmod(output.fileno(),0o600)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if target.exists() or target.is_symlink():
            raise ReceiptError('receipt_race')
        # Link evita sobrescribir un recibo creado por otro proceso concurrente.
        os.link(tmp,target,follow_symlinks=False)
        dfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except FileExistsError as exc:
        raise ReceiptError('receipt_race') from exc
    finally:
        Path(tmp).unlink(missing_ok=True)
    if target.read_bytes()!=data:
        raise ReceiptError('receipt_write_mismatch')
    return target
