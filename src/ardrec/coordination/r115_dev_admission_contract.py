"""R115-F1: pure, fail-closed DEV case contract; does not authorize execution.

A runtime authorization cannot be inferred from a self-supplied document, hash,
prior observation, or this offline validation. All A3 gates stay ND until their
trusted real-source adapters and the authorization path are implemented.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = 'ARDREC-R115-F1-DEV-FTP-T01-PREFLIGHT-v1'
GATES = ('SCOPE_APPROVED', 'LAB_ISOLATION_CONFIRMED',
         'DESTINATION_AUTHORIZED', 'CLIENT_COMPATIBLE', 'SERVICE_READY')
SUPPORTS = ('TARGET_ATTESTATION', 'INTEGRITY_PROVENANCE', 'CONTROL_CHANNEL_RESPONSE')
LIMIT_KEYS = ('timeout_seconds', 'operation_count', 'request_count',
              'transfer_bytes', 'output_bytes', 'memory_mib')
MAXIMUMS = dict(zip(LIMIT_KEYS, (120, 20, 20, 65536, 65536, 512)))
SHA = re.compile(r'[0-9a-f]{64}\Z')
GIT_SHA = re.compile(r'[0-9a-f]{40}\Z')
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{2,95}\Z')

class Rejected(ValueError):
    """Typed failure: data cannot be used as an operational approval."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise Rejected(code)


def unique_pairs(pairs):
    d = {}
    for k, v in pairs:
        require(k not in d, 'DUPLICATE_JSON_KEY')
        d[k] = v
    return d


def load(raw: bytes) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= 200000, 'INPUT_SIZE')
    try:
        val = json.loads(raw, object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Rejected('NONFINITE')))
    except (UnicodeError, ValueError, RecursionError, TypeError) as exc:
        raise Rejected('INVALID_JSON') from exc
    require(type(val) is dict, 'OBJECT_REQUIRED')
    return val


def canonical(data: Any) -> bytes:
    return (json.dumps(data, sort_keys=True, ensure_ascii=True,
                       allow_nan=False, separators=(',', ':')) + '\n').encode('ascii')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _instant(v: str, label: str) -> datetime:
    require(type(v) is str and len(v) <= 40, label + '_FORMAT')
    try:
        d = datetime.fromisoformat(v.replace('Z', '+00:00'))
    except ValueError as exc:
        raise Rejected(label + '_FORMAT') from exc
    require(d.tzinfo is not None and d.utcoffset() is not None, label + '_NO_TZ')
    return d.astimezone(timezone.utc)


def _reference(v: Any, label: str) -> None:
    require(type(v) is dict and set(v) == {'id', 'sha256'}, label + '_FIELDS')
    require(type(v['id']) is str and ID.fullmatch(v['id']) is not None,
            label + '_ID')
    require(type(v['sha256']) is str and SHA.fullmatch(v['sha256']) is not None,
            label + '_SHA')


def validate(source: dict, catalogue: dict, catalogue_raw: bytes) -> dict:
    """Offline static validation only, deliberately never issues GO or A6 admission."""
    fields = {'schema', 'case_id', 'family_id', 'stage', 'created_at', 'valid_from',
              'valid_until', 'source_commit', 'catalog_sha256', 'target', 'client',
              'profile', 'authority', 'isolation', 'service', 'limits'}
    require(type(source) is dict and set(source) == fields, 'CONTRACT_FIELDS')
    require(source['schema'] == SCHEMA and source['stage'] == 'DEV', 'CONTRACT_STAGE')
    require(source['family_id'] == 'FTP-T01', 'CASE_FAMILY')
    require(type(source['case_id']) is str and ID.fullmatch(source['case_id']), 'CASE_ID')
    require(type(source['source_commit']) is str and GIT_SHA.fullmatch(source['source_commit']), 'SOURCE_COMMIT')
    require(type(source['catalog_sha256']) is str and source['catalog_sha256'] == digest(catalogue_raw), 'CATALOG_DIGEST')
    created, start, stop = (_instant(source[k], k.upper()) for k in
                            ('created_at', 'valid_from', 'valid_until'))
    require(created <= stop and start < stop and (stop-start).total_seconds() <= 86400,
            'TIME_WINDOW_INVALID')
    require(type(catalogue) is dict and
            catalogue.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
            catalogue.get('execution_enabled') is False and
            catalogue.get('catalog_frozen') is False and
            catalogue.get('pilot_completed') is False, 'P7_DRAFT_STATE_DRIFT')
    families = catalogue.get('families')
    require(type(families) is list, 'P7_FAMILIES_MISSING')
    matched = [x for x in families if type(x) is dict and x.get('id') == 'FTP-T01']
    require(len(matched) == 1, 'FTP_T01_NOT_UNIQUE')
    family = matched[0]
    require(family.get('preconditions') == list(GATES) and
            family.get('required_supports') == list(SUPPORTS), 'P7_PRECONDITION_DRIFT')
    target = source['target']
    require(type(target) is dict and set(target) == {'vm', 'ip', 'port', 'mac', 'network'}, 'TARGET_FIELDS')
    require(target['vm'] == 'ardrec-r33-dev-ftp' and
            target['network'] == 'ardrec-r33-dev-net-ftp' and
            target['port'] == 21 and type(target['port']) is int, 'TARGET_SCOPE')
    try:
        addr = ipaddress.ip_address(target['ip'])
    except (ValueError, TypeError) as exc:
        raise Rejected('TARGET_IP') from exc
    require(str(addr) == '10.203.31.2', 'TARGET_IP_NOT_PINNED')
    require(type(target['mac']) is str and re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', target['mac']) is not None,
            'TARGET_MAC_FORMAT')
    for k in ('client', 'profile', 'authority', 'isolation', 'service'):
        _reference(source[k], k.upper())
    limits = source['limits']
    require(type(limits) is dict and set(limits) == set(LIMIT_KEYS) | {'ordinary_attempts', 'additional_attempts'},
            'LIMIT_FIELDS')
    require(type(limits['ordinary_attempts']) is int and limits['ordinary_attempts'] == 1 and
            type(limits['additional_attempts']) is int and limits['additional_attempts'] == 0,
            'ATTEMPT_BUDGET')
    for k, cap in MAXIMUMS.items():
        v = limits[k]
        require(type(v) is int and 0 < v <= cap, 'LIMIT_' + k.upper())
    # Each reference is an opaque locator + content digest, not proof of trust.
    return {
        'schema': 'ARDREC-R115-F1-STATIC-VALIDATION-REPORT-v1',
        'input_sha256': digest(canonical(source)),
        'catalog_sha256': digest(catalogue_raw),
        'family_id': 'FTP-T01', 'case_id': source['case_id'],
        'static_contract_valid': True, 'a3_status': {k: 'ND' for k in GATES},
        'a3_reason': 'TRUSTED_CURRENT_SOURCE_ADAPTER_NOT_IMPLEMENTED',
        'a5_executable': False, 'a6_classification': 'ND',
        'a7_final_risk': None, 'a9_published_generation': None,
        'p8': 'NO-GO', 'new_network_connections': 0,
        'new_guest_exec': 0, 'new_root_scripts': 0,
        'note': 'Reference digests and static checks do not authenticate authority, freshness or effective isolation.'
    }


def validate_bytes(source_raw: bytes, catalog_raw: bytes) -> bytes:
    return canonical(validate(load(source_raw), load(catalog_raw), catalog_raw))


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(description='Offline R115-F1 contract validator (never executes)')
    p.add_argument('--contract', required=True, type=Path)
    p.add_argument('--catalog', required=True, type=Path)
    a = p.parse_args(argv)
    try:
        report = validate_bytes(a.contract.read_bytes(), a.catalog.read_bytes())
    except (OSError, Rejected) as exc:
        print('R115_F1_STOP=' + str(exc))
        return 2
    print(report.decode('ascii'), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
