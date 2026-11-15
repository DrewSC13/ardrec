"""R56.0: auditable three-service acceptance gates, source-only and fail-closed.

This module does not run commands, open sockets, or grant P8 authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

MAIN = '34c8837a7cd626c36d9af2b9eaa2f593459997a7'
SCHEMA = 'ardrec-r560-three-service-closure-plan-v1'
ROLES = ('ssh', 'ftp', 'smb')
CONFIG_HASHES = {
    'ssh': '1b65472bfc96892fbb87a9d0496f92b751930f521a23a9a321d5e5fe410e6cae',
    'ftp': '299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8',
    'smb': '7e6b14afc0b3cd01cfe8a4a0e48a2ed32b830f610f9e1144e43056dd96b87ee3',
}
SERVICES = {
    'ssh': {'port': 22, 'ip':'10.203.30.2','runner':'10.203.30.1',
            'cidr':'10.203.30.0/28','domain':'ardrec-r33-dev-ssh',
            'network':'ardrec-r33-dev-net-ssh','families':8,
            'transport':'TCP_22',
            'checks':('ssh-identity','ssh-reference','ssh-limited-helper',
                      'ssh-restricted-denied','ssh-write','ssh-read-marker','ssh-cleanup')},
    'ftp': {'port': 21, 'ip':'10.203.31.2','runner':'10.203.31.1',
            'cidr':'10.203.31.0/28','domain':'ardrec-r33-dev-ftp',
            'network':'ardrec-r33-dev-net-ftp','families':8,
            'transport':'TCP_21_AND_PASSIVE_50000_50009_ONLY',
            'checks':('ftp-cleartext-login-denied','ftps-reference','ftps-write',
                      'ftps-read-marker','ftps-cleanup')},
    'smb': {'port': 445, 'ip':'10.203.32.2','runner':'10.203.32.1',
            'cidr':'10.203.32.0/28','domain':'ardrec-r33-dev-smb',
            'network':'ardrec-r33-dev-net-smb','families':9,
            'transport':'TCP_445_ONLY',
            'checks':('smb-reference','smb-restricted-denied','smb-encrypted-write',
                      'smb-encrypted-read','smb-cleanup')},
}
R559F1_REPORT_SHA = 'd28b78dba11457056ebcf8ad174cdfa2acfa5504de5c5bdc523094be95c9d2d1'

class ClosureError(ValueError):
    pass

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ClosureError(reason)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def pairs(kvs):
    result = {}
    for key, val in kvs:
        require(key not in result, 'duplicate_json_key')
        result[key] = val
    return result

def parse(raw: bytes):
    require(type(raw) is bytes and 0 < len(raw) <= 1000000, 'json_length')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'json_nonfinite'))

def validate_sources(manifest: dict, configs: dict, historical: dict, catalog: dict) -> dict:
    require(type(manifest) is dict and manifest.get('schema') == 'ardrec-p14-r51-dev-three-services-v1',
            'r51_schema')
    require(type(configs) is dict and set(configs) == set(ROLES), 'config_inventory')
    for role in ROLES:
        require(type(configs[role]) is bytes and sha(configs[role]) == CONFIG_HASHES[role],
                'config_hash_' + role)
    require(type(historical) is dict and historical.get('status') == 'RECORDED_HOST_SERVICE_SMOKE_PASS'
            and historical.get('experimental_data') is False, 'historical_status')
    old_checks = historical.get('checks')
    require(type(old_checks) is list and len(old_checks) == 17 and
            all(type(x) is dict and x.get('result') == 'PASS' for x in old_checks),
            'historical_check_inventory')
    names = [x['check'] for x in old_checks]
    require(len(set(names)) == 17 and set(names) ==
            {x for role in ROLES for x in SERVICES[role]['checks']},
            'historical_check_names')
    require(type(catalog) is dict and catalog.get('execution_enabled') is False and
            catalog.get('catalog_frozen') is False and
            catalog.get('derived_real_cases') == 0, 'catalog_must_be_unexecuted')
    units = manifest.get('units')
    require(type(units) is list and len(units) == 3, 'r51_unit_count')
    actual_family_ids = []
    result = []
    for role, unit in zip(ROLES, units):
        item = SERVICES[role]
        require(type(unit) is dict and unit.get('protocol') == role
                and unit.get('libvirt_target_domain') == item['domain']
                and unit.get('libvirt_network_name') == item['network']
                and unit.get('expected_target_ip') == item['ip']
                and unit.get('expected_runner_ip') == item['runner']
                and unit.get('expected_network_cidr') == item['cidr']
                and unit.get('server_tcp_port') == item['port']
                and unit.get('config_source_sha256') == CONFIG_HASHES[role],
                'r51_role_drift_' + role)
        families = unit.get('case_families')
        require(type(families) is list and len(families) == item['families'],
                'family_count_' + role)
        for number, f in enumerate(families, 1):
            fid = f'{role.upper()}-T{number:02d}'
            require(type(f) is dict and f.get('family_id') == fid
                    and f.get('coverage') in ('PENDING', 'PARTIAL')
                    and f.get('case_executable') is False
                    and f.get('evidence_admitted_by_A6') is False,
                    'unearned_family_acceptance_' + fid)
            actual_family_ids.append(fid)
        result.append({'role': role, 'dev_unit': unit.get('unit_id'),
                       'family_count': len(families), 'historical_smoke_checks': len(item['checks'])})
    require(len(set(actual_family_ids)) == 25, 'duplicate_family_id')
    require(catalog.get('counts') == {'ssh':8,'ftp':8,'smb':9,'total':25}, 'catalog_counts')
    require({x.get('id') for x in catalog.get('families', [])} == set(actual_family_ids),
            'catalog_family_ids')
    return {'roles': result, 'historical_checks': 17, 'families': 25}

def plan(provenance: dict) -> dict:
    require(provenance.get('historical_checks') == 17 and provenance.get('families') == 25,
            'provenance_invalid')
    rows = []
    for role in ROLES:
        data = SERVICES[role]
        rows.append({
            'role':role, 'target_domain': data['domain'], 'network':data['network'],
            'target_ip':data['ip'], 'runner_ip':data['runner'], 'transport':data['transport'],
            'family_count':data['families'], 'historical_checks':list(data['checks']),
            'current_smoke_status':'NOT_EXECUTED',
            'current_positive_packet_witness':'NOT_EXECUTED',
            'current_negative_packet_witness':'NOT_EXECUTED',
            'source_guest_attestation':'NOT_EXECUTED',
            'independent_watchdog_armed':False,
            'accepted_family_count':0,
            'accepted_service':False,
            'prerequisites': [
                'DENY_FIRST_AND_CURRENT_R34_READBACK',
                'SOURCE_AND_TARGET_IDENTITY_READBACK',
                'INDEPENDENT_ROOT_V2_WATCHDOG_AND_BOUND',
                'AUTHORIZED_L2_L3_POSITIVE_AND_NEGATIVE_WITNESSES',
                'AUTHORIZED_ROLE_SCOPED_TRANSPORT_WINDOW',
                'CURRENT_GUEST_SERVICE_AND_SYNTHETIC_SMOKE',
                'POST_WINDOW_DENY_AND_ORIGINAL_BINDINGS',
                'SEPARATE_A6_EVIDENCE_ADMISSION',
            ],
        })
    return {'schema':SCHEMA,'source_main':MAIN,
            'historical_service_checks':17, 'family_count':25,
            'r559f1_physical_receipt_sha256':R559F1_REPORT_SHA,
            'recovery_missing_binding':'SUPPORTED_BY_PRIVATE_R559F1_ONLY',
            'roles':rows,
            'allowed_progress':'SSH_FIRST_THEN_FTP_THEN_SMB_WITH_SEPARATE_AUTHORIZATION',
            'permissions':'NO_HOST_MUTATIONS_AND_NO_NETWORK_DISPATCH',
            'operational_p8':'NO-GO','rf':None,'confirmed_generation':None}

def validate_plan(doc: dict) -> None:
    require(type(doc) is dict and doc.get('schema') == SCHEMA and
            doc.get('source_main') == MAIN and
            doc.get('historical_service_checks') == 17 and
            doc.get('family_count') == 25 and
            doc.get('permissions') == 'NO_HOST_MUTATIONS_AND_NO_NETWORK_DISPATCH' and
            doc.get('operational_p8') == 'NO-GO' and
            doc.get('rf') is None and doc.get('confirmed_generation') is None,
            'plan_invalid')
    rows = doc.get('roles')
    require(type(rows) is list and len(rows) == 3, 'plan_roles')
    for i, role in enumerate(ROLES):
        entry = rows[i]
        ref = SERVICES[role]
        require(entry.get('role') == role and entry.get('target_ip') == ref['ip']
                and entry.get('family_count') == ref['families']
                and entry.get('accepted_service') is False
                and entry.get('accepted_family_count') == 0
                and entry.get('independent_watchdog_armed') is False
                and entry.get('current_smoke_status') == 'NOT_EXECUTED',
                'unearned_role_acceptance_' + role)
