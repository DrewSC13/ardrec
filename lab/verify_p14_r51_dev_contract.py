#!/usr/bin/env python3
"""R51: comprobación de tres fichas DEV y 25 familias sin contactar el host.

La autoridad técnica (A6/A9), la contención R34 y el despacho P8 permanecen NO-GO.
No modifica archivos, ejecuta procesos, accede a VM o interpreta silencio como negativa.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re

MANIFEST = 'lab/p14-r51-dev-three-services-v1/manifest.json'
SCHEMA = 'ardrec-p14-r51-dev-three-services-v1'
ROLES = ('ssh', 'ftp', 'smb')
COUNTS = {'ssh': 8, 'ftp': 8, 'smb': 9, 'total': 25}
CONFIG_SHA = {
    'ssh': '1b65472bfc96892fbb87a9d0496f92b751930f521a23a9a321d5e5fe410e6cae',
    'ftp': '299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8',
    'smb': '7e6b14afc0b3cd01cfe8a4a0e48a2ed32b830f610f9e1144e43056dd96b87ee3',
}
VERSIONS = {
    'ssh': ('openssh-server', '1:10.0p1-7+deb13u4'),
    'ftp': ('vsftpd', '3.0.5-0.2'),
    'smb': ('samba', '2:4.22.11+dfsg-0+deb13u1'),
}
PORTS = {'ssh': 22, 'ftp': 21, 'smb': 445}
HISTORIC_EVIDENCE = '1af109e8d62277b5609c5b8db4535e2b8021b97381b50045b1cda27292787c86'
DOMAIN = 'ardrec-r33-dev-'
PREFIX = 'ardrec-r33-dev-net-'

class ContractError(ValueError):
    pass

def must(ok: bool, reason: str) -> None:
    if not ok:
        raise ContractError(reason)

def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        must(key not in obj, 'json_duplicate_key')
        obj[key] = value
    return obj

def no_constant(x):
    raise ContractError('json_nonfinite')

def parse(raw: bytes):
    must(type(raw) is bytes and 0 < len(raw) <= 1_000_000, 'source_length_invalid')
    try:
        return json.loads(raw, object_pairs_hook=unique_pairs, parse_constant=no_constant)
    except ContractError:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ContractError('source_json_invalid') from exc

def secure_read(root: Path, path: str) -> bytes:
    must(type(path) is str and bool(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9/_.-]{0,239}', path)), 'path_invalid')
    relative = Path(path)
    must(not relative.is_absolute() and '..' not in relative.parts, 'path_escape')
    current = root
    for part in relative.parts:
        current = current / part
        must(not current.is_symlink(), 'symlink_not_allowed')
    must(current.is_file(), 'source_missing_' + path)
    must(root.resolve() in current.resolve().parents, 'path_outside_repository')
    must(current.stat().st_size <= 1_000_000, 'source_too_large')
    return current.read_bytes()

def valid(root: Path, manifest: dict, catalog: dict, topology: dict, resources: dict,
          versions: dict, evidence: dict, configs: dict[str, bytes]) -> dict:
    must(type(manifest) is dict and manifest.get('schema') == SCHEMA, 'manifest_schema')
    fixed = {
        'baseline_git_head': '8719ab89d78876028c07186428a0b7044e5ca006',
        'source_main': 'f59d7ace03aa6ff296b3f425e14a38c005610ecc',
        'environment': 'dev',
        'purpose': 'OFFLINE_SOURCE_AND_COVERAGE_RECONCILIATION',
        'source_status': 'NOT_HOST_ATTESTATION',
        'r34_live_containment': 'NOT_VERIFIED',
        'live_guest_configuration': 'NOT_VERIFIED',
        'p8_operational': 'NO-GO',
        'historical_service_receipt_sha256': HISTORIC_EVIDENCE,
        'frozen_experimental_units': 0,
        'real_derived_cases': 0,
    }
    for key, target in fixed.items():
        must(type(manifest.get(key)) is type(target) and manifest[key] == target, 'manifest_' + key)
    for name, target in {
        'stage_manifest_v1_unchanged': True, 'operational_dispatch': False,
        'automated_host_changes': False, 'lab_ssh_ftp_smb_fully_accepted': False,
        'development_data_only': True,
    }.items():
        must(manifest.get(name) is target, 'unauthorized_claim_' + name)
    must(manifest.get('counts') == COUNTS, 'catalog_counts')
    must(manifest.get('residual_findings') == ['AL-06', 'AL-07'], 'findings_unjustified_closure')
    must(type(manifest.get('required_before_any_physical_run')) is list and
         len(manifest['required_before_any_physical_run']) == 7 and
         len(set(manifest['required_before_any_physical_run'])) == 7, 'physical_guard_inventory')
    must(manifest.get('catalog_path') == 'lab/operational-catalog-v1/catalog.json' and
         manifest.get('topology_path') == 'lab/topology-v1.json' and
         manifest.get('resource_path') == 'lab/services-v1/resources.json' and
         manifest.get('version_path') == 'lab/services-v1/versions.json' and
         manifest.get('evidence_path') == 'lab/services-v1/evidence.json', 'source_reference_drift')
    must(type(catalog) is dict and catalog.get('counts') == COUNTS and
         catalog.get('status') == 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         catalog.get('execution_enabled') is False and
         catalog.get('catalog_frozen') is False and
         catalog.get('derived_real_cases') == 0, 'catalog_false_operational_state')
    must(type(catalog.get('families')) is list and len(catalog['families']) == 25, 'catalog_family_count')
    catalog_ids = [f.get('id') for f in catalog['families'] if type(f) is dict]
    expected_ids = {f'{r.upper()}-T{i:02d}' for r in ROLES for i in range(1, COUNTS[r] + 1)}
    must(len(catalog_ids) == 25 and set(catalog_ids) == expected_ids, 'catalog_family_identity')
    must(type(topology) is dict and topology.get('runner_forwarding') is False and
         topology.get('target_to_target') is False and
         topology.get('internet_during_measurement') is False and
         topology.get('management_nic_during_measurement') is False and
         topology.get('default_policy') == 'DENY', 'topology_deny_first_drift')
    must(type(topology.get('networks')) is list, 'topology_networks_missing')
    must(type(resources) is dict and type(resources.get('targets')) is list, 'resources_missing')
    must(type(versions) is dict and type(versions.get('guest_packages')) is dict, 'versions_missing')
    must(type(evidence) is dict and evidence.get('status') == 'RECORDED_HOST_SERVICE_SMOKE_PASS' and
         evidence.get('source_receipt_sha256') == HISTORIC_EVIDENCE and
         evidence.get('environment') == 'dev' and evidence.get('experimental_data') is False,
         'historical_evidence_mismatch')
    must(type(evidence.get('checks')) is list and len(evidence['checks']) == 17 and
         all(type(x) is dict and x.get('result') == 'PASS' for x in evidence['checks']),
         'historical_checks_invalid')
    checks = [x['check'] for x in evidence['checks']]
    must(len(set(checks)) == 17, 'duplicate_historical_check')
    must(type(manifest.get('units')) is list and len(manifest['units']) == 3,
         'dev_unit_count')
    projected = []
    seen_units: set[str] = set()
    seen_families: set[str] = set()
    for index, role in enumerate(ROLES):
        unit = manifest['units'][index]
        must(type(unit) is dict and unit.get('protocol') == role, 'unit_order_or_protocol')
        must(unit.get('unit_id') == f'DEV-{role.upper()}-001' and
             unit['unit_id'] not in seen_units, 'unit_identity')
        seen_units.add(unit['unit_id'])
        must(unit.get('environment') == 'dev' and
             unit.get('purpose') == 'DEVELOPMENT_ONLY_NOT_EXPERIMENTAL' and
             unit.get('service_scenario_status') == 'PROVISIONAL_SOURCE_DERIVED_NOT_FROZEN',
             'unit_experiment_promotion')
        for field, target in {'network_id': f'ardrec-dev-{role}',
                              'libvirt_target_domain': DOMAIN + role,
                              'libvirt_network_name': PREFIX + role,
                              'libvirt_runner_domain': DOMAIN + 'runner',
                              'synthetic_username': 'ardrec_' + role,
                              'server_tcp_port': PORTS[role]}.items():
            must(type(unit.get(field)) is type(target) and unit[field] == target,
                 'unit_' + field)
        topo = [x for x in topology['networks'] if x.get('environment') == 'dev' and x.get('protocol') == role]
        must(len(topo) == 1, 'topology_role_conflict')
        net = topo[0]
        for attr, topoattr in [('expected_network_cidr', 'cidr'), ('expected_runner_ip', 'runner'),
                              ('expected_target_ip', 'target')]:
            must(unit.get(attr) == net.get(topoattr), 'network_mismatch_' + attr)
        cidr = ipaddress.ip_network(unit['expected_network_cidr'], strict=True)
        must(cidr.version == 4 and cidr.prefixlen == 28 and
             ipaddress.ip_address(unit['expected_runner_ip']) in cidr and
             ipaddress.ip_address(unit['expected_target_ip']) in cidr and
             unit['expected_runner_ip'] != unit['expected_target_ip'], 'network_policy_invalid')
        for property_name in ('forward', 'host_ip', 'physical_uplink', 'default_gateway'):
            must(net.get(property_name) is None, 'network_route_escape')
        for property_name in ('dhcp', 'dns', 'ipv6'):
            must(net.get(property_name) is False, 'network_extra_service')
        account = [x for x in resources['targets'] if x.get('role') == role]
        must(len(account) == 1 and account[0].get('username') == unit['synthetic_username'] and
             account[0].get('credential') == 'PRIVATE_SYNTHETIC_UNIQUE_PER_ROLE',
             'synthetic_account_drift')
        package, pversion = VERSIONS[role]
        must(unit.get('expected_guest_package') == package and
             unit.get('expected_guest_version') == pversion and
             versions['guest_packages'].get(package) == pversion, 'package_source_drift')
        cpath = f'lab/services-v1/config/{role}.conf'
        must(unit.get('config_source_path') == cpath and
             unit.get('config_source_sha256') == CONFIG_SHA[role] and
             hashlib.sha256(configs[role]).hexdigest() == CONFIG_SHA[role],
             'service_config_changed_' + role)
        must(unit.get('historical_service_record') == 'lab/services-v1/evidence.json' and
             unit.get('historical_checks_only') is True, 'historical_scope_extended')
        for property_name in ('effective_guest_state_now', 'r34_containment_now', 'runner_pair_now'):
            must(unit.get(property_name) == 'NOT_VERIFIED', 'unearned_host_confirmation')
        must(unit.get('cases') == [] and unit.get('admitted_evidence') == [] and
             unit.get('confirmed_generation') is None and unit.get('recalibrated_risk') is None,
             'unearned_A6_A9_or_risk')
        entries = unit.get('case_families')
        must(type(entries) is list and len(entries) == COUNTS[role], 'unit_family_inventory')
        for i, entry in enumerate(entries, 1):
            fid = f'{role.upper()}-T{i:02d}'
            must(type(entry) is dict and entry.get('family_id') == fid and
                 fid in expected_ids and fid not in seen_families, 'family_duplicate_or_mismatch')
            seen_families.add(fid)
            must(entry.get('coverage') in ('PENDING', 'PARTIAL') and
                 entry.get('case_executable') is False and
                 entry.get('effective_case_verified') is False and
                 entry.get('evidence_admitted_by_A6') is False, 'family_false_acceptance')
            subset = entry.get('historical_smoke_checks')
            must(type(subset) is list and len(set(subset)) == len(subset) and
                 set(subset).issubset(checks) and
                 all(x.startswith('ssh-') if role == 'ssh' else
                     x.startswith(('ftp-', 'ftps-')) if role == 'ftp' else
                     x.startswith('smb-') for x in subset), 'family_smoke_cross_scope')
            must((entry['coverage'] == 'PARTIAL') is bool(subset), 'coverage_without_historical_support')
        projected.append({'unit_id': unit['unit_id'], 'protocol': role,
                          'families': len(entries),
                          'partial_historical': sum(x['coverage'] == 'PARTIAL' for x in entries),
                          'pending': sum(x['coverage'] == 'PENDING' for x in entries),
                          'effective_acceptance': 'PENDING_NO_GO'})
    must(seen_families == expected_ids, 'family_coverage_incomplete')
    return {
        'r51_result': 'PASS_OFFLINE_CONSISTENCY_ONLY',
        'environment': 'dev', 'units': projected,
        'families_total': len(seen_families),
        'complete_family_acceptance': 0,
        'confirmed_live_services': 0, 'host_queried': False,
        'operational_dispatch': False, 'p8_operational': 'NO-GO',
        'scientific_sample_n': 0,
        'next_gate': 'R34_AND_LIVE_HOST_OPERATOR_INSPECTION_REQUIRED',
        'manifest_sha256': hashlib.sha256(secure_read(root, MANIFEST)).hexdigest(),
    }

def verify(root: Path) -> dict:
    root = Path(root)
    must(root.is_dir() and not root.is_symlink(), 'repository_root_invalid')
    m = parse(secure_read(root, MANIFEST))
    catalog = parse(secure_read(root, m['catalog_path']))
    topology = parse(secure_read(root, m['topology_path']))
    resources = parse(secure_read(root, m['resource_path']))
    versions = parse(secure_read(root, m['version_path']))
    evidence = parse(secure_read(root, m['evidence_path']))
    configs = {role: secure_read(root, f'lab/services-v1/config/{role}.conf') for role in ROLES}
    return valid(root, m, catalog, topology, resources, versions, evidence, configs)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.repo), indent=2, ensure_ascii=False, sort_keys=True))
    except (ContractError, KeyError, TypeError, IndexError, OSError, ValueError) as e:
        raise SystemExit('R51_DEV_CONTRACT=FAIL:' + str(e))
