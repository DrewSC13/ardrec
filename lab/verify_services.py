#!/usr/bin/env python3
"""Validate the public historical service record; never operate the laboratory."""
import hashlib
import json
import re
from pathlib import Path

BASE = '93e1f4cdaff1bca621214d3a27798889baf03a86'
RECEIPT = '1af109e8d62277b5609c5b8db4535e2b8021b97381b50045b1cda27292787c86'
PROCEDURE = '1d43a43af92d1c1b3176b22657cabeda9ede32c42faead5a29cacc9e8a1ca6f3'
ROLE_RECEIPT = '46f4ceb8adffd5010714d0b365f46f96fc15fc8b8e7cb9585b15c13161890f3b'
CONFIGS = {
    'ssh': '1b65472bfc96892fbb87a9d0496f92b751930f521a23a9a321d5e5fe410e6cae',
    'ftp': '299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8',
    'smb': '7e6b14afc0b3cd01cfe8a4a0e48a2ed32b830f610f9e1144e43056dd96b87ee3',
}
CHECKS = ('ssh-identity ssh-reference ssh-limited-helper ssh-restricted-denied '
          'ssh-write ssh-read-marker ssh-cleanup ftp-cleartext-login-denied '
          'ftps-reference ftps-write ftps-read-marker ftps-cleanup smb-reference '
          'smb-restricted-denied smb-encrypted-write smb-encrypted-read smb-cleanup').split()
MANIFEST = 'docs/traceability/laboratory-services-v1.json'
PREFIX = 'lab/services-v1/'
ARTIFACTS = {
    PREFIX + name for name in ['README.md', 'versions.json', 'resources.json',
                              'evidence.json', 'procedures/activation-r8.py',
                              'config/ssh.conf', 'config/ftp.conf', 'config/smb.conf']
} | {'docs/verification/laboratory-services-v1.md', 'lab/verify_services.py',
     'lab/tests/test_service_record.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def verify(root):
    root = Path(root)
    def read(path):
        p = Path(path)
        require(not p.is_absolute() and '..' not in p.parts, 'Unsafe artifact path')
        target = root / p
        require(target.is_file() and not target.is_symlink(), 'Missing/linked: ' + path)
        require(root.resolve() in target.resolve().parents, 'Escaping artifact path')
        return target.read_bytes()
    def load(path):
        return json.loads(read(path), object_pairs_hook=unique_object)
    m = load(MANIFEST)
    e = load(PREFIX + 'evidence.json')
    d = load('docs/traceability/laboratory-design-v1.json')
    t = load('lab/topology-v1.json')
    v = load(PREFIX + 'versions.json')
    r = load(PREFIX + 'resources.json')
    require(m['schema_version'] == e['schema_version'] == '1.0', 'Schema')
    require(m['baseline_commit'] == e['baseline_commit'] == BASE, 'Base mismatch')
    require(m['source_sha256'] == d['source_sha256'], 'Thesis source mismatch')
    require(m['requirements'] == d['requirements'], 'Requirement scope changed')
    require(m['development_obligations'] == d['development_obligations'], 'Obligations changed')
    require(m['open_findings'] == ['AL-06', 'AL-07'], 'Findings changed')
    for key, expected in {
        'roadmap_step': 4,
        'status': 'DEV_SERVICES_VERIFIED_PENDING_REPOSITORY_INTEGRATION',
        'scope': 'THREE_DEVELOPMENT_SERVICE_BASELINES_NOT_25_OPERATIONAL_CASES',
        'requirement_claim': 'SUPPORTING_COMPONENT_EVIDENCE_NOT_FULL_REQUIREMENT_ACCEPTANCE',
        'experimental_validation': 'NOT_RUN', 'system_functional_acceptance': 'PENDING',
        'real_executor_gate': 'BLOCKED_BY_RESIDUAL_OBLIGATIONS',
        'point5': 'RESTORATION_AND_PHYSICAL_ISOLATION_VERIFICATION_PENDING',
        'physical_verification_plan': 'HISTORICAL_PLAN_PRESERVED_NO_BLANKET_PASS',
        'lab_v01': 'PARTIAL_DEV_THREE_NETWORKS_OBSERVED_NOT_ALL_NINE_OR_DYNAMIC_VPN_POOLS',
        'artifact_state': 'V4_READ_ONLY_BASES_PLUS_STOPPED_V6_RUNTIME_OVERLAYS_NOT_RESTORATION_SEALED_TEMPLATES',
    }.items():
        require(m[key] == expected, 'Unreviewed scope: ' + key)
    require(e['source_receipt_sha256'] == RECEIPT, 'Receipt mismatch')
    require(e['procedure_sha256'] == PROCEDURE, 'Procedure mismatch')
    require(e['role_receipt_sha256'] == ROLE_RECEIPT, 'Role receipt mismatch')
    require(sha(read(PREFIX + 'procedures/activation-r8.py')) == PROCEDURE, 'Procedure bytes changed')
    require(set(m['artifact_sha256']) == ARTIFACTS, 'Artifact inventory mismatch')
    for path, expected in m['artifact_sha256'].items():
        require(sha(read(path)) == expected, 'Artifact hash mismatch: ' + path)
    for path in m['documents']:
        require(path in ARTIFACTS, 'Untracked document')
    require(set(m['configurations']) == set(CONFIGS), 'Configuration roles')
    for role, digest in CONFIGS.items():
        c = m['configurations'][role]
        require(c['repository_path'] == PREFIX + 'config/' + role + '.conf', 'Config path')
        require(c['sha256'] == digest == sha(read(c['repository_path'])), 'Config differs from physical run')
    require(e['ftp_config_sha256'] == CONFIGS['ftp'], 'FTP correction missing')
    require(e['status'] == 'RECORDED_HOST_SERVICE_SMOKE_PASS', 'Evidence status')
    require(e['environment'] == r['environment'] == 'dev', 'Environment mismatch')
    require(e['experimental_data'] is False and e['forced_stop'] is False, 'False experiment/cleanup claim')
    require(set(e['cleanup']) == {'all_created_domains_stopped', 'created_networks_removed',
            'dedicated_firewall_removed', 'reused_bases_unchanged', 'previous_ftp_runtime_unchanged'}, 'Cleanup fields')
    require(all(x is True for x in e['cleanup'].values()), 'Incomplete cleanup')
    require([x['check'] for x in e['checks']] == CHECKS, 'Physical check inventory')
    for check in e['checks']:
        require(check['result'] == 'PASS', 'Failed physical check')
        if check['check'] == 'ftp-cleartext-login-denied':
            require(set(check) == {'check', 'result'}, 'Unexpected cleartext fields')
        else:
            require(set(check) == {'check', 'result', 'exit_code', 'output_sha256'}, 'Unexpected check fields')
            expected = 1 if check['check'] in ('ssh-restricted-denied', 'smb-restricted-denied') else 0
            require(type(check['exit_code']) is int and check['exit_code'] == expected, 'Invalid result code')
            require(re.fullmatch('[0-9a-f]{64}', check['output_sha256']) is not None, 'Invalid evidence hash')
    guests = e['guest_checks']
    require(set(guests) == {'ssh', 'ftp', 'smb', 'runner'}, 'Guest inventory')
    networks = {n['protocol']: n for n in t['networks'] if n['environment'] == 'dev'}
    for role, guest in guests.items():
        addresses = sorted(n['runner'] for n in networks.values()) if role == 'runner' else [networks[role]['target']]
        require(sorted(guest['addresses']) == addresses, 'Address/topology mismatch')
        for key, expected in {'identity': 'PASS', 'config_hashes': 'PASS',
                'default_routes': 'ABSENT', 'forwarding': 'DISABLED',
                'guest_firewall': 'ACTIVE_DEFAULT_DROP', 'boot_files': 'VERIFIED_AFTER_BOOT'}.items():
            require(guest[key] == expected, 'Guest check: ' + key)
        if role != 'runner':
            require(guest['listener_status'] == 'READY_STABLE_LISTENER' and guest['stable_samples'] == 3, 'Unstable service')
            require(guest['temporary_directory'] == 'EMPTY', 'Temporary resources remain')
            endpoint = {'ssh': '0.0.0.0:22', 'ftp': '10.203.31.2:21', 'smb': '10.203.32.2:445'}[role]
            require(guest['endpoint'] == endpoint, 'Unexpected listener')
    packages = v['guest_packages']
    for name, version in {'openssh-server': '1:10.0p1-7+deb13u4', 'vsftpd': '3.0.5-0.2',
                          'samba': '2:4.22.11+dfsg-0+deb13u1'}.items():
        require(packages[name] == version, 'Package mismatch')
    require(v['provisioning']['ansible_service_application'] == 'NOT_RUN', 'Unsubstantiated Ansible claim')
    require(v['provisioning']['actual_method'] == 'OFFLINE_VIRT_CUSTOMIZE_EXPLICIT_PYTHON', 'Provisioning mismatch')
    require([a['role'] for a in r['targets']] == ['ssh', 'ftp', 'smb'], 'Account inventory')
    for a in r['targets']:
        require(a['username'] == a['temporary_owner'] == 'ardrec_' + a['role'], 'Synthetic account mismatch')
        require(a['temporary_mode'] == a['restricted_directory_mode'] == '0700', 'Resource permissions')
        require(a['credential'] == 'PRIVATE_SYNTHETIC_UNIQUE_PER_ROLE', 'Credential custody')
    workflow = read('.github/workflows/ci.yml').decode()
    require(workflow.count('run: python3 lab/verify_services.py') == 1, 'Missing/duplicate CI step')
    require(workflow.count('run: python3 -m unittest discover -s lab/tests -p test_service_record.py -v') == 1, 'Missing/duplicate laboratory suite CI step')
    require(workflow.count('run: python3 lab/verify_design.py') == 1, 'Historical design CI removed')
    return {'status': 'PASS_PUBLIC_RECORD_CONSISTENCY_ONLY', 'recorded_host_checks': 17,
            'physical_tests_rerun': False, 'system_acceptance': 'PENDING',
            'experimental_validation': 'NOT_RUN'}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(Path(__file__).resolve().parents[1]), indent=2))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        raise SystemExit('ARDREC_SERVICE_RECORD=FAIL: ' + str(exc))
