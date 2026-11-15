"""R55.3: exact, OFFLINE transition contract and adversarial gate.

No subprocess, privileged operation, packet injection or host mutation.
A bounded physical operator is deliberately NOT exposed until an independent
recovery/watchdog and a recovery-under-failure experiment have been implemented.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from xml.etree import ElementTree as ET

SCHEMA = 'ardrec-p14-r553-transition-guard-v1'
SOURCE_HEAD = 'e1c2083a30343b22d602e3368a631377133b6478'
PLAN_SHA256 = 'b32855a66b5a7df8960e29c805a17f11b2e3b9902cd53ba8a44d6193b5fe33eb'
R551_SHA256 = '86169dc120e5e6d182d0ba24bcd3eb002e4ba68a4e0e716c5e630876b3d02e7e'
D1_SHA256 = 'fb8989b441f20968c4c6649d4a7782f8705c8f7d04b87921228a7e1d74755e8d'
DENY = 'ardrec-r33-block-until-containment'
TABLE = 'ardrec_r34_guard'
NETWORK = 'ardrec-r33-dev-net-ssh'
GUESTS = {
    'ssh': ('ardrec-r33-dev-ssh', 'a33d30t', '52:54:00:ad:30:02', '10.203.30.2',
            'ardrec-r45-ssh-icmp-candidate'),
    'runner': ('ardrec-r33-dev-runner', 'a33d30r', '52:54:00:ad:30:01', '10.203.30.1',
               'ardrec-r45-runner-icmp-candidate'),
}
TAPS = ('a33d30r', 'a33d30t', 'a33d31r', 'a33d31t', 'a33d32r', 'a33d32t')
FILES = frozenset({
    'ssh-binding-original.xml', 'ssh-binding-candidate.xml',
    'runner-binding-original.xml', 'runner-binding-candidate.xml',
    'nft-arp-icmp-NOT-AUTHORIZED.nft',
    'nft-deny-restore-NOT-EXECUTED.nft', 'commands.json',
    'plan.json', 'SHA256SUMS',
})
SHA = re.compile(r'[0-9a-f]{64}\Z')
FILENAME = re.compile(r'[A-Za-z0-9_.-]+\Z')


class TransitionGuardError(ValueError):
    """Fail-closed R55.3 rejection."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise TransitionGuardError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _pairs(rows):
    d = {}
    for key, value in rows:
        require(key not in d, 'duplicate_json_key')
        d[key] = value
    return d


def parse_json(raw: bytes):
    require(type(raw) is bytes and len(raw) <= 512000, 'json_size_invalid')
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: require(False, 'json_nonfinite'))
    except TransitionGuardError:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise TransitionGuardError('json_invalid') from exc


def verify_private_receipt(root: Path) -> dict[str, bytes]:
    """Authenticate exact, owner-private, non-symlink, immutable-file inventory."""
    require(isinstance(root, Path) and root.is_absolute(), 'receipt_path_invalid')
    for part in (root, *root.parents):
        require(not part.is_symlink(), 'receipt_symlink_component')
    info = root.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o700, 'receipt_directory_mode')
    require({p.name for p in root.iterdir()} == FILES, 'receipt_file_set_invalid')
    contents = {}
    for filename in FILES:
        p = root / filename
        st = p.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and
                st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600 and
                st.st_size <= 512000, 'receipt_file_insecure_' + filename)
        contents[filename] = p.read_bytes()
    manifest = contents['SHA256SUMS'].decode('ascii').splitlines()
    expected = {digest(contents[n]): n for n in FILES - {'SHA256SUMS'}}
    require(len(expected) == len(FILES) - 1, 'receipt_duplicate_content_digest')
    entries = {}
    for line in manifest:
        require(len(line) >= 67 and line[64:66] == '  ' and
                SHA.fullmatch(line[:64]) is not None, 'sha256_manifest_format')
        name = line[66:]
        require(FILENAME.fullmatch(name) is not None and
                name in FILES - {'SHA256SUMS'} and name not in entries,
                'sha256_manifest_filename')
        entries[name] = line[:64]
    require(set(entries) == FILES - {'SHA256SUMS'} and
            all(entries[name] == digest(contents[name]) for name in entries),
            'sha256_manifest_mismatch')
    require(digest(contents['plan.json']) == PLAN_SHA256, 'r552_f1_plan_hash_changed')
    return contents


def _nodes(raw: bytes):
    require(type(raw) is bytes and len(raw) <= 32768 and
            b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw,
            'binding_xml_size_or_entities')
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise TransitionGuardError('binding_xml_invalid') from exc


def _element(parent, tag, attributes=None):
    rows = [e for e in parent if e.tag == tag]
    require(len(rows) == 1, 'binding_required_child_' + tag)
    row = rows[0]
    if attributes is not None:
        require(row.attrib == attributes, 'binding_attribute_drift_' + tag)
    return row


def binding_identity(raw: bytes, *, role: str, candidate: bool) -> tuple:
    require(role in GUESTS, 'unknown_role')
    name, tap, mac, ip, offered = GUESTS[role]
    root = _nodes(raw)
    require(root.tag == 'filterbinding' and not root.attrib and
            [e.tag for e in root] ==
            ['owner', 'portdev', 'mac', 'filterref', 'backend'],
            'binding_topology_invalid')
    owner = _element(root, 'owner', {})
    require([e.tag for e in owner] == ['name', 'uuid'] and
            owner.findtext('name') == name and
            owner.find('name').attrib == {} and
            owner.find('uuid').attrib == {}, 'binding_owner_drift')
    owner_uuid = owner.findtext('uuid')
    require(type(owner_uuid) is str and
            re.fullmatch(r'[0-9a-fA-F-]{36}', owner_uuid) is not None,
            'binding_owner_uuid_invalid')
    require(_element(root, 'portdev', {'name': tap}).text in (None, ''),
            'binding_portdev_text')
    require(_element(root, 'mac', {'address': mac}).text in (None, ''),
            'binding_mac_text')
    ref = _element(root, 'filterref', {'filter': offered if candidate else DENY})
    require(len(ref) == 1 and ref[0].tag == 'parameter' and
            ref[0].attrib == {'name': 'MAC', 'value': mac} and
            len(ref[0]) == 0 and not (ref[0].text or '').strip(),
            'binding_mac_parameter_drift')
    backend = _element(root, 'backend', {'name': 'iptables'})
    require(len(backend) == 0 and not (backend.text or '').strip(),
            'binding_backend_invalid')
    return (owner_uuid, name, tap, mac, ip, offered)


def expected_nft(*, allow: bool) -> bytes:
    """Recreate R55.2-F1 script EXACTLY; no external input interpolated."""
    taps = ', '.join('"' + t + '"' for t in sorted(TAPS))
    def rule(chain, expression):
        return f'add rule bridge {TABLE} {chain} {expression}'
    rows = [
        f'flush table bridge {TABLE}',
        rule('input', f'iifname {{ {taps} }} counter drop'),
        rule('output', f'oifname {{ {taps} }} counter drop'),
    ]
    if allow:
        s = GUESTS['ssh']; r = GUESTS['runner']
        rows += [
          rule('forward', f'iifname "{s[1]}" oifname "{r[1]}" ether saddr {s[2]} ether type arp arp operation request arp saddr ip {s[3]} arp daddr ip {r[3]} counter accept'),
          rule('forward', f'iifname "{r[1]}" oifname "{s[1]}" ether saddr {r[2]} ether type arp arp operation reply arp saddr ip {r[3]} arp daddr ip {s[3]} counter accept'),
          rule('forward', f'iifname "{s[1]}" oifname "{r[1]}" ether saddr {s[2]} ether daddr {r[2]} ip saddr {s[3]} ip daddr {r[3]} icmp type echo-request counter accept'),
          rule('forward', f'iifname "{r[1]}" oifname "{s[1]}" ether saddr {r[2]} ether daddr {s[2]} ip saddr {r[3]} ip daddr {s[3]} icmp type echo-reply counter accept'),
        ]
    rows += [
        rule('forward', f'iifname {{ {taps} }} counter drop'),
        rule('forward', f'oifname {{ {taps} }} counter drop'),
    ]
    return ('\n'.join(rows) + '\n').encode('ascii')


def verify_plan(files: dict[str, bytes]) -> dict:
    plan = parse_json(files['plan.json'])
    require(type(plan) is dict and
            plan.get('schema') == 'ardrec-r552-f1-transition-plan-v1' and
            plan.get('status') == 'TRANSITION_CANDIDATES_VERIFIED_OFFLINE_ONLY' and
            plan.get('source_commit') == SOURCE_HEAD and
            plan.get('r551_sha256') == R551_SHA256 and
            plan.get('d1_sha256') == D1_SHA256 and
            plan.get('host_mutations') == 0 and
            plan.get('restoration_executed') is False and
            plan.get('operational_dispatch') is False and
            plan.get('p8_operational') == 'NO-GO',
            'plan_semantics_invalid')
    binds = plan.get('bindings')
    require(type(binds) is dict and set(binds) == set(GUESTS),
            'plan_bindings_missing')
    for role in GUESTS:
        old = files[f'{role}-binding-original.xml']
        new = files[f'{role}-binding-candidate.xml']
        previous_id = binding_identity(old, role=role, candidate=False)
        next_id = binding_identity(new, role=role, candidate=True)
        require(previous_id == next_id, 'binding_unexpected_change_' + role)
        require(ET.tostring(_nodes(old)) != ET.tostring(_nodes(new)),
                'binding_candidate_no_change')
        b = binds[role]
        require(type(b) is dict and
                b.get('original_sha256') == digest(old) and
                b.get('candidate_sha256') == digest(new) and
                b.get('parameter') == {'name': 'MAC', 'value': GUESTS[role][2]} and
                b.get('backend') == 'iptables',
                'binding_digest_or_metadata_invalid_' + role)
    for filename, allow, digest_key in (
        ('nft-arp-icmp-NOT-AUTHORIZED.nft', True, 'nft_candidate_sha256'),
        ('nft-deny-restore-NOT-EXECUTED.nft', False, 'nft_restore_sha256'),
    ):
        raw = files[filename]
        require(raw == expected_nft(allow=allow) and
                digest(raw) == plan.get(digest_key),
                'nft_policy_not_exact_' + digest_key)
        require(b'flush ruleset' not in raw and b'delete table' not in raw and
                b'10.203.31.' not in raw and b'10.203.32.' not in raw,
                'nft_forbidden_scope')
    require(plan.get('xml_schema_validation') is True and
            plan.get('nft_syntax_validation') is True and
            plan.get('guest_traffic_generated') is False,
            'unverified_preparation')
    return plan


STAGES = (
    'BASE_DENY',
    'BINDINGS_CANDIDATE_R34_DENY',
    'BOUNDED_ALLOW',
    'R34_RESTORED_DENY',
    'ALL_ORIGINAL_DENY',
)


def simulate(*, gate_verified: bool, fault_at: str | None = None) -> dict:
    """Pure dry-run of guarded stages. Not evidence of a physical restoration."""
    require(fault_at in STAGES or fault_at is None, 'fault_stage_invalid')
    events = []
    stage = STAGES[0]
    for target in STAGES:
        if target == 'BOUNDED_ALLOW':
            require(gate_verified, 'independent_watchdog_missing')
        if fault_at == target:
            events.append({'stage': stage, 'fault': target})
            return {'status': 'REVIEW_REQUIRED_NO_GO', 'stage': stage,
                    'events': events, 'physical_write': False,
                    'restoration_tested': False, 'p8_operational': 'NO-GO'}
        stage = target
        events.append({'stage': stage})
    return {'status': 'DRY_RUN_COMPLETE_NO_GO', 'stage': stage,
            'events': events, 'physical_write': False,
            'restoration_tested': False, 'p8_operational': 'NO-GO'}


def plan_contract(files: dict[str, bytes]) -> dict:
    report = verify_plan(files)
    return {
        'schema': SCHEMA,
        'status': 'SOURCE_AND_STATE_MACHINE_VERIFIED_NO_PHYSICAL_AUTHORITY',
        'source_commit': SOURCE_HEAD,
        'r552_plan_sha256': PLAN_SHA256,
        'bindings': sorted(GUESTS),
        'nft_allow_sha256': report['nft_candidate_sha256'],
        'nft_restore_sha256': report['nft_restore_sha256'],
        'stages': list(STAGES),
        'mandatory_for_physical_operation': [
            'independent_verified_watchdog_or_kernel_expiry',
            'live_storage_and_identity_preflight',
            'exclusive_maintenance_lock',
            'deny_first_during_both_binding_replacements',
            'restore_nft_deny_before_binding_restoration',
            'bounded_positive_and_negative_packet_witness',
            'adversarial_physical_rollback_evidence',
            'separate_maintenance_authorization',
        ],
        'no_shell_host_execution': True,
        'host_mutations': 0,
        'guest_packets': 0,
        'watchdog_armed': False,
        'physical_rollback_tested': False,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
