#!/usr/bin/env python3
"""P8-R25: measured SSH client config *source bytes*, never effective config.

Pure functions for public synthetic CI. The operator-only acquisition tool is
separate and cannot run from these functions.
"""
from __future__ import annotations
import hashlib
import json
import re

BASE = 'acf2f68b7687095a50691b93d3c538456b8b9cef'
R24_RECEIPT_SHA = '68747c677b41dea3f5c5329075ddc1a97b1bf8f47d34bc7c07a54be67a5194aa'
R24_MATRIX_SHA = 'e53900abea3d83ef27de6fc77e25d1698788a9616c90f696c5ea5781dbd6c5d2'
IMAGE_SHA = 'fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
ROOT_PATH = '/etc/ssh/ssh_config'
FRAGMENT_DIR = '/etc/ssh/ssh_config.d'
# Single literal exception authenticated by the operator in the frozen image.
ALIAS_NAME = '20-systemd-ssh-proxy.conf'
ALIAS_PATH = FRAGMENT_DIR + '/' + ALIAS_NAME
ALIAS_TARGET = '/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf'
SSH_PROFILES = tuple(f'SSH-T{i:02d}-BASE' for i in range(1, 9))
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.conf\Z')
SHA = re.compile('[0-9a-f]{64}\\Z')
MAX_FILE_BYTES = 262_144
MAX_FRAGMENT_FILES = 32
MAX_TOTAL_BYTES = 1_048_576
MAX_DIRECTORY_ENTRIES = 64

class SourceError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise SourceError('P8_R25_FAIL_CLOSED:' + reason)


def canonical_bytes(v: object, path: str) -> bytes:
    require(type(v) is bytes, 'bytes_required:' + path)
    require(0 < len(v) <= MAX_FILE_BYTES and b'\x00' not in v,
            'nontext_or_invalid_size:' + path)
    try:
        v.decode('utf-8')
    except UnicodeDecodeError as e:
        raise SourceError('P8_R25_FAIL_CLOSED:not_utf8:' + path) from e
    return v


def inspect_directives(raw: bytes) -> dict:
    """Only lexical counts; never evaluates Includes, Host, Match or options."""
    lines = raw.decode('utf-8').splitlines()
    counts = {'include': 0, 'host': 0, 'match': 0}
    for line in lines:
        s = line.lstrip()
        if not s or s.startswith('#'):
            continue
        head = s.split(None, 1)[0].split('=', 1)[0].lower()
        if head in counts:
            counts[head] += 1
    return {'line_count': len(lines), 'lexical_directives': counts}


def normalize_directory_entries(entries: object) -> list[str]:
    require(type(entries) is list and len(entries) <= MAX_DIRECTORY_ENTRIES,
            'directory_entry_limit')
    require(all(type(x) is str for x in entries), 'directory_entry_type')
    require(len(entries) == len(set(entries)), 'duplicate_directory_entry')
    require(all('\x00' not in x and '/' not in x and '\\' not in x and
                x not in ('.', '..') and 0 < len(x) <= 128 for x in entries),
            'unsafe_directory_entry')
    names = sorted(x for x in entries if NAME.fullmatch(x))
    require(len(names) <= MAX_FRAGMENT_FILES, 'fragment_file_limit')
    return names


def normalize_aliases(aliases: object, names: list[str]) -> list[dict]:
    """Only one literal path->target pair; a target is never an effective config claim."""
    require(type(aliases) is dict, 'source_aliases_type')
    require(len(aliases) <= 1, 'source_aliases_limit')
    rows = []
    for path, target in aliases.items():
        require(type(path) is str and type(target) is str and
                path == ALIAS_PATH and target == ALIAS_TARGET and
                ALIAS_NAME in names, 'unexpected_source_alias')
        rows.append({'guest_path': path, 'resolved_regular_path': target})
    return rows


def analyze(root: bytes, fragments: object, entries: object, image_sha: str,
            aliases: object = None) -> dict:
    """Return evidence of observed bytes only, not source precedence or capability."""
    require(image_sha == IMAGE_SHA, 'image_sha_mismatch')
    root = canonical_bytes(root, ROOT_PATH)
    names = normalize_directory_entries(entries)
    alias_rows = normalize_aliases({} if aliases is None else aliases, names)
    require(type(fragments) is dict and list(sorted(fragments)) == names,
            'fragment_directory_mismatch')
    require(all(type(n) is str for n in fragments), 'fragment_name_type')
    total = len(root)
    rows = []
    for name, raw in [(None, root)] + [(n, fragments[n]) for n in names]:
        path = ROOT_PATH if name is None else FRAGMENT_DIR + '/' + name
        raw = canonical_bytes(raw, path)
        total += 0 if name is None else len(raw)
        require(total <= MAX_TOTAL_BYTES, 'total_bytes_limit')
        stats = inspect_directives(raw)
        rows.append({
            'guest_path': path,
            'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(),
            'line_count': stats['line_count'],
            'include_directives_lexical': stats['lexical_directives']['include'],
            'host_directives_lexical': stats['lexical_directives']['host'],
            'match_directives_lexical': stats['lexical_directives']['match'],
        })
    return {
        'schema_version': '1.0',
        'scope': 'PINNED_QCOW2_SSH_CLIENT_CONFIG_SOURCE_BYTES_ONLY',
        'base_main_commit': BASE,
        'image_sha256': IMAGE_SHA,
        'source_files': rows,
        'source_aliases': alias_rows,
        'source_alias_count': len(alias_rows),
        'source_file_count': len(rows),
        'source_bytes_total': total,
        'fragment_file_count': len(names),
        'directory_entries_observed': len(entries),
        'unresolved_include_directive_count': sum(x['include_directives_lexical'] for x in rows),
        'ssh_profile_candidate_count': len(SSH_PROFILES),
        'source_bytes_measured': True,
        'include_graph_resolved': False,
        'effective_client_config_verified': False,
        'effective_loader_verified': False,
        'runtime_binary_identity_verified': False,
        'client_capability_verified': False,
        'case_authorized': False,
        'profiles_approved': 0,
        'cases_authorized': 0,
        'dispatch_allowed': False,
        'guest_binaries_executed': False,
        'guest_services_contacted': False,
        'private_file_contents_stored': False,
        'result': 'MEASURED_OFFLINE_SSH_CONFIG_SOURCE_NOT_EFFECTIVE_CONFIGURATION',
    }


def validate(doc: object) -> dict:
    require(type(doc) is dict, 'receipt_type')
    fields = {'schema_version', 'scope', 'base_main_commit', 'image_sha256',
              'source_files', 'source_aliases', 'source_alias_count',
              'source_file_count', 'source_bytes_total',
              'fragment_file_count', 'directory_entries_observed',
              'unresolved_include_directive_count', 'ssh_profile_candidate_count',
              'source_bytes_measured', 'include_graph_resolved',
              'effective_client_config_verified', 'effective_loader_verified',
              'runtime_binary_identity_verified', 'client_capability_verified',
              'case_authorized', 'profiles_approved', 'cases_authorized',
              'dispatch_allowed', 'guest_binaries_executed',
              'guest_services_contacted', 'private_file_contents_stored', 'result'}
    require(set(doc) == fields, 'receipt_fields')
    require(doc['schema_version'] == '1.0'
            and doc['scope'] == 'PINNED_QCOW2_SSH_CLIENT_CONFIG_SOURCE_BYTES_ONLY'
            and doc['base_main_commit'] == BASE and doc['image_sha256'] == IMAGE_SHA
            and doc['result'] == 'MEASURED_OFFLINE_SSH_CONFIG_SOURCE_NOT_EFFECTIVE_CONFIGURATION',
            'source_identity')
    for k in ('include_graph_resolved', 'effective_client_config_verified',
              'effective_loader_verified', 'runtime_binary_identity_verified',
              'client_capability_verified', 'case_authorized', 'dispatch_allowed',
              'guest_binaries_executed', 'guest_services_contacted',
              'private_file_contents_stored'):
        require(doc[k] is False, 'unsafe_promotion:' + k)
    require(doc['source_bytes_measured'] is True and
            type(doc['profiles_approved']) is int and doc['profiles_approved'] == 0 and
            type(doc['cases_authorized']) is int and doc['cases_authorized'] == 0 and
            type(doc['ssh_profile_candidate_count']) is int and
            doc['ssh_profile_candidate_count'] == 8, 'source_denial')
    rows = doc['source_files']
    require(type(rows) is list and 1 <= len(rows) <= MAX_FRAGMENT_FILES + 1,
            'files_count')
    require(rows[0].get('guest_path') == ROOT_PATH, 'root_first')
    names = [x.get('guest_path') for x in rows[1:]]
    require(all(type(x) is str and x.startswith(FRAGMENT_DIR + '/') and
                NAME.fullmatch(x.removeprefix(FRAGMENT_DIR + '/')) for x in names),
            'fragment_file_path')
    require(names == sorted(set(names)), 'fragment_order')
    alias_rows = doc['source_aliases']
    require(type(alias_rows) is list and len(alias_rows) <= 1 and
            type(doc['source_alias_count']) is int and
            doc['source_alias_count'] == len(alias_rows), 'alias_count_shape')
    for a in alias_rows:
        require(type(a) is dict and set(a) ==
                {'guest_path', 'resolved_regular_path'} and
                a['guest_path'] == ALIAS_PATH and
                a['resolved_regular_path'] == ALIAS_TARGET and
                ALIAS_PATH in names, 'alias_not_exact_or_missing')
    count = 0
    includes = 0
    for row in rows:
        require(type(row) is dict and set(row) ==
                {'guest_path', 'bytes', 'sha256', 'line_count',
                 'include_directives_lexical', 'host_directives_lexical',
                 'match_directives_lexical'}, 'file_row_shape')
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE_BYTES
                and type(row['sha256']) is str and SHA.fullmatch(row['sha256']) is not None,
                'file_bytes_sha')
        require(all(type(row[k]) is int and 0 <= row[k] <= row['bytes'] for k in
                    ('line_count', 'include_directives_lexical',
                     'host_directives_lexical', 'match_directives_lexical')),
                'lexical_counts')
        count += row['bytes']
        includes += row['include_directives_lexical']
    require(type(doc['source_file_count']) is int and doc['source_file_count'] == len(rows)
            and type(doc['fragment_file_count']) is int and
            doc['fragment_file_count'] == len(rows) - 1
            and type(doc['directory_entries_observed']) is int
            and doc['directory_entries_observed'] >= len(rows) - 1
            and doc['directory_entries_observed'] <= MAX_DIRECTORY_ENTRIES
            and type(doc['source_bytes_total']) is int
            and doc['source_bytes_total'] == count <= MAX_TOTAL_BYTES
            and type(doc['unresolved_include_directive_count']) is int
            and doc['unresolved_include_directive_count'] == includes,
            'receipt_counts')
    return doc


def public_contract() -> dict:
    """Pure, invariant-only statement: never claims an operator capture happened."""
    return {
        'status': 'PASS_P8_R25_OFFLINE_SOURCE_ACQUISITION_CONTRACT_ONLY',
        'base_main_commit': BASE,
        'target_profiles': list(SSH_PROFILES),
        'offline_image_sha256_required': IMAGE_SHA,
        'source_root': ROOT_PATH,
        'source_directory': FRAGMENT_DIR,
        'collects_actual_source_bytes_in_ci': False,
        'private_collector_available': True,
        'material_observation_already_performed': False,
        'operational_capability_verified': False,
        'effective_configuration_verified': False,
        'approved_profiles': 0,
        'authorized_cases': 0,
        'dispatch_allowed': False,
    }


def digest_json(v: object) -> str:
    return hashlib.sha256((json.dumps(v, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')) + '\n').encode()).hexdigest()
