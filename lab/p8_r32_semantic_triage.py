#!/usr/bin/env python3
"""P8-R32: fail-closed, documentary semantic-review queue, NOT a semantic verdict.

Pure functions only. Verify all R31 excerpt identities, then classify lexical leads
and produce source-linked, unanswered review questions. No program execution,
network, file access, commands, secrets, CLI permission or argv rendering here.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import re

R31_PRIVATE_SHA = '8f26fb577e2f744b2f7a67d0aaf8970f427a9f749fdd530996f26cea44d99542'
R31_BASE_SHA = 'e7caa5c49cebb3c7258c07bbfe72d802da2ae64b'
R32_BASE_SHA = '3a236a74da1b88f1e9485e3a6de82064592a04fa'
R14_FULL_SHA = '2968e57fc65554735cef5ad349ec8a159dcc42fae3b0f05a653b2df0b20af365'
R14_ANCHOR_SHA = '6b22b5ae82a3af897516a3c7eb5f37c7bff71ad7a6f2d9382de10b2855fccfb4'
MAX_RECEIPT_SIZE = 450000
HEX64 = re.compile(r'^[0-9a-f]{64}$', re.ASCII)

QUESTIONS = (
    'SCOPE_AND_OPERATION_SEMANTICS',
    'INPUT_ARGUMENT_SYNTAX_AND_PRECEDENCE',
    'DEFAULTS_ENVIRONMENT_AND_CONFIG_IMPORT',
    'AUTHENTICATION_AND_SECRET_HANDLING',
    'TLS_SIGNING_ENCRYPTION_AND_DOWNGRADE',
    'NETWORK_SIDE_EFFECTS_AND_REMOTE_COMMANDS',
    'DATA_READ_WRITE_DELETE_AND_ROLLBACK',
    'BOUNDS_ERRORS_AND_EXTERNAL_PROOF_NEEDED',
)
# These are byte-level search hints, NOT evidence that a feature exists or is safe.
LEXICAL_HINTS = {
    'AUTHENTICATION': (b'password', b'credential', b'kerberos', b'authenticat', b'user name'),
    'CONFIGURATION': (b'config', b'option', b'environment', b'variable'),
    'EXECUTION_SURFACE': (b'command', b'shell', b'exec', b'quote'),
    'FILE_MUTATION': (b'upload', b'write', b'delet', b'remove', b'put ', b'create'),
    'FILE_READ': (b'download', b' read', b'get ', b'list', b'directory'),
    'NETWORK_ROUTING': (b'proxy', b'connect', b'passive', b'port'),
    'RESOURCE_BOUNDS': (b'timeout', b'limit', b'rate', b'size'),
    'TRANSPORT_PROTECTION': (b'tls', b'ssl', b'certificat', b'encrypt', b'sign', b'insecure'),
}
HIGH_ATTENTION = frozenset({
    'curl.1.gz:--config', 'curl.1.gz:--insecure', 'curl.1.gz:--proxy',
    'curl.1.gz:--ftp-ssl-ccc', 'curl.1.gz:--ftp-ssl-control',
    'curl.1.gz:--upload-file', 'curl.1.gz:--quote', 'curl.1.gz:--user',
    'smbclient.1.gz:--command', 'smbclient.1.gz:--authentication-file',
    'smbclient.1.gz:--configfile', 'smbclient.1.gz:--user',
    'smbclient.1.gz:--use-kerberos', 'smbclient.1.gz:put',
    'smbclient.1.gz:del', 'rpcclient.1.gz:--command',
})

class Denied(ValueError):
    pass

def need(value, reason):
    if not value:
        raise Denied('P8_R32_DENY:' + reason)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def exact(obj, keys, label):
    need(type(obj) is dict and set(obj) == set(keys), 'exact_fields_' + label)

def clean_json(raw: bytes):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_RECEIPT_SIZE, 'receipt_size')
    need(digest(raw) == R31_PRIVATE_SHA, 'r31_private_receipt_digest')
    def no_pairs_duplicates(pairs):
        d = {}
        for key, value in pairs:
            need(key not in d, 'duplicate_json_key')
            d[key] = value
        return d
    def no_constant(value):
        raise Denied('P8_R32_DENY:invalid_json_constant')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=no_pairs_duplicates, parse_constant=no_constant)

def audit_r31(raw: bytes, anchors, expected_sha: str = R31_PRIVATE_SHA):
    """Authenticate R31 bytes and its 39 catalog bindings, without re-reading R14."""
    need(type(expected_sha) is str and HEX64.fullmatch(expected_sha), 'expected_digest_syntax')
    need(expected_sha == R31_PRIVATE_SHA, 'expected_digest_changed')
    doc = clean_json(raw)
    fields = (
        'schema_version', 'scope', 'source_main_sha', 'r14_private_report_sha256',
        'r14_anchor_catalog_sha256', 'profile_count', 'unique_documentary_entry_count',
        'manuals_used', 'source_windows', 'complete_semantic_reviews', 'approved_cli_options',
        'approved_argv_renderers', 'material_bindings_fulfilled', 'runtime_proof_gates_fulfilled',
        'authorized_profiles', 'authorized_cases', 'dispatch_allowed', 'p8_closed',
        'p9_started', 'algorithms_started',
    )
    exact(doc, fields, 'r31_root')
    need(doc['schema_version'] == '1.0' and
         doc['scope'] == 'P8_R31_AUTHENTICATED_PRIVATE_MANPAGE_WINDOWS_NOT_SEMANTIC_APPROVAL' and
         doc['source_main_sha'] == R31_BASE_SHA and
         doc['r14_private_report_sha256'] == R14_FULL_SHA and
         doc['r14_anchor_catalog_sha256'] == R14_ANCHOR_SHA and
         type(doc['profile_count']) is int and doc['profile_count'] == 21 and
         type(doc['unique_documentary_entry_count']) is int and
         doc['unique_documentary_entry_count'] == 39 and
         type(doc['manuals_used']) is int and doc['manuals_used'] == 3, 'r31_identity')
    for name in ('complete_semantic_reviews', 'approved_cli_options',
                 'approved_argv_renderers', 'material_bindings_fulfilled',
                 'runtime_proof_gates_fulfilled', 'authorized_profiles',
                 'authorized_cases'):
        need(type(doc[name]) is int and doc[name] == 0, 'r31_no_authority_' + name)
    for name in ('dispatch_allowed', 'p8_closed', 'p9_started', 'algorithms_started'):
        need(doc[name] is False, 'r31_no_promotion_' + name)
    need(type(anchors) is tuple and len(anchors) == 39, 'authenticated_anchor_catalog')
    rows = doc['source_windows']
    need(type(rows) is list and len(rows) == 39, 'exact_39_windows')
    allowed = (
        'term_id', 'manual_path', 'source_line_1based', 'exact_roff_line_sha256',
        'uncompressed_manual_sha256', 'profile_refs', 'source_line_start_1based',
        'source_line_end_1based', 'context_line_count', 'context_sha256',
        'context_b64_private', 'context_completeness', 'semantic_review_completed',
        'cli_option_approved',
    )
    checked = []
    for index, (row, anchor) in enumerate(zip(rows, anchors)):
        exact(row, allowed, 'window_' + str(index))
        for name in ('term_id', 'manual_path', 'source_line_1based',
                     'exact_roff_line_sha256', 'uncompressed_manual_sha256', 'profile_refs'):
            need(row[name] == anchor[name], 'catalog_binding_' + name)
        need(row['context_completeness'] == 'FIXED_WINDOW_NOT_A_CERTIFIED_COMPLETE_CLAUSE' and
             row['semantic_review_completed'] is False and row['cli_option_approved'] is False,
             'window_authority')
        count = row['context_line_count']
        start = row['source_line_start_1based']
        end = row['source_line_end_1based']
        need(type(count) is int and 1 <= count <= 24 and
             type(start) is int and start == anchor['source_line_1based'] and
             type(end) is int and end == start + count - 1, 'window_line_count')
        need(type(row['context_sha256']) is str and HEX64.fullmatch(row['context_sha256']) and
             type(row['context_b64_private']) is str, 'window_hash_and_encoded_type')
        try:
            raw_window = base64.b64decode(row['context_b64_private'], validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise Denied('P8_R32_DENY:invalid_b64') from exc
        need(0 < len(raw_window) <= 16384 and digest(raw_window) == row['context_sha256'],
             'window_digest')
        lines = raw_window.splitlines(keepends=True)
        need(len(lines) == count and digest(lines[0]) == row['exact_roff_line_sha256'],
             'anchored_first_line')
        checked.append((row, raw_window))
    return tuple(checked)

def semantic_queue(checked):
    """Evidence-linked HUMAN review assignments. Never approvals or judgments."""
    need(type(checked) is tuple and len(checked) == 39, 'review_count')
    terms = set()
    records = []
    priorities = Counter()
    hints = Counter()
    for row, excerpt in checked:
        term = row['term_id']
        need(term not in terms, 'duplicate_term')
        terms.add(term)
        lower = excerpt.lower()
        signals = tuple(sorted(k for k, patterns in LEXICAL_HINTS.items()
                               if any(pattern in lower for pattern in patterns)))
        attention = 'ELEVATED_REVIEW_PRIORITY_ONLY' if term in HIGH_ATTENTION else 'STANDARD_REVIEW_PRIORITY_ONLY'
        priorities[attention] += 1
        hints.update(signals)
        records.append({
            'term_id': term,
            'manual_path': row['manual_path'],
            'profile_refs': row['profile_refs'],
            'source_line_start_1based': row['source_line_start_1based'],
            'source_line_end_1based': row['source_line_end_1based'],
            'context_sha256': row['context_sha256'],
            'context_line_count': row['context_line_count'],
            'context_status': 'BOUNDED_ROFF_WINDOW_NOT_COMPLETE_SEMANTIC_CLAUSE',
            'lexical_signals_only_not_conclusions': list(signals),
            'attention': attention,
            'review_questions': {q: 'UNANSWERED_NEEDS_HUMAN_REVIEW' for q in QUESTIONS},
            'semantic_review_completed': False,
            'approved_cli_option': False,
            'argv_renderable': False,
            'capability_proven': False,
        })
    need(len(records) == 39, 'records_count')
    return {
        'schema_version': '1.0',
        'scope': 'P8_R32_PRIVATE_SEMANTIC_REVIEW_QUEUE_NO_SEMANTIC_VERDICTS',
        'source_main_sha': R32_BASE_SHA,
        'r31_private_receipt_sha256': R31_PRIVATE_SHA,
        'source_excerpt_bytes_copied': False,
        'profiles': 21,
        'source_terms': 39,
        'questions_per_term': len(QUESTIONS),
        'unanswered_review_questions': 39 * len(QUESTIONS),
        'priority_totals': dict(sorted(priorities.items())),
        'lexical_signal_counts_not_authority': dict(sorted(hints.items())),
        'review_rows': records,
        'semantic_reviews_completed': 0,
        'approved_cli_options': 0,
        'approved_argv_renderers': 0,
        'material_fields_unbound': 348,
        'runtime_proof_gates_unverified': 261,
        'authorized_cases': 0,
        'authorized_profiles': 0,
        'dispatch_allowed': False,
        'p8_closed': False,
        'p9_started': False,
        'a1_to_a10_started': False,
    }
