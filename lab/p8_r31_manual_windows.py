#!/usr/bin/env python3
"""P8-R31: bounded, source-authenticated FTP/SMB manual evidence windows.

The resulting private data are *excerpts of source*, never semantic approvals,
client capability, executable arguments, case authorizations, or dispatch.
No subprocess, filesystem, image, network or shell operations in this module.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import re

R14_FULL_SHA = '2968e57fc65554735cef5ad349ec8a159dcc42fae3b0f05a653b2df0b20af365'
R14_ANCHOR_SHA = '6b22b5ae82a3af897516a3c7eb5f37c7bff71ad7a6f2d9382de10b2855fccfb4'
MAIN_SHA = 'e7caa5c49cebb3c7258c07bbfe72d802da2ae64b'
WINDOW_LINES = 24
WINDOW_MAX_BYTES = 16384
MAX_SOURCE_BYTES = 300000
MANUALS = frozenset({
    '/usr/share/man/man1/curl.1.gz',
    '/usr/share/man/man1/smbclient.1.gz',
    '/usr/share/man/man1/rpcclient.1.gz',
})
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
TERM = re.compile(r'^(curl|smbclient|rpcclient)\.1\.gz:(?:--[a-z0-9-]+|[a-z][a-z0-9-]*)\Z', re.ASCII)

class Blocked(ValueError):
    pass


def require(test, reason):
    if not test:
        raise Blocked('P8_R31_FAIL_CLOSED:' + reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def catalog(anchor_doc):
    """Return only R14-authenticated names/locations, not manual semantics."""
    require(type(anchor_doc) is dict and anchor_doc.get('increment') == 'P8-R14' and
            anchor_doc.get('private_report_sha256') == R14_FULL_SHA and
            anchor_doc.get('approved_cli_options') == 0 and
            anchor_doc.get('dispatch_allowed') is False, 'r14_catalog_identity')
    refs = anchor_doc.get('profile_refs')
    anchors = anchor_doc.get('term_anchors')
    require(type(refs) is list and len(refs) == 29 and type(anchors) is list and
            len(anchors) == 91, 'anchor_counts')
    profiles = [r for r in refs if type(r) is dict and
                type(r.get('profile_id')) is str and
                r['profile_id'].startswith(('FTP-', 'SMB-'))]
    require(len(profiles) == 21 and
            dict(Counter(r['profile_id'].split('-')[0] for r in profiles)) ==
            {'FTP': 10, 'SMB': 11}, 'profile_count')
    names = set()
    usage = {}
    for row in profiles:
        require(row.get('symbolic_grammar_only') is True and
                row.get('complete_semantic_review') is False and
                row.get('approved_for_execution') is False and
                type(row.get('source_term_ids')) is list, 'profile_denial')
        require(len(set(row['source_term_ids'])) == len(row['source_term_ids']), 'duplicate_profile_refs')
        for term_id in row['source_term_ids']:
            require(type(term_id) is str and TERM.fullmatch(term_id), 'term_id')
            names.add(term_id)
            usage.setdefault(term_id, []).append(row['profile_id'])
    require(len(names) == 39, 'unique_ftp_smb_terms')
    by_id = {a.get('term_id'): a for a in anchors if type(a) is dict}
    require(len(by_id) == 91 and names <= set(by_id), 'r14_anchor_identity')
    selected = []
    for term_id in sorted(names):
        a = by_id[term_id]
        require(a.get('manual_path') in MANUALS and
                a.get('anchor_class') == 'EXACT_MANPAGE_ENTRY_LOCATED' and
                a.get('annotation_status') == 'SOURCE_LOCATION_ONLY_SEMANTIC_REVIEW_NOT_COMPLETED' and
                a.get('option_authorized') is False and
                a.get('caller_supplied_values_approved') is False and
                type(a.get('source_line_1based')) is int and a['source_line_1based'] > 0 and
                type(a.get('exact_roff_line_sha256')) is str and
                HEX.fullmatch(a['exact_roff_line_sha256']) and
                type(a.get('uncompressed_manual_sha256')) is str and
                HEX.fullmatch(a['uncompressed_manual_sha256']), 'r14_selected_anchor')
        selected.append({'term_id':term_id,'manual_path':a['manual_path'],
                         'source_line_1based':a['source_line_1based'],
                         'exact_roff_line_sha256':a['exact_roff_line_sha256'],
                         'uncompressed_manual_sha256':a['uncompressed_manual_sha256'],
                         'profile_refs':usage[term_id]})
    require(dict(Counter(a['manual_path'] for a in selected)) == {
        '/usr/share/man/man1/curl.1.gz':21,
        '/usr/share/man/man1/smbclient.1.gz':17,
        '/usr/share/man/man1/rpcclient.1.gz':1,
    }, 'source_distribution')
    return tuple(selected)


def window(source: bytes, anchor: dict):
    """Extract EXACT anchored line plus <=23 subsequent lines, without claiming a full clause."""
    require(type(source) is bytes and 0 < len(source) <= MAX_SOURCE_BYTES,
            'source_bytes')
    require(type(anchor) is dict and type(anchor.get('source_line_1based')) is int,
            'anchor_shape')
    require(type(anchor.get('uncompressed_manual_sha256')) is str and
            digest(source) == anchor['uncompressed_manual_sha256'], 'manual_sha256')
    lines = source.splitlines(keepends=True)
    n = anchor['source_line_1based'] - 1
    require(0 <= n < len(lines), 'anchor_range')
    require(digest(lines[n]) == anchor.get('exact_roff_line_sha256'), 'anchor_sha256')
    chosen = b''.join(lines[n:n+WINDOW_LINES])
    require(0 < len(chosen) <= WINDOW_MAX_BYTES, 'bounded_excerpt')
    return {'source_line_start_1based':n+1,
            'source_line_end_1based':min(len(lines),n+WINDOW_LINES),
            'context_line_count':min(WINDOW_LINES,len(lines)-n),
            'context_sha256':digest(chosen),
            'context_b64_private':base64.b64encode(chosen).decode('ascii'),
            'context_completeness':'FIXED_WINDOW_NOT_A_CERTIFIED_COMPLETE_CLAUSE',
            'semantic_review_completed':False,
            'cli_option_approved':False}


def from_authenticated_report(raw_private: bytes, anchors: dict, r14_reconcile):
    """Materially compare full captured roff bytes with R14 and extract private windows.

    r14_reconcile must be the existing pinned R14 verifier's private_reconcile.
    """
    require(type(raw_private) is bytes and 0 < len(raw_private) <= 1048576 and
            digest(raw_private) == R14_FULL_SHA, 'r14_private_report_sha256')
    info = r14_reconcile(raw_private, anchors)
    require(info['private_full_report'] == 'MATCH_7_FULL_SOURCES_91_ENTRY_HEADINGS',
            'r14_seven_sources_91_anchors')
    doc = json.loads(raw_private)
    source_map = {}
    for rec in doc['manuals']:
        path = rec['manual_path']
        if path in MANUALS:
            data = base64.b64decode(rec['full_roff_source_b64'],validate=True)
            require(digest(data)==rec['uncompressed_sha256'], 'source_digest')
            source_map[path]=data
    require(set(source_map)==MANUALS, 'three_real_manual_sources')
    windows = []
    for item in catalog(anchors):
        src = source_map[item['manual_path']]
        windows.append({**item,**window(src,item)})
    require(len(windows)==39, 'window_count')
    return {
        'schema_version':'1.0',
        'scope':'P8_R31_AUTHENTICATED_PRIVATE_MANPAGE_WINDOWS_NOT_SEMANTIC_APPROVAL',
        'source_main_sha':MAIN_SHA,
        'r14_private_report_sha256':R14_FULL_SHA,
        'r14_anchor_catalog_sha256':R14_ANCHOR_SHA,
        'profile_count':21,
        'unique_documentary_entry_count':39,
        'manuals_used':3,
        'source_windows':windows,
        'complete_semantic_reviews':0,
        'approved_cli_options':0,
        'approved_argv_renderers':0,
        'material_bindings_fulfilled':0,
        'runtime_proof_gates_fulfilled':0,
        'authorized_profiles':0,
        'authorized_cases':0,
        'dispatch_allowed':False,
        'p8_closed':False,
        'p9_started':False,
        'algorithms_started':False,
    }
