#!/usr/bin/env python3
"""ARDREC P8-R26: finite candidate Include graph over *synthetic* SSH sources.

This is not OpenSSH's parser, nor an effective-configuration evaluator.
No filesystem, process, subprocess, socket, VM, secret or client is accessed.
The one permitted alias is a structural label, never an actual symlink follow.
"""
from __future__ import annotations

import hashlib
import re
from typing import Mapping

ROOT = '/etc/ssh/ssh_config'
FRAGMENT_DIR = '/etc/ssh/ssh_config.d'
ALIAS = FRAGMENT_DIR + '/20-systemd-ssh-proxy.conf'
ALIAS_TARGET = '/usr/lib/systemd/ssh_config.d/20-systemd-ssh-proxy.conf'
GLOB = FRAGMENT_DIR + '/*.conf'
R25_SHA256 = 'eee28ad26a1d775b2d1f6215410ce072d64b1ea3a209567f8493848f4483fe5c'
BASE_MAIN = 'd4dfb21ba81143e27870586b9ebf442326287eb7'

MAX_FILE_BYTES = 262_144
MAX_TOTAL_BYTES = 1_048_576
MAX_SOURCES = 33
MAX_EDGES = 96
MAX_VISITS = 96
MAX_DEPTH = 8
MAX_LINES = 8192
MAX_LINE_BYTES = 4096
MAX_INCLUDE_TOKENS = 8
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\.conf\Z', re.ASCII)
SHA256 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
DIRECTIVE = re.compile(r'^([A-Za-z][A-Za-z0-9]*)(?:\s*=\s*|\s+)(.*)$', re.ASCII)
NO_UNSAFE_TOKEN = re.compile(r'[\s\x00-\x1f\x7f"\'`\\$%~{};!|&<>]', re.ASCII)


class GraphError(ValueError):
    """Unsupported/ambiguous input: fail closed rather than infer OpenSSH behavior."""


def need(cond: bool, why: str) -> None:
    if not cond:
        raise GraphError('P8_R26_FAIL_CLOSED:' + why)


def valid_path(path: object) -> bool:
    if type(path) is not str:
        return False
    if path == ROOT:
        return True
    if not path.startswith(FRAGMENT_DIR + '/'):
        return False
    name = path[len(FRAGMENT_DIR) + 1:]
    return bool(NAME.fullmatch(name)) and len(name) <= 128


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalize(sources: object, aliases: object) -> dict[str, bytes]:
    need(type(sources) is dict and 1 <= len(sources) <= MAX_SOURCES,
         'source_inventory_shape_or_bound')
    need(ROOT in sources and all(valid_path(k) for k in sources),
         'source_path_outside_fixed_scope')
    need(type(aliases) is dict and (not aliases or aliases == {ALIAS: ALIAS_TARGET}),
         'alias_not_literal')
    need(all(k in sources for k in aliases), 'alias_without_source')
    total = 0
    for path, raw in sources.items():
        need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE_BYTES, 'source_bytes:' + path)
        need(b'\x00' not in raw, 'nul_byte:' + path)
        total += len(raw)
        need(total <= MAX_TOTAL_BYTES, 'total_bytes')
        try:
            raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError as exc:
            raise GraphError('P8_R26_FAIL_CLOSED:invalid_utf8:' + path) from exc
    return sources


def _line_parts(raw: bytes, path: str):
    # This intentionally supports only an auditable subset of lexical forms.
    lines = raw.decode('utf-8').splitlines()
    need(len(lines) <= MAX_LINES, 'line_count:' + path)
    for number, text in enumerate(lines, 1):
        need(len(text.encode('utf-8')) <= MAX_LINE_BYTES, 'long_line:' + path)
        # Backslash continuation and quoted/include escapes are deliberately unsupported.
        s = text.strip()
        if not s or s.startswith('#'):
            continue
        # A hash starts a comment only when surrounded by whitespace in this subset.
        s = re.split(r'\s+#', s, maxsplit=1)[0].rstrip()
        parsed = DIRECTIVE.fullmatch(s)
        if parsed:
            yield number, parsed.group(1).lower(), parsed.group(2).strip()
        elif s.lower() in ('include', 'match', 'host'):
            yield number, s.lower(), ''
        elif re.match(r'(?i)^include[=\s]', s):
            raise GraphError('P8_R26_FAIL_CLOSED:ambiguous_include_line:' + path)


def analyze_synthetic_sources(sources: dict[str, bytes], *, aliases: dict[str, str] | None = None) -> dict:
    """Calculate a bounded *candidate* Include expansion for complete synthetic inventory.

    Paths are opaque guest-path labels, NOT host paths to open. No effective
    Host/Match filtering, user config, CLI override, tokens, canonicalization,
    actual glob expansion, or executable semantics is asserted.
    """
    sources = _normalize(sources, {} if aliases is None else aliases)
    source_hashes = [{'guest_path': p, 'sha256': digest(v), 'bytes': len(v)}
                     for p, v in sorted(sources.items())]
    edges: list[dict] = []
    visits = 0
    conditional_edges = 0
    paths_seen: set[str] = set()

    def walk(path: str, stack: tuple[str, ...], *, inherited_conditional: bool = False):
        # A nested Include cannot lose an unresolved Host/Match condition from
        # any ancestor. This is conservative provenance, not OpenSSH semantics.
        nonlocal visits, conditional_edges
        need(path not in stack, 'include_cycle')
        need(len(stack) < MAX_DEPTH, 'include_depth')
        need(visits < MAX_VISITS, 'include_visit_bound')
        visits += 1
        paths_seen.add(path)
        region = 'global'  # descriptive only; no Host/Match predicates evaluated
        for line, keyword, value in _line_parts(sources[path], path):
            if keyword == 'host':
                need(bool(value) and len(value) <= MAX_LINE_BYTES, 'invalid_host_header')
                region = 'host_unresolved'
                continue
            if keyword == 'match':
                need(bool(value) and len(value) <= MAX_LINE_BYTES, 'invalid_match_header')
                # Explicit and negated Match exec are both unsupported. Never
                # interpret, evaluate, interpolate or execute these predicates.
                criteria = re.split(r'[\s,]+', value.lower())
                need(not any(part.lstrip('!').split('=', 1)[0] == 'exec'
                             for part in criteria), 'match_exec_cannot_be_modeled')
                region = 'match_unresolved'
                continue
            if keyword != 'include':
                continue
            need(bool(value) and not value.endswith('\\'), 'invalid_include_syntax')
            # Quotes, escapes, substitutions and ambiguous comments are excluded.
            need('"' not in value and "'" not in value and '#' not in value,
                 'unsupported_include_quoting_or_comment')
            words = value.split()
            need(1 <= len(words) <= MAX_INCLUDE_TOKENS, 'include_token_count')
            for token in words:
                need(not NO_UNSAFE_TOKEN.search(token), 'include_token_unsafe')
                if token == GLOB:
                    # Ordered synthetic match, not a live filesystem glob.
                    targets = sorted(k for k in sources if k != ROOT)
                    need(bool(targets), 'glob_unmatched_or_inventory_incomplete')
                else:
                    need(valid_path(token) and token != ROOT and
                         '*' not in token and '?' not in token and '[' not in token and
                         ']' not in token, 'include_out_of_scope_or_unsupported_glob')
                    need(token in sources, 'include_target_not_observed')
                    targets = [token]
                for target in targets:
                    need(len(edges) < MAX_EDGES, 'edge_limit')
                    conditional = inherited_conditional or region != 'global'
                    edges.append({'source': path, 'line': line, 'token': token,
                                  'target': target, 'region': region,
                                  'conditional_context_inherited': inherited_conditional,
                                  'conditional_unresolved': conditional})
                    conditional_edges += int(conditional)
                    walk(target, stack + (path,),
                         inherited_conditional=conditional)

    walk(ROOT, ())
    return {
        'schema_version': '1.0',
        'scope': 'BOUNDED_SYNTHETIC_SSH_INCLUDE_CANDIDATE_GRAPH_ONLY',
        'base_main_commit': BASE_MAIN,
        'r25_private_receipt_sha256_declared_only': R25_SHA256,
        'synthetic_inventory_source_count': len(sources),
        'synthetic_inventory_sources': source_hashes,
        'candidate_edges': edges,
        'candidate_edge_count': len(edges),
        'conditional_edges_not_evaluated': conditional_edges,
        'visit_count_bounded': visits,
        'unique_paths_reached': len(paths_seen),
        'alias_declarations_synthetic_only': [
            {'guest_path': ALIAS, 'literal_target': ALIAS_TARGET}
        ] if aliases else [],
        'real_qcow2_access': False,
        'real_include_graph_resolved': False,
        'effective_ssh_configuration_verified': False,
        'user_config_observed': False,
        'host_match_predicates_evaluated': False,
        'client_or_match_exec_executed': False,
        'authorized_profiles': 0,
        'authorized_cases': 0,
        'dispatch_allowed': False,
        'status': 'SYNTHETIC_GRAPH_CANDIDATES_ONLY_DENY_ALL',
    }


def public_contract() -> dict:
    return {
        'status': 'PASS_P8_R26_SYNTHETIC_BOUNDED_INCLUDE_MODEL_ONLY',
        'roadmap_step': 8,
        'ssh_profile_count': 8,
        'profile_count_total': 29,
        'historical_binding_fields_pending': 348,
        'historical_proof_gates_pending': 261,
        'physical_include_graph_resolved': False,
        'effective_config_verified': False,
        'approved_profiles': 0,
        'authorized_cases': 0,
        'dispatch_allowed': False,
        'p9_started': False,
        'algorithms_a1_to_a10_started': False,
    }
