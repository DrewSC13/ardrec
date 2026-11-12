#!/usr/bin/env python3
"""P8-R30: strict FTP/SMB *synthetic-only* acceptance oracle; never dispatches.

This module verifies the shape of model-only evidence vectors. No observed
runtime evidence, authority, credentials, targets, executable arguments or
capability is accepted or inferred. Inputs are synthetic test data only.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re
from typing import Mapping

SYMBOL = re.compile(r'[A-Z][A-Z0-9_]*\Z', re.ASCII)
PROFILE = re.compile(r'(?:FTP|SMB)-T[0-9]{2}-(?:BASE|CONTROL|DATA|READ|WRITE|SIGNING|ENCRYPTION)\Z', re.ASCII)
OUTCOMES = frozenset({'PASS_SYNTHETIC', 'FAIL_SYNTHETIC', 'ND_SYNTHETIC'})
SYNTHETIC_ORIGIN = 'DECLARED_SYNTHETIC_FIXTURE_ONLY'
RESULT_KEYS = frozenset({'schema_version', 'profile_id', 'origin', 'observations',
                         'runtime_capability_asserted', 'case_authorization_asserted',
                         'dispatch_asserted'})
OBSERVATION_KEYS = frozenset({'support_id', 'outcome'})
WRITES = frozenset({'FTP-T07-BASE', 'FTP-T08-WRITE', 'SMB-T08-BASE', 'SMB-T09-WRITE'})
PER_PROTOCOL = {'ftp': 10, 'smb': 11}

class Rejected(ValueError):
    pass


def need(value, why):
    if not value:
        raise Rejected('P8_R30_FAIL_CLOSED:' + why)


def sha_obj(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'),
                                      ensure_ascii=False) + '\n').encode('utf-8')).hexdigest()


def _symbol_list(value, name):
    need(type(value) is list and 0 < len(value) <= 16, name + '_count')
    need(all(type(v) is str and 0 < len(v) < 96 and SYMBOL.fullmatch(v) for v in value),
         name + '_invalid_symbol')
    need(len(value) == len(set(value)), name + '_duplicates')
    return tuple(value)


def build_catalog(r29_registry, spec):
    """Bind exact P8 R29 declarations to a 21-profile acceptance oracle spec.

    A successful catalog build is design consistency only, never proof of
    runtime capability, validity of material claims, or permission to operate.
    """
    need(type(spec) is dict and set(spec) == {'schema_version', 'scope', 'roadmap_step',
         'increment', 'base_main_commit', 'r29_model_module_sha256',
         'r29_spec_git_blob', 'protocol_counts', 'profile_count', 'write_profiles',
         'profiles', 'material_fields_unbound', 'runtime_gates_unverified',
         'synthetic_only', 'dispatch_allowed', 'approved_profiles',
         'authorized_cases', 'p8_closed', 'p9_started', 'a1_to_a10_started'}, 'spec_keys')
    need(spec['schema_version'] == '1.0' and spec['scope'] ==
         'FTP_SMB_OPERATION_SPECIFIC_SYNTHETIC_ACCEPTANCE_ORACLES_DENY_ONLY' and
         spec['roadmap_step'] == 8 and spec['increment'] == 'P8-R30' and
         spec['base_main_commit'] == 'a3ecc122bcd5819c6a211174ac33214bb19bc021',
         'spec_identity')
    need(spec['protocol_counts'] == PER_PROTOCOL and spec['profile_count'] == 21 and
         spec['write_profiles'] == sorted(WRITES) and
         spec['material_fields_unbound'] == 348 and spec['runtime_gates_unverified'] == 261,
         'spec_counts')
    need(spec['synthetic_only'] is True and spec['dispatch_allowed'] is False and
         spec['approved_profiles'] == 0 and spec['authorized_cases'] == 0 and
         spec['p8_closed'] is False and spec['p9_started'] is False and
         spec['a1_to_a10_started'] is False, 'spec_denial')
    need(type(r29_registry) in (tuple, list) and len(r29_registry) == 29,
         'r29_registry_shape')
    need(type(spec['profiles']) is list and len(spec['profiles']) == 21,
         'spec_profile_count')
    legacy = list(r29_registry[8:])
    identities = [r.get('profile_id') for r in legacy]
    need(len(set(identities)) == 21 and all(type(x) is str and PROFILE.fullmatch(x)
         for x in identities), 'profile_identities')
    need([r.get('profile_id') for r in spec['profiles']] == identities,
         'spec_registry_order')
    result = []
    for origin, expected in zip(legacy, spec['profiles']):
        need(type(origin) is dict and type(expected) is dict and set(expected) ==
             {'profile_id', 'protocol', 'operation_id', 'acceptance_supports',
              'cleanup_contract', 'write_variant'}, 'profile_keys')
        pid = origin['profile_id']
        need(expected['profile_id'] == pid and expected['protocol'] == origin['protocol']
             and expected['operation_id'] == origin['operation_id'] and
             expected['cleanup_contract'] == origin['cleanup_contract'] and
             expected['write_variant'] is (pid in WRITES) and
             origin['write_variant'] is (pid in WRITES), 'profile_crosswalk:' + pid)
        supports = _symbol_list(expected['acceptance_supports'], 'supports:' + pid)
        need(supports == _symbol_list(origin['required_acceptance_supports'],
                                     'r29_supports:' + pid), 'support_mismatch:' + pid)
        need(origin['authorization'] == 'DENIED' and
             origin['argv_renderable'] is False and
             origin['dispatch_allowed'] is False and
             origin['material_fields_unbound'] and
             len(origin['material_fields_unbound']) == 12,
             'upstream_promotion:' + pid)
        write = pid in WRITES
        need((origin['cleanup_contract'] == 'VERIFY_THEN_REMOVE_MARKER') is write,
             'cleanup:' + pid)
        if write:
            need({'MARKER_CREATED', 'MARKER_VERIFIED', 'CLEANUP_CONFIRMED'}
                 <= set(supports), 'independent_cleanup_markers:' + pid)
        if pid in ('FTP-T02-CONTROL', 'FTP-T02-DATA'):
            need('TLS_CHANNEL_PROTECTION' in supports and
                 ('CONTROL_DATA_CORRELATION' in supports) ==
                 (pid == 'FTP-T02-DATA'), 'ftp_tls_channel_distinction')
        if pid in ('SMB-T03-SIGNING', 'SMB-T03-ENCRYPTION'):
            need(('SMB_SIGNATURE' in supports) == (pid == 'SMB-T03-SIGNING') and
                 ('SMB_ENCRYPTION' in supports) == (pid == 'SMB-T03-ENCRYPTION'),
                 'smb_protection_distinction')
        if pid.endswith('-READ'):
            need(not {'MARKER_CREATED', 'MARKER_VERIFIED', 'CLEANUP_CONFIRMED'} &
                 set(supports), 'read_must_not_mutate')
        result.append({**deepcopy(expected), 'acceptance_supports': list(supports),
                       'authority': 'DENIED', 'runtime_proof_admitted': False,
                       'dispatch_allowed': False,
                       'status': 'SYNTHETIC_ORACLE_ONLY_UNPROVEN'})
    need(dict(Counter(x['protocol'] for x in result)) == PER_PROTOCOL and
         sum(x['write_variant'] for x in result) == 4, 'protocol_writer_counts')
    return tuple(result)


def evaluate_synthetic(catalog, vector):
    """Evaluate *synthetic* declared observations, never externally observed proof.

    PASS_SYNTHETIC only means all symbolic supports match a fixture. Outcomes
    FAIL_SYNTHETIC/ND_SYNTHETIC are recorded but never reinterpreted as success.
    No authorization or runtime claim is accepted even with full synthetic PASS.
    """
    need(type(catalog) in (tuple, list) and len(catalog) == 21, 'catalog_shape')
    need(type(vector) is dict and set(vector) == RESULT_KEYS, 'vector_keys')
    need(vector['schema_version'] == '1.0' and vector['origin'] == SYNTHETIC_ORIGIN,
         'vector_origin')
    need(all(vector[k] is False for k in ('runtime_capability_asserted',
         'case_authorization_asserted', 'dispatch_asserted')), 'asserted_authority')
    pid = vector['profile_id']
    need(type(pid) is str and PROFILE.fullmatch(pid), 'profile_type')
    row = next((r for r in catalog if r.get('profile_id') == pid), None)
    need(row is not None and row.get('authority') == 'DENIED' and
         row.get('dispatch_allowed') is False and
         row.get('runtime_proof_admitted') is False, 'unknown_or_promoted_profile')
    observed = vector['observations']
    supports = row['acceptance_supports']
    need(type(observed) is list and len(observed) == len(supports), 'observation_count')
    normalized = []
    for event, expected in zip(observed, supports):
        need(type(event) is dict and set(event) == OBSERVATION_KEYS,
             'observation_keys')
        need(event['support_id'] == expected and type(event['outcome']) is str and
             event['outcome'] in OUTCOMES, 'observation_outcome_or_order')
        normalized.append(event['outcome'])
    all_positive = all(x == 'PASS_SYNTHETIC' for x in normalized)
    any_negative = any(x == 'FAIL_SYNTHETIC' for x in normalized)
    if any_negative:
        disposition = 'SYNTHETIC_NEGATIVE_ORACLE'
    elif all_positive:
        disposition = 'SYNTHETIC_POSITIVE_ORACLE_NOT_RUNTIME_PROOF'
    else:
        disposition = 'SYNTHETIC_ND_ORACLE'
    if row['write_variant']:
        cleanup = next(x['outcome'] for x in observed
                       if x['support_id'] == 'CLEANUP_CONFIRMED')
        need(not (disposition == 'SYNTHETIC_POSITIVE_ORACLE_NOT_RUNTIME_PROOF')
             or cleanup == 'PASS_SYNTHETIC', 'positive_without_synthetic_cleanup')
    return {'profile_id': pid, 'classification': disposition,
            'synthetic_observations_complete': len(observed) == len(supports),
            'synthetic_all_positive': all_positive,
            'synthetic_negative': any_negative,
            'synthetic_cleanup_positive': (not row['write_variant'] or
                 next(x['outcome'] for x in observed
                      if x['support_id'] == 'CLEANUP_CONFIRMED') == 'PASS_SYNTHETIC'),
            'runtime_proof_admitted': False, 'proof_gates_closed': 0,
            'material_bindings_completed': 0, 'approved_profiles': 0,
            'authorized_cases': 0, 'argv': None, 'spawn': False,
            'dispatch_allowed': False, 'decision': 'DENY'}


def summarize(catalog):
    need(type(catalog) in (list, tuple) and len(catalog) == 21 and
         all(row['authority'] == 'DENIED' and not row['dispatch_allowed']
             for row in catalog), 'summary_catalog')
    return {'status': 'PASS_P8_R30_21_SYNTHETIC_ORACLES_DENY_ONLY',
            'profile_count': 21, 'protocol_counts': dict(PER_PROTOCOL),
            'write_variants': 4, 'catalog_sha256': sha_obj(list(catalog)),
            'material_bindings_unbound': 348, 'unverified_proof_gates': 261,
            'approved_profiles': 0, 'authorized_cases': 0,
            'runtime_capability_proven': False, 'dispatch_allowed': False,
            'p8_closed': False, 'p9_started': False, 'a1_to_a10_started': False}
