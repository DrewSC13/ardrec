#!/usr/bin/env python3
"""R25 public CI: verify source pin and *contract*; never collect guest data."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r25_ssh_source_provenance as r25
import verify_p8_r24_capability_proof_boundary as v24

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT/'lab/p8-r25-ssh-source-provenance-v1/spec.json'
SPEC_SHA = '5792a53ea9729f3ff1b8bb618e3f727de19237594a7952391b44c114d3129a61'


def verify() -> dict:
    old = v24.verify()
    r25.require(old['status'] == 'PASS_P8_R24_PROOF_SUFFICIENCY_BOUNDARY_DENY_ONLY'
                and old['matrix_sha256'] == r25.R24_MATRIX_SHA
                and old['profiles'] == 29
                and old['unverified_gate_instances'] == 261
                and old['pending_binding_fields'] == 348
                and old['authorized_cases'] == 0
                and old['dispatch_allowed'] is False,
                'r24_public_contract')
    raw=SPEC.read_bytes()
    r25.require(hashlib.sha256(raw).hexdigest() == SPEC_SHA, 'spec_sha')
    spec = json.loads(raw)
    r25.require(type(spec) is dict and spec['schema_version'] == '1.0'
                and spec['roadmap_step'] == 8 and spec['increment'] == 'P8-R25'
                and spec['scope'] == 'ACTUAL_PINNED_QCOW2_SSH_CONFIG_SOURCE_READONLY_OPERATOR_CAPTURE'
                and spec['base_main_commit'] == r25.BASE
                and spec['r24_private_receipt_sha256_operator_only'] == r25.R24_RECEIPT_SHA
                and spec['r24_matrix_sha256'] == r25.R24_MATRIX_SHA
                and spec['pinned_image_sha256'] == r25.IMAGE_SHA
                and spec['source_root'] == r25.ROOT_PATH
                and spec['source_fragment_directory'] == r25.FRAGMENT_DIR
                and spec['target_profile_count'] == 8
                and spec['profile_total_unchanged'] == 29
                and spec['unbound_fields_unchanged'] == 348
                and spec['unverified_gates_unchanged'] == 261,
                'spec_contract')
    alias = spec.get('literal_symlink_exception')
    r25.require(type(alias) is dict and set(alias) ==
                {'guest_path', 'resolved_regular_path', 'max_aliases',
                 'arbitrary_following', 'effective_include_resolution'} and
                alias['guest_path'] == r25.ALIAS_PATH and
                alias['resolved_regular_path'] == r25.ALIAS_TARGET and
                type(alias['max_aliases']) is int and alias['max_aliases'] == 1 and
                alias['arbitrary_following'] is False and
                alias['effective_include_resolution'] is False,
                'literal_alias_contract')
    for k in ('ci_reads_qcow2', 'ci_reads_private_receipts', 'guest_binaries_execute',
              'active_vm_access', 'effective_configuration_verified',
              'client_capability_verified', 'dispatch_allowed'):
        r25.require(spec[k] is False, 'unsafe_spec:' + k)
    r25.require(spec['operator_readonly_qcow2_access_requires_explicit_execution'] is True
                and spec['authorized_profiles'] == 0
                and spec['authorized_cases'] == 0,
                'operator_authorization')
    contract=r25.public_contract()
    r25.require(contract['material_observation_already_performed'] is False
                and contract['dispatch_allowed'] is False
                and len(contract['target_profiles']) == 8,
                'ci_must_not_claim_material_capture')
    return contract


if __name__ == '__main__':
    try:
        print(json.dumps(verify(), sort_keys=True))
    except (r25.SourceError, ValueError, KeyError, TypeError, OSError) as exc:
        print('P8_R25=FAIL_CLOSED:' + str(exc), file=sys.stderr)
        raise SystemExit(1)
