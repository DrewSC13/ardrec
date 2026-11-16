#!/usr/bin/env python3
"""Offline-only synthetic campaign registry + real ephemeral Ed25519 verification."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))

from ardrec.analytics.exact_preview import canonical
from ardrec.evidence.r58f_signed_witness import SCHEMA, signing_bytes, SERVICES
from ardrec.evidence.r58g_trust_registry import (
    SCHEMA as REGISTRY_SCHEMA, registry_digest, read_pinned_registry,
)
from ardrec.coordination.r58g_registry_bridge import (
    build_registry_bridge, verify_registry_bridge,
)
from scripts.ardrec_p14_r58e_unit_bridge import synthetic_units

OPENSSL = '/usr/bin/openssl'
AS_OF = '2026-11-16T12:00:00Z'


def _run(*args: str) -> None:
    proc = subprocess.run([OPENSSL, *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=8, check=False)
    if proc.returncode != 0:
        raise ValueError('DEMO_OPENSSL_FAILED')


def build_demo() -> dict:
    units = synthetic_units()
    evidence = b'ARDREC R58-G synthetic observation, no real guest or network\n'
    statement = {
        'schema': SCHEMA, 'record_id': 'R58G_SYNTH_001',
        'session_id': 'DEV_TUTOR_001', 'service_id': 'SSH_DEV',
        'case_id': 'CASE_REFERENCE', 'assessment_index': 0,
        'configuration_sha256': 'a'*64,
        'captured_at_utc': '2026-11-16T11:59:00Z',
        'method_id': SERVICES['SSH_DEV'], 'observed_claim': 'INCONCLUSIVE',
        'support_sha256': hashlib.sha256(evidence).hexdigest(),
        'support_bytes': len(evidence),
    }
    signatures = {}
    authorities = []
    with tempfile.TemporaryDirectory(prefix='ardrec-r58g-synthetic-') as folder:
        root = Path(folder)
        message = root / 'message.bin'
        message.write_bytes(signing_bytes(statement))
        for role, owner, org in (('observer','SYNTH_OWNER_A','SYNTH_ORG_A'),
                                 ('reviewer','SYNTH_OWNER_B','SYNTH_ORG_B')):
            private = root / (role + '.private.pem')
            public = root / (role + '.public.pem')
            signed = root / (role + '.signature')
            _run('genpkey', '-algorithm', 'ED25519', '-out', str(private))
            private.chmod(0o600)
            _run('pkey', '-in', str(private), '-pubout', '-out', str(public))
            _run('pkeyutl', '-sign', '-inkey', str(private), '-rawin',
                 '-in', str(message), '-out', str(signed))
            key_id = 'SYNTH_KEY_' + role.upper()
            signatures[role] = {'key_id': key_id,
                                'signature_b64':base64.b64encode(signed.read_bytes()).decode('ascii')}
            authorities.append({
                'role': role, 'key_id': key_id, 'owner_id': owner,
                'organization_id': org, 'public_key_pem': public.read_text('ascii'),
                'enrolled_at_utc': '2026-11-14T00:00:00Z',
                'valid_from_utc': '2026-11-15T00:00:00Z',
                'valid_until_utc': '2026-11-17T23:00:00Z',
                'revoked_at_utc': None,
            })
        registry = {
            'schema': REGISTRY_SCHEMA, 'campaign_id': 'DEV_TUTOR_001',
            'session_id': 'DEV_TUTOR_001',
            'review_status': 'DOCUMENTARY_ONLY_NO_TECHNICAL_AUTHORITY',
            'window_start_utc': '2026-11-16T00:00:00Z',
            'window_end_utc': '2026-11-17T00:00:00Z',
            'scope': sorted([{
                'service_id':unit['service_id'], 'case_id':unit['case_id'],
                'assessment_index':unit['assessment_index'],
                'configuration_sha256':'a'*64,
                'method_id':SERVICES[unit['service_id']],
            } for unit in units], key=lambda x:(x['service_id'],x['case_id'],x['assessment_index'])),
            'authorities': authorities,
        }
        registry_path = root / 'registry.canonical.json'
        registry_path.write_bytes(canonical(registry) + b'\n')
        # This same-process pin is exclusively a demonstration fixture.
        # Production pins MUST arrive independently from an authorized source.
        demo_pin = registry_digest(registry)
        checked = read_pinned_registry(registry_path, pinned_sha256=demo_pin)
        bundle = {'statement':statement, 'signatures':signatures, 'support':evidence}
        result = build_registry_bridge(units,[bundle], registry=checked,
                                       pinned_registry_sha256=demo_pin,
                                       as_of_utc=AS_OF, prior_record_ids=())
        assert verify_registry_bridge(result,units,[bundle],registry=checked,
                                      pinned_registry_sha256=demo_pin,
                                      as_of_utc=AS_OF,prior_record_ids=())
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--synthetic-offline', action='store_true', required=True)
    args = parser.parse_args()
    if not args.synthetic_offline:
        return 23
    result = build_demo()
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
