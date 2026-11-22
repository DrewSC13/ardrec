"""R136: pure signed B4/B9 policy admission over pinned source bytes.

Tests and source-only integration only. This is NOT a root installer.  The caller
must independently attest the provenance/ownership of every supplied input.
No network, VM, firewall or host control operation is invoked.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
from pathlib import Path
import types

from . import r135_root_transaction as transaction

SCHEMA = 'ARDREC-R136-B4-B9-SEMANTIC-ADMISSION-v1'
B4_SHA = transaction.B4_SHA
B9_SHA = transaction.B9_SHA

ROOT_EXTERNAL = frozenset({
    'root_trust', 'root_revocation', 'scope_trust', 'scope_revocation',
    'pilot_trust', 'pilot_revocation', 'window_trust', 'window_revocation',
    'traffic_trust', 'traffic_revocation',
})


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def pinned_module(raw: bytes, expected: str, name: str):
    """Load only exact verified historical controller bytes for pure functions.

    This is source-only and must not be used by privileged code to import from
    the mutable repository; a future root agent needs root-owned byte pinning.
    """
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == expected,
            'CONTROLLER_SOURCE_PIN_MISMATCH:' + name)
    module = types.ModuleType('ardrec_r136_' + name)
    module.__file__ = '<r136-pinned-' + name + '>'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def validate(*, payload: dict[str, bytes], external: dict[str, bytes],
             b4_source: bytes, b9_source: bytes, head: str,
             boot_id: str, now: datetime) -> dict:
    """Validate B4 DENY, B9 handoff and signed one-shot traffic documents.

    A positive result proves semantics for supplied test data ONLY. It never
    attests provenance of root trust or authorizes installation/traffic.
    """
    plan = transaction.validate_payload(payload, head)
    require(type(external) is dict and set(external) == ROOT_EXTERNAL,
            'EXTERNAL_DOCUMENT_SCOPE')
    require(type(now) is datetime and now.tzinfo is not None and
            now.utcoffset() is not None, 'CLOCK_NOT_AWARE')
    b4 = pinned_module(b4_source, B4_SHA, 'b4')
    b9 = pinned_module(b9_source, B9_SHA, 'b9')

    docs = {
        'grant': b4.parse(payload['B4/grant.json']),
        'contract': b4.parse(payload['B4/contract.json']),
        'scope_authorization': b4.parse(payload['B4/scope-authorization.json']),
        'pilot_permit': b4.parse(payload['B4/pilot-permit.json']),
        'traffic_window': b4.parse(payload['B4/traffic-window.json']),
    }
    docs.update({name: b4.parse(raw) for name, raw in external.items()
                 if name not in {'traffic_trust', 'traffic_revocation'}})

    checked = b4.validate_bundle(docs, now=now,
                                  expected_head=head, boot_id=boot_id)
    window = docs['traffic_window']['statement']
    budget = window['budget']
    handoff = b9.parse(payload['B9/f13-handoff.json'])
    b9.validate_handoff(handoff, head=head,
                        session=checked['session'],
                        b4grant=docs['grant']['statement'],
                        budget=budget)
    traffic = b9.signed_traffic(
        auth_module=b4,
        grant=b9.parse(payload['B9/traffic-grant.json']),
        trust=b9.parse(external['traffic_trust']),
        revocation=b9.parse(external['traffic_revocation']),
        handoff=handoff,
        b4docs=docs,
        approved_head=head,
        boot_id=boot_id,
        now=now,
    )
    require(traffic['action'] == 'ONE_FTP_T01_GUEST_GREETING',
            'TRAFFIC_ACTION_UNEXPECTED')

    return {
        'schema': SCHEMA + '-review',
        'head': head,
        'session': checked['session'],
        'inventory_sha256': plan['inventory_sha256'],
        'b4_signed_semantics': 'PASS',
        'b9_handoff_semantics': 'PASS',
        'b9_traffic_signed_semantics': 'PASS',
        'root_trust_independently_attested': False,
        'git_commit_signature_independently_verified': False,
        'root_install_authorized': False,
        'root_install_executed': False,
        'physical_5_1_proved': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def capabilities():
    return {
        'schema': SCHEMA + '-capabilities',
        'verifies_real_ed25519': True,
        'validates_b4_signed_operational_documents': True,
        'validates_b9_signed_traffic_and_handoff': True,
        'trust_provenance_attested': False,
        'root_installer': False,
        'can_open_network': False,
        'p8': 'NO-GO',
    }
