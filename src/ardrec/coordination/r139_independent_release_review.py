"""R139: independent B9 release review joined to R136 signed operational semantics.

All inputs to this function are caller-supplied, untrusted bytes. A correct
signature over a statement does NOT authenticate the filesystem provenance of
trust anchors or independently attest its source commit. The module is pure;
it has no root installer, filesystem writes, sockets or VM/network commands.

DO NOT use this module as a root-authorizing callback for R135. A separately
provisioned root-owned agent must authenticate files, verify the actual Git
commit signature, and revalidate live revocation BEFORE EACH write.
"""
from __future__ import annotations

from datetime import datetime
import hashlib

from . import r135_root_transaction as txn
from . import r136_operational_semantics as op

SCHEMA = 'ARDREC-R139-COMPLETE-SIGNED-RELEASE-REVIEW-v1'
REFERENCE_SCHEMA = 'ARDREC-R115-F8-RUNNER-FTP-DENY-v1-f8-boot-reference'
HEX64 = txn.re.compile(r'[0-9a-f]{64}\Z')


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def review(*, payload: dict[str, bytes], external: dict[str, bytes],
           release_trust: bytes, release_revocation: bytes,
           f8_reference: bytes, b4_source: bytes, b9_source: bytes,
           head: str, boot_id: str, now: datetime) -> dict:
    """Review 10 operational signers + two *distinct* release signers.

    The historical F8 reference is documentary until its root-owned origin
    and actual F7/F8 boot receipts are checked independently.
    """
    need(type(f8_reference) is bytes and 0 < len(f8_reference) <= 8192,
         'F8_REFERENCE_SIZE')
    f8 = txn.parse_json(f8_reference)
    need(set(f8) == {'schema', 'plan', 'boot'} and
         f8['schema'] == REFERENCE_SCHEMA and
         type(f8['plan']) is str and f8['plan'] and
         type(f8['boot']) is str and f8['boot'], 'F8_REFERENCE_SCHEMA')
    need(type(release_trust) is bytes and type(release_revocation) is bytes,
         'RELEASE_DOCUMENT_BYTES_REQUIRED')
    signed = op.validate(payload=payload, external=external,
                         b4_source=b4_source, b9_source=b9_source,
                         head=head, boot_id=boot_id, now=now)
    b4 = op.pinned_module(b4_source, op.B4_SHA, 'r139_b4')
    b9 = op.pinned_module(b9_source, op.B9_SHA, 'r139_b9')
    b4docs = {
        name: b4.parse(raw)
        for name, raw in external.items()
        if name not in {'traffic_trust', 'traffic_revocation'}
    }
    b4docs.update({
        'grant': b4.parse(payload['B4/grant.json']),
        'contract': b4.parse(payload['B4/contract.json']),
        'scope_authorization': b4.parse(payload['B4/scope-authorization.json']),
        'pilot_permit': b4.parse(payload['B4/pilot-permit.json']),
        'traffic_window': b4.parse(payload['B4/traffic-window.json']),
    })
    verdict = b9.signed_release(
        auth=b4,
        manifest=b9.parse(payload['B9/manifest.json']),
        release=b9.parse(payload['B9/release.json']),
        trust=b9.parse(release_trust),
        revocation=b9.parse(release_revocation),
        b4docs=b4docs,
        boot_id=boot_id,
        f8_reference_sha256=hashlib.sha256(f8_reference).hexdigest(),
        traffic_trust=b9.parse(external['traffic_trust']),
        now=now,
    )
    need(verdict['head'] == signed['head'] and
         verdict['root_release_signed'] is True and
         verdict['operational_traffic_granted'] is False and
         verdict['p8'] == 'NO-GO', 'RELEASE_SEMANTIC_DRIFT')
    need(signed['root_install_authorized'] is False and
         signed['traffic_enabled'] is False and signed['p8'] == 'NO-GO',
         'OPERATIONAL_REVIEW_ESCALATED')
    return {
        'schema': SCHEMA + '-result',
        'head': head,
        'boot_id': boot_id,
        'inventory_sha256': signed['inventory_sha256'],
        'operational_signed_semantics': 'PASS',
        'release_signed_semantics': 'PASS',
        'release_sha256': verdict['release_sha256'],
        'release_revocation_sha256': verdict['revocation_sha256'],
        'f8_reference_sha256': verdict['f8_reference_sha256'],
        'twelve_distinct_signers_in_supplied_documents': True,
        'root_trust_provenance_verified': False,
        'source_commit_signature_independently_verified': False,
        'f8_physical_boot_chain_attested': False,
        'installation_permission': False,
        'root_installed': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def capabilities() -> dict:
    return {
        'schema': SCHEMA + '-capabilities',
        'b4_b9_operational_signatures': True,
        'b9_independent_release_signature': True,
        'b9_independent_release_revocation': True,
        'rejects_reused_signer_keys': True,
        'offline_supplied_bytes_only': True,
        'root_provenance_verified': False,
        'real_git_signature_verified': False,
        'root_installer': False,
        'traffic_enabled': False,
        'p8': 'NO-GO',
    }
