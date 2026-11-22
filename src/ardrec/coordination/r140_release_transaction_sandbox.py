"""R140: bind R139 signed review to R135 durable publication in a sandbox.

This is strictly a NONROOT, TEST-ONLY integration harness. It rejects the
operational installation paths and can write only under a uniquely named,
private directory directly inside the system temporary directory. No API
here can grant root installation or traffic. A successful offline signature
review does not independently authenticate any trust anchor's provenance.

IMPORTANT: never pass this harness or its authorizer to privileged R135 code.
A new independently provisioned root agent must implement real authorization.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import os
from pathlib import Path
import stat
import tempfile
from typing import Callable

from . import r135_root_transaction as txn
from . import r139_independent_release_review as release

SCHEMA = 'ARDREC-R140-SIGNED-TRANSACTION-SANDBOX-v1'
PREFIX = 'ardrec-r140-sandbox-'
STAGES = ('before_journal', 'before_b4', 'before_b9', 'before_receipt')


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def _sandbox(parent):
    need(os.geteuid() != 0, 'ROOT_FORBIDDEN')
    need(isinstance(parent, Path) and parent.is_absolute(), 'SANDBOX_PATH_INVALID')
    base = Path(tempfile.gettempdir()).resolve()
    # No descendant paths: only freshly allocated direct children of /tmp.
    need(parent.parent == base and parent.name.startswith(PREFIX),
         'SANDBOX_SCOPE_REQUIRED')
    need(not parent.is_symlink(), 'SANDBOX_SYMLINK_DENIED')
    st = parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700, 'SANDBOX_METADATA_INVALID')
    return parent


def _fingerprint(*, payload, external, release_trust, release_revocation,
                 f8_reference, b4_source, b9_source, head, boot_id):
    """Hash exact caller-supplied bytes to detect changes between phases."""
    need(type(payload) is dict and type(external) is dict, 'INPUT_MAPPING_TYPE')
    need(all(type(k) is str and type(v) is bytes for d in (payload, external)
             for k, v in d.items()), 'INPUT_ENTRY_TYPE')
    fields = (release_trust, release_revocation, f8_reference, b4_source, b9_source)
    need(all(type(x) is bytes for x in fields), 'DOCUMENT_BYTES_REQUIRED')
    need(type(head) is str and type(boot_id) is str, 'IDENTITY_TYPE_INVALID')
    identity = {
        'payload': {k: txn.digest(v) for k, v in sorted(payload.items())},
        'external': {k: txn.digest(v) for k, v in sorted(external.items())},
        'documents': [txn.digest(v) for v in fields],
        'head': head, 'boot_id': boot_id,
    }
    return txn.digest(txn.canonical(identity))


def _validate(*, payload, external, release_trust, release_revocation,
              f8_reference, b4_source, b9_source, head, boot_id, clock):
    current = clock()
    need(type(current) is datetime and current.tzinfo is not None and
         current.utcoffset() is not None, 'AWARE_CLOCK_REQUIRED')
    result = release.review(
        payload=payload, external=external, release_trust=release_trust,
        release_revocation=release_revocation, f8_reference=f8_reference,
        b4_source=b4_source, b9_source=b9_source, head=head,
        boot_id=boot_id, now=current,
    )
    plan = txn.validate_payload(payload, head)
    need(result['inventory_sha256'] == plan['inventory_sha256'] and
         result['head'] == head and result['boot_id'] == boot_id and
         result['operational_signed_semantics'] == 'PASS' and
         result['release_signed_semantics'] == 'PASS' and
         result['installation_permission'] is False and
         result['root_trust_provenance_verified'] is False and
         result['source_commit_signature_independently_verified'] is False and
         result['f8_physical_boot_chain_attested'] is False and
         result['root_installed'] is False and
         result['traffic_enabled'] is False and result['p8'] == 'NO-GO',
         'RELEASE_REVIEW_CANNOT_AUTHORIZE_INSTALL')
    return result, plan


def exercise_sandbox(*, parent: Path, payload: dict[str, bytes],
                     external: dict[str, bytes], release_trust: bytes,
                     release_revocation: bytes, f8_reference: bytes,
                     b4_source: bytes, b9_source: bytes, head: str,
                     boot_id: str, clock: Callable[[], datetime],
                     fault: str | None = None, test_phase_hook=None) -> dict:
    """Run two-phase durable R135 publication, exclusively in an offline sandbox.

    Each mutating phase reruns R139 against fresh synthetic inputs and checks
    the original byte fingerprint. The callback is deliberately internal, not
    an independently trusted authorizer. Publication is NEVER in TARGETS.

    ``test_phase_hook`` exists only for deterministic adversarial unit tests.
    """
    _sandbox(parent)
    need(fault in (None, 'after_stage', 'before_b4', 'after_b4',
                   'after_b9', 'before_receipt'), 'UNKNOWN_FAULT')
    need(callable(clock), 'CLOCK_REQUIRED')
    need(test_phase_hook is None or callable(test_phase_hook), 'HOOK_INVALID')
    named = dict(payload=payload, external=external,
                 release_trust=release_trust, release_revocation=release_revocation,
                 f8_reference=f8_reference, b4_source=b4_source,
                 b9_source=b9_source, head=head, boot_id=boot_id)
    frozen = _fingerprint(**named)
    initial, plan = _validate(**named, clock=clock)
    frozen_payload = dict(payload)
    phases = []

    def synthetic_authorizer(phase, state):
        need(phase in STAGES, 'UNKNOWN_TRANSACTION_PHASE')
        if test_phase_hook is not None:
            test_phase_hook(phase)
        need(_fingerprint(**named) == frozen,
             'INPUT_MUTATED_BETWEEN_PHASES')
        current, _ = _validate(**named, clock=clock)
        need(current['inventory_sha256'] == initial['inventory_sha256'] and
             state['inventory_sha256'] == initial['inventory_sha256'] and
             state['head'] == head, 'TRANSACTION_PLAN_BINDING_MISMATCH')
        phases.append(phase)
        # Synthetic approval ONLY for R135 writing into a private /tmp sandbox.
        # This is explicitly not a root-install permission or P8 authorization.
        return True

    outcome = txn.publish_pair(parent=parent, payload=frozen_payload,
                               head=head, authorize=synthetic_authorizer,
                               fault=fault)
    need(outcome['root_install_authorized'] is False and
         outcome['traffic_enabled'] is False and outcome['p8'] == 'NO-GO',
         'SANDBOX_OUTCOME_ESCALATED')
    return {
        'schema': SCHEMA + '-result',
        'status': outcome['status'],
        'receipt_sha256': outcome['receipt_sha256'],
        'inventory_sha256': initial['inventory_sha256'],
        'review_sha256': txn.digest(txn.canonical(initial)),
        'reviewed_phases': phases,
        'reviewed_phase_count': len(phases),
        'synthetic_unprivileged_publication': True,
        'operational_destinations_written': False,
        'root_trust_provenance_verified': False,
        'installation_permission': False,
        'root_install_executed': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def capabilities():
    return {
        'schema': SCHEMA + '-capabilities',
        'r139_signed_review_checked_before_each_mutation': True,
        'r135_durable_two_phase_publication_exercised': True,
        'requires_private_nonroot_tmp_sandbox': True,
        'accepts_untrusted_root_authorizer': False,
        'root_installer': False,
        'root_trust_provenance_verified': False,
        'physical_5_1_attested': False,
        'traffic_enabled': False,
        'p8': 'NO-GO',
    }
