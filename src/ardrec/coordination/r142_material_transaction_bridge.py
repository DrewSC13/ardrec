"""R142: guarded R141 snapshot -> R139 signed review -> R140 nonroot transaction.

A fixed file-descriptor root is re-read before EVERY synthetic publication phase.
The fresh snapshot must match the initial snapshot byte-for-byte; R139 then
revalidates the signatures and revocations at the current supplied clock.

This bridge is an unprivileged test harness. Its snapshot root is a private
fixture, NOT host /. It cannot authenticate out-of-band root provenance or
actual Git signatures, and cannot install an operational root bundle.
"""
from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
from typing import Callable

from . import r141_root_material_reader as reader141
from . import r140_release_transaction_sandbox as sandbox140

SCHEMA = 'ARDREC-R142-MATERIAL-TRANSACTION-REVIEW-v1'
EXPECTED_EXTERNAL = frozenset(
    set(reader141.POLICY) - {'release_trust', 'release_revocation'}
)


class Refusal(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Refusal(why)


def _snapshot(reader):
    need(os.geteuid() != 0, 'ROOT_FORBIDDEN')
    need(isinstance(reader, reader141.LockedTree) and reader.fd >= 0 and
         reader.system_root is False and reader.owner == os.geteuid() and
         reader.root != Path('/'), 'UNPRIVILEGED_READER_REQUIRED')
    snapshot = reader141.capture(reader, include_policies=True)
    need(set(snapshot['external']) == set(reader141.POLICY) | {'f8_reference'},
         'EXTERNAL_SOURCE_SCOPE_INVALID')
    need(snapshot['receipt']['payload_count'] == 13 and
         snapshot['receipt']['external_count'] == 13 and
         snapshot['receipt']['root_install_authorized'] is False,
         'READER_RECEIPT_SCOPE_INVALID')
    need(snapshot['receipt']['documentary_approval_is_authority'] is False,
         'DOCUMENTARY_APPROVAL_NOT_AUTHORITY')
    return snapshot


def _inputs(snapshot, *, head, boot_id):
    external = snapshot['external']
    need(set(external) == set(reader141.POLICY) | {'f8_reference'},
         'EXTERNAL_SOURCE_SCOPE_INVALID')
    return {
        'payload': dict(snapshot['payload']),
        'external': {name: external[name] for name in sorted(EXPECTED_EXTERNAL)},
        'release_trust': external['release_trust'],
        'release_revocation': external['release_revocation'],
        'f8_reference': external['f8_reference'],
        'b4_source': snapshot['payload']['B4/root-controller.py'],
        'b9_source': snapshot['payload']['B9/root-executor.py'],
        'head': head,
        'boot_id': boot_id,
    }


def review_from_reader(*, reader, head: str, boot_id: str,
                       clock: Callable[[], datetime]):
    """Review actual fixture bytes; no publication and no authority granted."""
    need(callable(clock), 'CLOCK_REQUIRED')
    snapshot = _snapshot(reader)
    inputs = _inputs(snapshot, head=head, boot_id=boot_id)
    signed, plan = sandbox140._validate(**inputs, clock=clock)
    need(signed['installation_permission'] is False and
         plan['root_install_authorized'] is False, 'REVIEW_AUTHORITY_ESCALATED')
    return {
        'schema': SCHEMA + '-readonly-review',
        'input_receipt': snapshot['receipt'],
        'operational_signed_semantics': signed['operational_signed_semantics'],
        'release_signed_semantics': signed['release_signed_semantics'],
        'inventory_sha256': signed['inventory_sha256'],
        'head': head,
        'boot_id': boot_id,
        'root_provenance_verified': False,
        'independent_git_signature_verified': False,
        'root_install_authorized': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def exercise_from_reader(*, reader: reader141.LockedTree, parent: Path,
                         head: str, boot_id: str,
                         clock: Callable[[], datetime],
                         fault: str | None = None,
                         test_phase_hook=None):
    """Exercise a signed transaction in a private NONROOT sandbox only.

    Every phase re-reads the protected tree and checks the exact capture digest
    AND the documentary approval digest against the initial read. The R140
    authorization callback revalidates R139 semantics/freshness afterwards.
    Initial or phase-local success never authorizes root or network operations.
    """
    need(os.geteuid() != 0, 'ROOT_FORBIDDEN')
    need(callable(clock), 'CLOCK_REQUIRED')
    need(test_phase_hook is None or callable(test_phase_hook), 'HOOK_INVALID')
    first = _snapshot(reader)
    input_values = _inputs(first, head=head, boot_id=boot_id)
    before = first['receipt']['content_sha256']
    before_approval = first['receipt']['documentary_approval_sha256']
    read_phases = []

    def reread(phase):
        if test_phase_hook is not None:
            test_phase_hook(phase)
        current = _snapshot(reader)
        need(current['receipt']['content_sha256'] == before and
             current['receipt']['documentary_approval_sha256'] == before_approval,
             'ROOT_INPUT_CHANGED_BETWEEN_PHASES')
        # There are 13 payload bytes and 13 external bytes. Compare concrete
        # bytes too, so a changed memory object cannot be hidden by a digest.
        need(current['payload'] == first['payload'] and
             current['external'] == first['external'] and
             current['approval_raw'] == first['approval_raw'],
             'ROOT_INPUT_BYTES_CHANGED')
        read_phases.append(phase)

    result = sandbox140.exercise_sandbox(
        parent=parent, clock=clock, fault=fault,
        test_phase_hook=reread, **input_values,
    )
    # Ensure the source remains unchanged up to the receipt/readback boundary.
    final = _snapshot(reader)
    need(final['receipt']['content_sha256'] == before and
         final['receipt']['documentary_approval_sha256'] == before_approval and
         final['payload'] == first['payload'] and
         final['external'] == first['external'] and
         final['approval_raw'] == first['approval_raw'],
         'SOURCE_CHANGED_AFTER_PUBLICATION')
    need(result['reviewed_phases'] == read_phases and
         result['root_install_executed'] is False and
         result['installation_permission'] is False and
         result['traffic_enabled'] is False and result['p8'] == 'NO-GO',
         'SANDBOX_OUTCOME_ESCALATED')
    return {
        'schema': SCHEMA + '-result',
        'status': result['status'],
        'input_receipt_sha256': reader141.digest(reader141.canonical(first['receipt'])),
        'input_content_sha256': before,
        'inventory_sha256': result['inventory_sha256'],
        'receipt_sha256': result['receipt_sha256'],
        'phases_rechecked': list(read_phases),
        'phase_readbacks': len(read_phases),
        'protected_files_checked_per_read': 27,
        'root_provenance_verified': False,
        'independent_git_signature_verified': False,
        'physical_f8_chain_attested': False,
        'root_install_authorized': False,
        'root_install_executed': False,
        'operational_destinations_written': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }


def capabilities():
    return {
        'schema': SCHEMA + '-capabilities',
        'snapshot_and_phase_recheck': True,
        'rechecks_ed25519_and_revocation_per_phase': True,
        'sandbox_transaction_recovery': True,
        'root_provenance_verified': False,
        'source_commit_signature_independently_verified': False,
        'root_installer': False,
        'root_install_authorized': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }
