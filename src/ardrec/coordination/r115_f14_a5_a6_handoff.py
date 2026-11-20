"""R115-F14: replayable A5 journal -> A6 support-boundary review.

Never dispatches traffic, never authenticates a socket's physical origin,
never admits an A6 fact, computes confirmed risk, changes A8 state, publishes
A9, or claims an A10 generation.  Designed to consume a future P8 source
without confusing a byte-integrity check with independent provenance.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f10_ftp_a5_transport as f10
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13

SCHEMA = 'ARDREC-R115-F14-A5-A6-CANDIDATE-BRIDGE-v1'
ROOT = Path('/home/cicada/ardrec-lab/r115-f14-a5-a6-boundary-v1')
CATALOG = Path('lab/operational-catalog-v1/catalog.json')
CATALOG_SHA256 = '5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e'
SOURCE = 'src/ardrec/coordination/r115_f14_a5_a6_handoff.py'
SCRIPT = 'scripts/ardrec_p14_r115_f14_a5_a6_handoff.py'

class Stop(ValueError):
    """Fail closed without creating an operational authorization."""


def need(ok, code):
    if not ok:
        raise Stop(code)


def catalog_check(raw):
    need(type(raw) is bytes and f1.digest(raw) == CATALOG_SHA256,
         'PINNED_CATALOG_DIGEST')
    # Reuse F12's complete original family and prepilot guard, never freeze P7.
    try:
        status = f12.prepilot_review(raw, head='0'*40)
    except (f12.Stop, f1.Rejected, KeyError, TypeError) as exc:
        raise Stop('CATALOG_OR_PREPILOT_INVALID') from exc
    need(status['execution_enabled'] is False and
         status['pilot_completed'] is False and
         status['catalog_frozen'] is False and
         status['p8'] == 'NO-GO', 'P7_STATUS_CHANGED')
    return status


def _source(folder):
    need(isinstance(folder, Path) and folder.is_absolute(),
         'SOURCE_PATH_ABSOLUTE_REQUIRED')
    try:
        status = f13.inspect(folder)
        reservation = f13._read_json(folder, 'reservation.json')
        terminal = (f13._read_json(folder, 'result.json')
                    if status['status'] == 'RESULT_CANDIDATE_ONLY' else None)
        return status, reservation, terminal
    except (f13.Stop, f12.Stop, f1.Rejected, OSError,
            ValueError, TypeError, KeyError) as exc:
        raise Stop('F13_SOURCE_NOT_REPLAYABLE') from exc


def build(folder, catalog_raw):
    """Reconstruct source bytes and conservatively classify required supports.

    A complete 220 greeting confirms only that the candidate contains a
    syntactically complete 220 reply. It does not prove physical source, service
    security, vulnerability, FTP login, or any positive A6 technical condition.
    """
    prepilot = catalog_check(catalog_raw)
    state, reservation, terminal = _source(folder)
    intent = reservation['intent']
    need(intent['family_id'] == 'FTP-T01' and
         intent['target'] == {'ip': f10.TARGET_IP, 'port': f10.TARGET_PORT},
         'SOURCE_NOT_FTP_T01')
    need(state['reservation_sha256'] == f1.digest(f1.canonical(reservation)),
         'SOURCE_RESERVATION_CHANGED')
    complete = False
    f10_hash = None
    recv_calls = None
    recv_bytes = None
    outcome = 'NO_RESULT'
    if terminal is not None:
        # F13 inspect() already replayed F10/F12 byte, budget and manifest checks.
        need(terminal['status'] == 'RESULT_CANDIDATE_ONLY' and
             terminal['physical_provenance_attested'] is False,
             'SOURCE_FALSE_PROVENANCE')
        outcome = terminal['f10']['reply_status']
        complete = terminal['audit']['reply_complete_220'] is True
        f10_hash = f1.digest(f1.canonical(terminal['f10']))
        need(terminal['audit']['candidate_f10_sha256'] == f10_hash,
             'F10_AUDIT_SHA_MISMATCH')
        recv_calls = terminal['meter']['recv_calls']
        recv_bytes = terminal['meter']['received_bytes']
        need(terminal['f10']['target'] == intent['target'] and
             recv_bytes <= reservation['profile']['max_recv_bytes'],
             'TARGET_OR_BUDGET_DRIFT')
    elif state['status'] in ('FAILED_NO_RETRY', 'ATTEMPT_CONSUMED_UNRESOLVED',
                             'RESERVED_NO_RETRY'):
        outcome = state['status']
    else:
        raise Stop('SOURCE_STATUS_UNKNOWN')
    supports = {
        'TARGET_ATTESTATION': {
            'technical_truth': 'ND',
            'review': 'VM_TARGET_AND_LIVE_PEER_NOT_INDEPENDENTLY_ATTESTED',
            'support_accepted': False},
        'INTEGRITY_PROVENANCE': {
            'technical_truth': 'ND',
            'review': 'LOCAL_HASHES_VERIFIED_BUT_PHYSICAL_SOURCE_NOT_ATTESTED',
            'support_accepted': False},
        'CONTROL_CHANNEL_RESPONSE': {
            'technical_truth': 'ND',
            'review': ('CANDIDATE_BYTES_REPLAY_VERIFIED_NOT_A6_SUPPORT'
                       if terminal is not None else 'NO_COMPLETE_A5_CANDIDATE'),
            'support_accepted': False},
    }
    need(tuple(supports) == f1.SUPPORTS, 'CATALOG_SUPPORT_ORDER')
    summary = {
        'schema': SCHEMA+'-report',
        'source_kind': 'F13_LOCAL_RECEIPT_NOT_INDEPENDENT_PHYSICAL_PROVENANCE',
        'source_case_key': state['case_key'],
        'source_reservation_sha256': state['reservation_sha256'],
        'source_status': state['status'],
        'source_f10_sha256': f10_hash,
        'source_receipt_path': str(folder),
        'intent_sha256': f1.digest(f1.canonical(intent)),
        'case_id': intent['case_id'],
        'session_id': intent['session_id'],
        'assessment_index': intent['assessment_index'],
        'family_id': 'FTP-T01',
        'catalog_sha256': prepilot['catalog_sha256'],
        'candidate_outcome': outcome,
        'candidate_complete_220': complete,
        'candidate_recv_calls': recv_calls,
        'candidate_received_bytes': recv_bytes,
        'supports': supports,
        'required_supports': list(f1.SUPPORTS),
        'accepted_support_count': 0,
        'physical_origin_attested': False,
        'technical_truth_accredited': False,
        'a3': {name: 'ND' for name in f1.GATES},
        'a5': 'CANDIDATE_ONLY_NOT_PHYSICAL_ATTESTATION',
        'a6': 'ND',
        'a7_confirmed_risk': None,
        'a8_transition_applied': None,
        'a9_published_generation': None,
        'a10_generation_confirmation': None,
        'p7_pilot_completed': False,
        'p7_execution_enabled': False,
        'p8': 'NO-GO',
        'p8_blockers': [
            'P7_PILOT_NOT_COMPLETED',
            'INDEPENDENT_SCOPE_AND_P8_TRUST_NOT_ATTESTED',
            'RUNTIME_A3_AND_F11_R34_NOT_ATTESTED_HERE',
            'F13_NO_INDEPENDENT_PHYSICAL_PROVENANCE',
            'A6_SUPPORTS_NOT_ACCREDITED',
        ],
        'socket_connections_by_f14': 0,
        'guest_starts_by_f14': 0,
        'firewall_changes_by_f14': 0,
    }
    # Prevent ambiguous serialization across source types.
    need(len(f1.canonical(summary)) < 16000, 'REPORT_TOO_LARGE')
    return summary


def replay(report, catalog_raw):
    need(type(report) is dict and report.get('schema') == SCHEMA+'-report',
         'REPORT_SCHEMA')
    path = report.get('source_receipt_path')
    need(type(path) is str and len(path) <= 512, 'SOURCE_PATH_INVALID')
    expected = build(Path(path), catalog_raw)
    need(f1.canonical(report) == f1.canonical(expected),
         'REPORT_NOT_REPRODUCIBLE')
    return True


def _secure_folder(path):
    need(isinstance(path, Path) and path.is_absolute(), 'PRIVATE_PATH_REQUIRED')
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700, 'PRIVATE_DIRECTORY_MODE')


def persist(report, *, root=ROOT):
    """Write a private audit receipt. Never opens a network connection."""
    need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    need(isinstance(root, Path) and root.is_absolute(), 'ROOT_PATH_REQUIRED')
    # Do not use untrusted arbitrary parent/symlink for a private store.
    need(not root.is_symlink() and root.parent.is_dir() and
         not root.parent.is_symlink(), 'ROOT_PARENT_UNSAFE')
    _secure_folder(root.parent)
    if root.exists():
        _secure_folder(root)
    else:
        root.mkdir(mode=0o700)
        _secure_folder(root)
    folder = f7._create(root, 'review-')
    raw = f1.canonical(report)
    f2.exclusive(folder/'report.json', raw)
    f2.exclusive(folder/'manifest.json', f1.canonical({
        'schema': SCHEMA+'-manifest', 'report_sha256': f1.digest(raw),
        'physical_source_attested': False, 'a6': 'ND', 'p8': 'NO-GO'}))
    return folder


def verify_persisted(path, catalog_raw):
    need(isinstance(path, Path) and path.is_absolute(), 'REPORT_PATH_REQUIRED')
    _secure_folder(path)
    # F13's _read_json allowlist is journal-specific; use a distinct private
    # report reader rather than weakening its protected journal API.
    def one(name):
        p = path/name
        st = p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
             stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1 and
             0 < st.st_size < 20000, 'REPORT_FILE_UNSAFE')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            at = os.fstat(fd)
            need((at.st_dev,at.st_ino,at.st_size,at.st_uid)==
                 (st.st_dev,st.st_ino,st.st_size,st.st_uid),
                 'REPORT_FILE_RACE')
            data = os.read(fd, 20000)
            need(len(data) == st.st_size, 'REPORT_FILE_SHORT')
            value = f1.load(data)
            need(data == f1.canonical(value), 'REPORT_NOT_CANONICAL')
            return value
        finally:
            os.close(fd)
    need({p.name for p in path.iterdir()} ==
         {'report.json', 'manifest.json'}, 'REPORT_FILES_CHANGED')
    manifest = one('manifest.json')
    report = one('report.json')
    need(type(manifest) is dict and set(manifest) ==
         {'schema','report_sha256','physical_source_attested','a6','p8'} and
         manifest['schema'] == SCHEMA+'-manifest' and
         manifest['report_sha256'] == f1.digest(f1.canonical(report)) and
         manifest['physical_source_attested'] is False and
         manifest['a6'] == 'ND' and manifest['p8'] == 'NO-GO',
         'REPORT_MANIFEST_DRIFT')
    replay(report, catalog_raw)
    return report

def capabilities():
    return {'schema': SCHEMA+'-capabilities', 'family_id': 'FTP-T01',
            'verifies_f13_journal_and_f10_f12_replay': True,
            'records_a6_supports_as_unaccredited': True,
            'reports_p7_p8_blockers': True,
            'issues_approval': False, 'opens_sockets': False,
            'boots_guests': False, 'changes_firewall': False,
            'admits_a6': False, 'publishes_a9_generation': False,
            'a6': 'ND', 'p8': 'NO-GO'}
