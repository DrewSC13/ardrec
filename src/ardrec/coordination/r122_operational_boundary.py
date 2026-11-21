"""R122: source-bound FTP-T01 host/case preflight (no authority or traffic).

Reconciles R115-F5 physical capture, F16 safety/boot/P7 boundary, F13/F14
source journal, R121's exact interval and the previously existing A9 barrier.
This is not a traffic window, witness certification, A6 admission, Rf, or an
A9 generation. A host snapshot cannot prove connection-level provenance.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r115_f16_physical_pilot_controller as f16
from ardrec.coordination import r119_live_inspection as r119
from ardrec.coordination import r121_ftp_case_chain as r121

SCHEMA = 'ARDREC-R122-FTP-T01-F5-F16-F13-R121-BOUNDARY-v1'
ROOT = Path('/home/cicada/ardrec-lab/r122-ftp-boundary-audit-v1')
GIT = re.compile(r'[0-9a-f]{40}\Z')
MAX_SIZE = 65536


class Stop(ValueError):
    """Stable refusal code. Never an authorization signal."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def _clock(now: datetime) -> str:
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'CLOCK_UNTRUSTED')
    # F16's timestamps use whole seconds; refuse ambiguous precision.
    need(now.microsecond == 0, 'CLOCK_SUBSECOND_NOT_REPLAYABLE')
    return now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _source_paths(capture_folder: Path, journal_folder: Path | None) -> None:
    need(isinstance(capture_folder, Path) and capture_folder.is_absolute(),
         'CAPTURE_PATH_REQUIRED')
    if journal_folder is not None:
        need(isinstance(journal_folder, Path) and journal_folder.is_absolute(),
             'JOURNAL_PATH_REQUIRED')


def build(*, capture_folder: Path, catalog_raw: bytes, head: str,
          now: datetime, journal_folder: Path | None = None,
          unit: dict | None = None) -> dict[str, Any]:
    """Verify real F5 receipt and optional F13/R121 case; fail closed.

    F16 proof is recomputed; any signed scope/permit or root service changes
    must be admitted by a future *distinct* privileged executor. None are
    inferred from a clean offline/deny capture or from a local F13 candidate.
    """
    need(type(head) is str and GIT.fullmatch(head) is not None, 'GIT_HEAD')
    stamp = _clock(now)
    _source_paths(capture_folder, journal_folder)
    need((journal_folder is None) == (unit is None), 'PARTIAL_CASE_INPUT')
    need(type(catalog_raw) is bytes and
         f1.digest(catalog_raw) == f14.CATALOG_SHA256,
         'CATALOG_PIN_MISMATCH')
    try:
        capture, host = r119.replay_capture(capture_folder)
        physical = f16.assess(head=head, catalog_raw=catalog_raw,
                              capture=capture, now=now)
    except (f16.Stop, r119.Stop, f7.Stop, OSError,
            ValueError, KeyError, TypeError) as exc:
        raise Stop('F5_F16_PHYSICAL_REPLAY_REJECTED') from exc
    need(physical['pilot_release'] is False and
         physical['ordinary_p8'] == 'NO-GO' and
         physical['root_window_open'] is False and
         physical['a6'] == 'ND' and physical['a9'] is None and
         physical['network_connections_by_module'] == 0 and
         physical['guest_starts_by_module'] == 0,
         'PHYSICAL_BOUNDARY_PROMOTION')

    case = None
    case_head = None
    if journal_folder is not None:
        try:
            case = r121.build(journal_folder, catalog_raw, unit)
            r121.verify(case, catalog_raw)
            reservation = f13._read_json(journal_folder, 'reservation.json')
        except (r121.Stop, f13.Stop, f14.Stop, ValueError,
                KeyError, TypeError, OSError) as exc:
            raise Stop('F13_R121_CASE_REJECTED') from exc
        case_head = reservation['intent']['head']
        need(case_head == head, 'CASE_HEAD_NOT_CURRENT')
        need(case['case_id'] == reservation['intent']['case_id'] and
             case['a6_classification'] == 'ND' and
             case['a7_confirmed_rf'] is None and
             case['a8_applied_transition'] is None and
             case['a9_published_generation'] is None,
             'CASE_PROMOTION_FORBIDDEN')

    physical_sha = f1.digest(f1.canonical(physical))
    capture_sha = f1.digest(f1.canonical(capture))
    snapshot_sha = f1.digest(f1.canonical(host))
    blockers = set(physical['blockers'])
    blockers.update({
        'P7_DRAFT_NOT_FROZEN',
        'ROOT_ENFORCED_OPERATIONAL_P8_NOT_ADMITTED',
        'A6_INDEPENDENT_PHYSICAL_SUPPORT_NOT_ADMITTED',
        'A9_CONFIRMED_GENERATION_NOT_PUBLISHED',
    })
    if case is None:
        blockers.add('F13_R121_CASE_NOT_SELECTED')
    else:
        blockers.add('F13_CANDIDATE_NOT_INDEPENDENT_PHYSICAL_WITNESS')
    # Recorded F5 state is not a fresh, independently authorized connection.
    age = (now.astimezone(timezone.utc) -
           f1._instant(capture['end'], 'R122_CAPTURE_END')).total_seconds()
    need(-86400 <= age <= 86400 * 365, 'CAPTURE_CLOCK_OUTSIDE_REPLAY_WINDOW')
    if not (-2 <= age <= f16.MAX_READBACK_AGE_SECONDS):
        blockers.add('F5_CAPTURE_NOT_FRESH')
    if host['lifecycle_stage'] == 'OFFLINE_DENY_BASELINE_MATCH':
        blockers.add('HOST_OFFLINE_NO_FTP_T01_TRAFFIC')
    need(blockers, 'GATE_BLOCKERS_REQUIRED')
    out = {
        'schema': SCHEMA,
        'head': head,
        'evaluated_at_utc': stamp,
        'capture_folder': str(capture_folder),
        'capture_sha256': capture_sha,
        'host_report_sha256': snapshot_sha,
        'host_lifecycle': host['lifecycle_stage'],
        'host_states': host['states'],
        'host_f11_r34': {'nft': host['nft'], 'helper': host['helper'],
                         'f11_hook': host['f11_hook']},
        'f16_report_sha256': physical_sha,
        'f16_blockers': physical['blockers'],
        'f16_signed_documents_checked': False,
        'f16_live_ftp_deny_stage_attested': physical['physical_deny'] is not None,
        'journal_folder': None if journal_folder is None else str(journal_folder),
        'journal_head': case_head,
        'case_id': None if case is None else case['case_id'],
        'case_key': None if case is None else case['case_key'],
        'case_sha256': None if case is None else case['sha256'],
        'declared_unit': None if case is None else case['declared_unit'],
        'a5_source_status': 'NOT_SELECTED' if case is None else case['f14_source_status'],
        'a6': 'ND',
        'a7_interval': None if case is None else [case['a7_lower'], case['a7_upper']],
        'a7_confirmed_rf': None,
        'a8_recommendation': None if case is None else case['a8_recommendation'],
        'a8_authoritative_transition': None,
        'a9_generation': None,
        'a10': 'REPLAYABLE_INSPECTION_NOT_AUTHORITATIVE_PUBLICATION',
        'p7': 'DRAFT_NOT_EXECUTABLE',
        'p8': 'NO-GO',
        'physical_origin_attested': False,
        'dispatch_authorized': False,
        'network_connections_by_r122': 0,
        'guest_starts_by_r122': 0,
        'firewall_changes_by_r122': 0,
        'blockers': sorted(blockers),
    }
    need(len(f1.canonical(out)) < MAX_SIZE, 'BOUNDARY_TOO_LARGE')
    out['sha256'] = f1.digest(f1.canonical(out))
    return out


def verify(report: dict, catalog_raw: bytes) -> bool:
    need(type(report) is dict and report.get('schema') == SCHEMA and
         type(report.get('capture_folder')) is str and
         type(report.get('head')) is str and
         type(report.get('evaluated_at_utc')) is str and
         (report.get('journal_folder') is None or
          type(report.get('journal_folder')) is str), 'REPORT_SCHEMA')
    raw_unit = report.get('declared_unit')
    if report.get('journal_folder') is None:
        need(raw_unit is None, 'PARTIAL_UNIT_IN_REPORT')
    else:
        need(type(raw_unit) is dict, 'UNIT_MISSING_FROM_REPORT')
    need(len(report['capture_folder']) <= 1024 and
         (report['journal_folder'] is None or len(report['journal_folder']) <= 1024),
         'REPORT_PATH_LIMIT')
    try:
        when = datetime.strptime(report['evaluated_at_utc'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        expected = build(capture_folder=Path(report['capture_folder']),
                         journal_folder=(None if report['journal_folder'] is None else
                                         Path(report['journal_folder'])),
                         unit=raw_unit, catalog_raw=catalog_raw,
                         head=report['head'], now=when)
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise Stop('REPLAY_SOURCE_MISSING_OR_CHANGED') from exc
    need(f1.canonical(report) == f1.canonical(expected),
         'BOUNDARY_REPORT_DRIFT')
    return True


def persist(report: dict, catalog_raw: bytes, *, root: Path = ROOT) -> Path:
    """Write one append-only private audit. Never uses global DurableStore HEAD."""
    need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    verify(report, catalog_raw)
    need(isinstance(root, Path) and root.is_absolute() and
         root.parent.is_dir() and not root.parent.is_symlink() and
         not root.is_symlink(), 'AUDIT_ROOT')
    r121._private(root.parent)
    if not root.exists():
        root.mkdir(mode=0o700)
        f13._fsync_directory(root.parent)
    r121._private(root)
    folder = f7._create(root, 'assessment-')
    body = f1.canonical(report)
    f2.exclusive(folder/'report.json', body)
    f2.exclusive(folder/'manifest.json', f1.canonical({
        'schema': SCHEMA+'-manifest',
        'report_sha256': f1.digest(body),
        'capture_sha256': report['capture_sha256'],
        'case_sha256': report['case_sha256'],
        'p8': 'NO-GO', 'a9': None,
    }))
    f13._fsync_directory(folder)
    f13._fsync_directory(root)
    return folder


def verify_persisted(folder: Path, catalog_raw: bytes) -> dict:
    need(isinstance(folder, Path) and folder.is_absolute(), 'AUDIT_FOLDER_REQUIRED')
    r121._private(folder.parent)
    r121._private(folder)
    need({p.name for p in folder.iterdir()} == {'report.json', 'manifest.json'},
         'AUDIT_FILES_CHANGED')
    try:
        report_raw = r121._read(folder, 'report.json', MAX_SIZE)
        manifest_raw = r121._read(folder, 'manifest.json', 4096)
    except (r121.Stop, OSError, ValueError) as exc:
        raise Stop('AUDIT_FILE_UNSAFE_OR_CHANGED') from exc
    report = f1.load(report_raw)
    manifest = f1.load(manifest_raw)
    need(report_raw == f1.canonical(report) and
         manifest_raw == f1.canonical(manifest) and
         type(manifest) is dict and set(manifest) == {
             'schema','report_sha256','capture_sha256','case_sha256','p8','a9'
         } and manifest['schema'] == SCHEMA+'-manifest' and
         manifest['report_sha256'] == f1.digest(report_raw) and
         manifest['capture_sha256'] == report.get('capture_sha256') and
         manifest['case_sha256'] == report.get('case_sha256') and
         manifest['p8'] == 'NO-GO' and manifest['a9'] is None,
         'AUDIT_MANIFEST_DRIFT')
    verify(report, catalog_raw)
    return report


def capabilities() -> dict:
    return {
        'schema': SCHEMA+'-capabilities',
        'real_f5_capture_verified': True,
        'f16_root_pilot_boundary_replayed': True,
        'f13_f14_r121_case_bound_when_supplied': True,
        'a7_exact_interval_when_supplied': True,
        'private_a10_audit_replay': True,
        'independent_current_p8_permit_accepted': False,
        'physical_provenance_admitted': False,
        'a6': 'ND', 'a9_generation': None, 'p8': 'NO-GO',
        'opens_sockets': False, 'boots_vms': False, 'changes_firewall': False,
    }
