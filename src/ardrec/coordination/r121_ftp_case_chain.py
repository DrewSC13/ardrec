"""R121: reproducible FTP-T01 candidate -> A6 ND -> exact A7 -> A8 guard -> A10 audit.

Read-only case coordinator over existing F13/F14 and R58-E kernels.  A local
candidate is NOT authenticated physical evidence.  This module NEVER grants
P8, runs sockets/VMs, updates the A8 state machine, or publishes an A9 generation.
Audit persistence is not authoritative state publication.  R121 accepts only
explicit rational input magnitudes bound to the F13 case identity.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f14_a5_a6_handoff as f14
from ardrec.coordination import r58e_evidence_risk_bridge as bridge
from ardrec.analytics.r58d_interval_kernel import UNIT_KEYS
from ardrec.stopping.development_stop import verify_stop

SCHEMA = 'ARDREC-R121-FTP-T01-CONDITIONAL-A5-A10-CASE-v1'
ROOT = Path('/home/cicada/ardrec-lab/r121-ftp-case-audit-v1')
MAX_REPORT = 65536
HEX = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
COVERAGE = ('A1','A2','A3','A4','A5','A6','A7','A8','A9','A10')


class Stop(ValueError):
    """Fail closed, never evidence of execution permission."""


def need(ok: bool, code: str):
    if not ok:
        raise Stop(code)


def _unit(journal: dict, unit: dict) -> dict:
    """Bind explicitly declared baseline magnitudes to a single F13 window."""
    need(type(unit) is dict and set(unit) == UNIT_KEYS, 'UNIT_FIELDS')
    case_id = journal['case_id']
    expected = {
        'service_id': 'FTP_DEV', 'case_id': case_id.replace('-', '_'),
        'assessment_index': journal['assessment_index'],
    }
    need(all(type(unit.get(k)) is type(v) and unit[k] == v
             for k, v in expected.items()), 'UNIT_NOT_BOUND_TO_F13')
    need(type(unit['evidence']) is list and unit['evidence'] == [],
         'UNIT_PREDECLARED_EVIDENCE_FORBIDDEN')
    # Math normalization is delegated to R58-E/R58-D, not silently corrected.
    return dict(unit)


def _source(journal_folder: Path, catalog_raw: bytes, unit: dict) -> tuple[dict, dict]:
    need(isinstance(journal_folder, Path) and journal_folder.is_absolute(),
         'F13_ABSOLUTE_PATH_REQUIRED')
    handoff = f14.build(journal_folder, catalog_raw)
    need(handoff['a6'] == 'ND' and handoff['accepted_support_count'] == 0
         and handoff['physical_origin_attested'] is False
         and handoff['a9_published_generation'] is None
         and handoff['p8'] == 'NO-GO', 'F14_PROMOTION_REJECTED')
    return handoff, _unit(handoff, unit)


def build(journal_folder: Path, catalog_raw: bytes, unit: dict) -> dict[str, Any]:
    """Execute existing F14 + R58-E/R58-D + A8 decision on ONE case.

    R58-E receives no documentary admission because F14 supplies no independently
    admitted physical support. Its A7 is an unresolved mathematical interval,
    never a confirmed risk number.  The result is an auditable R121 projection,
    not an A9 global generation.
    """
    handoff, bound_unit = _source(journal_folder, catalog_raw, unit)
    mathematical = bridge.build_unit_bridge([bound_unit], [])
    bridge.verify_unit_bridge(mathematical)
    decision = mathematical['decisions'][0]
    risk = mathematical['a7']['results'][0]
    need(decision['a6_status'] == 'MISSING_DOCUMENTARY_ADMISSION'
         and decision['a6_classification'] == 'ND'
         and decision['confirmed_rf'] is None
         and decision['a8_applied_transition'] is None
         and risk['point_identified'] is False
         and risk['evidence_lower'] == '0' and risk['evidence_upper'] == '1'
         and risk['confirmed_rf'] is None
         and mathematical['published_generation'] is None,
         'KERNEL_ADMISSION_OR_RISK_PROMOTED')
    source_sha = f1.digest(f1.canonical(handoff))
    math_sha = mathematical['sha256']
    stage_inputs = (
        ('A1','NOT_AUTHENTICATED_CURRENT', source_sha),
        ('A2','P7_DRAFT_NOT_EXECUTABLE', handoff['catalog_sha256']),
        ('A3','AUTHORITY_NOT_ATTESTED', source_sha),
        ('A4','NOT_DISPATCH_ELIGIBLE', handoff['catalog_sha256']),
        ('A5',handoff['source_status'], handoff['source_reservation_sha256']),
        ('A6','ND_NO_ADMITTED_PHYSICAL_SUPPORT', source_sha),
        ('A7','UNRESOLVED_EXACT_INTERVAL', math_sha),
        ('A8','PAUSE_RECOMMENDED_NOT_APPLIED', decision['a8_stop_sha256']),
        ('A9','NO_GENERATION_PUBLISHED', f1.digest(f1.canonical({'generation': None}))),
        ('A10','REPLAYABLE_AUDIT_ONLY', math_sha),
    )
    previous = None
    stages = []
    for ordinal, (algo, status, source) in enumerate(stage_inputs, 1):
        item = {'ordinal': ordinal, 'algorithm': algo, 'status': status,
                'source_sha256': source, 'previous_sha256': previous,
                'operationally_executed': False}
        item['sha256'] = f1.digest(f1.canonical(item))
        previous = item['sha256']
        stages.append(item)
    out = {
        'schema': SCHEMA,
        'mode': 'F13_REPLAY_F14_REVIEW_R58E_EXACT_NO_AUTHORITY',
        'case_id': handoff['case_id'], 'session_id': handoff['session_id'],
        'assessment_index': handoff['assessment_index'],
        'case_key': handoff['source_case_key'], 'family_id': 'FTP-T01',
        'f13_folder': str(journal_folder),
        'catalog_sha256': handoff['catalog_sha256'],
        'f14_report_sha256': source_sha,
        'f14_source_status': handoff['source_status'],
        'candidate_outcome': handoff['candidate_outcome'],
        'candidate_complete_220': handoff['candidate_complete_220'],
        'declared_unit': bound_unit,
        'r58e_bridge_sha256': math_sha,
        'a7_lower': risk['rf_lower'], 'a7_upper': risk['rf_upper'],
        'a7_uncertainty': 'UNRESOLVED_0_TO_1', 'a7_confirmed_rf': None,
        'a6_classification': 'ND', 'a6_supports_accepted': 0,
        'a8_recommendation': decision['a8_recommendation'],
        'a8_stop_sha256': decision['a8_stop_sha256'],
        'a8_applied_transition': None,
        'a9_published_generation': None,
        'a9_audit_only_not_global_store': True,
        'a10_status': 'REPLAYABLE_AUDIT_NO_OPERATIONAL_GENERATION',
        'physical_provenance_attested': False,
        'p7_catalog_frozen': False,
        'p8': 'NO-GO',
        'physical_actions_by_r121': 0,
        'stages': stages, 'stage_head_sha256': previous,
    }
    raw = f1.canonical(out)
    need(len(raw) <= MAX_REPORT, 'REPORT_TOO_LARGE')
    out['sha256'] = f1.digest(raw)
    return out


def verify(report: dict, catalog_raw: bytes) -> bool:
    need(type(report) is dict and report.get('schema') == SCHEMA
         and type(report.get('f13_folder')) is str
         and len(report['f13_folder']) <= 1024
         and type(report.get('declared_unit')) is dict,
         'REPORT_SCHEMA')
    expected = build(Path(report['f13_folder']), catalog_raw, report['declared_unit'])
    need(report == expected and f1.canonical(report) == f1.canonical(expected),
         'CASE_CHAIN_NOT_REPRODUCIBLE')
    return True


def _private(folder: Path) -> None:
    need(isinstance(folder, Path) and folder.is_absolute(), 'PRIVATE_PATH')
    st = folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o700, 'PRIVATE_DIRECTORY_OWNER_MODE')


def _read(folder: Path, name: str, limit=MAX_REPORT) -> bytes:
    need(name in ('report.json', 'manifest.json'), 'FILE_NAME_NOT_ALLOWED')
    _private(folder)
    p = folder/name
    st = p.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
         and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o600
         and 0 < st.st_size <= limit, 'AUDIT_FILE_UNSAFE')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(fd)
        need((observed.st_dev, observed.st_ino, observed.st_size, observed.st_uid) ==
             (st.st_dev, st.st_ino, st.st_size, st.st_uid), 'AUDIT_RACE')
        raw = os.read(fd, limit+1)
        need(len(raw) == st.st_size, 'AUDIT_SHORT_READ')
        return raw
    finally:
        os.close(fd)


def persist(report: dict, catalog_raw: bytes, *, root=ROOT) -> Path:
    """Store one private, append-only R121 audit (NOT an A9 generation)."""
    need(os.geteuid() != 0, 'ROOT_SHELL_FORBIDDEN')
    verify(report, catalog_raw)
    need(isinstance(root, Path) and root.is_absolute(), 'ROOT_PATH')
    need(not root.is_symlink() and root.parent.is_dir()
         and not root.parent.is_symlink(), 'ROOT_PARENT')
    _private(root.parent)
    if not root.exists():
        root.mkdir(mode=0o700)
        f13._fsync_directory(root.parent)
    _private(root)
    folder = f7._create(root, 'audit-')
    body = f1.canonical(report)
    f2.exclusive(folder/'report.json', body)
    manifest = {
        'schema': SCHEMA+'-manifest',
        'report_sha256': f1.digest(body),
        'source_case_key': report['case_key'],
        'stage_head_sha256': report['stage_head_sha256'],
        'p8': 'NO-GO', 'a9_generation': None,
    }
    f2.exclusive(folder/'manifest.json', f1.canonical(manifest))
    f13._fsync_directory(folder)
    f13._fsync_directory(root)
    return folder


def verify_persisted(folder: Path, catalog_raw: bytes) -> dict:
    need(isinstance(folder, Path) and folder.is_absolute(), 'REPLAY_PATH')
    _private(folder.parent)
    _private(folder)
    need({p.name for p in folder.iterdir()} == {'report.json', 'manifest.json'},
         'AUDIT_ENTRY_SET')
    raw = _read(folder, 'report.json')
    manifest_raw = _read(folder, 'manifest.json', 4096)
    report = f1.load(raw)
    manifest = f1.load(manifest_raw)
    need(raw == f1.canonical(report) and manifest_raw == f1.canonical(manifest),
         'AUDIT_NOT_CANONICAL')
    need(type(manifest) is dict and set(manifest) == {
        'schema','report_sha256','source_case_key','stage_head_sha256',
        'p8','a9_generation'}
         and manifest['schema'] == SCHEMA+'-manifest'
         and manifest['report_sha256'] == f1.digest(raw)
         and manifest['source_case_key'] == report.get('case_key')
         and manifest['stage_head_sha256'] == report.get('stage_head_sha256')
         and manifest['p8'] == 'NO-GO'
         and manifest['a9_generation'] is None, 'AUDIT_MANIFEST_DRIFT')
    verify(report, catalog_raw)
    return report


def capabilities() -> dict:
    return {'schema': SCHEMA+'-capabilities', 'family_id': 'FTP-T01',
            'source_f13_replay': True, 'f14_reconstruction': True,
            'r58e_exact_math': True, 'a8_stop_recommendation': True,
            'a10_immutable_audit_replay': True,
            'a6_admitted_real_physical': False,
            'a7_confirmed_risk': False, 'a8_authoritative_transition': False,
            'a9_global_generation_publication': False,
            'p8': 'NO-GO', 'network_connections': 0, 'vm_starts': 0}
