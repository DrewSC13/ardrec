"""P14-R43: ejecución de desarrollo A1-A10 mediante el fixture benigno existente.

NO es pentesting. Reutiliza el pipeline durable P9-P12, el ciclo R28,
la evidencia física de solo lectura R42.4 y el TUI original R38/R42.5.
No llama a QGA, virsh, tcpdump, sudo ni operaciones de red.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any

from ardrec.benign_pipeline import BenignPipeline
from ardrec.coordination import benign_review, demo_session, development_cycle
from ardrec.coordination import r424_evidence_tui as r424
from ardrec.coordination import r425_classic_evidence_dashboard as r425
from ardrec.persistence import development_receipt
from ardrec.coordination import r365_first_boot as r365

BASE_MAIN = '2169c2bd24f87efe03357d90a41843a2d900e619'
LOCAL_DIR = re.compile(r'^r43-local-cycle-[0-9]{8}T[0-9]{6}Z-[0-9]{1,10}$')


class LocalCycleError(ValueError):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise LocalCycleError(reason)


def private_journal_guard(r422_dir: Path, r423_dir: Path, journal: Path) -> None:
    """Autoriza escritura solo en subdirectorio privado hermano a los recibos.

    No cambia permisos. La construcción del root la efectúa BenignPipeline.
    """
    need(all(isinstance(p, Path) for p in (r422_dir, r423_dir, journal)),
         'path_type_invalid')
    need(all(p.is_absolute() for p in (r422_dir, r423_dir, journal)),
         'absolute_paths_required')
    base = r423_dir.parent
    need(base == r422_dir.parent and journal.parent == base,
         'private_receipt_parent_mismatch')
    need(LOCAL_DIR.fullmatch(journal.name) is not None,
         'journal_name_not_in_allowlist')
    need(base.is_dir() and not base.is_symlink() and
         base.stat().st_uid == os.getuid() and
         base.stat().st_mode & 0o077 == 0,
         'private_parent_not_owned_mode_0700')
    need(not journal.is_symlink() and
         (not journal.exists() or
          (journal.is_dir() and journal.stat().st_uid == os.getuid() and
           journal.stat().st_mode & 0o077 == 0)),
         'journal_invalid_or_not_private')
    need(not any(p.is_symlink() for p in base.parents), 'symlink_in_private_path')


def verify_local_run(journal: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Relee la persistencia R27/R28 y demuestra reserva de un solo inicio."""
    development_cycle.verify_development_cycle(report)
    need(report.get('source_kind') == 'SYNTHETIC_AND_LOCAL_BENIGN_ONLY' and
         report['r27']['a5_state'] == 'RECORDED_LIMITED' and
         report['r27']['a5_start_count'] == 1 and
         report['r27']['a6_classification'] == 'ND' and
         report['a9']['durable_local_receipt'] is True and
         report['a9']['published_generation'] is None and
         report['a7']['confirmed_rf'] is None and
         report['a7']['technical_evidence'] is None and
         report['vm_checks_executed'] is False and
         report['operational_dispatch'] is False and
         report['p8_operational'] == 'NO-GO',
         'development_execution_boundary_invalid')
    pipeline = BenignPipeline(journal)
    row = pipeline.read(benign_review.RID)
    att = pipeline.verify(benign_review.RID)
    need(row.get('fixture') == 'ok' and row.get('state') == 'RECORDED_LIMITED' and
         row.get('start_count') == 1 and row.get('p8_operational') == 'NO-GO' and
         att.get('artifacts_verified') is True and
         att.get('p8_operational') == 'NO-GO' and
         report['r27']['artifact_sha256'] == att.get('event_head_sha256'),
         'local_attempt_receipt_invalid')
    file = journal / development_receipt.FILE_NAME
    need(file.is_file() and not file.is_symlink() and file.stat().st_mode & 0o077 == 0,
         'development_receipt_missing_or_insecure')
    receipt = r365.read_json(file.read_bytes())
    development_receipt.verify_receipt(receipt)
    need(receipt['sha256'] == report['a9']['receipt_sha256'] and
         receipt['sources']['r26_session'] == report['session_sha256'] and
         receipt['sources']['r27_review'] == report['r27']['source_sha256'] and
         receipt['sources']['a7_oracle'] == report['a7']['oracle_sha256'] and
         receipt['sources']['a8_stop_preview'] == report['a8']['sha256'],
         'development_receipt_binding_invalid')
    return {'state': row['state'], 'start_count': row['start_count'],
            'artifacts_verified': True, 'attempt_chain_sha256': att['event_head_sha256'],
            'development_receipt_sha256': receipt['sha256'],
            'operational_dispatch': False, 'technical_truth_accredited': False,
            'p8_operational': 'NO-GO'}


def execute_local_cycle(r422_dir: Path, r423_dir: Path, fixture: Path,
                        journal_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """One explicit local attempt; existing pipeline is idempotent on same root.

    A5 corresponds only to a Python fixture, never to SSH/FTP/SMB. A6 stays ND.
    """
    private_journal_guard(r422_dir, r423_dir, journal_root)
    physical = r424.read_physical(r422_dir, r423_dir)
    scenario = demo_session.read_fixed_scenario(fixture)
    report = development_cycle.build_development_cycle(
        scenario, journal_root=journal_root, run_local_benign=True)
    verify_local_run(journal_root, report)
    bundle = r424.make_bundle(physical, report)
    r424.verify_bundle(bundle)
    r425.validate_binding(report, bundle)
    return report, bundle
