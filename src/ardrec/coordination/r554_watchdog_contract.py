"""R55.4: restricted independent user-timer proof contract.

Never modifies nftables, libvirt, domains or traffic. A synthetic user timer
changes exactly one private file from ALLOW_SIMULATED to DENY_SIMULATED.
This is evidence of timer execution after worker termination, NOT evidence
of privileged firewall restoration or isolation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from ardrec.coordination import r553_transition_guard as r553

SCHEMA = 'ardrec-p14-r554-user-timer-proof-v1'
SOURCE_MAIN = 'ce3b9e9f30751f99d2915cef8041c82eeb3c2aec'
DEFAULT_PARENT = Path('/home/cicada/ardrec-lab/r55-watchdog')
PREPARED = b'DENY_SIMULATED\n'
OPENED = b'ALLOW_SIMULATED\n'
RESTORED = b'DENY_SIMULATED\n'
EXPECTED_BIN = '/usr/bin/mv'
UNIT = re.compile(r'ardrec-r554-probe-[0-9]{8}T[0-9]{6}Z-[1-9][0-9]{0,9}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
FILES = frozenset({'intent.json', 'timer.json', 'result.json', 'SHA256SUMS', 'state.txt'})

class R554Error(ValueError):
    pass


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise R554Error(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canon(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def verify_source_plan(root: Path) -> dict:
    files = r553.verify_private_receipt(root)
    plan = r553.verify_plan(files)
    need(plan['p8_operational'] == 'NO-GO' and
         plan['host_mutations'] == 0 and
         plan['restoration_executed'] is False,
         'r552_not_offline')
    return r553.plan_contract(files)


def safe_directory(root: Path, *, existing: bool) -> None:
    need(isinstance(root, Path) and root.is_absolute() and
         not any(p.is_symlink() for p in (root, *root.parents)),
         'private_path_or_symlink_invalid')
    parent = root.parent
    st = parent.stat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
         stat.S_IMODE(st.st_mode) == 0o700,
         'private_parent_ownership_or_mode_invalid')
    need(root.is_dir() if existing else not root.exists(),
         'private_root_state_invalid')
    if existing:
        st = root.stat()
        need(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o700,
             'private_root_permissions_invalid')


def timer_command(unit: str, restore: Path, state: Path, *, delay_s: int = 8) -> list[str]:
    need(UNIT.fullmatch(unit) is not None, 'unit_name_invalid')
    need(type(delay_s) is int and 5 <= delay_s <= 15, 'timer_delay_invalid')
    need(restore.name == 'restore-pending.txt' and state.name == 'state.txt' and
         restore.parent == state.parent and restore.is_absolute() and
         not any(p.is_symlink() for p in (restore, state, *restore.parents)),
         'timer_paths_invalid')
    return [
        '/usr/bin/systemd-run', '--user',
        '--unit=' + unit,
        '--on-active=' + str(delay_s) + 's',
        '--timer-property=AccuracySec=1s',
        EXPECTED_BIN, str(restore), str(state),
    ]


def verify_timer_command(argv: list[str], unit: str, restore: Path, state: Path, *, delay_s: int = 8) -> None:
    need(type(argv) is list and argv == timer_command(unit, restore, state, delay_s=delay_s),
         'timer_command_drift')
    need(not any('sudo' in x or 'nft' in x or 'virsh' in x or '/bin/sh' in x for x in argv),
         'privileged_or_shell_in_timer_command')


def synthetic_report(*, unit: str, started: bool, worker_killed: bool,
                     restored: bool, seconds: float, timer_state: str) -> dict:
    need(UNIT.fullmatch(unit) is not None, 'unit_name_invalid')
    need(type(seconds) in (int, float) and 0 <= seconds <= 60,
         'duration_invalid')
    need(timer_state in ('ARMED', 'FIRED', 'UNCONFIRMED'), 'timer_state_invalid')
    success = started and worker_killed and restored and timer_state == 'FIRED'
    return {
        'schema': SCHEMA,
        'source_main': SOURCE_MAIN,
        'status': 'SYNTHETIC_USER_TIMER_RESTORED_NO_GO' if success else 'REVIEW_REQUIRED_NO_GO',
        'unit': unit,
        'timer_armed': bool(started),
        'worker_killed': bool(worker_killed),
        'synthetic_state_restored': bool(restored),
        'observed_elapsed_seconds': round(seconds, 3),
        'timer_state': timer_state,
        'physical_firewall_restored': False,
        'physical_restore_tested': False,
        'physical_binding_change': False,
        'host_firewall_mutations': 0,
        'host_libvirt_mutations': 0,
        'user_timer_created': bool(started),
        'guest_packets': 0,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }


def verify_report(doc: dict) -> None:
    need(type(doc) is dict and
         doc.get('schema') == SCHEMA and
         doc.get('source_main') == SOURCE_MAIN and
         doc.get('p8_operational') == 'NO-GO' and
         doc.get('operational_dispatch') is False and
         doc.get('physical_firewall_restored') is False and
         doc.get('physical_restore_tested') is False and
         doc.get('physical_binding_change') is False and
         doc.get('host_firewall_mutations') == 0 and
         doc.get('host_libvirt_mutations') == 0 and
         doc.get('guest_packets') == 0 and
         UNIT.fullmatch(str(doc.get('unit', ''))) is not None,
         'physical_authority_or_report_invalid')
    expected = synthetic_report(
        unit=doc['unit'], started=doc['timer_armed'],
        worker_killed=doc['worker_killed'],
        restored=doc['synthetic_state_restored'],
        seconds=doc['observed_elapsed_seconds'],
        timer_state=doc['timer_state'])
    need(doc == expected, 'report_semantics_mismatch')
