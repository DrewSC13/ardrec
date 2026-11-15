#!/usr/bin/env python3
"""R55.4: bounded user-systemd timer experiment, synthetic private files ONLY."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.coordination import r554_watchdog_contract as g

PLAN = Path('/home/cicada/ardrec-lab/r55-transition/r552-f1-plan-20261115T152309Z-39487')


def cmd(argv: list[str], *, timeout: int = 20):
    return subprocess.run(argv, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False, close_fds=True)


def write_once(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def seal(root: Path, result: dict, timer: dict) -> None:
    g.verify_report(result)
    write_once(root / 'timer.json', g.canon(timer))
    write_once(root / 'result.json', g.canon(result))
    files = ['intent.json', 'timer.json', 'result.json', 'state.txt']
    if (root / 'restore-pending.txt').exists():
        files.append('restore-pending.txt')
    checksums = ''.join(g.sha((root / name).read_bytes()) + '  ' + name + '\n'
                        for name in sorted(files))
    write_once(root / 'SHA256SUMS', checksums.encode('ascii'))


def probe(plan: Path) -> int:
    # Authenticate source before any user timer is created.
    g.verify_source_plan(plan)
    parent = g.DEFAULT_PARENT
    if not parent.exists():
        parent.mkdir(mode=0o700)
    # A private directory cannot be borrowed from another owner.
    if parent.is_symlink() or parent.stat().st_uid != os.getuid() or (parent.stat().st_mode & 0o777) != 0o700:
        raise g.R554Error('watchdog_private_parent_invalid')
    g.safe_directory(parent / 'r554-preflight-placeholder', existing=False)

    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    unit = f'ardrec-r554-probe-{stamp}-{os.getpid()}'
    folder = parent / unit
    g.safe_directory(folder, existing=False)
    folder.mkdir(mode=0o700, exist_ok=False)
    state = folder / 'state.txt'
    pending = folder / 'restore-pending.txt'
    write_once(state, g.PREPARED)
    write_once(pending, g.RESTORED)
    write_once(folder / 'intent.json', g.canon({
        'schema': g.SCHEMA, 'source_main': g.SOURCE_MAIN,
        'unit': unit, 'r552_plan': str(plan),
        'purpose': 'PRIVATE_SYNTHETIC_TIMER_ONLY',
        'nftables_writes': False, 'libvirt_writes': False,
        'p8_operational': 'NO-GO'}))
    command = g.timer_command(unit, pending, state)
    g.verify_timer_command(command, unit, pending, state)
    started = False
    worker_killed = False
    timer_state = 'UNCONFIRMED'
    t0 = time.monotonic()
    info = {}
    try:
        # Neither of these calls uses root or sudo.
        check = cmd(['/usr/bin/systemctl', '--user', 'is-system-running'])
        info['systemctl_rc'] = check.returncode
        info['systemctl_summary'] = check.stdout.decode('utf-8', 'replace').strip()[:100]
        # 'degraded' user systemd is acceptable if systemd-run succeeds.
        start = cmd(command)
        info['systemd_run_rc'] = start.returncode
        info['systemd_run_stdout_sha256'] = g.sha(start.stdout)
        info['systemd_run_stderr_sha256'] = g.sha(start.stderr)
        if start.returncode != 0:
            raise g.R554Error('user_systemd_timer_not_available')
        started = True
        timer_state = 'ARMED'
        # Synthetic ALLOW state becomes active ONLY after timer is armed.
        state.write_bytes(g.OPENED)
        if state.read_bytes() != g.OPENED:
            raise g.R554Error('synthetic_open_marker_not_visible')
        worker = subprocess.Popen(['/usr/bin/sleep', '120'],
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, close_fds=True)
        try:
            worker.kill()  # Only the child created immediately above.
            worker.wait(timeout=5)
            worker_killed = (worker.returncode == -9)
        finally:
            if worker.poll() is None:
                worker.terminate()
                worker.wait(timeout=5)
        if not worker_killed:
            raise g.R554Error('test_worker_not_killed')
        deadline = t0 + 24
        while time.monotonic() < deadline:
            if state.read_bytes() == g.RESTORED and not pending.exists():
                timer_state = 'FIRED'
                break
            time.sleep(0.3)
    except (g.R554Error, OSError, subprocess.TimeoutExpired) as exc:
        info['error'] = type(exc).__name__ + ':' + str(exc)[:160]
    seconds = time.monotonic() - t0
    restored = state.read_bytes() == g.RESTORED and not pending.exists()
    report = g.synthetic_report(unit=unit, started=started,
                                worker_killed=worker_killed,
                                restored=restored,
                                seconds=min(round(seconds, 3), 60),
                                timer_state=timer_state)
    # If user timer was accepted but has not fired yet, leave it armed;
    # do not cancel or remove it. The marker has no network privileges.
    seal(folder, report, info)
    print('R554_RECEIPT=' + str(folder))
    print('R554_RESULT=' + report['status'])
    print('R554_WORKER_KILLED=' + str(worker_killed).upper())
    print('R554_TIMER_STATE=' + timer_state)
    print('R554_SYNTHETIC_DENY_RESTORED=' + str(restored).upper())
    print('R554_FIREWALL_MUTATIONS=0')
    print('R554_LIBVIRT_MUTATIONS=0')
    print('R554_PHYSICAL_RESTORE_TESTED=NO')
    print('R554_P8=NO-GO')
    return 0 if report['status'] == 'SYNTHETIC_USER_TIMER_RESTORED_NO_GO' else 2


def main(argv=None):
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--verify-offline', action='store_true')
    modes.add_argument('--probe-user-timer', action='store_true')
    parser.add_argument('--r552-plan', type=Path, default=PLAN)
    parser.add_argument('--i-authorize-synthetic-user-timer-only', action='store_true')
    args = parser.parse_args(argv)
    if args.verify_offline and args.i_authorize_synthetic_user_timer_only:
        parser.error('no authorization in offline mode')
    if args.probe_user_timer != args.i_authorize_synthetic_user_timer_only:
        parser.error('probe requires separate explicit authorization')
    try:
        contract = g.verify_source_plan(args.r552_plan)
        if args.verify_offline:
            print('R554_R553_SOURCE=PASS')
            print('R554_R552_SHA256=' + contract['r552_plan_sha256'])
            print('R554_USER_TIMER=NOT_STARTED')
            print('R554_HOST_MUTATIONS=0')
            print('R554_PHYSICAL_RESTORE_TESTED=NO')
            print('R554_P8=NO-GO')
            return 0
        return probe(args.r552_plan)
    except (ValueError, OSError, RuntimeError) as exc:
        print('R554=BLOCKED:' + type(exc).__name__ + ':' + str(exc)[:180])
        print('R554_P8=NO-GO')
        return 2

if __name__ == '__main__':
    sys.exit(main())
