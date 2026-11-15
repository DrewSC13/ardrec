#!/usr/bin/env python3
"""ARDREC R42.2: host-only bounded PASSIVE tcpdump startup diagnostic.

This is NOT an ARDREC packet test. Does not use QEMU Guest Agent or cause
network traffic. Uses exact original tcpdump argv for forensic comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.coordination import r422_independent_packet_witness as r422
from ardrec.coordination import r41_ssh_resume as r41

SCHEMA = 'ardrec-p14-r422-passive-observer-startup-diagnostic-v1'
REPORT = 'r422_observer_diagnostic.json'
MAX_STDOUT = 4096
MAX_STDERR = 8192
MAX_STARTUP_WAIT = 3.5


def need(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def capture_command(label: str, tcpdump: str, sudo: str) -> list[str]:
    """Exact R42.2 active observer argv: no additional executable surface."""
    need(label in r422.INTERFACES, 'interface_not_in_allowlist')
    need(tcpdump in ('/usr/bin/tcpdump', '/usr/sbin/tcpdump'), 'tcpdump_not_allowed')
    need(sudo in ('/usr/bin/sudo', '/bin/sudo'), 'sudo_not_allowed')
    iface = r422.INTERFACES[label]
    return [sudo, '-n', '--', '/usr/bin/timeout', '-s', 'INT',
            str(r422.CAPTURE_MAX_SECONDS), tcpdump, '-n', '-p', '-i', iface,
            '-s', str(r422.SNAPLEN), '-U', '-c', str(r422.MAX_CAPTURE_PACKETS),
            '-w', '-', r422.FILTER]


def categorize(stderr: bytes) -> str:
    info = stderr.decode('utf-8', errors='replace').lower()
    if ('password is required' in info or 'password required' in info or
            'a terminal is required' in info):
        return 'SUDO_NONINTERACTIVE_AUTH_REQUIRED'
    if ('not allowed to execute' in info or 'not in the sudoers' in info or
            'is not allowed' in info):
        return 'SUDO_EXEC_DENIED'
    if ('permission denied' in info or 'operation not permitted' in info or
            "don't have permission" in info):
        return 'CAPTURE_PERMISSION_DENIED'
    if ('no such device' in info or 'interface does not exist' in info or
            'device not found' in info):
        return 'CAPTURE_INTERFACE_UNAVAILABLE'
    if ('syntax error' in info or 'invalid filter' in info or
            'parse error' in info):
        return 'CAPTURE_FILTER_INVALID'
    if ('command not found' in info or 'no such file' in info):
        return 'CAPTURE_EXECUTABLE_MISSING'
    return 'UNCLASSIFIED' if stderr else 'NO_STDERR'


def redacted_excerpt(stderr: bytes) -> str:
    raw = stderr.decode('utf-8', errors='replace')
    raw = re.sub(r'[\x00-\x1f\x7f]+', ' ', raw)
    return raw[:240]


def classic_header_valid(data: bytes) -> bool:
    if len(data) < 24:
        return False
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                       b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
        return False
    order = '<' if data[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    try:
        major, minor, _tz, _sig, snaplen, link = struct.unpack_from(order+'HHiIII', data, 4)
    except struct.error:
        return False
    return (major, minor, snaplen, link) == (2, 4, r422.SNAPLEN, 1)


def _stop_process(proc: Any) -> tuple[bytes, bytes, int | None]:
    """Never leave an observer running; terminate its dedicated process group."""
    try:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGINT)
            except ProcessLookupError:
                pass
        try:
            rest, stderr = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            rest, stderr = proc.communicate(timeout=3)
        return rest, stderr, proc.returncode
    except Exception:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            proc.communicate(timeout=2)
        except Exception:
            pass
        raise


def probe(label: str, tcpdump: str, sudo: str, *, launcher=subprocess.Popen,
          wait_ready: float = MAX_STARTUP_WAIT) -> dict[str, Any]:
    """Observe startup only; no VM, QGA, or packet generator calls."""
    argv = capture_command(label, tcpdump, sudo)
    start = time.monotonic()
    # Distinct process group without setsid: preserve sudo's TTY-scoped
    # authentication cache while keeping killpg limited to this observer.
    proc = launcher(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, close_fds=True, process_group=0)
    head = bytearray()
    remaining, stderr, code = b'', b'', None
    try:
        deadline = time.monotonic() + wait_ready
        while len(head) < r422.PCAP_HEADER_BYTES and time.monotonic() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [],
                                        min(0.3, max(0, deadline - time.monotonic())))
            if ready:
                part = os.read(proc.stdout.fileno(), r422.PCAP_HEADER_BYTES - len(head))
                if not part:
                    break
                head.extend(part)
            elif proc.poll() is not None:
                break
    finally:
        remaining, stderr, code = _stop_process(proc)
    captured = bytes(head) + remaining
    need(len(captured) <= MAX_STDOUT and len(stderr) <= MAX_STDERR,
         'passive_diagnostic_output_limit')
    valid = classic_header_valid(captured)
    state = ('PCAP_HEADER_READY' if valid and code in (0, 124, 130, -2)
             else 'OBSERVER_STARTUP_FAILED')
    return {
        'interface': r422.INTERFACES[label], 'status': state,
        'exit_code': code,
        'stdout_bytes': len(captured), 'stdout_sha256': hashlib.sha256(captured).hexdigest(),
        'pcap_header_valid': valid, 'stderr_bytes': len(stderr),
        'stderr_sha256': hashlib.sha256(stderr).hexdigest(),
        'stderr_class': categorize(stderr), 'stderr_excerpt': redacted_excerpt(stderr),
        'elapsed_seconds_rounded': round(time.monotonic() - start, 2),
    }


def run(*, source: dict[str, str], receipt_dir: Path, host=None,
        factory=probe) -> dict[str, Any]:
    """Create local authenticated diagnostic receipt without QGA or traffic."""
    need(source.get('source_r421_report_sha256') == r422.R421_REPORT_PIN,
         'source_r421_receipt_not_pinned')
    ready = r422.preflight(host)
    need(ready.get('status') == 'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
         'host_preflight_not_ready')
    r41._make_dir(receipt_dir)
    rows = {}
    for label in r422.INTERFACES:
        try:
            rows[label] = factory(label, ready['tcpdump_binary'], '/usr/bin/sudo')
        except Exception as exc:
            rows[label] = {'interface':r422.INTERFACES[label],
                           'status':'OBSERVER_DIAGNOSTIC_ERROR',
                           'reason':type(exc).__name__+':'+str(exc)[:160]}
    status = ('PASSIVE_OBSERVERS_READY_NO_GO' if
              all(row.get('status') == 'PCAP_HEADER_READY' for row in rows.values())
              else 'PASSIVE_OBSERVER_STARTUP_FAILURE_NO_GO')
    doc = {
        'schema': SCHEMA, 'source_main': r422.MAIN_PIN,
        'source_r421_report_sha256': r422.R421_REPORT_PIN,
        'mode': 'EXACT_ARGV_PASSIVE_TCPDUMP_STARTUP_ONLY', 'status': status,
        'captured_at_utc': r41.now_utc(), 'interfaces': rows,
        'qemu_guest_agent_contacted': False, 'guest_exec_attempted': False,
        'icmp_injected_by_diagnostic': False,
        'network_configuration_modified': False, 'vm_lifecycle_modified': False,
        'isolation_proven': False, 'p8_operational':'NO-GO',
        'automatic_retry': False,
    }
    doc['sha256'] = r41.sha(r41.canon(doc))
    raw = r41.canon(doc) + b'\n'
    r41._write_once(receipt_dir / REPORT, raw)
    r41._write_once(receipt_dir / 'SHA256SUMS',
                    (r41.sha(raw)+'  '+REPORT+'\n').encode('ascii'))
    return doc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='R42.2 passive observer startup diagnostic')
    for arg in ('r421-result','r420-baseline','r411-observation',
                'r41-preflight','r40-preflight','r39-reconciliation',
                'r365-preflight','r365-first-boot','receipt-dir'):
        parser.add_argument('--'+arg, required=True, type=Path)
    parser.add_argument('--i-authorize-r422-passive-observer-diagnostic', action='store_true')
    args = parser.parse_args(argv)
    if not args.i_authorize_r422_passive_observer_diagnostic:
        parser.error('explicit_passive_capture_authorization_required')
    try:
        source = r422.load_source(args.r421_result,args.r420_baseline,
                                  args.r411_observation,args.r41_preflight,
                                  args.r40_preflight,args.r39_reconciliation,
                                  args.r365_preflight,args.r365_first_boot)
        doc = run(source=source, receipt_dir=args.receipt_dir)
    except Exception as exc:
        print('R422_DIAG_STATUS=BLOCKED_NO_PACKET_INJECTION')
        print('R422_DIAG_ERROR='+type(exc).__name__+':'+str(exc)[:200])
        print('R422_DIAG_P8=NO-GO')
        return 2
    print('R422_DIAG_STATUS='+doc['status'])
    print('R422_DIAG_RECEIPT_DIR='+str(args.receipt_dir))
    print('R422_DIAG_REPORT_SHA256='+doc['sha256'])
    for label,row in doc['interfaces'].items():
        print('R422_DIAG_'+label.upper()+'_STATUS='+row['status'])
        print('R422_DIAG_'+label.upper()+'_ERROR_CLASS='+row.get('stderr_class','UNKNOWN'))
        print('R422_DIAG_'+label.upper()+'_EXIT='+str(row.get('exit_code','UNKNOWN')))
    print('R422_DIAG_GUEST_EXEC=NO')
    print('R422_DIAG_PACKET_INJECTION=NO')
    print('R422_DIAG_P8=NO-GO')
    return 0 if doc['status']=='PASSIVE_OBSERVERS_READY_NO_GO' else 2

if __name__=='__main__':
    raise SystemExit(main())
