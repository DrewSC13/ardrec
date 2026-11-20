"""ARDREC R115-F10: bounded, receive-only FTP-T01 control-reply transport.

This function consumes an ALREADY CONNECTED socket handed off by a separately
trusted P8 dispatcher. It never creates sockets, connects, sends, logs into FTP,
or changes F11/R34. The caller's guard is invoked before AND after each read.
The returned transcript is a candidate only, never A6 admission or authority.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Callable


SCHEMA = 'ARDREC-R115-F10-FTP-T01-BOUNDED-CONTROL-REPLY-v1'
TARGET_IP = '10.203.31.2'
TARGET_PORT = 21
MAX_SECONDS = 10
MAX_BYTES = 4096
MAX_LINES = 16
MAX_RECV = 512

class Stop(ValueError):
    """Invalid scope, missing guard or attempted budget violation."""


def need(ok, reason):
    if not ok:
        raise Stop(reason)


@dataclass(frozen=True)
class Limits:
    timeout_seconds: int = 5
    max_bytes: int = 1024
    max_lines: int = 10
    read_size: int = 256

    def check(self):
        for field in ('timeout_seconds', 'max_bytes', 'max_lines', 'read_size'):
            need(type(getattr(self, field)) is int, 'LIMIT_TYPE_' + field)
        need(0 < self.timeout_seconds <= MAX_SECONDS, 'TIME_LIMIT')
        need(0 < self.max_bytes <= MAX_BYTES, 'BYTE_LIMIT')
        need(0 < self.max_lines <= MAX_LINES, 'LINE_LIMIT')
        need(0 < self.read_size <= MAX_RECV, 'READ_SIZE_LIMIT')
        return self


def _line_state(data: bytes, max_lines: int):
    """RFC 959 three-digit reply, allowing multiline 220-... 220 ... ."""
    need(type(data) is bytes, 'RAW_BYTES_REQUIRED')
    if b'\x00' in data or any(x < 32 and x not in (9, 10, 13) for x in data):
        return 'MALFORMED_REPLY', None
    lines = data.split(b'\r\n')
    complete = lines[:-1]
    if len(complete) > max_lines:
        return 'LINE_LIMIT_REACHED', None
    if not complete:
        return 'INCOMPLETE_REPLY', None
    first = complete[0]
    if len(first) < 4 or not first[:3].isdigit() or first[3:4] not in (b' ', b'-'):
        return 'MALFORMED_REPLY', None
    code = int(first[:3])
    if code < 100 or code > 599:
        return 'MALFORMED_REPLY', None
    if first[3:4] == b' ':
        return 'REPLY_COMPLETE', code
    end = first[:3] + b' '
    if any(line.startswith(end) for line in complete[1:]):
        return 'REPLY_COMPLETE', code
    if len(complete) == max_lines:
        return 'LINE_LIMIT_REACHED', None
    return 'INCOMPLETE_REPLY', None


def _peer(sock):
    """Only the fixed IPv4 FTP control endpoint is ever an eligible handoff."""
    need(sock is not None and getattr(sock, 'family', None) == socket.AF_INET,
         'SOCKET_NOT_IPV4')
    kind = getattr(sock, 'type', None)
    need(isinstance(kind, int) and type(kind) is not bool and
         (kind & 15) == socket.SOCK_STREAM,
         'SOCKET_NOT_TCP_STREAM')
    try:
        actual = sock.getpeername()
    except (AttributeError, OSError, ValueError) as exc:
        raise Stop('SOCKET_NOT_CONNECTED') from exc
    need(type(actual) is tuple and len(actual) >= 2 and
         type(actual[0]) is str and type(actual[1]) is int,
         'PEER_FORMAT')
    try:
        address = str(ipaddress.IPv4Address(actual[0]))
    except ipaddress.AddressValueError as exc:
        raise Stop('PEER_INVALID_IP') from exc
    need(address == TARGET_IP and actual[1] == TARGET_PORT,
         'PEER_OUT_OF_AUTHORIZED_SCOPE')
    return [address, actual[1]]


def _allowed(guard: Callable[[], bool]):
    """Caller is responsible for CURRENT independent P8 verification."""
    try:
        allowed = guard()
    except Exception as exc:
        raise Stop('AUTHORITY_GUARD_FAILED') from exc
    need(type(allowed) is bool and allowed, 'AUTHORITY_GUARD_DENIED')


def receive_control_reply(connected_socket, *, current_p8_guard, limits=Limits(),
                          monotonic=time.monotonic):
    """Receive a single bounded FTP server greeting; never transmit a byte.

    The **caller** must externally attest socket creation, finite connection
    budget, current A3/P8 approval, F11/R34 and independent provenance. A
    callback returning True is NOT itself a cryptographic authorization.
    
    Returned bytes are source candidates. A6, A7, A8, A9 and A10 remain ND.
    """
    need(type(limits) is Limits, 'LIMITS_TYPE')
    limits.check()
    need(callable(current_p8_guard), 'AUTHORITY_GUARD_MISSING')
    need(callable(monotonic), 'CLOCK_MISSING')
    peer = _peer(connected_socket)
    _allowed(current_p8_guard)
    try:
        started = monotonic()
        need(type(started) in (float, int), 'CLOCK_INVALID')
    except (TypeError, ValueError) as exc:
        raise Stop('CLOCK_UNAVAILABLE') from exc
    deadline = started + limits.timeout_seconds
    raw = b''
    calls = 0
    status = 'INCOMPLETE_REPLY'
    code = None
    while len(raw) < limits.max_bytes:
        _allowed(current_p8_guard)
        remaining = deadline - monotonic()
        if remaining <= 0:
            status = 'DEADLINE_REACHED'
            break
        # Timeout is bounded by the signed/authorized deadline.
        try:
            connected_socket.settimeout(remaining)
        except (OSError, ValueError, TypeError):
            status = 'SOCKET_TIMEOUT_CONFIGURATION_FAILED'
            break
        request_size = min(limits.read_size, limits.max_bytes - len(raw))
        try:
            data = connected_socket.recv(request_size)
            calls += 1
        except (TimeoutError, socket.timeout):
            status = 'DEADLINE_REACHED'
            break
        except OSError:
            status = 'SOCKET_READ_ERROR'
            break
        # Recheck immediately after each network read. A revoked grant does
        # not yield an A5 accepted attempt, even if bytes were read.
        _allowed(current_p8_guard)
        need(type(data) is bytes and len(data) <= request_size,
             'SOCKET_INVALID_DATA')
        if not data:
            status = 'CONNECTION_CLOSED'
            break
        raw += data
        status, code = _line_state(raw, limits.max_lines)
        if status in ('REPLY_COMPLETE', 'MALFORMED_REPLY', 'LINE_LIMIT_REACHED'):
            break
    else:
        status = 'BYTE_LIMIT_REACHED'
    need(calls >= 0 and len(raw) <= limits.max_bytes,
         'RECEIPT_BUDGET_OVERRUN')
    elapsed = monotonic() - started
    need(type(elapsed) in (int, float), 'CLOCK_INVALID')
    return {
        'schema': SCHEMA,
        'family_id': 'FTP-T01',
        'target': {'ip': peer[0], 'port': peer[1]},
        'transport': 'TCP_IPV4_EXISTING_CONNECTION_READ_ONLY',
        'limits': {'timeout_seconds': limits.timeout_seconds,
                   'max_bytes': limits.max_bytes,
                   'max_lines': limits.max_lines,
                   'read_size': limits.read_size},
        'recv_calls': calls,
        'received_bytes': len(raw),
        'raw_b64': base64.b64encode(raw).decode('ascii'),
        'raw_sha256': hashlib.sha256(raw).hexdigest(),
        'reply_status': status,
        'ftp_reply_code': code,
        'greeting_220_observed': status == 'REPLY_COMPLETE' and code == 220,
        'elapsed_seconds': round(max(0.0, float(elapsed)), 6),
        'socket_opened_by_this_module': False,
        'network_connections_created_by_this_module': 0,
        'client_bytes_transmitted_by_this_module': 0,
        'a5_physical_origin_independently_attested': False,
        'a6_classification': 'ND',
        'a7_confirmed_risk': None,
        'a8_applied_transition': None,
        'a9_published_generation': None,
        'a10_commit': None,
        'p8_review_performed_by_this_module': False,
        'note': 'Not an A3/P8 approval. Source candidate until an independent real-session attestor binds A5 and A6.',
    }


def declared_capabilities():
    """Static capability declaration: safely callable without network or sudo."""
    return {'schema': SCHEMA+'-capabilities', 'family_id': 'FTP-T01',
            'max_seconds': MAX_SECONDS, 'max_bytes': MAX_BYTES,
            'max_lines': MAX_LINES, 'max_recv': MAX_RECV,
            'network_connect': False, 'ftp_commands_sent': False,
            'a3_approval': False, 'p8_approval': False,
            'a6_admission': False}
