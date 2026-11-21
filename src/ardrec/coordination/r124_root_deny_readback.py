"""R124: authenticated read-only assessment of the installed R116 DENY guard.

The root-owned R116 guard checks nft/libvirt. This module checks its pinned
identity, verifies the parsed report, and distinguishes the *periodic* R34
watchdog from a session-specific 45s systemd timer. Neither is a P8 permit.
No service starts, socket operations, nft writes, or root deployment are here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Callable

SCHEMA = 'ARDREC-R124-ROOT-DENY-READBACK-SOURCE-v1'
PIN = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
GUARD = '/var/lib/ardrec/r116-f1-five-one-deny-v1/root-guard.py'
MARKER = '/var/lib/ardrec/r116-f1-five-one-deny-v1/arm-consumed.once'
R34 = 'ardrec-r34-deny-watchdog.timer'
R116_SCHEMA = 'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-check'
VM_KEYS = {'ssh':('ssh',), 'runner':('runner_ssh','runner_ftp','runner_smb'),
           'ftp':('ftp',), 'smb':('smb',)}
KEYS = frozenset(k for ks in VM_KEYS.values() for k in ks)
ALLOWED = (frozenset(), frozenset({'ssh'}), frozenset({'ssh','runner'}),
           frozenset({'ssh','runner','ftp'}))
GIT = re.compile(r'[0-9a-f]{40}\Z')
ID = re.compile(r'[0-9a-f]{16}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
SYSCTL = '/usr/bin/systemctl'
SUDO = '/usr/bin/sudo'

class Stop(ValueError):
    """Refuse with a machine-readable code; never an authorization signal."""

def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)

def canonical(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, 'DUPLICATE_JSON_FIELD')
        out[key] = value
    return out

def strict(raw: bytes, *, maximum: int = 8192) -> dict:
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'JSON_LENGTH')
    try:
        doc = json.loads(raw, object_pairs_hook=unique_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(Stop('NONFINITE_JSON')))
        need(type(doc) is dict and raw == canonical(doc), 'NONCANONICAL_JSON')
        return doc
    except (UnicodeError, ValueError, TypeError, OverflowError) as exc:
        raise Stop('INVALID_JSON') from exc

def policy_check(doc: dict) -> dict:
    need(type(doc) is dict and set(doc) ==
         {'schema','states','policy','deny','host_writes','p8'}, 'DENY_FIELDS')
    need(doc['schema'] == R116_SCHEMA and doc['deny'] == 'MATCH' and
         type(doc['host_writes']) is int and doc['host_writes'] == 0 and
         doc['p8'] == 'NO-GO', 'DENY_REFUSED')
    states = doc['states']
    need(type(states) is dict and set(states) == set(VM_KEYS) and
         all(type(x) is str and x in ('OFF','RUNNING') for x in states.values()),
         'GUEST_STATES_INVALID')
    running = frozenset(k for k,v in states.items() if v == 'RUNNING')
    need(running in ALLOWED, 'UNEXPECTED_GUEST_LIFECYCLE')
    active = frozenset(k for role in running for k in VM_KEYS[role])
    absent = KEYS - active
    expected = {'running':sorted(running),'active':sorted(active),
                'absent':sorted(absent),'active_count':len(active),
                'absent_count':len(absent),'allow_traffic':False,'p8':'NO-GO'}
    need(type(doc['policy']) is dict and
         type(doc['policy'].get('active_count')) is int and
         type(doc['policy'].get('absent_count')) is int and
         type(doc['policy'].get('allow_traffic')) is bool and
         all(type(doc['policy'].get(k)) is list for k in ('running','active','absent')) and
         doc['policy'] == expected, 'POLICY_COUNT_OR_IDENTITY_MISMATCH')
    need(len(active) in (0,1,4,5), 'UNEXPECTED_BINDING_COUNT')
    return {'states':states, 'active_count':len(active),
            'absent_count':len(absent), 'stage':'FIVE_ONE_DENY_MATCH' if len(active)==5
            else 'OFFLINE_DENY_MATCH' if not active else 'TRANSITION_DENY_MATCH'}

def parse_sha(raw: bytes) -> str:
    need(type(raw) is bytes and 0 < len(raw) < 256, 'SHA_OUTPUT_INVALID')
    try:
        text = raw.decode('ascii')
    except UnicodeError as exc:
        raise Stop('SHA_OUTPUT_ENCODING') from exc
    # sha256sum emits digest, TWO blanks and the exact pinned pathname.
    need(text == PIN+'  '+GUARD+'\n', 'ROOT_GUARD_PIN_MISMATCH')
    return PIN

def parse_timer(raw: bytes, *, unit: str) -> dict:
    need(type(raw) is bytes and len(raw) <= 1024, 'TIMER_OUTPUT_LENGTH')
    try:
        decoded = raw.decode('ascii')
    except UnicodeError as exc:
        raise Stop('TIMER_OUTPUT_ENCODING') from exc
    parts = decoded.splitlines()
    need(len(parts) == 4 and all(p.count('=') == 1 for p in parts),
         'TIMER_OUTPUT_FIELDS')
    pairs = [p.split('=',1) for p in parts]
    data = unique_pairs(pairs)
    need(set(data) == {'LoadState','ActiveState','Unit','NextElapseUSecMonotonic'},
         'TIMER_OUTPUT_SCHEMA')
    need(data['LoadState'] in ('loaded','not-found') and
         data['ActiveState'] in ('active','inactive','failed') and
         data['Unit'] in (unit.removesuffix('.timer')+'.service','') and
         0 <= len(data['NextElapseUSecMonotonic']) <= 100 and
         all(0x20 <= ord(c) < 0x7f for c in data['NextElapseUSecMonotonic']),
         'TIMER_OUTPUT_UNTRUSTED')
    return data

def marker_check(raw: bytes) -> str:
    doc = strict(raw, maximum=512)
    need(set(doc) == {'session','arm_attempted','ordinary_p8'} and
         type(doc['session']) is str and ID.fullmatch(doc['session']) is not None and
         doc['arm_attempted'] is True and doc['ordinary_p8'] == 'NO-GO',
         'SESSION_MARKER_REJECTED')
    return doc['session']

def fixed_run(cmd: tuple[str,...]) -> tuple[int,bytes]:
    """Execute only fixed read commands; no shell, no interactive password."""
    need(type(cmd) is tuple and cmd and
         cmd[0] in (SYSCTL,SUDO), 'UNTRUSTED_READ_COMMAND')
    if cmd[0] == SUDO:
        need(cmd[:3] == (SUDO,'-n','--') and
             (cmd[3:] in (( '/usr/bin/sha256sum',GUARD),
                          ('/usr/bin/python3','-I','-B',GUARD,'--check'),
                          ('/usr/bin/test','-e',MARKER),
                          ('/usr/bin/cat',MARKER))),
             'SUDO_READ_NOT_ALLOWLISTED')
    else:
        need(len(cmd) == 12 and cmd[:3] == (SYSCTL,'show',cmd[2]) and
             cmd[3:] == ('--no-pager','-p','LoadState','-p','ActiveState',
                         '-p','Unit','-p','NextElapseUSecMonotonic') and
             (cmd[2] == R34 or re.fullmatch(r'ardrec-r116-f1-deny-[0-9a-f]{16}\.timer',cmd[2])),
             'TIMER_NOT_ALLOWLISTED')
    try:
        completed = subprocess.run(list(cmd), stdin=subprocess.DEVNULL,
              capture_output=True, timeout=20, check=False,
              env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Stop('READ_COMMAND_FAILED') from exc
    need(len(completed.stdout) < 8192 and len(completed.stderr) < 2048,
         'READ_OUTPUT_TOO_LARGE')
    return completed.returncode, completed.stdout

def inspect(*, head: str, now: datetime,
            run: Callable[[tuple[str,...]],tuple[int,bytes]] = fixed_run) -> dict:
    need(type(head) is str and GIT.fullmatch(head) is not None,'HEAD_INVALID')
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'CLOCK_INVALID')
    stamp = now.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    def read(cmd: tuple[str,...], *, rc: tuple[int,...] = (0,)) -> tuple[int,bytes]:
        result = run(cmd)
        need(type(result) is tuple and len(result)==2 and
             type(result[0]) is int and result[0] in rc and
             type(result[1]) is bytes, 'ROOT_READ_FAILED')
        return result

    sha_cmd = (SUDO,'-n','--','/usr/bin/sha256sum',GUARD)
    guard_cmd = (SUDO,'-n','--','/usr/bin/python3','-I','-B',GUARD,'--check')
    marker_cmd = (SUDO,'-n','--','/usr/bin/test','-e',MARKER)
    marker_read = (SUDO,'-n','--','/usr/bin/cat',MARKER)
    timer = lambda name: (SYSCTL,'show',name,'--no-pager','-p','LoadState',
                 '-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic')

    parse_sha(read(sha_cmd)[1])
    report = strict(read(guard_cmd)[1])
    stage = policy_check(report)
    r34 = parse_timer(read(timer(R34))[1],unit=R34)
    marker_rc, _ = read(marker_cmd,rc=(0,1))
    session = marker_check(read(marker_read)[1]) if marker_rc == 0 else None
    session_timer = None
    if session is not None:
        name = 'ardrec-r116-f1-deny-'+session+'.timer'
        session_timer = parse_timer(read(timer(name))[1],unit=name)
    # Second root hash read blocks silent file substitution within inspection.
    parse_sha(read(sha_cmd)[1])
    blockers = ['P7_DRAFT_NOT_FROZEN','CURRENT_P8_AUTHORITY_NOT_ADMITTED',
                'INDEPENDENT_REVOCATION_NOT_ATTESTED','A6_PHYSICAL_ORIGIN_ND',
                'A9_GLOBAL_GENERATION_NOT_PUBLISHED','ROOT_60S_CLOSURE_NOT_ATTESTED']
    if session is None:
        blockers.append('SESSION_45S_TIMER_NOT_ARMED')
    elif session_timer['ActiveState'] != 'active':
        blockers.append('SESSION_TIMER_NOT_ACTIVE_OR_EXPIRED')
    else:
        blockers.append('SESSION_TIMER_ACTIVE_NOT_CLOSURE_PROOF')
    if stage['active_count'] != 5:
        blockers.append('FTP_5_1_STAGE_NOT_PRESENT')
    if r34['ActiveState'] != 'active':
        blockers.append('PERIODIC_R34_NOT_ACTIVE')
    out = {'schema':SCHEMA,'head':head,'observed_at_utc':stamp,
           'root_guard_sha256':PIN,'root_guard_check_sha256':digest(canonical(report)),
           'root_guard':'PINNED_INSTALLED_DENY_CHECK_OK',
           'denied':True,'host':stage,'r34_timer_state':r34['ActiveState'],
           'r34_is_session_45s_watchdog':False,
           'session_marker_consumed':session is not None,
           'session_timer_state':None if session_timer is None else session_timer['ActiveState'],
           'session_autonomous_closure_verified':False,
           'root_60s_deadline_verified':False,
           'f13_physical_attempt_admitted':False,'a6':'ND','a9':None,'p8':'NO-GO',
           'guest_starts_by_r124':0,'network_connections_by_r124':0,
           'nft_writes_by_r124':0,'blockers':sorted(blockers)}
    out['sha256'] = digest(canonical(out))
    return out

def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'supports_installed_root_guard_pinning':True,
            'supports_active_and_offline_deny_check':True,
            'distinguishes_r34_timer_from_session_timer':True,
            'proves_physical_60s_closure':False,
            'installs_or_arms_root_watchdog':False,
            'opens_network_or_starts_vm':False,'a6':'ND','a9':None,'p8':'NO-GO'}
