"""ARDREC R113-F7: pure, bounded systemd DENY-watchdog contract.

This module NEVER enables traffic. Its sole live action, performed by the
separate CLI with explicit authorization, is to schedule the pinned F6
root-only --restore-deny helper. Systemd owns the timer, not the caller.
"""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path

ROOT_HELPER = '/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py'
GIT_PARENT = '6cbfeaa0a465cbb6885726691b789fa54d30bb69'
SCHEMA = 'ARDREC-R113-F7-SYSTEMD-DENY-SMOKE-v1'
TOKEN = re.compile(r'[0-9a-f]{12}\Z')
F6_ATTESTED = 'SIX_BINDING_DENY_ATTESTED'
F6_CHECK = 'ROOT_BUNDLE_VERIFIED'
INTERVAL = 20

class GuardError(ValueError):
    pass

def need(condition: bool, message: str) -> None:
    if not condition:
        raise GuardError(message)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canonical(obj: object) -> bytes:
    return (json.dumps(obj, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(',', ':'))+'\n').encode('ascii')

def units(token: str) -> tuple[str, str]:
    need(isinstance(token, str) and TOKEN.fullmatch(token) is not None,
         'UNSAFE_TIMER_TOKEN')
    stem = 'ardrec-r113-f7-deny-' + token
    return stem + '.service', stem + '.timer'

def schedule(token: str) -> list[str]:
    service, timer = units(token)
    return [
        '/usr/bin/systemd-run', '--system', '--unit='+service[:-8],
        '--on-active='+str(INTERVAL)+'s',
        '--timer-property=AccuracySec=1s',
        '--description=ARDREC F7 isolated DENY-only recovery rehearsal',
        '/usr/bin/python3', ROOT_HELPER, '--restore-deny',
    ]

def check_command() -> list[str]:
    return ['/usr/bin/python3', ROOT_HELPER, '--check-root-bundle']

def attest_command() -> list[str]:
    return ['/usr/bin/python3', ROOT_HELPER, '--attest-deny']

def show_timer(token: str) -> list[str]:
    return ['/usr/bin/systemctl', 'show', units(token)[1], '--no-pager',
            '-p', 'LoadState', '-p', 'ActiveState', '-p', 'Unit',
            '-p', 'NextElapseUSecMonotonic']

def show_service(token: str) -> list[str]:
    return ['/usr/bin/systemctl', 'show', units(token)[0], '--no-pager',
            '-p', 'LoadState', '-p', 'ActiveState', '-p', 'Result',
            '-p', 'ExecMainStatus', '-p', 'ExecMainStartTimestampMonotonic']

def journal(token: str) -> list[str]:
    return ['/usr/bin/journalctl', '--system', '--no-pager',
            '-u', units(token)[0], '-n', '30', '-o', 'short-iso']

def props(raw: bytes) -> dict[str, str]:
    need(type(raw) is bytes and 0 < len(raw) < 16384, 'SYSTEMD_SHOW_BYTES_INVALID')
    try:
        lines=raw.decode('utf-8','strict').splitlines()
    except UnicodeError as exc:
        raise GuardError('SYSTEMD_SHOW_ENCODING_INVALID') from exc
    result:dict[str,str]={}
    for line in lines:
        need('=' in line, 'SYSTEMD_SHOW_LINE_MALFORMED')
        key,value=line.split('=',1)
        need(key and key not in result and re.fullmatch('[A-Za-z0-9]+',key),
             'SYSTEMD_SHOW_DUPLICATE_OR_KEY_INVALID')
        result[key]=value
    return result

def armed(raw: bytes, token: str) -> bool:
    service, timer = units(token)
    d=props(raw)
    need(set(d)=={'LoadState','ActiveState','Unit','NextElapseUSecMonotonic'},
         'SYSTEMD_TIMER_PROPERTIES_INVALID')
    need(d['LoadState']=='loaded' and d['ActiveState']=='active' and
         d['Unit']==service and d['NextElapseUSecMonotonic'] not in ('','0','n/a'),
         'SYSTEMD_TIMER_NOT_ARMED')
    return True

def triggered_success(raw: bytes) -> bool:
    d=props(raw)
    need(set(d)=={'LoadState','ActiveState','Result','ExecMainStatus',
                 'ExecMainStartTimestampMonotonic'},
         'SYSTEMD_SERVICE_PROPERTIES_INVALID')
    if not d['ExecMainStartTimestampMonotonic'].isdigit() or int(d['ExecMainStartTimestampMonotonic'])<=0:
        return False
    if d['ActiveState']=='failed' or d['Result'] not in ('success',''):
        raise GuardError('SYSTEMD_RESTORE_SERVICE_FAILED')
    return (d['LoadState']=='loaded' and d['ActiveState']=='inactive' and
            d['Result']=='success' and d['ExecMainStatus']=='0')

def checked_root_result(raw: bytes, expected: str) -> bool:
    need(type(raw) is bytes and 0 < len(raw) < 16384,'F6_OUTPUT_SIZE_INVALID')
    try:
        d=json.loads(raw)
    except ValueError as exc:
        raise GuardError('F6_ROOT_RESULT_JSON_INVALID') from exc
    need(type(d) is dict and d.get('result')==expected and d.get('bindings')==6
         and d.get('p8')=='NO-GO','F6_ROOT_PROVENANCE_FAILED')
    return True

AUX_NAMES = {k+".stderr" for k in ("root_check","before_attest","schedule",
                                    "timer_armed","service_done","after_attest","journal")} | {
    "timer_status_early.stdout", "timer_status_early.stderr",
    "service_status_early.stdout", "service_status_early.stderr"
}

def receipt(intent: dict, outputs: dict[str,bytes], aux: dict[str,bytes]) -> dict:
    need(intent['schema']==SCHEMA and intent['action']=='DENY_ONLY_SMOKE' and
         intent['allow_traffic'] is False and intent['p8']=='NO-GO',
         'INTENT_NOT_DENY_ONLY')
    token=intent['token']; units(token)
    need(set(outputs)=={'root_check','before_attest','schedule','timer_armed',
                        'service_done','after_attest','journal'},
         'RECEIPT_OUTPUT_SCOPE_INVALID')
    need(set(aux)==AUX_NAMES and all(type(raw) is bytes and len(raw)<65536 for raw in aux.values()),
         'AUXILIARY_EVIDENCE_SCOPE_INVALID')
    checked_root_result(outputs['root_check'],F6_CHECK)
    checked_root_result(outputs['before_attest'],F6_ATTESTED)
    armed(outputs['timer_armed'],token)
    need(triggered_success(outputs['service_done']), 'WATCHDOG_NOT_TRIGGERED_SUCCESSFULLY')
    checked_root_result(outputs['after_attest'],F6_ATTESTED)
    return {'schema':SCHEMA, 'token':token, 'purpose':'INDEPENDENT_ROOT_DENY_TIMER',
            'intent_sha256':sha(canonical(intent)),
            'stdout_sha256':{k:sha(v) for k,v in sorted(outputs.items())},
            'aux_sha256':{k:sha(v) for k,v in sorted(aux.items())},
            'physical_deny_restore_tested':True,'protocol_connections':0,
            'firewall_allow_rules':0,'p8':'NO-GO'}
