"""R114-F1: ingest authentic F10R raw guest result and DENY closure.

This is a *source-only*, physical evidence intake. Network reachability and
protocol banner are not proof of exploitability or a matching A6 condition.
No A5 case binding, Rf, confirmed vulnerability, state transition, or P8 grant.
"""
from __future__ import annotations
import base64, hashlib, json, re
from typing import Any

SCHEMA = 'ARDREC-R114-F1-REAL-RECEIPT-INTAKE-v1'
F10R_RECEIPT_SHA = '8aecaaccafca822da5204aedd781bc64af44c79afa38e8ca1e091eadd6ea5363'
F10R_SOURCE = '/var/lib/ardrec/r113-f10r-window-v1/window-13af3370'
ROLES = (
    ('ssh', '10.203.30.1', '10.203.30.2', 22),
    ('ftp', '10.203.31.1', '10.203.31.2', 21),
    ('smb', '10.203.32.1', '10.203.32.2', 445),
)
SOURCE_FILES = (
    'receipt.json',
    'runner-probe-stdout.json',
    'qga_status_1.stdout',
    'f6_restore_final.stdout',
    'f6_attest_final.stdout',
    'timer_active.stdout',
    'nft_live_check.stdout',
)
HEX = re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
MAX_BYTES=200_000

class EvidenceError(ValueError): pass

def need(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)

def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def canonical(value: Any) -> bytes:
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def jload(raw: bytes, name: str) -> dict:
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES, 'INVALID_LENGTH_'+name)
    try: doc=json.loads(raw)
    except (ValueError,UnicodeError) as e: raise EvidenceError('INVALID_JSON_'+name) from e
    need(type(doc) is dict, 'INVALID_OBJECT_'+name)
    return doc

def analyze(raw: dict[str, bytes], *, expected_receipt_sha: str = F10R_RECEIPT_SHA) -> dict:
    """Fail closed on source substitution; only fixed role/IP/port evidence."""
    need(type(raw) is dict and set(raw)==set(SOURCE_FILES),'SOURCE_SCOPE_INVALID')
    need(type(expected_receipt_sha) is str and HEX.fullmatch(expected_receipt_sha),'PIN_INVALID')
    need(digest(raw['receipt.json'])==expected_receipt_sha,'ROOT_RECEIPT_HASH_CHANGED')
    receipt=jload(raw['receipt.json'],'receipt')
    need(receipt.get('schema')=='ARDREC-R113-F10R-ROOT-EVENT-v1'
         and receipt.get('status')=='CLOSED_DENY_WITH_REAL_PROBES'
         and receipt.get('p8')=='NO-GO'
         and receipt.get('traffic_scope')=='THREE_FIXED_PRIVATE_TCP_PORTS',
         'ROOT_RECEIPT_STATUS_INVALID')
    file_map=receipt.get('files')
    need(type(file_map) is dict and all(type(x) is str and type(v) is str
         and HEX.fullmatch(v) is not None for x,v in file_map.items()),
         'ROOT_RECEIPT_MANIFEST_INVALID')
    for name in SOURCE_FILES[1:]:
        need(name in file_map and digest(raw[name])==file_map[name],
             'ROOT_SOURCE_HASH_CHANGED_'+name)
    qga=jload(raw['qga_status_1.stdout'],'qga')['return']
    need(type(qga) is dict and qga.get('exited') is True and
         type(qga.get('exitcode')) is int and qga['exitcode']==0,
         'QGA_NOT_SUCCESSFUL')
    try:
        qga_out=base64.b64decode(qga['out-data'],validate=True)
        qga_err=base64.b64decode(qga.get('err-data',''),validate=True)
    except (ValueError,KeyError) as e: raise EvidenceError('QGA_BASE64_INVALID') from e
    need(qga_out==raw['runner-probe-stdout.json'] and qga_err==b'',
         'QGA_OUT_OF_SYNC_OR_STDERR')
    guest=jload(qga_out,'runner')
    need(guest.get('schema')=='ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1',
         'GUEST_SCHEMA_INVALID')
    results=guest.get('results')
    need(type(results) is list and len(results)==3,'RUNNER_RESULTS_INVALID')
    classified=[]
    for row, (role,src,dst,port) in zip(results,ROLES):
        need(type(row) is dict and row.get('role')==role and row.get('src')==src
             and row.get('dst')==dst and type(row.get('port')) is int and row['port']==port,
             'RUNNER_TARGET_IDENTITY_INVALID_'+role)
        need(row.get('tcp')=='CONNECTED','RUNNER_TCP_NOT_CONNECTED_'+role)
        value=row.get('response_hex')
        need(type(value) is str and len(value)<=320 and len(value)%2==0,
             'RESPONSE_FORMAT_'+role)
        try: data=bytes.fromhex(value)
        except ValueError as e: raise EvidenceError('RESPONSE_HEX_INVALID_'+role) from e
        if role=='ssh':
            need(row.get('protocol')=='BANNER_RECEIVED' and
                 data.startswith(b'SSH-2.0-') and data.endswith(b'\r\n'),
                 'SSH_BANNER_NOT_VERIFIED')
            classification='SSH_IDENTIFICATION_BANNER_OBSERVED'
        elif role=='ftp':
            need(row.get('protocol')=='BANNER_RECEIVED' and
                 data.startswith(b'220 ') and data.endswith(b'\r\n'),
                 'FTP_CONTROL_GREETING_NOT_VERIFIED')
            classification='FTP_220_CONTROL_GREETING_OBSERVED'
        else:
            need(row.get('protocol')=='UNVERIFIED_RESPONSE' and data==b'',
                 'SMB_RESULT_NOT_AS_RECORDED')
            classification='SMB_TCP_CONNECTED_NO_SMB2_RESPONSE_VERIFIED'
        classified.append({
            'role':role,'source_ip':src,'target_ip':dst,'target_port':port,
            'tcp':'CONNECTED','protocol_observation':classification,
            'raw_response_sha256':digest(data),'response_length':len(data),
            'smb2_negotiation_accredited':False,
            'case_identity':None,'a5_case_binding':'NOT_ACCREDITED',
            'a6_condition':'ND_NO_DECLARED_FAMILY_CONDITION',
            'verified_vulnerability':False,
        })
    restore=jload(raw['f6_restore_final.stdout'],'f6_restore')
    attest=jload(raw['f6_attest_final.stdout'],'f6_attest')
    need(restore.get('result')=='SIX_BINDING_DENY_RESTORED'
         and restore.get('nft_deny_verified') is True
         and restore.get('traffic_allowed') is False
         and type(restore.get('bindings')) is int and restore['bindings']==6
         and restore.get('p8')=='NO-GO','F6_RESTORE_INVALID')
    need(attest.get('result')=='SIX_BINDING_DENY_ATTESTED'
         and type(attest.get('bindings')) is int and attest['bindings']==6
         and attest.get('host_writes')==0 and attest.get('p8')=='NO-GO',
         'F6_FINAL_DENY_INVALID')
    timer=raw['timer_active.stdout'].decode('ascii')
    need('LoadState=loaded' in timer and 'ActiveState=active' in timer,
         'TIMER_WAS_NOT_ARMED')
    nft=jload(raw['nft_live_check.stdout'],'nft')
    entries=nft.get('nftables')
    need(type(entries) is list,'NFT_CAPTURE_INVALID')
    rules=[x['rule'] for x in entries if type(x) is dict and 'rule' in x]
    need(len(rules)==16 and
         sum(any(type(e) is dict and 'accept' in e for e in r.get('expr',[])) for r in rules)==12 and
         sum(any(type(e) is dict and 'drop' in e for e in r.get('expr',[])) for r in rules)==4,
         'NFT_SCOPED_WINDOW_NOT_PROVEN')
    return {
        'schema':SCHEMA,'origin':'REAL_F10R_QGA_RUNNER_AND_ROOT_CLOSURE',
        'root_source':F10R_SOURCE,
        'root_receipt_sha256':digest(raw['receipt.json']),
        'source_sha256':{name:digest(raw[name]) for name in SOURCE_FILES},
        'observations':classified,
        'counts':{'tcp_connections':3,'verified_banners':2,'verified_smb2':0,
                  'a5_case_bound':0,'a6_conditions_admitted':0},
        'watchdog_armed_at_open':True,
        'final_f6_restore':'SIX_BINDING_DENY_RESTORED',
        'final_f6_attest':'SIX_BINDING_DENY_ATTESTED',
        'no_new_network_traffic':True,
        'no_new_guest_exec':True,
        'operational_dispatch':False,
        'risk_recalculation_performed':False,
        'confirmed_final_risk':None,
        'p8':'NO-GO',
    }

def verified_report(report: dict, sources: dict[str, bytes], *, expected_receipt_sha: str=F10R_RECEIPT_SHA) -> None:
    need(canonical(report)==canonical(analyze(sources,expected_receipt_sha=expected_receipt_sha)),
         'REPORT_NOT_REPRODUCIBLE')
