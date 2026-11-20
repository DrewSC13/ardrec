"""R114-F5: one FTP control-channel A5 physical attempt, no A6 admission.

Only a new independently authorized runner-origin TCP/21 observation may
satisfy the control-response fact. Historical F10R/F4 observations are
provenance and configuration context, never retroactive A5 evidence.
"""
from __future__ import annotations
import base64
import hashlib
import json
import re
from typing import Any

SCHEMA='ARDREC-R114-F5-FTP-T01-REAL-A5-ATTEMPT-v1'
PROBE_SCHEMA='ARDREC-R114-F5-FTP-T01-ONE-PROBE-v1'
F4_MANIFEST_SHA='a3261fcefb15ef67c5436d74eadc546f3874cef9185d9f89ca22cf6976a31e62'
F4_CONFIG_SHA='299faa64aaf4181053441d2de69999a8ef9f07e28c504cfcbaf36a7070cf1ac8'
F4_DIR='/home/cicada/ardrec-lab/r114-f4-ftp-configuration-read-v1/capture-499b62a4'
ROOT='/var/lib/ardrec/r114-f5-ftp-t01-root-v1'
VM_RUNNER='ardrec-r33-dev-runner'
VM_TARGET='ardrec-r33-dev-ftp'
SRC_IP='10.203.31.1'
DST_IP='10.203.31.2'
DST_PORT=21
SRC_MAC='52:54:00:ad:31:01'
DST_MAC='52:54:00:ad:31:02'
CASE='FTP-T01-S01-01'
ATTEMPT='ATT_R114_F5_FTP_T01_01'
MAX_GREETING=256
DURATION=120

class Stop(ValueError):pass

def need(ok:bool,reason:str)->None:
    if not ok:raise Stop(reason)

def canon(doc:Any)->bytes:
    return (json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def sha(raw:bytes)->str:return hashlib.sha256(raw).hexdigest()

def runner_source()->str:
    """One outgoing TCP connection. No login, enumeration or shell commands."""
    return r'''import socket,json
DOC={'schema':'ARDREC-R114-F5-FTP-T01-ONE-PROBE-v1','src':'10.203.31.1','dst':'10.203.31.2','port':21,'case_id':'FTP-T01-S01-01','attempt':'ATT_R114_F5_FTP_T01_01'}
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(3)
try:
 s.bind(('10.203.31.1',0));s.connect(('10.203.31.2',21));DOC['tcp']='CONNECTED'
 try:
  data=s.recv(256);DOC['response_hex']=data.hex()
  DOC['response']='BANNER_RECEIVED' if data else 'EMPTY_GREETING'
 except socket.timeout:
  DOC['response_hex']='';DOC['response']='GREETING_TIMEOUT'
except (OSError,TimeoutError) as exc:
 DOC['tcp']='FAILED';DOC['response_hex']='';DOC['response']='NO_CONNECT';DOC['error']=type(exc).__name__
finally:
 s.close()
print(json.dumps(DOC,sort_keys=True,separators=(',',':')))
'''

def parse_probe(raw:bytes)->dict:
    need(type(raw) is bytes and 0<len(raw)<4000,'PROBE_SIZE_INVALID')
    try:doc=json.loads(raw)
    except (ValueError,UnicodeError,RecursionError) as e:raise Stop('PROBE_JSON_INVALID') from e
    need(type(doc) is dict and doc.get('schema')==PROBE_SCHEMA and
         doc.get('src')==SRC_IP and doc.get('dst')==DST_IP and
         type(doc.get('port')) is int and doc['port']==DST_PORT and
         doc.get('case_id')==CASE and doc.get('attempt')==ATTEMPT,
         'PROBE_IDENTITY_CHANGED')
    need(doc.get('tcp') in ('CONNECTED','FAILED') and
         doc.get('response') in ('BANNER_RECEIVED','EMPTY_GREETING','GREETING_TIMEOUT','NO_CONNECT'),
         'PROBE_RESULT_INVALID')
    try:
        raw_banner=bytes.fromhex(doc.get('response_hex',''))
    except (ValueError,TypeError) as e:raise Stop('RESPONSE_HEX_INVALID') from e
    need(len(raw_banner)<=MAX_GREETING,'RESPONSE_OVERFLOW')
    if doc['tcp']=='CONNECTED':
        need('error' not in doc and doc['response']!='NO_CONNECT','CONNECTED_RESULT_CONTRADICTS')
        need((doc['response']=='BANNER_RECEIVED')==(len(raw_banner)>0),
             'BANNER_AND_RESULT_CONTRADICT')
    else:
        need(doc['response']=='NO_CONNECT' and not raw_banner and
             doc.get('error') in ('TimeoutError','ConnectionRefusedError','OSError','NetworkUnreachableError','ConnectionResetError'),
             'FAILED_RESULT_CONTRADICTS')
    need(set(doc)==({'schema','src','dst','port','case_id','attempt','tcp','response','response_hex'} |
                      ({'error'} if doc['tcp']=='FAILED' else set())),
         'PROBE_UNEXPECTED_FIELDS')
    return doc

def valid_ftp_220(greeting:bytes)->bool:
    """Strict initial FTP control-line evidence; not proof of vulnerability."""
    if not isinstance(greeting,bytes) or not 5<=len(greeting)<=MAX_GREETING:return False
    if b'\x00' in greeting or b'\n' not in greeting:return False
    if not greeting.startswith((b'220 ',b'220-')):return False
    if not greeting.endswith(b'\r\n'):return False
    # Single 220 line only; prevents hidden additional protocol dialogue.
    if greeting.count(b'\r\n')!=1:return False
    return all(32<=c<=126 or c in (13,10) for c in greeting)

def validate_f4_source(f4_report:dict,f4_manifest:dict,*,manifest_sha:str,report_sha:str)->bool:
    need(manifest_sha==F4_MANIFEST_SHA,'F4_MANIFEST_NOT_PINNED')
    need(type(f4_manifest) is dict and
         f4_manifest.get('schema')=='ARDREC-R114-F4-FTP-QGA-PARTIAL-REPLAY-v1' and
         f4_manifest.get('report_sha256')==report_sha and
         f4_manifest.get('source_f3_manifest_sha256')=='9a216b641f01fdeba5c5e559bb4819393212ecc6c5bbc6f7d90e79f8663f2acf' and
         f4_manifest.get('a5_family_completed') is False and
         f4_manifest.get('a6_conditions_admitted')==0 and
         f4_manifest.get('new_network_connections')==0 and
         f4_manifest.get('risk_recalculated') is False and
         f4_manifest.get('p8')=='NO-GO' and
         f4_manifest.get('files_sha256',{}).get('config.bytes')==F4_CONFIG_SHA,
         'F4_MANIFEST_SCOPE_CHANGED')
    need(type(f4_report) is dict and
         f4_report.get('schema')=='ARDREC-R114-F4-FTP-CONFIG-SOURCE-OBSERVATION-v1' and
         f4_report.get('vm')==VM_TARGET and f4_report.get('mac')==DST_MAC and
         f4_report.get('ipv4_cidr')==DST_IP+'/28' and
         f4_report.get('observed_file')=='/etc/vsftpd.conf' and
         f4_report.get('config_file_sha256')==F4_CONFIG_SHA and
         f4_report.get('case_intent',{}).get('derived_case_id')==CASE and
         f4_report.get('case_intent',{}).get('family_id')=='FTP-T01' and
         f4_report.get('a5_family_execution_completed') is False and
         f4_report.get('effective_configuration_accredited') is False and
         f4_report.get('a6_classification')=='ND' and
         f4_report.get('p8')=='NO-GO', 'F4_REPORT_SCOPE_CHANGED')
    return True

def classify_attempt(*,raw_probe:bytes,qga_raw_status:bytes,f6_final_raw:bytes,
                     f4_manifest_sha:str,f4_report_sha:str)->dict:
    """Physical A5 attempt classification; A6 remains unadmitted by design."""
    need(f4_manifest_sha==F4_MANIFEST_SHA and
         re.fullmatch('[0-9a-f]{64}',f4_report_sha) is not None,
         'F4_LINEAGE_CHANGED')
    data=parse_probe(raw_probe)
    try:
        completed=json.loads(qga_raw_status)['return']
        deny=json.loads(f6_final_raw)
        encoded=base64.b64decode(completed.get('out-data',''),validate=True)
        err=base64.b64decode(completed.get('err-data',''),validate=True)
    except (KeyError,TypeError,ValueError,UnicodeError,RecursionError) as e:
        raise Stop('QGA_OR_F6_DATA_INVALID') from e
    need(type(completed) is dict and completed.get('exited') is True and
         type(completed.get('exitcode')) is int and completed.get('exitcode')==0 and
         not err and encoded==raw_probe,'QGA_COMPLETION_OR_BYTES_MISMATCH')
    need(type(deny) is dict and deny.get('result')=='SIX_BINDING_DENY_ATTESTED' and
         deny.get('bindings')==6 and deny.get('p8')=='NO-GO' and
         deny.get('host_writes')==0,'F6_FINAL_DENY_NOT_ATTESTED')
    greeting=bytes.fromhex(data['response_hex'])
    observed=bool(data['tcp']=='CONNECTED' and valid_ftp_220(greeting))
    return {
       'schema':SCHEMA,'case_id':CASE,'attempt_id':ATTEMPT,'family_id':'FTP-T01',
       'service_id':'FTP_DEV','vm_runner':VM_RUNNER,'vm_target':VM_TARGET,
       'source_ip':SRC_IP,'target_ip':DST_IP,'tcp_port':DST_PORT,
       'source_mac':SRC_MAC,'target_mac':DST_MAC,
       'source_f4_manifest_sha256':f4_manifest_sha,
       'source_f4_report_sha256':f4_report_sha,
       'qga_completion_sha256':sha(qga_raw_status),'raw_probe_sha256':sha(raw_probe),
       'raw_banner_sha256':sha(greeting),'raw_banner_bytes':len(greeting),
       'tcp_connected':data['tcp']=='CONNECTED',
       'ftp_220_response_observed':observed,
       'a5_one_physical_attempt_recorded':True,
       'a5_family_condition_candidate':('FTP_CONTROL_RESPONSE_OBSERVED'
                                          if observed else 'FTP_CONTROL_RESPONSE_UNRESOLVED'),
       'a6_classification':'ND','a6_technical_truth_admitted':False,
       'a6_supports_admitted':[],
       'vulnerability_confirmed':False,'a7_final_risk':None,
       'a8_applied_transitions':0,'a9_published_generation':None,
       'final_deny':'SIX_BINDING_DENY_ATTESTED','p8':'NO-GO'
    }
