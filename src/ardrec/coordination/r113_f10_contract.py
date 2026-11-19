"""F10 contract. Fixed ARDREC isolated lab, no discovery or arbitrary targets."""
from __future__ import annotations
import hashlib, json, re, struct
from pathlib import Path

HEAD = 'c6fd58e59227d95bff86a9f58a95c9af8539f22e'
BRANCH = 'feat/p14-r111-r114-real-lab'
PLAN = Path('/home/cicada/ardrec-lab/r113-f8r-arp-xml-v1/plan-h1neoltf')
F9R_REPORT = Path('/home/cicada/ardrec-lab/r113-f9r-arp-host-acceptance-v1/validation-zqh78yo7/report.json')
F9R_HASH = 'b336a40851a5723b507449042aed7010729327c57336e90bd1e95251c774870e'
F6_ROOT = Path('/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py')
ROOT = Path('/var/lib/ardrec/r113-f10-window-v1')
ROOT_SCRIPT = ROOT / 'root-window.py'
DENY = 'ardrec-r33-block-until-containment'
NFT_TABLE = 'ardrec_r34_guard'
DURATION = 120
OPEN_DEADLINE = 60
ROWS = {
    'runner-ssh': ('runner','ssh','a33d30r','52:54:00:ad:30:01','10.203.30.1','10.203.30.2',22),
    'ssh': ('ssh','ssh','a33d30t','52:54:00:ad:30:02','10.203.30.2','10.203.30.1',22),
    'runner-ftp': ('runner','ftp','a33d31r','52:54:00:ad:31:01','10.203.31.1','10.203.31.2',21),
    'ftp': ('ftp','ftp','a33d31t','52:54:00:ad:31:02','10.203.31.2','10.203.31.1',21),
    'runner-smb': ('runner','smb','a33d32r','52:54:00:ad:32:01','10.203.32.1','10.203.32.2',445),
    'smb': ('smb','smb','a33d32t','52:54:00:ad:32:02','10.203.32.2','10.203.32.1',445),
}
ROLES = tuple(ROWS)
NAMES = ('r34-window-CANDIDATE.nft',) + tuple('ardrec-r113-'+r+'-tcp-v1.xml' for r in ROLES)

class Stop(ValueError): pass

def need(cond, reason):
    if not cond: raise Stop(reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def canonical(obj):
    return (json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()

def name(role):
    need(role in ROWS,'ROLE_NOT_ALLOWED')
    return 'ardrec-r113-'+role+'-tcp-v1'

def validate_f9r(raw,policy_manifest):
    need(sha(raw)==F9R_HASH,'F9R_REPORT_HASH_CHANGED')
    doc=json.loads(raw)
    need(doc['schema']=='ARDREC-R113-F9R-CORRECTED-ARP-HOST-CHECK-v1' and
         doc['outcome']=='PASS_READONLY_HOST_ACCEPTANCE' and
         doc['nft_check_only'] is True and doc['libvirt_schema_only'] is True and
         doc['network_probes']==0 and doc['protocol_connections']==0 and
         doc['host_mutations_requested']==0 and doc['p8']=='NO-GO', 'F9R_STATUS_NOT_ACCEPTED')
    need(doc['f8_manifest_sha256']==sha(policy_manifest),'F9R_LINK_INVALID')
    queries=doc['queries']
    need(all(queries[x]['rc']==0 for x in
             ['nft_check','f6_root_check','f6_before','f6_after']+
             ['xml_'+r.replace('-','_') for r in ROLES]),'F9R_FAILED_HOST_VALIDATOR')
    return doc

def probe_source():
    # A single constrained guest-exec in runner, three authorized ports only.
    return r'''import socket,struct,json
R=[('ssh','10.203.30.1','10.203.30.2',22),('ftp','10.203.31.1','10.203.31.2',21),('smb','10.203.32.1','10.203.32.2',445)]
D=[]
for role,src,dst,port in R:
    row={'role':role,'src':src,'dst':dst,'port':port}
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.bind((src,0)); s.connect((dst,port)); row['tcp']='CONNECTED'
        if role in ('ssh','ftp'):
            try:
                value=s.recv(160); row['response_hex']=value.hex()
                row['protocol']='BANNER_RECEIVED' if value else 'NO_BANNER'
            except socket.timeout: row['protocol']='NO_BANNER_TIMEOUT'
        else:
            h=b'\xfeSMB'+struct.pack('<HHIHHIIQIIQ',64,0,0,0,1,0,0,1,0,0,0)+bytes(16)
            b=struct.pack('<HHHHI',36,4,1,0,0)+bytes(16)+struct.pack('<IHH',0,0,0)+struct.pack('<HHHH',0x0202,0x0210,0x0300,0x0311)
            req=h+b; s.sendall(b'\x00'+len(req).to_bytes(3,'big')+req)
            try:
                response=s.recv(160); row['response_hex']=response.hex()
                row['protocol']='SMB2_REPLY' if len(response)>=8 and response[4:8]==b'\xfeSMB' else 'UNVERIFIED_RESPONSE'
            except socket.timeout: row['protocol']='SMB2_RESPONSE_TIMEOUT'
    except (OSError,TimeoutError) as ex:
        row['tcp']='FAILED';row['error']=type(ex).__name__
    finally:s.close()
    D.append(row)
print(json.dumps({'schema':'ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1','results':D},sort_keys=True,separators=(',',':')))
'''

def validate_probe(raw):
    need(isinstance(raw,bytes) and 0<len(raw)<16000,'PROBE_OUTPUT_INVALID')
    doc=json.loads(raw)
    need(doc.get('schema')=='ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1','PROBE_SCHEMA_INVALID')
    rows=doc.get('results')
    need(type(rows) is list and len(rows)==3,'PROBE_ROW_COUNT')
    for row,(role,src,dst,port) in zip(rows,[('ssh','10.203.30.1','10.203.30.2',22),('ftp','10.203.31.1','10.203.31.2',21),('smb','10.203.32.1','10.203.32.2',445)]):
        need(row.get('role')==role and row.get('src')==src and row.get('dst')==dst and row.get('port')==port,'PROBE_DESTINATION_CHANGED')
        need(row.get('tcp') in ('CONNECTED','FAILED'),'PROBE_TCP_INVALID')
        need(not any(k in row for k in ('username','password','credentials')),'PROBE_SENSITIVE_FIELDS')
        need(len(row.get('response_hex',''))<=320,'PROBE_UNBOUNDED_OUTPUT')
        if 'response_hex' in row:
            bytes.fromhex(row['response_hex'])
    return doc
