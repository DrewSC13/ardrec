"""R112-F9: isolated runner QEMU boot, without network traffic authority.

Pure validation. Only expected running-state drift is runner: OFF -> RUNNING;
SSH is running before/after; FTP/SMB shut off before/after.
"""
from __future__ import annotations
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA = 'ardrec-p14-r112-f9-one-real-runner-boot-v1'
PARENT = '2ec2dbdac50ce259364b4c79f772aebd5db01e46'
GUEST = 'ardrec-r33-dev-runner'
ROLES = ('runner', 'ssh', 'ftp', 'smb')
NETWORKS = ('ssh', 'ftp', 'smb')
ROOT = '/run/ardrec-f11-boot-v1'
LEASE = ROOT+'/allow-'+GUEST+'.json'
MARKERS = {x: ROOT+'/'+x+'-'+GUEST+'.sha256' for x in ('used','stage','active')}
START = ('sudo','-n','virsh','-c','qemu:///system','start',GUEST)
TTL=180

class F9Error(ValueError): pass

def need(ok: bool, reason: str):
    if not ok: raise F9Error(reason)

def canon(obj: Any) -> bytes:
    return json.dumps(obj,sort_keys=True,ensure_ascii=True,allow_nan=False,
                      separators=(',', ':')).encode('ascii')+b'\n'

def digest(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()
def sha(obj: Any) -> str: return digest(canon(obj))

def ticket(now:int, nonce:str)->dict:
    need(type(now) is int and now>0 and type(nonce) is str and
         re.fullmatch('[0-9a-f]{64}',nonce) is not None,'INVALID_TICKET_TIME_OR_NONCE')
    return {'schema':f8.LEASE_SCHEMA,'guest':GUEST,'issued_at':now,
            'expires_at':now+TTL,'nonce':nonce,
            'mode':'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY','p8_operational':'NO-GO',
            'r34_policy':'DENY_PRESERVED','scope':'R112_LAB_BOOT_PREAUTHORIZATION_ONLY',
            'phases':['prepare','start','started']}

def state(snapshot:dict, role:str) -> str:
    return f8._vm_state(snapshot,role)

def audited(record:dict, *, runner_running:bool, legacy, f4) -> bool:
    need(type(record) is dict and set(record)=={'snapshot','english_info','other_domains'},
         'SNAPSHOT_SCHEMA')
    s=record['snapshot']
    need(type(s) is dict and set(s)=={'schema','commands','probes','summary'} and
         s['schema']==legacy.SCHEMA and
         s['commands']=={k:list(v) for k,v in legacy.command_list().items()} and
         set(s['probes'])==set(s['commands']) and len(s['probes'])==29 and
         s['summary']==legacy.summarize(s['probes']), 'UNREPRODUCIBLE_29_PROBES')
    need(all(type(p) is dict and p['rc']==0 and p['timeout'] is False and
             p['truncated'] is False for p in s['probes'].values()),
         'PHYSICAL_PROBE_ERROR')
    need(s['summary']['hook_sha256']==f8.HOOK_SHA and
         s['summary']['nft_rule_count']==4,'F11_OR_R34_DRIFT')
    expected={'ssh':'RUNNING','runner':'RUNNING' if runner_running else 'SHUTOFF',
              'ftp':'SHUTOFF','smb':'SHUTOFF'}
    for role in ROLES:
        need(state(record,role)==expected[role],'WRONG_GUEST_STATE_'+role)
        nic.validate_domain(s['probes']['vm-'+role+'-inactive-xml']['stdout'],
                            role,configured=role=='runner')
    inventory=s['summary']['domain_inventory']['runner']['interfaces']
    need(tuple(x['network'] for x in inventory)==
         tuple('ardrec-r33-dev-net-'+r for r in NETWORKS) and
         all(x['filter']==nic.FILTER for x in inventory), 'RUNNER_NIC_FILTER_DRIFT')
    need(record['other_domains']['status']=='NO_UNRELATED_R33_NET_ATTACHMENTS'
         and record['other_domains']['inspected'] is True,'UNRELATED_VM_SCOPE')
    need(set(record['english_info'])==set(NETWORKS),'NETWORK_SET_DRIFT')
    for role in NETWORKS:
        item=record['english_info'][role]
        need(item['rc']==0 and item['timeout'] is False and item['truncated'] is False and
             f4.core.parse_net_info(item['stdout'],role)=='ACTIVE',
             'NETWORK_NOT_ACTIVE_'+role)
        nic._safe_net(s['probes']['net-'+role+'-xml']['stdout'],role)
    for role in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(s['summary']['systemd'][role]['ActiveState']=='active',
             'SYSTEMD_NOT_ACTIVE_'+role)
    filt=ET.fromstring(s['probes']['deny-nwfilter-xml']['stdout'])
    rules=filt.findall('rule')
    need(filt.tag=='filter' and filt.get('name')==nic.FILTER and
         len(rules)==1 and rules[0].get('action')=='drop' and
         rules[0].get('direction')=='inout' and
         rules[0].find('all') is not None, 'NWFILTER_DENY_CHANGED')
    nic._nft_structure(s['probes']['r34-nft']['stdout'])
    return True

def compare(before,after,*,legacy,f4):
    audited(before,runner_running=False,legacy=legacy,f4=f4)
    audited(after,runner_running=True,legacy=legacy,f4=f4)
    a,b=before['snapshot']['probes'],after['snapshot']['probes']
    need(before['snapshot']['commands']==after['snapshot']['commands'],
         'COMMAND_INVENTORY_CHANGED')
    for key in ([f'vm-{r}-{field}' for r in ROLES for field in ('inactive-xml','block')]
                +['f11-hook-stat','f11-hook-hash','deny-nwfilter-xml']):
        need(a[key]['stdout']==b[key]['stdout'],'STATIC_RESOURCE_CHANGED_'+key)
    for role in NETWORKS:
        key='net-'+role+'-xml'
        need(f8._r112_f8_static_network_xml(a[key]['stdout'])==
             f8._r112_f8_static_network_xml(b[key]['stdout']),
             'NETWORK_STATIC_DRIFT_'+role)
    need(before['other_domains']==after['other_domains'],
         'UNRELATED_DOMAIN_SCOPE_CHANGED')
    need(before['english_info']==after['english_info'],
         'NETWORK_STATE_SUMMARY_CHANGED')
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']), 'R34_NFT_STRUCTURE_CHANGED')
    for role in ('ssh','ftp','smb'):
        key='vm-'+role+'-state'
        need(a[key]['stdout']==b[key]['stdout'], 'UNEXPECTED_VM_STATE_CHANGED_'+role)
    return True

def live_runner(raw:str):
    nic.validate_domain(raw,'runner',configured=True)
    root=ET.fromstring(raw)
    need(root.findtext('name')==GUEST and
         len(root.findall('devices/interface'))==3 and
         len(root.findall('devices/disk[@device="disk"]'))==1 and
         not root.findall('devices/hostdev') and
         not root.findall('devices/filesystem') and
         not root.findall('devices/interface[@type="bridge"]') and
         not root.findall('devices/interface[@type="direct"]'),
         'RUNNER_LIVE_XML_UNAUTHORIZED_DEVICE')
    return True

def claims_ok(ticket_doc:dict,grant:dict,claims:dict):
    need(type(ticket_doc) is dict and ticket_doc==ticket(ticket_doc['issued_at'],ticket_doc['nonce']),
         'TICKET_SCHEMA_INVALID')
    expected_sha=digest(canon(ticket_doc))
    need(type(grant) is dict and set(grant)=={'directory_stat','lease_stat','lease_sha256'}
         and grant['directory_stat'].strip()=='0:0 700 '+ROOT
         and grant['lease_stat'].strip()==
             '0:0 600 1 '+str(len(canon(ticket_doc)))+' '+LEASE
         and grant['lease_sha256']==expected_sha, 'ROOT_LEASE_NOT_ATTESTED')
    need(type(claims) is dict and set(claims)==set(MARKERS), 'F11_MARKER_SET')
    for name,path in MARKERS.items():
        item=claims[name]
        need(type(item) is dict and set(item)=={'stat','content'} and
             item['stat'].strip()=='0:0 600 1 65 '+path and
             item['content']==expected_sha+'\n',
             'F11_LIFECYCLE_STAGE_MISSING_'+name)
    return expected_sha

def classify(before,after,started,live,ticket_doc,grant,claims,*,legacy,f4):
    need(type(started) is dict and set(started)==
         {'rc','stdout','stderr','timeout','truncated'} and
         started['rc']==0 and started['timeout'] is False and
         started['truncated'] is False, 'RUNNER_START_NOT_ATTESTED')
    compare(before,after,legacy=legacy,f4=f4)
    live_runner(live)
    lease_sha=claims_ok(ticket_doc,grant,claims)
    return {'schema':SCHEMA+'-receipt','guest':GUEST,
            'mode':'ONE_RUNNER_QEMU_BOOT_WITH_SSH_RUNNING_R34_DENY',
            'parent_commit':PARENT,'before_sha256':sha(before),'after_sha256':sha(after),
            'lease_sha256':lease_sha,'hook_sha256':f8.HOOK_SHA,
            'ssh_running':True,'runner_running':True,'ftp_smb_shutoff':True,
            'networks_active_and_denied':True,
            'f11_claims':['prepare','start','started'],
            'traffic_authorized':False,'protocol_tested':False,
            'a5_dispatched':False,'a6':'ND','a7':'NOT_ATTESTED','a9':False,
            'p8_operational':'NO-GO'}
