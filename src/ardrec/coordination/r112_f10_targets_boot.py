"""R112-F10: pure audit of one FTP then one SMB physical boot (R34 DENY)."""
from __future__ import annotations
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_f9_runner_boot as f9
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA='ardrec-p14-r112-f10-ftp-then-smb-boot-v1'
PARENT='e57b985db04464991ca7b04dbd4a70fae9d3abe6'
ROLES=('ssh','runner','ftp','smb')
NETWORKS=('ssh','ftp','smb')
TARGETS=('ftp','smb')
LEASE_ROOT='/run/ardrec-f11-boot-v1'
TTL=180

class F10Error(ValueError): pass

def need(ok:bool,reason:str):
    if not ok: raise F10Error(reason)

def canon(obj:Any)->bytes:
    return json.dumps(obj,ensure_ascii=True,sort_keys=True,allow_nan=False,
                      separators=(',',':')).encode('ascii')+b'\n'

def digest(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def sha(obj:Any)->str: return digest(canon(obj))

def target_ok(role:str):
    need(type(role) is str and role in TARGETS,'TARGET_NOT_IN_ALLOWLIST')

def guest(role:str)->str:
    target_ok(role)
    return 'ardrec-r33-dev-'+role

def lease(role:str)->str:
    return LEASE_ROOT+'/allow-'+guest(role)+'.json'

def markers(role:str)->dict:
    return {stage:LEASE_ROOT+'/'+stage+'-'+guest(role)+'.sha256'
            for stage in ('used','stage','active')}

def start(role:str)->tuple:
    return ('sudo','-n','virsh','-c','qemu:///system','start',guest(role))

def ticket(role:str,now:int,nonce:str)->dict:
    target_ok(role)
    need(type(now) is int and now>0 and type(nonce) is str and
         re.fullmatch('[0-9a-f]{64}',nonce) is not None,
         'INVALID_TICKET_TIME_OR_NONCE')
    return {'schema':f8.LEASE_SCHEMA,'guest':guest(role),'issued_at':now,
            'expires_at':now+TTL,'nonce':nonce,
            'mode':'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY','p8_operational':'NO-GO',
            'r34_policy':'DENY_PRESERVED','scope':'R112_LAB_BOOT_PREAUTHORIZATION_ONLY',
            'phases':['prepare','start','started']}

def expected(role:str,after:bool)->dict:
    target_ok(role)
    if role=='ftp':
        return {'ssh':'RUNNING','runner':'RUNNING',
                'ftp':'RUNNING' if after else 'SHUTOFF','smb':'SHUTOFF'}
    return {'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING',
            'smb':'RUNNING' if after else 'SHUTOFF'}

def audited(record:dict,role:str,*,after:bool,legacy,f4)->bool:
    target_ok(role)
    need(type(record) is dict and set(record)=={'snapshot','english_info','other_domains'},
         'SNAPSHOT_SCHEMA')
    s=record['snapshot']
    need(type(s) is dict and set(s)=={'schema','commands','probes','summary'} and
         s['schema']==legacy.SCHEMA and
         s['commands']=={k:list(v) for k,v in legacy.command_list().items()} and
         set(s['probes'])==set(s['commands']) and len(s['probes'])==29 and
         s['summary']==legacy.summarize(s['probes']),
         'UNREPRODUCIBLE_29_PROBES')
    need(all(type(p) is dict and p['rc']==0 and p['timeout'] is False and
             p['truncated'] is False for p in s['probes'].values()),
         'PHYSICAL_PROBE_ERROR')
    need(s['summary']['hook_sha256']==f8.HOOK_SHA and
         s['summary']['nft_rule_count']==4,'F11_OR_R34_DRIFT')
    states=expected(role,after)
    for r in ROLES:
        need(f8._vm_state(record,r)==states[r],'WRONG_GUEST_STATE_'+r)
        nic.validate_domain(s['probes']['vm-'+r+'-inactive-xml']['stdout'],
                            r,configured=r=='runner')
    inventory=s['summary']['domain_inventory']['runner']['interfaces']
    need(tuple(x['network'] for x in inventory)==
         tuple('ardrec-r33-dev-net-'+r for r in NETWORKS) and
         all(x['filter']==nic.FILTER for x in inventory),
         'RUNNER_NIC_FILTER_DRIFT')
    need(record['other_domains']['status']=='NO_UNRELATED_R33_NET_ATTACHMENTS' and
         record['other_domains']['inspected'] is True,'UNRELATED_VM_SCOPE')
    need(set(record['english_info'])==set(NETWORKS),'NETWORK_SET_DRIFT')
    for r in NETWORKS:
        info=record['english_info'][r]
        need(info['rc']==0 and info['timeout'] is False and info['truncated'] is False and
             f4.core.parse_net_info(info['stdout'],r)=='ACTIVE',
             'NETWORK_NOT_ACTIVE_'+r)
        nic._safe_net(s['probes']['net-'+r+'-xml']['stdout'],r)
    for service in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(s['summary']['systemd'][service]['ActiveState']=='active',
             'SYSTEMD_NOT_ACTIVE_'+service)
    filt=ET.fromstring(s['probes']['deny-nwfilter-xml']['stdout'])
    rules=filt.findall('rule')
    need(filt.tag=='filter' and filt.get('name')==nic.FILTER and
         len(rules)==1 and rules[0].get('action')=='drop' and
         rules[0].get('direction')=='inout' and rules[0].find('all') is not None,
         'NWFILTER_DENY_CHANGED')
    nic._nft_structure(s['probes']['r34-nft']['stdout'])
    return True

def compare(before:dict,after_record:dict,role:str,*,legacy,f4)->bool:
    audited(before,role,after=False,legacy=legacy,f4=f4)
    audited(after_record,role,after=True,legacy=legacy,f4=f4)
    a,b=before['snapshot']['probes'],after_record['snapshot']['probes']
    need(before['snapshot']['commands']==after_record['snapshot']['commands'],
         'COMMAND_INVENTORY_CHANGED')
    for key in ([f'vm-{r}-{field}' for r in ROLES
                 for field in ('inactive-xml','block')]
                +['f11-hook-stat','f11-hook-hash','deny-nwfilter-xml']):
        need(a[key]['stdout']==b[key]['stdout'],'STATIC_RESOURCE_CHANGED_'+key)
    for r in NETWORKS:
        key='net-'+r+'-xml'
        need(f8._r112_f8_static_network_xml(a[key]['stdout'])==
             f8._r112_f8_static_network_xml(b[key]['stdout']),
             'NETWORK_STATIC_DRIFT_'+r)
    need(before['english_info']==after_record['english_info'] and
         before['other_domains']==after_record['other_domains'],
         'NETWORK_OR_UNRELATED_SCOPE_CHANGED')
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),'R34_NFT_STRUCTURE_CHANGED')
    for r in ROLES:
        if r != role:
            key='vm-'+r+'-state'
            need(a[key]['stdout']==b[key]['stdout'],
                 'UNEXPECTED_VM_STATE_CHANGED_'+r)
    return True

def live_target(xml:str,role:str)->bool:
    target_ok(role)
    nic.validate_domain(xml,role)
    root=ET.fromstring(xml)
    need(root.findtext('name')==guest(role) and
         len(root.findall('devices/interface'))==1 and
         len(root.findall('devices/disk[@device="disk"]'))==1 and
         not root.findall('devices/hostdev') and
         not root.findall('devices/filesystem') and
         not root.findall('devices/interface[@type="bridge"]') and
         not root.findall('devices/interface[@type="direct"]'),
         'LIVE_XML_UNAUTHORIZED_DEVICE')
    return True

def claims_ok(role:str,doc:dict,grant:dict,claims:dict)->str:
    target_ok(role)
    need(type(doc) is dict and doc==ticket(role,doc['issued_at'],doc['nonce']),
         'TICKET_SCHEMA_INVALID')
    token_sha=digest(canon(doc))
    grant_path=lease(role)
    need(type(grant) is dict and set(grant)=={'directory_stat','lease_stat','lease_sha256'} and
         grant['directory_stat'].strip()=='0:0 700 '+LEASE_ROOT and
         grant['lease_stat'].strip()==
             '0:0 600 1 '+str(len(canon(doc)))+' '+grant_path and
         grant['lease_sha256']==token_sha,'ROOT_LEASE_NOT_ATTESTED')
    names=markers(role)
    need(type(claims) is dict and set(claims)==set(names),'F11_MARKER_SET')
    for key,path in names.items():
        item=claims[key]
        need(type(item) is dict and set(item)=={'stat','content'} and
             item['stat'].strip()=='0:0 600 1 65 '+path and
             item['content']==token_sha+'\n','F11_LIFECYCLE_STAGE_MISSING_'+key)
    return token_sha

def classify(before,after_record,started,live,doc,grant,claims,role,*,legacy,f4):
    target_ok(role)
    need(type(started) is dict and set(started)==
         {'rc','stdout','stderr','timeout','truncated'} and
         started['rc']==0 and started['timeout'] is False and
         started['truncated'] is False,'START_NOT_ATTESTED')
    compare(before,after_record,role,legacy=legacy,f4=f4)
    live_target(live,role)
    lease_sha=claims_ok(role,doc,grant,claims)
    return {'schema':SCHEMA+'-receipt','target':role,'guest':guest(role),
            'mode':'ONE_TARGET_QEMU_BOOT_R34_DENY_ONLY',
            'parent_commit':PARENT,'before_sha256':sha(before),
            'after_sha256':sha(after_record),'lease_sha256':lease_sha,
            'hook_sha256':f8.HOOK_SHA,'ssh_runner_running':True,
            'ftp_running':True,'smb_running':role=='smb',
            'networks_active_and_denied':True,'f11_claims':['prepare','start','started'],
            'traffic_authorized':False,'protocol_tested':False,
            'a5_dispatched':False,'a6':'ND','a7':'NOT_ATTESTED','a9':False,
            'p8_operational':'NO-GO'}
