"""R112-F11N: pure, fail-closed post-reboot R33 network reconciliation.

No traffic authorization; no VM boot. All evidence is read from actual host probes.
"""
from __future__ import annotations
import hashlib
import json
import xml.etree.ElementTree as ET

from ardrec.coordination import r112_f8_ssh_positive_boot as f8
from ardrec.coordination import r112_runner_nic_definition as nic

SCHEMA='ardrec-r112-f11n-postreboot-network-recovery-v1'
PARENT='351d1912edaecac7208601de5666a08a0aec709f'
NETWORKS=('ssh','ftp','smb')
ROLES=('ssh','runner','ftp','smb')
HOOK_SHA=f8.HOOK_SHA

class Stop(ValueError): pass

def need(ok,reason):
    if not ok: raise Stop(reason)

def canon(obj):
    return json.dumps(obj,ensure_ascii=True,sort_keys=True,allow_nan=False,
                      separators=(',',':')).encode('ascii')+b'\n'

def sha(obj): return hashlib.sha256(canon(obj)).hexdigest()

def network_states(record,legacy,f4):
    need(type(record) is dict and set(record)=={'snapshot','english_info','other_domains'},
         'SNAPSHOT_TOP_LEVEL')
    snap=record['snapshot']
    need(type(snap) is dict and set(snap)=={'schema','commands','probes','summary'}
         and snap['schema']==legacy.SCHEMA
         and snap['commands']=={key:list(value) for key,value in legacy.command_list().items()}
         and len(snap['probes'])==29 and set(snap['probes'])==set(snap['commands'])
         and snap['summary']==legacy.summarize(snap['probes']),
         'HOST_PROBES_NOT_REPRODUCIBLE')
    need(all(type(p) is dict and p.get('rc')==0 and p.get('timeout') is False
             and p.get('truncated') is False for p in snap['probes'].values()),
         'HOST_READ_INCOMPLETE')
    need(snap['summary']['hook_sha256']==HOOK_SHA and
         snap['summary']['nft_rule_count']==4 and
         snap['summary']['p8_operational']=='NO-GO', 'HOOK_OR_R34_NOT_PINNED')
    hook_stat=snap['probes']['f11-hook-stat']['stdout'].strip().split()
    need(len(hook_stat)==4 and hook_stat[0]=='0:0' and hook_stat[1]=='755'
         and hook_stat[2].isdigit() and int(hook_stat[2])>0
         and hook_stat[3]=='/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny',
         'HOOK_OWNER_MODE_OR_PATH_DRIFT')
    for role in ROLES:
        need(f8._vm_state(record,role)=='SHUTOFF','VM_NOT_SHUTOFF_'+role)
        nic.validate_domain(snap['probes'][f'vm-{role}-inactive-xml']['stdout'],role,
                            configured=role=='runner')
    for role in NETWORKS:
        nic._safe_net(snap['probes'][f'net-{role}-xml']['stdout'],role)
        root=ET.fromstring(snap['probes'][f'net-{role}-xml']['stdout'])
        need(root.find('forward') is None and root.find('ip') is None and
             root.find('dhcp') is None and root.get('ipv6') in (None,'no'),
             'NETWORK_L3_DRIFT_'+role)
    xml=ET.fromstring(snap['probes']['deny-nwfilter-xml']['stdout'])
    rules=xml.findall('rule')
    need(xml.tag=='filter' and xml.get('name')==nic.FILTER and len(rules)==1
         and rules[0].get('action')=='drop' and rules[0].get('direction')=='inout'
         and rules[0].find('all') is not None,'NWFILTER_NOT_DENY')
    nic._nft_structure(snap['probes']['r34-nft']['stdout'])
    for unit in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        need(snap['summary']['systemd'][unit]['ActiveState']=='active',
             'SYSTEMD_NOT_ACTIVE_'+unit)
    extras=record['other_domains']
    need(type(extras) is dict and extras.get('status')=='NO_UNRELATED_R33_NET_ATTACHMENTS'
         and extras.get('inspected') is True,'OTHER_DOMAINS_NOT_ATTESTED')
    need(set(record['english_info'])==set(NETWORKS),'NETWORK_INFO_SCOPE')
    states={}
    for role in NETWORKS:
        item=record['english_info'][role]
        need(item['rc']==0 and item['timeout'] is False and item['truncated'] is False,
             'NET_INFO_COMMAND_FAILED_'+role)
        states[role]=f4.core.parse_net_info(item['stdout'],role)
    return states

def compare(before,after,activated,legacy,f4):
    need(tuple(activated)==NETWORKS[:len(activated)],'NETWORK_START_ORDER_CHANGED')
    need(network_states(before,legacy,f4)==dict.fromkeys(NETWORKS,'INACTIVE'),
         'PLAN_BASE_NOT_ALL_INACTIVE')
    expect={r:('ACTIVE' if r in activated else 'INACTIVE') for r in NETWORKS}
    need(network_states(after,legacy,f4)==expect,'NETWORK_STATE_DRIFT')
    a,b=before['snapshot']['probes'],after['snapshot']['probes']
    stable=([f'vm-{r}-{field}' for r in ROLES for field in ('state','inactive-xml','block')]
           +['f11-hook-hash','f11-hook-stat','deny-nwfilter-xml'])
    for key in stable:
        need(a[key]['stdout']==b[key]['stdout'],'STATIC_RESOURCE_DRIFT_'+key)
    for r in NETWORKS:
        k='net-'+r+'-xml'
        need(f8._r112_f8_static_network_xml(a[k]['stdout'])==
             f8._r112_f8_static_network_xml(b[k]['stdout']),
             'STATIC_NETWORK_XML_DRIFT_'+r)
    need(before['other_domains']==after['other_domains'],'UNRELATED_SCOPE_CHANGED')
    need(nic._nft_structure(a['r34-nft']['stdout'])==
         nic._nft_structure(b['r34-nft']['stdout']),'R34_STRUCTURE_CHANGED')
    return True

def verify_steps(before,steps,legacy,f4):
    need(type(steps) is list and len(steps)==3,'STEP_COUNT')
    for i,(step,role) in enumerate(zip(steps,NETWORKS),1):
        need(type(step) is dict and set(step)=={'role','command','after'} and
             step['role']==role,'STEP_SCHEMA')
        result=step['command']
        need(type(result) is dict and result.get('rc')==0 and
             result.get('timeout') is False and result.get('truncated') is False,
             'NET_START_NOT_ATTESTED_'+role)
        compare(before,step['after'],NETWORKS[:i],legacy,f4)
    return {'schema':SCHEMA+'-receipt','before_sha256':sha(before),
            'after_sha256':sha(steps[-1]['after']),
            'networks_active':list(NETWORKS),'network_start_count':3,
            'guest_start_count':0,'f11_hook':HOOK_SHA,'r34':'DENY_UNCHANGED',
            'traffic_authorized':False,'protocol_tested':False,
            'a6':'ND','p8_operational':'NO-GO'}
