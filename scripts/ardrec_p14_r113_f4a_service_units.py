#!/usr/bin/env python3
"""R113-F4A: inventario local systemd FTP/SMB con QGA, 4 guest-exec, cero tráfico.

Huellas, autorizaciones, marcadores y replay. La falta de unidades no prueba falta de software.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path('/home/cicada/ardrec-lab/r113-f4a-service-inventory-v1')
F3T=Path('/home/cicada/ardrec-lab/r113-f3t-ssh-reuse-ftp-smb-v1/recover-eqlue6vf')
F3T_SHA='08ff65f60f3967276e03ef9f47f24ea21ee574e095c0c07f304d91426b63afd0'
SCHEMA='ardrec-r113-f4a-service-units-v1'
ROLES=('ftp','smb')
KINDS=('unit-files','units')
FILE_NAMES=(['intent.json','before.json','agent_preflight.json'] +
            [f'started-{role}-{kind}.once' for role in ROLES for kind in KINDS] +
            [f'capture-{role}-{kind}.json' for role in ROLES for kind in KINDS] +
            ['after.json','classification.json','receipt.json','manifest.json'])
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f4a_service_units as core
from ardrec.coordination import r113_f3_guest_listeners as listeners
import ardrec_p14_r113_f3t_recover_listener as f3t


def need(cond,msg):core.need(cond,msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canon(obj):return (json.dumps(obj,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def put(path,value):return f3t.put(path,value)
def read(path):return f3t.read(path)
def private(path):return f3t.private(path)

def predecessor():
    private(F3T.parent);private(F3T)
    need(sha((F3T/'manifest.json').read_bytes())==F3T_SHA,'F3T_MANIFEST_SHA_CHANGED')
    previous=f3t.verify(F3T)
    need(previous['ssh']['local_listener_state']=='LISTENING_ON_LAB_IPV4' and
         previous['ftp']['local_listener_state']=='NO_LISTENER_AT_EXPECTED_PORT' and
         previous['smb']['local_listener_state']=='NO_LISTENER_AT_EXPECTED_PORT',
         'F3T_LISTENER_CLASSIFICATION_CHANGED')
    return {'session':str(F3T),'manifest_sha256':F3T_SHA,
            'classification_sha256':sha((F3T/'classification.json').read_bytes())}

def validated_capture(role,kind,capture):
    path,args=core.CMDS[kind]
    need(type(capture) is dict and capture.get('role')==role and
         capture.get('kind')==kind and
         capture.get('command')==[path,*args],'CAPTURE_SCOPE_INVALID')
    pid=listeners.started(capture['start'])
    exited,exitcode,stdout,stderr=listeners.status(capture['completion'])
    need(exited and exitcode==0 and stderr==b'',
         'SYSTEMD_EXECUTION_UNCONFIRMED_'+role+'_'+kind)
    return pid,stdout

def verify(folder):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith('inventory-'),'SESSION_SCOPE_INVALID')
    private(ROOT);private(folder)
    need({p.name for p in folder.iterdir()}==set(FILE_NAMES),'SESSION_FILE_SCOPE_INVALID')
    man=read(folder/'manifest.json')
    need(man.get('schema')==SCHEMA+'-manifest' and
         man.get('p8_operational')=='NO-GO' and
         man.get('guest_processes_started')==4 and
         man.get('network_connections')==0 and
         man.get('firewall_changes')==0,'MANIFEST_INVALID')
    expected={name:sha((folder/name).read_bytes()) for name in FILE_NAMES if name!='manifest.json'}
    need(man.get('files')==expected,'RECEIPT_HASH_DRIFT')
    prev=predecessor()
    intent=read(folder/'intent.json')
    receipt=read(folder/'receipt.json')
    classification=read(folder/'classification.json')
    need(intent.get('predecessor')==prev and
         intent.get('scope')==['ftp','smb'] and
         intent.get('commands')=={k:[p,*a] for k,(p,a) in core.CMDS.items()} and
         intent.get('authorized_process_count')==4 and
         intent.get('p8_operational')=='NO-GO',
         'SESSION_INTENT_DRIFT')
    need(man.get('f3t_manifest_sha256')==F3T_SHA and
         receipt.get('f3t_manifest_sha256')==F3T_SHA and
         receipt.get('classification_sha256')==sha((folder/'classification.json').read_bytes()) and
         receipt.get('guest_processes_started')==4 and
         receipt.get('network_connections')==0 and
         receipt.get('firewall_changes')==0 and
         receipt.get('p8_operational')=='NO-GO','SESSION_RECEIPT_DRIFT')
    need(set(classification)==set(ROLES),'CLASSIFICATION_ROLE_DRIFT')
    for role in ROLES:
        payload={}
        for kind in KINDS:
            capture=read(folder/f'capture-{role}-{kind}.json')
            marker=read(folder/f'started-{role}-{kind}.once')
            need(marker.get('role')==role and marker.get('kind')==kind and
                 marker.get('intent_sha256')==sha((folder/'intent.json').read_bytes()),
                 'MARKER_DRIFT_'+role+'_'+kind)
            _,out=validated_capture(role,kind,capture)
            payload[kind]=out
        need(core.inventory(role,payload)==classification[role],
             'CLASSIFICATION_DRIFT_'+role)
    return classification

def preflight():
    f3t.f3.parent();prev=predecessor()
    before=f3t.f3.live()
    ips=f3t.f3.endpoints()
    agents={}
    for role in ROLES:
        reply=f3t.f3.qga(role,{'execute':'guest-info'})
        listeners.agent_info(reply)
        agents[role]=reply
    return prev,before,ips,agents

def audit():
    prev,before,ips,agents=preflight()
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    private(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='inventory-',dir=ROOT));private(folder)
    put(folder/'intent.json',{
        'schema':SCHEMA+'-intent','timestamp_utc':datetime.now(timezone.utc).isoformat(),
        'predecessor':prev,'scope':list(ROLES),
        'commands':{k:[p,*a] for k,(p,a) in core.CMDS.items()},
        'authorized_process_count':4,'p8_operational':'NO-GO'})
    put(folder/'before.json',before)
    put(folder/'agent_preflight.json',{'ips':ips,'agents':agents})
    print('R113_F4A_SESSION='+str(folder),flush=True)
    classifications={}
    for role in ROLES:
        stdout={}
        for kind in KINDS:
            name=f'started-{role}-{kind}.once'
            put(folder/name,{
                'role':role,'kind':kind,
                'intent_sha256':sha((folder/'intent.json').read_bytes())})
            path,args=core.CMDS[kind]
            start=f3t.f3.qga(role,{'execute':'guest-exec','arguments':{
                'path':path,'arg':list(args),'capture-output':True}})
            pid=listeners.started(start)
            completed=None
            for _ in range(20):
                reply=f3t.f3.qga(role,{'execute':'guest-exec-status',
                                       'arguments':{'pid':pid}})
                if type(reply.get('return')) is dict and reply['return'].get('exited') is True:
                    completed=reply;break
                listeners.status(reply)
                time.sleep(.25)
            need(completed is not None,'GUEST_STATUS_TIMEOUT_'+role+'_'+kind)
            put(folder/f'capture-{role}-{kind}.json',{
                'role':role,'kind':kind,'command':[path,*args],
                'start':start,'completion':completed})
            # Los datos originales quedan escritos antes de toda interpretación.
            _,out=validated_capture(role,kind,read(folder/f'capture-{role}-{kind}.json'))
            stdout[kind]=out
        classifications[role]=core.inventory(role,stdout)
        matches=classifications[role]['observed']
        print('R113_F4A_'+role.upper()+'_SYSTEMD_UNITS='+json.dumps(matches,sort_keys=True,ensure_ascii=True),flush=True)
    after=f3t.f3.live()
    put(folder/'after.json',after)
    put(folder/'classification.json',classifications)
    checksum=sha((folder/'classification.json').read_bytes())
    put(folder/'receipt.json',{
        'schema':SCHEMA+'-receipt','classification_sha256':checksum,
        'f3t_manifest_sha256':F3T_SHA,'guest_processes_started':4,
        'network_connections':0,'firewall_changes':0,'p8_operational':'NO-GO'})
    put(folder/'manifest.json',{
        'schema':SCHEMA+'-manifest','f3t_manifest_sha256':F3T_SHA,
        'files':{name:sha((folder/name).read_bytes()) for name in FILE_NAMES if name!='manifest.json'},
        'guest_processes_started':4,'network_connections':0,
        'firewall_changes':0,'p8_operational':'NO-GO'})
    verify(folder)
    print('R113_F4A_RECEIPT='+str(folder),flush=True)
    print('R113_F4A_MANIFEST_SHA256='+sha((folder/'manifest.json').read_bytes()),flush=True)
    print('R113_F4A_R34=DENY_PRESERVED',flush=True)
    print('R113_F4A_PROTOCOL_TESTS=NOT_EXECUTED',flush=True)
    print('R113_F4A_P8=NO-GO',flush=True)
    return 0

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--preflight',action='store_true')
    group.add_argument('--audit',action='store_true')
    group.add_argument('--replay',type=Path)
    parser.add_argument('--i-authorize-four-local-systemctl-queries',action='store_true')
    a=parser.parse_args()
    try:
        if a.preflight:
            need(not a.i_authorize_four_local_systemctl_queries,'PREFLIGHT_CANNOT_AUTHORIZE')
            preflight()
            print('R113_F4A_PREFLIGHT=PASS_F3T_QGA_R34',flush=True)
            print('R113_F4A_GUEST_EXECUTIONS=0',flush=True)
            print('R113_F4A_P8=NO-GO',flush=True)
            return 0
        if a.audit:
            need(a.i_authorize_four_local_systemctl_queries,'EXPLICIT_GUEST_EXEC_AUTHORIZATION_REQUIRED')
            return audit()
        need(not a.i_authorize_four_local_systemctl_queries,'REPLAY_NO_AUTHORIZATION')
        f3t.f3.parent()
        classifications=verify(a.replay)
        for role in ROLES:
            print('R113_F4A_'+role.upper()+'_SYSTEMD_UNITS='+
                  json.dumps(classifications[role]['observed'],sort_keys=True,ensure_ascii=True))
        print('R113_F4A_REPLAY=PASS',flush=True)
        print('R113_F4A_P8=NO-GO',flush=True)
        return 0
    except (RuntimeError,ValueError,KeyError,TypeError,OSError,TimeoutError) as exc:
        print('R113_F4A_STOP='+type(exc).__name__+':'+str(exc)[:250],flush=True)
        print('R113_F4A_ACTION=NO_RETRY_NO_AUTO_CLEANUP',flush=True)
        print('R113_F4A_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
