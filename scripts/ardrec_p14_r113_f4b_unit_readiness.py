#!/usr/bin/env python3
"""R113-F4B: dos consultas QGA local-only, evidencia persistida y replay sin QGA."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path('/home/cicada/ardrec-lab/r113-f4b-unit-readiness-v1')
F4A=Path('/home/cicada/ardrec-lab/r113-f4a-service-inventory-v1/inventory-idg8na42')
F4A_SHA='510b8e729c5bbd73f9cfa8ff6efab22c7d689637b5c5512516e6c738cb090eb8'
ROLES=('ftp','smb')
FILES=('intent.json','before.json','agent_preflight.json',
       'started-ftp.once','capture-ftp.json',
       'started-smb.once','capture-smb.json',
       'after.json','classification.json','receipt.json','manifest.json')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f4b_unit_readiness as core
from ardrec.coordination import r113_f3_guest_listeners as listeners
import ardrec_p14_r113_f4a_service_units as f4a

SCHEMA=core.SCHEMA

def need(ok,why):core.need(ok,why)
def sha(data):return hashlib.sha256(data).hexdigest()
def put(path,obj):return f4a.put(path,obj)
def read(path):return f4a.read(path)
def private(path):return f4a.private(path)

def predecessor():
    private(F4A.parent);private(F4A)
    need(sha((F4A/'manifest.json').read_bytes())==F4A_SHA,'F4A_MANIFEST_CHANGED')
    classification=f4a.verify(F4A)
    need(set(classification)==set(ROLES),'F4A_ROLE_DRIFT')
    for role,unit in core.UNITS.items():
        details=classification[role]['observed'].get(unit,{})
        need('unit-files' in details and
             details['unit-files'].split()[:2]==[unit,'disabled'],
             'F4A_UNIT_NOT_DISABLED_'+role)
    return {'session':str(F4A),'manifest_sha256':F4A_SHA,
            'classification_sha256':sha((F4A/'classification.json').read_bytes())}

def checked_capture(role,capture):
    need(type(capture) is dict and capture.get('role')==role and
         capture.get('command')==core.command(role),'CAPTURE_COMMAND_DRIFT')
    listeners.started(capture['start'])
    exited,rc,out,err=listeners.status(capture['completion'])
    need(exited and rc==0 and err==b'','SYSTEMCTL_SHOW_FAILED_'+role)
    return core.classify(role,out)

def verify(folder):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith('readiness-'),'SESSION_OUT_OF_SCOPE')
    private(ROOT);private(folder)
    need({x.name for x in folder.iterdir()}==set(FILES),'SESSION_FILE_DRIFT')
    man=read(folder/'manifest.json')
    need(man.get('schema')==SCHEMA+'-manifest' and
         man.get('guest_processes')==2 and
         man.get('network_probes')==0 and
         man.get('firewall_mutations')==0 and
         man.get('p8_operational')=='NO-GO','MANIFEST_INVALID')
    need(man.get('files')=={n:sha((folder/n).read_bytes()) for n in FILES if n!='manifest.json'},
         'MANIFEST_FILE_HASH_DRIFT')
    prev=predecessor()
    intent=read(folder/'intent.json')
    need(intent.get('predecessor')==prev and
         intent.get('roles')==list(ROLES) and
         intent.get('commands')=={r:core.command(r) for r in ROLES} and
         intent.get('p8_operational')=='NO-GO','INTENT_DRIFT')
    classifications=read(folder/'classification.json')
    need(set(classifications)==set(ROLES),'CLASSIFICATION_SCOPE_DRIFT')
    for role in ROLES:
        marker=read(folder/f'started-{role}.once')
        need(marker.get('role')==role and
             marker.get('intent_sha256')==sha((folder/'intent.json').read_bytes()),
             'MARKER_CHANGED_'+role)
        classified=checked_capture(role,read(folder/f'capture-{role}.json'))
        need(classifications[role]==classified,'CLASSIFICATION_CHANGED_'+role)
    receipt=read(folder/'receipt.json')
    need(receipt.get('schema')==SCHEMA+'-receipt' and
         receipt.get('predecessor')==prev and
         receipt.get('classification_sha256')==sha((folder/'classification.json').read_bytes()) and
         receipt.get('guest_processes')==2 and
         receipt.get('service_starts')==0 and
         receipt.get('firewall_mutations')==0 and
         receipt.get('p8_operational')=='NO-GO','RECEIPT_DRIFT')
    return classifications

def preflight():
    prev=predecessor()
    _,before,ips,agents=f4a.preflight()
    return prev,before,ips,agents

def capture_one(role):
    command=core.command(role)
    start=f4a.f3t.f3.qga(role,{'execute':'guest-exec','arguments':{
        'path':command[0],'arg':command[1:],'capture-output':True}})
    pid=listeners.started(start)
    for _ in range(40):
        reply=f4a.f3t.f3.qga(role,{'execute':'guest-exec-status',
                                   'arguments':{'pid':pid}})
        if type(reply.get('return')) is dict and reply['return'].get('exited') is True:
            return {'role':role,'command':command,'start':start,'completion':reply}
        listeners.status(reply)
        time.sleep(.25)
    raise core.GuardError('GUEST_EXEC_STATUS_UNCERTAIN_'+role)

def audit():
    prev,before,ips,agents=preflight()
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);private(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='readiness-',dir=ROOT));private(folder)
    put(folder/'intent.json',{
        'schema':SCHEMA+'-intent','utc':datetime.now(timezone.utc).isoformat(),
        'predecessor':prev,'roles':list(ROLES),
        'commands':{role:core.command(role) for role in ROLES},
        'guest_processes_authorized':2,'p8_operational':'NO-GO'})
    put(folder/'before.json',before)
    put(folder/'agent_preflight.json',{'ips':ips,'agents':agents})
    print('R113_F4B_SESSION='+str(folder),flush=True)
    classifications={}
    for role in ROLES:
        put(folder/f'started-{role}.once',{
            'role':role,'intent_sha256':sha((folder/'intent.json').read_bytes())})
        reply=capture_one(role)
        # Persistir la respuesta original antes de interpretarla.
        put(folder/f'capture-{role}.json',reply)
        classified=checked_capture(role,read(folder/f'capture-{role}.json'))
        classifications[role]=classified
        print('R113_F4B_'+role.upper()+'_READINESS='+classified['readiness'],flush=True)
        print('R113_F4B_'+role.upper()+'_ACTIVE='+classified['active_state'],flush=True)
        print('R113_F4B_'+role.upper()+'_LOAD='+classified['load_state'],flush=True)
    put(folder/'after.json',f4a.f3t.f3.live())
    put(folder/'classification.json',classifications)
    put(folder/'receipt.json',{
        'schema':SCHEMA+'-receipt','predecessor':prev,
        'classification_sha256':sha((folder/'classification.json').read_bytes()),
        'guest_processes':2,'service_starts':0,'firewall_mutations':0,
        'p8_operational':'NO-GO'})
    put(folder/'manifest.json',{
        'schema':SCHEMA+'-manifest',
        'files':{n:sha((folder/n).read_bytes()) for n in FILES if n!='manifest.json'},
        'guest_processes':2,'network_probes':0,'firewall_mutations':0,
        'p8_operational':'NO-GO'})
    verify(folder)
    print('R113_F4B_RECEIPT='+str(folder),flush=True)
    print('R113_F4B_MANIFEST_SHA256='+sha((folder/'manifest.json').read_bytes()),flush=True)
    print('R113_F4B_RESULT=LOCAL_READINESS_ATTESTED_NO_SERVICE_START',flush=True)
    print('R113_F4B_P8=NO-GO',flush=True)
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--preflight',action='store_true')
    g.add_argument('--audit',action='store_true')
    g.add_argument('--replay',type=Path)
    p.add_argument('--i-authorize-two-readonly-systemctl-show',action='store_true')
    a=p.parse_args()
    try:
        if a.preflight:
            need(not a.i_authorize_two_readonly_systemctl_show,'INVALID_PREFLIGHT_AUTHORIZATION')
            preflight()
            print('R113_F4B_PREFLIGHT=PASS_F4A_R34_F11_QGA',flush=True)
            print('R113_F4B_GUEST_EXECUTIONS=0',flush=True)
            print('R113_F4B_P8=NO-GO',flush=True)
            return 0
        if a.audit:
            need(a.i_authorize_two_readonly_systemctl_show,
                 'EXPLICIT_TWO_GUEST_QUERY_AUTHORIZATION_REQUIRED')
            return audit()
        need(not a.i_authorize_two_readonly_systemctl_show,'REPLAY_AUTHORIZATION_INVALID')
        f4a.f3t.f3.parent()
        classes=verify(a.replay)
        for role in ROLES:
            print('R113_F4B_'+role.upper()+'_READINESS='+classes[role]['readiness'],flush=True)
        print('R113_F4B_REPLAY=PASS',flush=True)
        print('R113_F4B_P8=NO-GO',flush=True)
        return 0
    except (RuntimeError,ValueError,TypeError,KeyError,OSError,TimeoutError) as exc:
        print('R113_F4B_STOP='+type(exc).__name__+':'+str(exc)[:250],flush=True)
        print('R113_F4B_NO_RETRY_NO_ROLLBACK=TRUE',flush=True)
        print('R113_F4B_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
