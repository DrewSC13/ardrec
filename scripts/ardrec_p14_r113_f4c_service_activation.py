#!/usr/bin/env python3
"""R113-F4C: iniciar únicamente una unidad autorizada y verificar su socket local.

No modifica R34, XML, redes, filtros ni servicios auxiliares; no genera conexiones.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path('/home/cicada/ardrec-lab/r113-f4c-service-activation-v1')
PREVIOUS=Path('/home/cicada/ardrec-lab/r113-f4b-unit-readiness-v1/readiness-h1asomyk')
PREVIOUS_SHA='dd8377392b03c1f15f1a907483b65c5d63145837310e69a4f328bf62431b2924'
FILES=('intent.json','preflight.json','before.json','pre.json',
       'started-start.once','start.json','post.json','socket.json',
       'after.json','classification.json','receipt.json','manifest.json')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f4c_service_activation as core
from ardrec.coordination import r113_f3_guest_listeners as listener
import ardrec_p14_r113_f4b_unit_readiness as f4b

def need(ok,reason):core.need(ok,reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,obj):return f4b.put(path,obj)
def read(path):return f4b.read(path)
def private(path):return f4b.private(path)

def predecessor(role):
    need(role in core.ROLES,'ROLE_INVALID')
    private(PREVIOUS.parent);private(PREVIOUS)
    need(sha((PREVIOUS/'manifest.json').read_bytes())==PREVIOUS_SHA,
         'F4B_ORIGINAL_MANIFEST_CHANGED')
    outcomes=f4b.verify(PREVIOUS)
    need(set(outcomes)==set(core.ROLES),'F4B_ROLE_DRIFT')
    need(all(outcomes[r]['readiness']=='CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION'
             and outcomes[r]['active_state']=='inactive' for r in core.ROLES),
         'F4B_READINESS_NOT_CANDIDATE')
    return {'session':str(PREVIOUS), 'sha256':PREVIOUS_SHA,
            'class_sha256':sha((PREVIOUS/'classification.json').read_bytes())}

def preflight(role):
    f4b.f4a.f3t.f3.parent()  # Rama, HEAD firmado, árbol limpio.
    predecessor_record=predecessor(role)
    prev,before,ips,agents=f4b.preflight()  # QGA guest-info + F11/R34 + IP.
    need(prev['manifest_sha256']==f4b.F4A_SHA,'F4A_SOURCE_DRIFT')
    return predecessor_record,before,{'ips':ips,'agents':agents}

def capture(role,phase):
    cmd=core.command(role,phase)
    reply=f4b.f4a.f3t.f3.qga(role,{'execute':'guest-exec','arguments':{
        'path':cmd[0],'arg':cmd[1:],'capture-output':True}})
    pid=listener.started(reply)
    for _ in range(80):
        status=f4b.f4a.f3t.f3.qga(role,{'execute':'guest-exec-status',
                                         'arguments':{'pid':pid}})
        if type(status.get('return')) is dict and status['return'].get('exited') is True:
            return {'role':role,'phase':phase,'command':cmd,
                    'start':reply,'completion':status}
        listener.status(status)
        time.sleep(0.25)
    raise core.GuardError('QGA_RESULT_UNCERTAIN_'+phase)

def verify(folder):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith(('ftp-','smb-')),'SESSION_SCOPE_INVALID')
    private(ROOT);private(folder)
    need({p.name for p in folder.iterdir()}==set(FILES),'SESSION_FILES_CHANGED')
    manifest=read(folder/'manifest.json')
    need(manifest.get('schema')==core.SCHEMA+'-manifest' and
         manifest.get('files')=={name:sha((folder/name).read_bytes())
                                 for name in FILES if name!='manifest.json'},
         'MANIFEST_FILE_DRIFT')
    intent=read(folder/'intent.json')
    role=intent.get('role')
    need(role in core.ROLES and folder.name.startswith(role+'-'), 'SESSION_ROLE_CHANGED')
    prev=predecessor(role)
    need(intent.get('predecessor')==prev and
         intent.get('command_scope')=={k:core.command(role,k)
                 for k in ('pre','start','post','socket')} and
         intent.get('p8_operational')=='NO-GO', 'INTENT_CHANGED')
    marker=read(folder/'started-start.once')
    need(marker.get('role')==role and
         marker.get('intent_sha256')==sha((folder/'intent.json').read_bytes()),
         'START_MARKER_CHANGED')
    captures={phase:read(folder/(phase+'.json'))
              for phase in ('pre','start','post','socket')}
    classified=core.classify(role,captures)
    need(classified==read(folder/'classification.json'),'CLASSIFICATION_CHANGED')
    receipt=read(folder/'receipt.json')
    need(receipt.get('schema')==core.SCHEMA+'-receipt' and
         receipt.get('predecessor')==prev and
         receipt.get('classification_sha256')==sha((folder/'classification.json').read_bytes()) and
         receipt.get('unit')==core.f4b.UNITS[role] and
         receipt.get('service_starts')==1 and
         receipt.get('network_connections')==0 and
         receipt.get('firewall_changes')==0 and
         receipt.get('p8_operational')=='NO-GO', 'RECEIPT_CHANGED')
    need(manifest.get('predecessor_manifest_sha256')==PREVIOUS_SHA and
         manifest.get('service_starts')==1 and
         manifest.get('network_connections')==0 and
         manifest.get('p8_operational')=='NO-GO','MANIFEST_SCOPE_CHANGED')
    return classified

def activate(role):
    prev,before,agents=preflight(role)
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);private(ROOT)
    folder=Path(tempfile.mkdtemp(prefix=role+'-',dir=ROOT));private(folder)
    put(folder/'intent.json',{
        'schema':core.SCHEMA+'-intent','utc':datetime.now(timezone.utc).isoformat(),
        'role':role,'unit':core.f4b.UNITS[role], 'predecessor':prev,
        'command_scope':{p:core.command(role,p) for p in ('pre','start','post','socket')},
        'authorized_service_starts':1,'p8_operational':'NO-GO'})
    put(folder/'preflight.json',agents)
    put(folder/'before.json',before)
    print('R113_F4C_SESSION='+str(folder),flush=True)
    print('R113_F4C_TARGET='+role.upper(),flush=True)
    # Estado de systemd ACTUAL, no solo recibo histórico F4B.
    prior=capture(role,'pre')
    put(folder/'pre.json',prior)
    _,prior_bytes=core.checked(role,'pre',read(folder/'pre.json'))
    need(core.f4b.classify(role,prior_bytes)['readiness']==
         'CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION','CURRENT_UNIT_NOT_CANDIDATE')
    # Marcador duradero ANTES del único systemctl start; no reintentar automáticamente.
    put(folder/'started-start.once',{
        'role':role,'intent_sha256':sha((folder/'intent.json').read_bytes())})
    start=capture(role,'start')
    put(folder/'start.json',start)
    core.checked(role,'start',read(folder/'start.json'))
    # Verificación local: estado activo + socket, no conexión entre VM.
    post=capture(role,'post')
    put(folder/'post.json',post)
    core.checked(role,'post',read(folder/'post.json'))
    socket=capture(role,'socket')
    put(folder/'socket.json',socket)
    core.checked(role,'socket',read(folder/'socket.json'))
    after=f4b.f4a.f3t.f3.live()  # R34 DENY + F11 intactos + 4 VM activas.
    put(folder/'after.json',after)
    classifications={p:read(folder/(p+'.json')) for p in ('pre','start','post','socket')}
    result=core.classify(role,classifications)
    put(folder/'classification.json',result)
    put(folder/'receipt.json',{
        'schema':core.SCHEMA+'-receipt','predecessor':prev,
        'unit':core.f4b.UNITS[role],
        'classification_sha256':sha((folder/'classification.json').read_bytes()),
        'service_starts':1,'network_connections':0,
        'firewall_changes':0,'p8_operational':'NO-GO'})
    put(folder/'manifest.json',{
        'schema':core.SCHEMA+'-manifest',
        'files':{name:sha((folder/name).read_bytes()) for name in FILES if name!='manifest.json'},
        'predecessor_manifest_sha256':PREVIOUS_SHA,
        'service_starts':1,'network_connections':0,'p8_operational':'NO-GO'})
    verify(folder)
    print('R113_F4C_ROLE='+role.upper(),flush=True)
    print('R113_F4C_UNIT_ACTIVE=YES',flush=True)
    print('R113_F4C_LISTENER='+result['socket']['local_listener_state'],flush=True)
    print('R113_F4C_OUTCOME='+result['outcome'],flush=True)
    print('R113_F4C_RECEIPT='+str(folder),flush=True)
    print('R113_F4C_MANIFEST_SHA256='+sha((folder/'manifest.json').read_bytes()),flush=True)
    print('R113_F4C_R34=DENY_PRESERVED',flush=True)
    print('R113_F4C_P8=NO-GO',flush=True)
    return 0

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--preflight',action='store_true')
    modes.add_argument('--activate',action='store_true')
    modes.add_argument('--replay',type=Path)
    parser.add_argument('--role',choices=core.ROLES)
    parser.add_argument('--i-authorize-one-real-guest-service-start',action='store_true')
    opts=parser.parse_args()
    try:
        if opts.replay is not None:
            need(opts.role is None and not opts.i_authorize_one_real_guest_service_start,
                 'REPLAY_ARGS_INVALID')
            f4b.f4a.f3t.f3.parent()
            result=verify(opts.replay)
            print('R113_F4C_REPLAY=PASS_'+result['role'].upper(),flush=True)
            print('R113_F4C_OUTCOME='+result['outcome'],flush=True)
            print('R113_F4C_P8=NO-GO',flush=True)
            return 0
        need(opts.role in core.ROLES,'ROLE_REQUIRED')
        if opts.preflight:
            need(not opts.i_authorize_one_real_guest_service_start,'PREFLIGHT_WITH_AUTH')
            preflight(opts.role)
            print('R113_F4C_PREFLIGHT=PASS_'+opts.role.upper()+'_R34_DENY',flush=True)
            print('R113_F4C_SERVICE_STARTS=0',flush=True)
            print('R113_F4C_P8=NO-GO',flush=True)
            return 0
        need(opts.i_authorize_one_real_guest_service_start,
             'EXPLICIT_ONE_SERVICE_START_AUTHORIZATION_REQUIRED')
        return activate(opts.role)
    except (RuntimeError,ValueError,TypeError,KeyError,OSError,TimeoutError) as exc:
        print('R113_F4C_STOP='+type(exc).__name__+':'+str(exc)[:200],flush=True)
        print('R113_F4C_ACTION=NO_RETRY_NO_AUTOMATIC_ROLLBACK',flush=True)
        print('R113_F4C_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':raise SystemExit(main())
