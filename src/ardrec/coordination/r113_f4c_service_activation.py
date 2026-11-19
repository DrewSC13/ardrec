"""R113-F4C: arranques locales explícitos; probar sockets sin conexiones de red."""
from __future__ import annotations
from ardrec.coordination import r113_f4b_unit_readiness as f4b
from ardrec.coordination import r113_f3_guest_listeners as listeners
import base64

SCHEMA='ardrec-r113-f4c-local-service-start-v1'
ROLES=('ftp','smb')

class GuardError(ValueError):pass

def need(ok,why):
    if not ok:raise GuardError(why)

def command(role,phase):
    need(role in ROLES,'ROLE_INVALID')
    need(phase in ('pre','start','post','socket'),'PHASE_INVALID')
    if phase in ('pre','post'):return f4b.command(role)
    if phase=='start':return ['/usr/bin/systemctl','start',f4b.UNITS[role]]
    return ['/usr/bin/ss','-H','-ltn4']

def checked(role,phase,capture):
    need(type(capture) is dict and capture.get('role')==role and
         capture.get('phase')==phase and capture.get('command')==command(role,phase),
         'CAPTURE_SCOPE_INVALID')
    pid=listeners.started(capture['start'])
    exited,rc,out,err=listeners.status(capture['completion'])
    need(exited and rc==0 and err==b'', 'EXECUTION_NOT_CONFIRMED_'+phase)
    return pid,out

def classify(role,captures):
    need(type(captures) is dict and set(captures)=={'pre','start','post','socket'},
         'CAPTURE_PHASES_INCOMPLETE')
    outputs={}
    for phase in ('pre','start','post','socket'):
        _,outputs[phase]=checked(role,phase,captures[phase])
    before=f4b.classify(role,outputs['pre'])
    need(before['readiness']=='CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION',
         'PRE_START_NOT_CANDIDATE')
    need(outputs['start']==b'','START_UNEXPECTED_STDOUT')
    after=f4b.classify(role,outputs['post'])
    need(after['load_state']=='loaded' and after['active_state']=='active',
         'SERVICE_NOT_ACTIVE_AFTER_START')
    rec={'pid':listeners.started(captures['socket']['start']),
         'status':0,'command':command(role,'socket'),
         'stdout_b64':captures['socket']['completion']['return'].get('out-data',''),
         'stderr_b64':captures['socket']['completion']['return'].get('err-data','')}
    socket=listeners.classify(role,rec)
    state=('ACTIVE_WITH_LAB_IPV4_LISTENER' if socket['local_listener_state']=='LISTENING_ON_LAB_IPV4'
           else 'ACTIVE_WITHOUT_VERIFIED_LAB_IPV4_LISTENER')
    return {'role':role,'unit':f4b.UNITS[role], 'pre':before,'post':after,
            'socket':socket,'outcome':state,'guest_service_started':True,
            'network_connection_attempted':False,'p8_operational':'NO-GO'}
