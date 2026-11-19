"""R113-F4B: interpretar systemctl show sin iniciar servicios ni inferir conectividad."""
from __future__ import annotations
from pathlib import PurePosixPath

SCHEMA = 'ardrec-r113-f4b-service-readiness-v1'
UNITS = {'ftp': 'vsftpd.service', 'smb': 'smbd.service'}
KEYS = ('Id','LoadState','ActiveState','SubState','UnitFileState',
        'FragmentPath','ExecStart','Result')
ALLOWED_CMD = ('/usr/bin/systemctl','show','--no-pager',
               '--property='+','.join(KEYS))

class GuardError(ValueError): pass

def need(ok,reason):
    if not ok: raise GuardError(reason)

def command(role):
    need(role in UNITS, 'ROLE_NOT_ALLOWED')
    return list(ALLOWED_CMD + (UNITS[role],))

def classify(role, output:bytes)->dict:
    need(role in UNITS,'ROLE_NOT_ALLOWED')
    need(type(output) is bytes and len(output)<=48000, 'OUTPUT_NOT_BOUNDED')
    try: lines=output.decode('utf-8','strict').splitlines()
    except UnicodeDecodeError as exc: raise GuardError('ENCODING_INVALID') from exc
    props={}
    for line in lines:
        need(len(line)<=8192 and '=' in line, 'SYSTEMCTL_SHOW_INVALID_LINE')
        key,value=line.split('=',1)
        need(key in KEYS and key not in props,'SYSTEMCTL_PROPERTY_INVALID_OR_DUPLICATE')
        props[key]=value
    need(set(props)==set(KEYS),'SYSTEMCTL_PROPERTIES_INCOMPLETE')
    need(props['Id']==UNITS[role], 'SYSTEMCTL_UNIT_CHANGED')
    need(props['ActiveState'] in ('inactive','active','failed','activating','deactivating'),
         'SYSTEMCTL_ACTIVE_STATE_INVALID')
    need(props['LoadState'] in ('loaded','not-found','masked','error'),
         'SYSTEMCTL_LOAD_STATE_INVALID')
    need(props['UnitFileState'] in ('enabled','disabled','masked','static','generated','linked','indirect','alias','bad',''),
         'SYSTEMCTL_UNIT_FILE_STATE_INVALID')
    fragment=props['FragmentPath']
    if fragment:
        parts=PurePosixPath(fragment)
        need(parts.is_absolute() and '..' not in parts.parts and '\x00' not in fragment,
             'SYSTEMCTL_FRAGMENT_UNSAFE')
    can_start=(props['LoadState']=='loaded' and
               props['ActiveState']=='inactive' and
               props['SubState'] in ('dead','exited') and
               props['UnitFileState'] in ('disabled','enabled') and
               bool(fragment) and bool(props['ExecStart']))
    if can_start: state='CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION'
    elif props['ActiveState']=='active': state='ALREADY_ACTIVE_RECHECK_LISTENER'
    elif props['ActiveState']=='failed': state='FAILED_REQUIRES_DIAGNOSIS'
    else: state='BLOCKED_OR_INCONCLUSIVE'
    return {
        'role':role,'unit':UNITS[role],
        'load_state':props['LoadState'],
        'active_state':props['ActiveState'],
        'sub_state':props['SubState'],
        'unit_file_state':props['UnitFileState'],
        'fragment_path':fragment,
        'exec_start_declared':bool(props['ExecStart']),
        'unit_result':props['Result'],
        'readiness':state,
        'config_validated':False,
        'guest_service_started':False,
        'protocol_connectivity_proven':False,
        'p8_operational':'NO-GO',
    }
