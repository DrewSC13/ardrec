#!/usr/bin/env python3
"""R113-F3T: recuperar captura SSH inmutable; inspeccionar SOLO FTP/SMB por QGA.

No abre tráfico ni modifica firewall. Sin reintentos automáticos de guest-exec.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ROOT=Path('/home/cicada/ardrec-lab/r113-f3t-ssh-reuse-ftp-smb-v1')
PREVIOUS=Path('/home/cicada/ardrec-lab/r113-f3-guest-listeners-v1/inspect-9nl15krt')
PREVIOUS_HASHES={
    'agent_preflight.json':'a8adb39f21b020628fa95852345dd933f8eeea776dfc10778f0d95cae84227d4',
    'before.json':'f62e8e693e7e945724490b5d505c0d9fed12da72316d9ae2c800571493527d58',
    'capture-ssh.json':'64cec801d60ab9fbcb4e675153e7157994d09f35bbebff2bbe64578e26b657cd',
    'intent.json':'a6734adb610f86a12160400f5173642f3b35f511be140b1acf8cb2c45eecd80d',
    'started-ssh.once':'49d6ad5f1f0bd2fd4b4e329d05869d2e691af42cabbe9dac19da4771a0c7bcd4',
}
SSH_STDOUT_HASH='6a8b61d6c5fe645829d978a00d13bbdfa8550b3634fad211df11ee152de646fc'
SCHEMA='ardrec-p14-r113-f3t-ssh-reuse-v1'
ROLES=('ftp','smb')
FILES=('intent.json','before.json','agent_preflight.json','started-ftp.once',
       'started-smb.once','capture-ftp.json','capture-smb.json','after.json',
       'classification.json','receipt.json','manifest.json')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f3_guest_listeners as core
import ardrec_p14_r113_f3_guest_listeners as f3


def need(value, reason):core.need(value,reason)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canon(o):return (json.dumps(o,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def put(path, data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canon(data));stream.flush();os.fsync(stream.fileno())
def read(path):return f3.get(path)
def private(path):return f3.private(path)


def recover_ssh():
    """Reusar solo evidencia SSH original, sin QGA, sin reinterpretar incidentes fallidos."""
    private(PREVIOUS.parent)
    private(PREVIOUS)
    need({p.name for p in PREVIOUS.iterdir()}==set(PREVIOUS_HASHES),
         'F3R_INCIDENT_FILE_SCOPE_CHANGED')
    for filename,digest in PREVIOUS_HASHES.items():
        need(sha((PREVIOUS/filename).read_bytes())==digest,
             'F3R_INCIDENT_SHA_CHANGED_'+filename)
    incident=f3.previous_incident()  # F3 original: lectura estricta, sin mutación
    old_intent=read(PREVIOUS/'intent.json')
    need(old_intent.get('previous_incident')==incident,
         'F3R_FIRST_INCIDENT_LINK_CHANGED')
    need(old_intent.get('scope')==['ssh','ftp','smb'] and
         old_intent.get('p8_operational')=='NO-GO',
         'F3R_INTENT_NOT_AUTHORITATIVE')
    marker=read(PREVIOUS/'started-ssh.once')
    need(marker.get('role')=='ssh' and
         marker.get('intent_sha256')==PREVIOUS_HASHES['intent.json'],
         'F3R_SSH_MARKER_CHANGED')
    capture=read(PREVIOUS/'capture-ssh.json')
    need(capture.get('role')=='ssh' and
         capture.get('command')==['/usr/bin/ss','-H','-ltn4'],
         'F3R_SSH_COMMAND_CHANGED')
    pid=core.started(capture['start'])
    exited,rc,out,err=core.status(capture['completion'])
    need(exited and rc==0 and err==b'' and sha(out)==SSH_STDOUT_HASH,
         'F3R_SSH_OUTPUT_CHANGED')
    record={'pid':pid,'status':rc,'command':capture['command'],
            'stdout_b64':capture['completion']['return'].get('out-data',''),
            'stderr_b64':capture['completion']['return'].get('err-data','')}
    result=core.classify('ssh',record)
    need(result['local_listener_state']=='LISTENING_ON_LAB_IPV4' and
         result['bound_ipv4']==['0.0.0.0'] and
         result['observed_ipv4_socket_count']==4 and
         result['network_reachability_proven'] is False,
         'F3R_SSH_LISTENER_NOT_CONFIRMED')
    return {'source_session':str(PREVIOUS),'source_file':'capture-ssh.json',
            'source_sha256':PREVIOUS_HASHES['capture-ssh.json'],
            'source_stdout_sha256':SSH_STDOUT_HASH,
            'source_incident_fingerprint':sha(canon(PREVIOUS_HASHES)),
            'original_f3_fingerprint':incident['fingerprint_sha256']},result


def classify_capture(role, capture):
    need(capture.get('role')==role and
         capture.get('command')==['/usr/bin/ss','-H','-ltn4'],
         'CAPTURE_ROLE_OR_COMMAND_DRIFT_'+role)
    pid=core.started(capture['start'])
    exited,rc,out,err=core.status(capture['completion'])
    need(exited and rc==0 and err==b'', 'CAPTURE_EXECUTION_NOT_CLEAN_'+role)
    ret=capture['completion']['return']
    record={'pid':pid,'status':rc,'command':capture['command'],
            'stdout_b64':ret.get('out-data',''),
            'stderr_b64':ret.get('err-data','')}
    return core.classify(role,record)


def verify(folder):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith('recover-'), 'RECOVERY_PATH_OUTSIDE_SCOPE')
    private(ROOT);private(folder)
    need({p.name for p in folder.iterdir()}==set(FILES),'RECOVERY_FILES_CHANGED')
    man=read(folder/'manifest.json')
    need(man.get('schema')==SCHEMA+'-manifest' and
         man.get('p8_operational')=='NO-GO' and
         man.get('guest_processes_started')==2 and
         man.get('network_connections')==0 and
         man.get('firewall_changes')==0,'RECOVERY_MANIFEST_INVALID')
    actual={name:sha((folder/name).read_bytes()) for name in FILES if name!='manifest.json'}
    need(man.get('files')==actual,'RECOVERY_MANIFEST_HASH_MISMATCH')
    intent=read(folder/'intent.json')
    prev,ssh=recover_ssh()
    need(intent.get('ssh_provenance')==prev and
         intent.get('scope')==list(ROLES) and
         intent.get('authorized_guest_processes')==2 and
         intent.get('p8_operational')=='NO-GO',
         'RECOVERY_PREDECESSOR_CHANGED')
    receipt=read(folder/'receipt.json')
    classification=read(folder/'classification.json')
    need(set(classification)=={'ssh','ftp','smb'} and
         classification['ssh']==ssh,'REPLAY_SSH_DRIFT')
    for role in ROLES:
        capture=read(folder/('capture-'+role+'.json'))
        marker=read(folder/('started-'+role+'.once'))
        need(marker.get('role')==role and
             marker.get('intent_sha256')==sha((folder/'intent.json').read_bytes()),
             'REPLAY_MARKER_DRIFT_'+role)
        need(classify_capture(role,capture)==classification[role],
             'REPLAY_CAPTURE_DRIFT_'+role)
    need(receipt.get('schema')==SCHEMA+'-receipt' and
         receipt.get('classification_sha256')==sha((folder/'classification.json').read_bytes()) and
         receipt.get('guest_processes_started')==2 and
         receipt.get('ssh_guest_processes_reexecuted')==0 and
         receipt.get('network_connections')==0 and
         receipt.get('firewall_changes')==0 and
         receipt.get('p8_operational')=='NO-GO' and
         receipt.get('ssh_source_sha256')==prev['source_sha256'],
         'RECOVERY_RECEIPT_DRIFT')
    need(man.get('ssh_source_sha256')==prev['source_sha256'] and
         man.get('classification_sha256')==receipt['classification_sha256'],
         'RECOVERY_MANIFEST_LINK_DRIFT')
    # Vinculamos la prueba de identidad real de F2, sin solicitar datos nuevos de red.
    f3.origin()
    return classification


def inspect():
    f3.parent();f3.origin()
    # Se valida la captura SSH previa antes de cualquier consulta QGA.
    provenance,ssh=recover_ssh()
    before=f3.live()  # R34 DENY + F11 + todas las VM activas
    ips=f3.endpoints()
    agent_info={}
    for role in ROLES:
        response=f3.qga(role,{'execute':'guest-info'})
        core.agent_info(response)
        agent_info[role]=response
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);private(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='recover-',dir=ROOT));private(folder)
    put(folder/'intent.json',{
        'schema':SCHEMA+'-intent','utc':datetime.now(timezone.utc).isoformat(),
        'ssh_provenance':provenance,'scope':list(ROLES),
        'authorized_guest_processes':2,'approved_binary':'/usr/bin/ss',
        'approved_arguments':['-H','-ltn4'],
        'p8_operational':'NO-GO'})
    put(folder/'before.json',before)
    put(folder/'agent_preflight.json',{'ip_identities':ips,'guest_info':agent_info})
    print('R113_F3T_RECOVERY_SESSION='+str(folder),flush=True)
    print('R113_F3T_SSH=REUSED_FROM_SHA256_VERIFIED_QGA_CAPTURE',flush=True)
    print('R113_F3T_SSH_LISTENER='+ssh['local_listener_state'],flush=True)
    classified={'ssh':ssh}
    for role in ROLES:
        # El marcador se sincroniza antes de guest-exec; jamás repetir automáticamente.
        put(folder/('started-'+role+'.once'),{
            'role':role,'intent_sha256':sha((folder/'intent.json').read_bytes())})
        start=f3.qga(role,{'execute':'guest-exec','arguments':{
            'path':'/usr/bin/ss','arg':['-H','-ltn4'],'capture-output':True}})
        pid=core.started(start)
        complete=None
        for _ in range(12):
            response=f3.qga(role,{'execute':'guest-exec-status',
                                  'arguments':{'pid':pid}})
            if type(response.get('return')) is dict and response['return'].get('exited') is True:
                complete=response;break
            core.status(response)
            time.sleep(0.2)
        need(complete is not None,'GUEST_EXEC_COMPLETION_UNCERTAIN_'+role)
        put(folder/('capture-'+role+'.json'),{
            'role':role,'command':['/usr/bin/ss','-H','-ltn4'],
            'start':start,'completion':complete})
        # Captura ORIGINAL persistida antes de evaluar: cualquier fallo deja evidencia.
        classified[role]=classify_capture(role,read(folder/('capture-'+role+'.json')))
        print('R113_F3T_'+role.upper()+'_LISTENER='+classified[role]['local_listener_state'],flush=True)
    after=f3.live()
    put(folder/'after.json',after)
    put(folder/'classification.json',classified)
    classification_sha=sha((folder/'classification.json').read_bytes())
    put(folder/'receipt.json',{
        'schema':SCHEMA+'-receipt','classification_sha256':classification_sha,
        'ssh_source_sha256':provenance['source_sha256'],
        'guest_processes_started':2,'ssh_guest_processes_reexecuted':0,
        'network_connections':0,'firewall_changes':0,'p8_operational':'NO-GO'})
    put(folder/'manifest.json',{
        'schema':SCHEMA+'-manifest','utc':datetime.now(timezone.utc).isoformat(),
        'files':{name:sha((folder/name).read_bytes()) for name in FILES if name!='manifest.json'},
        'ssh_source_sha256':provenance['source_sha256'],
        'classification_sha256':classification_sha,
        'guest_processes_started':2,'network_connections':0,
        'firewall_changes':0,'p8_operational':'NO-GO'})
    verify(folder)
    print('R113_F3T_RECEIPT='+str(folder),flush=True)
    print('R113_F3T_MANIFEST_SHA256='+sha((folder/'manifest.json').read_bytes()),flush=True)
    print('R113_F3T_GUEST_EXECUTIONS=2_FTP_SMB_ONLY',flush=True)
    print('R113_F3T_PROTOCOL_CONNECTIVITY=NOT_TESTED',flush=True)
    print('R113_F3T_R34=DENY_PRESERVED',flush=True)
    print('R113_F3T_P8=NO-GO',flush=True)
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--inspect',action='store_true')
    g.add_argument('--replay',type=Path)
    g.add_argument('--verify-ssh-source',action='store_true')
    p.add_argument('--i-authorize-two-new-ftp-smb-local-inspections',action='store_true')
    args=p.parse_args()
    try:
        if args.verify_ssh_source:
            need(not args.i_authorize_two_new_ftp_smb_local_inspections,
                 'SSH_SOURCE_CHECK_NO_AUTHORIZATION_ALLOWED')
            f3.parent();f3.origin()
            provenance,listener=recover_ssh()
            print('R113_F3T_SSH_FORENSIC=PASS_SOURCE_SHA256_VERIFIED')
            print('R113_F3T_SSH_SOURCE_SHA256='+provenance['source_sha256'])
            print('R113_F3T_SSH_LISTENER='+listener['local_listener_state'])
            print('R113_F3T_GUEST_EXECUTIONS=0')
            print('R113_F3T_P8=NO-GO')
            return 0
        if args.inspect:
            need(args.i_authorize_two_new_ftp_smb_local_inspections,
                 'EXPLICIT_TWO_GUEST_INSPECTIONS_REQUIRED')
            return inspect()
        need(not args.i_authorize_two_new_ftp_smb_local_inspections,
             'REPLAY_CANNOT_REQUEST_AUTHORIZATION')
        f3.parent()
        classification=verify(args.replay)
        for role in ('ssh','ftp','smb'):
            print('R113_F3T_'+role.upper()+'_LISTENER='+classification[role]['local_listener_state'])
        print('R113_F3T_REPLAY=PASS')
        print('R113_F3T_P8=NO-GO')
        return 0
    except (ValueError,KeyError,TypeError,OSError,RuntimeError,TimeoutError) as exc:
        print('R113_F3T_STOP='+type(exc).__name__+':'+str(exc)[:250],flush=True)
        print('R113_F3T_ACTION=NO_AUTOMATIC_RETRY_NO_HOST_CLEANUP',flush=True)
        print('R113_F3T_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
