#!/usr/bin/env python3
"""R113-F3: inspección acotada de puertos TCP IPv4 dentro de tres VM mediante QGA."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/home/cicada/ardrec-lab/r113-f3-guest-listeners-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
PARENT = '7e4c7b48cdccdc36df499919bb511469ea02096e'
F2_PROOF = Path('/home/cicada/ardrec-lab/r113-f2-agent-ip-identity-v1/proof-c40akbko')
F2_MANIFEST_SHA = '84e81025cac7180619edd530765052576a6726efe304ec3247bab68075df810b'
URI = 'qemu:///system'
ROLES = ('ssh','ftp','smb')
FILES = ('intent.json','before.json','after.json','agent_preflight.json','exec.json',
         'classification.json','receipt.json', 'started-ssh.once',
         'started-ftp.once','started-smb.once','manifest.json')
sys.path[:0] = [str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f3_guest_listeners as core
from ardrec.coordination import r113_f2_agent_ip_identity as f2core
from ardrec.coordination import r112_f10_targets_boot as f10core
import ardrec_p14_r113_f2_agent_ip_identity as f2
import ardrec_p14_r113_f1_network_audit as f1
import ardrec_p14_r112_f6_hook_lifecycle as f6
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4


def need(value, reason):
    core.need(value, reason)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def canon(obj):
    return (json.dumps(obj, ensure_ascii=True, sort_keys=True,
                       separators=(',',':'), allow_nan=False)+'\n').encode('ascii')

def private(directory):
    need(directory.is_dir() and not directory.is_symlink(),'DIRECTORY_NOT_PRIVATE')
    st=directory.stat()
    need(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,'DIRECTORY_OWNER_OR_MODE')

def put(path, content):
    raw=canon(content)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())

def get(path):
    need(path.is_file() and not path.is_symlink(),'UNSAFE_FILE')
    st=path.stat()
    need(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600,'UNSAFE_FILE_MODE')
    need(st.st_size<500000,'FILE_TOO_LARGE')
    return json.loads(path.read_bytes())

def command(args,timeout=18):
    p=subprocess.run(args,cwd=REPO,stdin=subprocess.DEVNULL,capture_output=True,
                     text=True,errors='replace',timeout=timeout,check=False)
    need(p.returncode==0,'COMMAND_FAILED_'+args[0]+'_'+str(p.returncode)+':'+p.stderr[:180])
    need(len(p.stdout.encode())<=100000 and not p.stderr.strip(),'COMMAND_OUTPUT_INVALID')
    return p.stdout.strip()

def parent():
    need(Path.cwd().resolve()==REPO,'WRONG_WORKING_DIRECTORY')
    need(command(['git','branch','--show-current'])==BRANCH,'WRONG_BRANCH')
    subprocess.run(['git','merge-base','--is-ancestor',PARENT,'HEAD'],cwd=REPO,
                   capture_output=True,check=True,timeout=12)
    need(command(['git','log','-1','--format=%G?'])=='G','HEAD_SIGNATURE_NOT_G')
    need(not command(['git','status','--porcelain=v1','-uall']),'WORKTREE_CHANGED')

def origin():
    private(F2_PROOF.parent)
    private(F2_PROOF)
    path=F2_PROOF/'manifest.json'
    need(sha(path.read_bytes())==F2_MANIFEST_SHA,'F2_MANIFEST_SHA_DRIFT')
    f2.verify(F2_PROOF)

def live():
    snapshot=f6.capture()
    f10core.audited(snapshot,'smb',after=True,legacy=legacy,f4=f4)
    return snapshot

def qga(role, request):
    name='ardrec-r33-dev-'+role
    args=['virsh','-c',URI,'qemu-agent-command',name,canon(request).decode().strip(),
          '--timeout','8']
    raw=command(args,timeout=15)
    need(len(raw)<100000,'QGA_TOO_LARGE')
    decoded=json.loads(raw)
    need(type(decoded) is dict,'QGA_NOT_OBJECT')
    need('error' not in decoded,'QGA_REPORTED_ERROR')
    return decoded

def endpoints():
    answers={}
    for role in ('ssh','runner','ftp','smb'):
        name='ardrec-r33-dev-'+role
        raw=command(['virsh','-c',URI,'domifaddr',name,'--source','agent'],timeout=15)
        expected={name:mac for name,(mac,ip) in f2core.EXPECTED[role].items()}
        parsed=f1.core.agent_addresses(raw,expected)
        for network,(mac,cidr) in f2core.EXPECTED[role].items():
            need(parsed[network]==[cidr],'QGA_IP_CHANGED_'+role+'_'+network)
        answers[role]={'agent_output_sha256':sha(raw.encode()),'verified':parsed}
    return answers

def verify(folder):
    need(folder.is_absolute() and folder.parent==ROOT and
         folder.name.startswith('inspect-'),'INSPECTION_SCOPE')
    private(ROOT);private(folder)
    need({p.name for p in folder.iterdir()}==set(FILES),'INSPECTION_FILES_CHANGED')
    man=get(folder/'manifest.json')
    need(man.get('schema')==core.SCHEMA+'-manifest' and
         man.get('f2_proof_sha256')==F2_MANIFEST_SHA and
         man.get('traffic_authorized') is False and
         man.get('protocol_connection_count')==0 and
         man.get('p8_operational')=='NO-GO','MANIFEST_AUTHORITY_DRIFT')
    need(man.get('files')=={name:sha((folder/name).read_bytes())
         for name in FILES if name!='manifest.json'},'MANIFEST_HASH_MISMATCH')
    classification=get(folder/'classification.json')
    records=get(folder/'exec.json')
    need(set(records)==set(ROLES) and set(classification)==set(ROLES),'ROLE_SCOPE_DRIFT')
    for role in ROLES:
        need(core.classify(role,records[role])==classification[role],
             'CLASSIFICATION_REPLAY_DRIFT_'+role)
    intent=get(folder/'intent.json')
    need(intent.get('scope')==list(ROLES) and intent.get('p8_operational')=='NO-GO',
         'INTENT_CHANGED')
    receipt=get(folder/'receipt.json')
    need(receipt.get('classification_sha256')==sha((folder/'classification.json').read_bytes())
         and receipt.get('guest_processes_started')==3
         and receipt.get('firewall_changes')==0
         and receipt.get('network_connections')==0,'RECEIPT_SCOPE_DRIFT')
    origin()
    return classification

def inspect():
    parent();origin()
    before=live()
    ips=endpoints()
    # No guest-exec hasta que los tres agentes declaren soporte explícito.
    agents={}
    for role in ROLES:
        reply=qga(role,{'execute':'guest-info'})
        core.agent_info(reply)
        agents[role]=reply
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);private(ROOT)
    folder=Path(tempfile.mkdtemp(prefix='inspect-',dir=ROOT));private(folder)
    put(folder/'intent.json',{
        'schema':core.SCHEMA+'-intent','created_utc':datetime.now(timezone.utc).isoformat(),
        'scope':list(ROLES),'allowed_guest_binary':'/usr/bin/ss',
        'allowed_guest_argv':['-H','-ltn4'],
        'approved_guest_process_count':3,'p8_operational':'NO-GO'})
    put(folder/'before.json',before)
    put(folder/'agent_preflight.json',{'ip_identities':ips,'guest_info':agents})
    print('R113_F3_GUEST_INFO=PASS_3',flush=True)
    print('R113_F3_INSPECTION_SESSION='+str(folder),flush=True)
    records={}
    for role in ROLES:
        # Once-marker durable antes de enviar la ejecución: incertidumbre -> sin reintentos.
        put(folder/('started-'+role+'.once'),{'role':role,'intent_sha256':sha((folder/'intent.json').read_bytes())})
        response=qga(role,{'execute':'guest-exec','arguments':{
            'path':'/usr/bin/ss','arg':['-H','-ltn4'],'capture-output':True}})
        pid=core.started(response)
        completed=None
        for poll in range(12):
            item=qga(role,{'execute':'guest-exec-status','arguments':{'pid':pid}})
            exited,rc,out,err=core.status(item)
            if exited:
                completed=item
                break
            time.sleep(0.2)
        need(completed is not None,'GUEST_EXEC_NOT_FINISHED_'+role)
        ret=completed['return']
        result={'pid':pid,'status':ret['exitcode'],
                'command':['/usr/bin/ss','-H','-ltn4'],
                'stdout_b64':ret.get('out-data',''),
                'stderr_b64':ret.get('err-data','')}
        records[role]=result
        status=core.classify(role,result)
        print('R113_F3_'+role.upper()+'_LISTENER='+status['local_listener_state'],flush=True)
    after=live()
    # Ambas instantáneas deben acreditar aislamiento sin cambios en autorizaciones.
    put(folder/'after.json',after)
    put(folder/'exec.json',records)
    classification={role:core.classify(role,data) for role,data in records.items()}
    put(folder/'classification.json',classification)
    put(folder/'receipt.json',{
        'schema':core.SCHEMA+'-receipt','f2_proof_sha256':F2_MANIFEST_SHA,
        'before_sha256':sha((folder/'before.json').read_bytes()),
        'after_sha256':sha((folder/'after.json').read_bytes()),
        'classification_sha256':sha((folder/'classification.json').read_bytes()),
        'guest_processes_started':3,'firewall_changes':0,'network_connections':0,
        'traffic_authorized':False,'protocol_tested':False,'p8_operational':'NO-GO'})
    put(folder/'manifest.json',{
        'schema':core.SCHEMA+'-manifest','created_utc':datetime.now(timezone.utc).isoformat(),
        'source_commit':command(['git','rev-parse','HEAD']),
        'f2_proof_sha256':F2_MANIFEST_SHA,
        'files':{name:sha((folder/name).read_bytes())
                 for name in FILES if name!='manifest.json'},
        'traffic_authorized':False,'protocol_connection_count':0,
        'p8_operational':'NO-GO'})
    verify(folder)
    print('R113_F3_RECEIPT='+str(folder),flush=True)
    print('R113_F3_MANIFEST_SHA256='+sha((folder/'manifest.json').read_bytes()),flush=True)
    print('R113_F3_GUEST_EXECUTIONS=3_SS_ONLY',flush=True)
    print('R113_F3_NETWORK_PROTOCOL_CONNECTIONS=0',flush=True)
    print('R113_F3_R34=DENY_PRESERVED',flush=True)
    print('R113_F3_P8=NO-GO',flush=True)
    return 0

def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--inspect',action='store_true')
    group.add_argument('--replay',type=Path)
    p.add_argument('--i-authorize-three-passive-guest-listener-inspections',action='store_true')
    args=p.parse_args()
    try:
        if args.inspect:
            need(args.i_authorize_three_passive_guest_listener_inspections,
                 'EXPLICIT_AUTHORIZATION_REQUIRED')
            return inspect()
        need(not args.i_authorize_three_passive_guest_listener_inspections,
             'REPLAY_MUST_NOT_REQUEST_AUTHORITY')
        parent(); result=verify(args.replay)
        for role in ROLES:
            print('R113_F3_'+role.upper()+'_LISTENER='+result[role]['local_listener_state'])
        print('R113_F3_REPLAY=PASS')
        print('R113_F3_P8=NO-GO')
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            json.JSONDecodeError) as exc:
        print('R113_F3_STOP='+type(exc).__name__+':'+str(exc)[:250],flush=True)
        print('R113_F3_NO_AUTO_RETRY_OR_CLEANUP=TRUE',flush=True)
        print('R113_F3_P8=NO-GO',flush=True)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
