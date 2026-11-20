#!/usr/bin/env python3
"""R114-F4: one physical QGA read of FTP configuration source, DENY preserved.

One-shot source capture. Do not rerun after a session/attempt marker exists.
Replay makes NO privileged, QGA, systemd, libvirt, or network calls.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
from xml.etree import ElementTree as ET

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.dont_write_bytecode=True
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r114_f4_ftp_config_observation as core
from ardrec.coordination import r114_f3_asset_anchor as f3
import ardrec_p14_r114_f3_asset_anchor as f3cli

ROOT=Path('/home/cicada/ardrec-lab/r114-f4-ftp-configuration-read-v1')
F3_DIR=Path(core.F3_DIR)
F6='/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
QGA=['/usr/bin/virsh','-c','qemu:///system','qemu-agent-command',core.VM]
STATIC_FILES={'intent.json','f6_before.stdout','f6_after.stdout','vm.xml',
              'guest_info.stdout','started-ftp.once','qga_start.stdout',
              'config.bytes','qga_completion.json','report.json','manifest.json'}
class Stop(RuntimeError): pass

def need(ok,why):
 if not ok:raise Stop(why)

def private_dir(path:Path):
 need(path.is_dir() and not path.is_symlink(),'PRIVATE_DIR_MISSING_OR_SYMLINK_'+path.name)
 st=path.stat()
 need(st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o700,
      'PRIVATE_DIR_OWNER_MODE_'+path.name)

def read(path:Path,limit=100000,*,allow_empty=False)->bytes:
 need(path.is_file() and not path.is_symlink(),'PRIVATE_FILE_MISSING_OR_LINK_'+path.name)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and
       st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
       (0 if allow_empty else 1)<=st.st_size<=limit,
       'PRIVATE_FILE_MODE_SIZE_OWNER_'+path.name)
  out=b''
  while len(out)<st.st_size:
   chunk=os.read(fd,st.st_size-len(out))
   need(bool(chunk),'READ_INTERRUPTED_'+path.name)
   out+=chunk
  st2=os.fstat(fd)
  need((st.st_size,st.st_mtime_ns,st.st_ctime_ns)==
       (st2.st_size,st2.st_mtime_ns,st2.st_ctime_ns),
       'FILE_CHANGED_DURING_READ_'+path.name)
  return out
 finally:os.close(fd)

def write(p:Path,raw:bytes):
 need(len(raw)<=100000 and p.parent.is_dir(),'OUTPUT_SIZE_OR_DIRECTORY_INVALID')
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as h:
  h.write(raw);h.flush();os.fsync(h.fileno())

def cmd(argv:list[str],*,max_size:int=95000,timeout:int=20)->bytes:
 need(all(type(a) is str for a in argv),'COMMAND_ARGUMENT_TYPE')
 p=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,
                  timeout=timeout,check=False,env=ENV)
 need(p.returncode==0 and not p.stderr and len(p.stdout)<=max_size,
      'READONLY_COMMAND_FAILED_'+Path(argv[0]).name+'_'+str(p.returncode))
 return p.stdout

def qga(command:dict)->bytes:
 raw=cmd([*QGA,json.dumps(command,sort_keys=True,separators=(',',':'))],max_size=95000,timeout=15)
 try:
  reply=json.loads(raw)
 except (ValueError,UnicodeError,RecursionError) as e: raise Stop('QGA_JSON_INVALID') from e
 need(type(reply) is dict and set(reply)=={'return'},'QGA_RETURN_OR_ERROR_INVALID')
 return raw

def source():
 private_dir(F3_DIR.parent);private_dir(F3_DIR)
 need({p.name for p in F3_DIR.iterdir()}=={'report.json','manifest.json'},'F3_FILES_SCOPE_DRIFT')
 raw_m=read(F3_DIR/'manifest.json');raw_r=read(F3_DIR/'report.json')
 need(core.sha(raw_m)==core.F3_MANIFEST_PIN and core.sha(raw_r)==core.F3_REPORT_PIN,
      'ORIGINAL_F3_SHA_PIN_CHANGED')
 m=json.loads(raw_m);r=json.loads(raw_r)
 need(raw_m==f3.canonical(m) and raw_r==f3.canonical(r), 'F3_NONCANONICAL')
 matrix,identity,msha,isha,rsha=f3cli.sources()
 f3.verify(r,matrix,identity,matrix_manifest_sha256=msha,
           identity_manifest_sha256=isha,matrix_report_sha256=rsha)
 return r,m

def xml_identity(raw:bytes):
 try: root=ET.fromstring(raw)
 except ET.ParseError as e: raise Stop('LIVE_VM_XML_UNPARSABLE') from e
 iface=root.findall('./devices/interface')
 need(len(iface)==1,'LIVE_FTP_INTERFACE_COUNT')
 mac=iface[0].find('mac');filterref=iface[0].find('filterref')
 need(mac is not None and mac.attrib.get('address')==core.EXPECTED_MAC and
      filterref is not None and filterref.attrib.get('filter')==
      'ardrec-r33-block-until-containment', 'LIVE_VM_MAC_OR_FILTER_DRIFT')

def f6_attest()->bytes:
 raw=cmd(['/usr/bin/sudo','-n','/usr/bin/python3',F6,'--attest-deny'],max_size=3000,timeout=35)
 v=json.loads(raw)
 need(v.get('result')=='SIX_BINDING_DENY_ATTESTED' and v.get('bindings')==6 and
      v.get('p8')=='NO-GO' and v.get('host_writes')==0,'F6_DENY_NOT_ATTESTED')
 return raw

def manifest(files:dict[str,str],report:dict)->dict:
 return {'schema':'ARDREC-R114-F4-FTP-QGA-PARTIAL-REPLAY-v1',
         'files_sha256':files,'report_sha256':core.sha(core.canonical(report)),
         'source_f3_manifest_sha256':core.F3_MANIFEST_PIN,
         'physical_attempts_max':1,'new_network_connections':0,
         'host_firewall_writes':0,'a5_family_completed':False,
         'a6_conditions_admitted':0,'risk_recalculated':False,
         'p8':'NO-GO'}

def capture()->int:
 need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
 r,m=source()
 intent=core.plan(r,m,msha=core.F3_MANIFEST_PIN,rsha=core.F3_REPORT_PIN)
 private_dir(ROOT.parent)
 if not ROOT.exists():ROOT.mkdir(mode=0o700)
 private_dir(ROOT)
 need(not list(ROOT.glob('capture-*')),'F4_ALREADY_ATTEMPTED_DO_NOT_RETRY')
 folder=ROOT/('capture-'+secrets.token_hex(4));folder.mkdir(mode=0o700)
 print('R114_F4_SESSION='+str(folder),flush=True)
 write(folder/'intent.json',core.canonical(intent))
 try:
  before=f6_attest();write(folder/'f6_before.stdout',before)
  vm=cmd(['/usr/bin/virsh','-c','qemu:///system','dumpxml',core.VM],timeout=15)
  write(folder/'vm.xml',vm);xml_identity(vm)
  agent=qga({'execute':'guest-info'})
  write(folder/'guest_info.stdout',agent)
  info=json.loads(agent)['return']
  need(type(info) is dict and type(info.get('supported_commands')) is list and
       any(type(c) is dict and c.get('name')=='guest-exec' and c.get('enabled') is True
           for c in info['supported_commands']) and
       any(type(c) is dict and c.get('name')=='guest-exec-status' and c.get('enabled') is True
           for c in info['supported_commands']), 'QGA_REQUIRED_COMMAND_NOT_ENABLED')
  # One-time marker is durably written BEFORE guest-exec, including on crash.
  write(folder/'started-ftp.once',core.canonical({'vm':core.VM,'command':core.CMD,
                                                 'one_physical_attempt':True,'p8':'NO-GO'}))
  started=qga({'execute':'guest-exec','arguments':{
    'path':core.CMD[0],'arg':[core.CMD[1]],'capture-output':True}})
  write(folder/'qga_start.stdout',started)
  pid=json.loads(started)['return'].get('pid')
  need(type(pid) is int and pid>0,'QGA_GUEST_EXEC_PID_INVALID')
  completed=None
  deadline=time.monotonic()+20
  for i in range(1,21):
   if time.monotonic()>deadline:break
   time.sleep(.4)
   state=qga({'execute':'guest-exec-status','arguments':{'pid':pid}})
   # Preserve every status BEFORE any parsing or validation.
   write(folder/('status-'+str(i).zfill(2)+'.json'),state)
   if json.loads(state)['return'].get('exited') is True:
    completed=state;break
  need(completed is not None,'QGA_COMPLETION_NOT_OBSERVED_NO_RETRY')
  write(folder/'qga_completion.json',completed)
  # Preserve exact raw bytes BEFORE semantic interpretation.
  import base64
  config=base64.b64decode(json.loads(completed)['return']['out-data'],validate=True)
  need(len(config)<=core.MAX_DATA,'CONFIG_TOO_LARGE')
  write(folder/'config.bytes',config)
  after=f6_attest();write(folder/'f6_after.stdout',after)
  report=core.classify(intent,completed,config,f6_before_raw=before,f6_after_raw=after,
                       f3_report=r,f3_manifest=m,msha=core.F3_MANIFEST_PIN,
                       rsha=core.F3_REPORT_PIN)
  write(folder/'report.json',core.canonical(report))
  files={p.name:core.sha(read(p,allow_empty=True)) for p in folder.iterdir()}
  write(folder/'manifest.json',core.canonical(manifest(files,report)))
  print('R114_F4_PHYSICAL_QGA=PASS_ONE_FTP_CAT')
  print('R114_F4_CONFIG_SOURCE_SHA256='+report['config_file_sha256'])
  print('R114_F4_CONFIG_SOURCE_BYTES='+str(report['config_file_bytes']))
  print('R114_F4_CASE_INTENT='+report['case_intent']['derived_case_id'])
  print('R114_F4_A5=SOURCE_READ_ONLY_NOT_FULL_FAMILY_EXECUTION')
  print('R114_F4_A6=ND')
  print('R114_F4_FINAL_DENY=PASS')
  print('R114_F4_MANIFEST_SHA256='+core.sha(read(folder/'manifest.json')))
  print('R114_F4_P8=NO-GO')
  return 0
 except Exception as e:
  print('R114_F4_STOP='+type(e).__name__+':'+str(e)[:180],flush=True)
  print('R114_F4_INCOMPLETE_PRESERVED='+str(folder),flush=True)
  print('R114_F4_NO_GUEST_EXEC_RETRY=TRUE',flush=True)
  print('R114_F4_P8=NO-GO',flush=True)
  return 23

def replay(folder:Path)->int:
 need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
 private_dir(ROOT.parent);private_dir(ROOT);private_dir(folder)
 need(folder.parent==ROOT and re.fullmatch('capture-[0-9a-f]{8}',folder.name),
      'REPLAY_PATH_INVALID')
 names={p.name for p in folder.iterdir()}
 need(STATIC_FILES<=names and all(re.fullmatch(r'status-(?:0[1-9]|1[0-9]|20)\.json',x)
      for x in names-STATIC_FILES), 'REPLAY_FILES_SCOPE_INVALID')
 mraw=read(folder/'manifest.json');m=json.loads(mraw)
 need(mraw==core.canonical(m) and m.get('schema')=='ARDREC-R114-F4-FTP-QGA-PARTIAL-REPLAY-v1' and
      m.get('source_f3_manifest_sha256')==core.F3_MANIFEST_PIN and
      m.get('a5_family_completed') is False and m.get('a6_conditions_admitted')==0 and
      m.get('new_network_connections')==0 and m.get('host_firewall_writes')==0 and
      m.get('risk_recalculated') is False and m.get('p8')=='NO-GO',
      'REPLAY_MANIFEST_AUTHORITY_INVALID')
 need(set(m['files_sha256'])==names-{'manifest.json'},'REPLAY_FILES_MANIFEST_SCOPE')
 for name,digest in m['files_sha256'].items():
  need(core.sha(read(folder/name,allow_empty=True))==digest,'REPLAY_TAMPERED_'+name)
 r,fm=source()
 plan_doc=json.loads(read(folder/'intent.json'))
 need(read(folder/'intent.json')==core.canonical(plan_doc),'INTENT_CANONICAL_DRIFT')
 xml_identity(read(folder/'vm.xml'))
 started=json.loads(read(folder/'qga_start.stdout'))['return']
 need(type(started.get('pid')) is int and started['pid']>0,'QGA_START_NOT_VERIFIED')
 marker=json.loads(read(folder/'started-ftp.once'))
 need(marker=={'vm':core.VM,'command':core.CMD,'one_physical_attempt':True,'p8':'NO-GO'},
      'ONE_TIME_MARKER_INVALID')
 statuses=sorted(names-STATIC_FILES)
 need(bool(statuses),'QGA_STATUS_MISSING')
 completed=read(folder/'qga_completion.json')
 need(read(folder/statuses[-1])==completed,'QGA_COMPLETION_NOT_LAST_CAPTURE')
 for name in statuses:
  status=json.loads(read(folder/name))['return']
  need(type(status) is dict and ('exited' in status),'QGA_INTERMEDIATE_STATUS_INVALID')
 report=json.loads(read(folder/'report.json'))
 need(read(folder/'report.json')==core.canonical(report),'REPORT_NONCANONICAL')
 core.verify_report(report,plan_doc,completed,read(folder/'config.bytes'),
     f6_before=read(folder/'f6_before.stdout'),f6_after=read(folder/'f6_after.stdout'),
     f3_report=r,f3_manifest=fm,msha=core.F3_MANIFEST_PIN,rsha=core.F3_REPORT_PIN)
 need(m.get('report_sha256')==core.sha(read(folder/'report.json')),
      'REPORT_NOT_LINKED_TO_MANIFEST')
 print('R114_F4_REPLAY=PASS_F3_F6_QGA_CONFIG_BYTE_CHAIN')
 print('R114_F4_MANIFEST_SHA256='+core.sha(mraw))
 print('R114_F4_CASE_INTENT='+core.CASE)
 print('R114_F4_EFFECTIVE_CONFIG=NOT_ATTESTED')
 print('R114_F4_A6=ND')
 print('R114_F4_HOST_COMMANDS=0')
 print('R114_F4_P8=NO-GO')
 return 0

def main():
 os.umask(0o077)
 ap=argparse.ArgumentParser(description=__doc__)
 x=ap.add_mutually_exclusive_group(required=True)
 x.add_argument('--capture',action='store_true')
 x.add_argument('--replay',type=Path)
 ap.add_argument('--i-authorize-one-ftp-local-config-read',action='store_true')
 args=ap.parse_args()
 try:
  if args.capture:
   need(args.i_authorize_one_ftp_local_config_read,'EXPLICIT_FTP_AUTHORIZATION_REQUIRED')
   return capture()
  need(not args.i_authorize_one_ftp_local_config_read,'REPLAY_MUST_NOT_BE_AUTHORIZED_AS_CAPTURE')
  return replay(args.replay)
 except Exception as e:
  print('R114_F4_STOP='+type(e).__name__+':'+str(e)[:180],flush=True)
  print('R114_F4_NO_AUTOMATIC_RETRY=TRUE',flush=True)
  print('R114_F4_P8=NO-GO',flush=True)
  return 23

if __name__=='__main__':raise SystemExit(main())
