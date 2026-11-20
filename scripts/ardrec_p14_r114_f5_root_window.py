#!/usr/bin/env python3
"""R114-F5: SINGLE FTP-T01 real A5 control greeting, autonomous F6 DENY.

Installed as a root-owned 0600 file. Exactly two candidate bindings may be
transiently selected; R34 FTP-only 4 ACCEPT + original 4 DROP is last-to-open.
One-shot marker precedes ANY access admission; systemd root independent backup.
Never auto-retry an attempted physical operation.
"""
from __future__ import annotations
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT=Path('/var/lib/ardrec/r114-f5-ftp-t01-root-v1')
F6='/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py'
VIRSH=['/usr/bin/virsh','-c','qemu:///system']
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'}
FILES={'root-window.py','core.py','contract.py','semantic.py',
       'ftp-runner.xml','ftp-target.xml','r34-ftp-only.nft','f4-report.json',
       'f4-manifest.json'}
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
import core
import contract as c
import semantic

class Stop(RuntimeError):pass

def need(ok,reason):
 if not ok:raise Stop(reason)

def read(p:Path,limit:int=300000):
 need(p.is_file() and not p.is_symlink(),'FILE_MISSING_OR_SYMLINK_'+p.name)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
       stat.S_IMODE(st.st_mode)==0o600 and 0<=st.st_size<limit,
       'ROOT_FILE_MODE_OR_LENGTH_'+p.name)
  out=os.read(fd,limit)
  need(len(out)==st.st_size,'ROOT_FILE_SIZE_CHANGED_'+p.name)
  return out
 finally:os.close(fd)

def save(directory:Path,name:str,raw:bytes):
 need(re.fullmatch('[a-z0-9._-]{1,80}',name) is not None and
      isinstance(raw,bytes) and len(raw)<300000,'OUTPUT_INVALID')
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as h:
  h.write(raw);h.flush();os.fsync(h.fileno())

def auth_bundle():
 need(os.geteuid()==0,'ROOT_REQUIRED')
 need(ROOT.is_dir() and not ROOT.is_symlink() and ROOT.stat().st_uid==0 and
      stat.S_IMODE(ROOT.stat().st_mode)==0o700,'ROOT_BUNDLE_DIR_INVALID')
 names={p.name for p in ROOT.iterdir()}
 need(FILES|{'manifest.json'}<=names and
      names <= FILES|{'manifest.json','window-attempted.once'}|{p for p in names if re.fullmatch('window-[0-9a-f]{8}',p)},
      'ROOT_BUNDLE_FILE_SCOPE_CHANGED')
 mraw=read(ROOT/'manifest.json')
 m=json.loads(mraw)
 need(m.get('schema')=='ARDREC-R114-F5-FTP-ROOT-BUNDLE-v1' and
      m.get('source_f4_manifest_sha256')==core.F4_MANIFEST_SHA and
      m.get('source_f10r_bundle_manifest_sha256') is not None and
      m.get('allowed_tcp')==[{'source':core.SRC_IP,'target':core.DST_IP,'port':21}] and
      m.get('window_seconds')==120 and
      m.get('a6_admitted')==0 and m.get('p8')=='NO-GO' and
      set(m.get('sha256',{}))==FILES,'ROOT_BUNDLE_MANIFEST_INVALID')
 raw={name:read(ROOT/name) for name in FILES}
 need(all(core.sha(raw[name])==m['sha256'][name] for name in FILES),
      'ROOT_BUNDLE_PAYLOAD_TAMPERED')
 need(raw['root-window.py']==Path(__file__).read_bytes(),'ROOT_CODE_NOT_SAME')
 need(core.sha(raw['f4-manifest.json'])==core.F4_MANIFEST_SHA and
      core.sha(raw['f4-report.json'])==m['source_f4_report_sha256'],
      'F4_SOURCE_DIGEST_DRIFT')
 core.validate_f4_source(json.loads(raw['f4-report.json']),json.loads(raw['f4-manifest.json']),
       manifest_sha=core.sha(raw['f4-manifest.json']),
       report_sha=core.sha(raw['f4-report.json']))
 # The policy was derived from protected F10R: 4 FTP accepts, 4 DROP, no SSH/SMB accepts.
 nft=raw['r34-ftp-only.nft']
 need(len(nft.splitlines())==9 and nft.startswith(b'flush table bridge ardrec_r34_guard\n') and
      nft.count(b' counter accept\n')==4 and nft.count(b' counter drop\n')==4 and
      all(b'a33d30' not in x and b'a33d32' not in x
          for x in nft.splitlines() if b' counter accept' in x),
      'FTP_ONLY_POLICY_CHANGED')
 return raw

def run(name,argv,folder,*,stdin=None,timeout=15):
 need(re.fullmatch('[a-z0-9_]{2,50}',name) is not None,'COMMAND_NAME_INVALID')
 need(all(type(a) is str for a in argv),'COMMAND_ARGUMENT_INVALID')
 try:
  p=subprocess.run(argv,input=stdin,stdin=subprocess.DEVNULL if stdin is None else None,
     capture_output=True,timeout=timeout,env=ENV,check=False,close_fds=True)
  rc,out,err=p.returncode,p.stdout,p.stderr
 except (OSError,subprocess.TimeoutExpired) as e:
  rc=124 if isinstance(e,subprocess.TimeoutExpired) else 127
  out=(e.stdout or b'') if isinstance(e,subprocess.TimeoutExpired) else b''
  err=(type(e).__name__+':'+str(e)).encode()[:3000]
 need(len(out)<150000 and len(err)<20000,'COMMAND_OUTPUT_TOO_LARGE_'+name)
 save(folder,name+'.stdout',out)
 save(folder,name+'.stderr',err)
 print('R114_F5_'+name.upper()+'_RC='+str(rc),flush=True)
 need(rc==0,'COMMAND_FAILED_'+name)
 return out

def f6(name,flag,folder):
 raw=run(name,['/usr/bin/python3',F6,flag],folder,timeout=35)
 expected={'--check-root-bundle':'ROOT_BUNDLE_VERIFIED',
           '--attest-deny':'SIX_BINDING_DENY_ATTESTED',
           '--restore-deny':'SIX_BINDING_DENY_RESTORED'}[flag]
 doc=json.loads(raw)
 need(doc.get('result')==expected and doc.get('bindings')==6 and
      doc.get('p8')=='NO-GO','F6_RESULT_INVALID_'+name)
 return raw

def run_invariants(folder,raw):
 f6('f6_bundle','--check-root-bundle',folder)
 f6('f6_before','--attest-deny',folder)
 hook=run('f11_sha',['/usr/bin/sha256sum','/etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'],folder)
 need(hook.decode().split()[0]=='1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b',
      'F11_HOOK_DRIFT')
 watch=run('r34_watchdog',['/usr/bin/systemctl','show','ardrec-r34-deny-watchdog.timer',
                          '--no-pager','-p','LoadState','-p','ActiveState'],folder)
 need(b'LoadState=loaded' in watch and b'ActiveState=active' in watch,
      'R34_WATCHDOG_NOT_ACTIVE')
 for role,key in (('runner-ftp','ftp-runner.xml'),('ftp','ftp-target.xml')):
  actual=run('filter_'+role.replace('-','_'),VIRSH+['nwfilter-dumpxml',c.name(role)],folder)
  need(semantic.semantically_identical(raw[key],actual,expected_name=c.name(role)),
       'FILTER_DEFINITION_DRIFT_'+role)
 for guest in (core.VM_RUNNER,core.VM_TARGET):
  state=run('vm_'+('runner' if guest==core.VM_RUNNER else 'ftp'),VIRSH+['domstate',guest],folder)
  need(state.decode().strip() in ('running','ejecutando'),'VM_NOT_RUNNING')
  xml=run('xml_'+('runner' if guest==core.VM_RUNNER else 'ftp'),VIRSH+['dumpxml',guest],folder)
  tree=ET.fromstring(xml)
  interfaces=tree.findall('./devices/interface')
  # The runner has three interfaces; FTP target must have one. Bind matching MAC.
  expected_mac=core.SRC_MAC if guest==core.VM_RUNNER else core.DST_MAC
  matching=[x for x in interfaces if x.find('mac') is not None and
            x.find('mac').get('address')==expected_mac]
  need(len(matching)==1 and matching[0].find('filterref') is not None and
       matching[0].find('filterref').get('filter')==c.DENY,
       'VM_EXPECTED_MAC_OR_DENY_MISSING')
 guest_info=run('runner_guest_info',VIRSH+['qemu-agent-command',core.VM_RUNNER,
       '{"execute":"guest-info"}'],folder)
 x=json.loads(guest_info)
 need('return' in x and type(x['return'].get('supported_commands')) is list and
      any(type(y) is dict and y.get('name')=='guest-exec' and y.get('enabled') is True
          for y in x['return']['supported_commands']), 'RUNNER_QGA_GUEST_EXEC_DISABLED')

def agent(folder,label,msg):
 encoded=json.dumps(msg,sort_keys=True,separators=(',',':'))
 raw=run(label,VIRSH+['qemu-agent-command',core.VM_RUNNER,encoded],folder,timeout=12)
 x=json.loads(raw)
 need(type(x) is dict and set(x)=={'return'},'QGA_INVALID_'+label)
 return x['return'],raw

def one_probe(folder):
 start,_=agent(folder,'qga_start',{'execute':'guest-exec',
   'arguments':{'path':'/usr/bin/python3','arg':['-c',core.runner_source()],
                'capture-output':True}})
 pid=start.get('pid')
 need(type(pid) is int and pid>0,'QGA_NO_PID')
 last=None
 deadline=time.monotonic()+20
 for i in range(1,25):
  if time.monotonic()>deadline:break
  time.sleep(.35)
  obj,raw=agent(folder,'qga_status_'+str(i),{'execute':'guest-exec-status',
                                                 'arguments':{'pid':pid}})
  if obj.get('exited') is True:
   need(obj.get('exitcode')==0,'GUEST_PROBE_EXIT_INVALID')
   try:
    output=base64.b64decode(obj.get('out-data',''),validate=True)
    err=base64.b64decode(obj.get('err-data',''),validate=True)
   except (TypeError,ValueError) as e:raise Stop('QGA_RESPONSE_INVALID') from e
   need(not err and 0<len(output)<4000,'GUEST_PROBE_STDOUT_INVALID')
   core.parse_probe(output)
   save(folder,'runner_probe.json',output)
   save(folder,'qga_completion.json',raw)
   last=raw
   break
 need(last is not None,'QGA_STATUS_TIMEOUT_NO_RETRY')
 return output,last

def audit_live_nft(raw):
 doc=json.loads(raw)
 need(type(doc) is dict and type(doc.get('nftables')) is list,'NFT_JSON_INVALID')
 rules=[row['rule'] for row in doc['nftables'] if 'rule' in row]
 need(len(rules)==8,'NFT_LIVE_RULE_COUNT_DRIFT')
 accept=[r for r in rules if any('accept' in e for e in r.get('expr',[]))]
 drop=[r for r in rules if any('drop' in e for e in r.get('expr',[]))]
 need(len(accept)==4 and len(drop)==4,'NFT_LIVE_ACCEPT_DROP_COUNT')
 # Each allow must be a fixed bridge forward rule and include FTP tap/IP/port.
 for r in accept:
  need(r.get('table')=='ardrec_r34_guard' and r.get('family')=='bridge' and
       r.get('chain')=='forward','NFT_ACCEPT_CHAIN_INVALID')
  body=json.dumps(r,sort_keys=True,separators=(',',':'))
  need('a33d31r' in body and 'a33d31t' in body and
       'a33d30' not in body and 'a33d32' not in body and
       ('10.203.31.1' in body and '10.203.31.2' in body),
       'NFT_ACCEPT_NOT_FTP_ONLY')
 for r in drop:
  need(r.get('family')=='bridge' and r.get('table')=='ardrec_r34_guard' and
       r.get('chain') in ('input','output','forward'),'NFT_DROP_CHAIN_INVALID')
 return True

def create_session():
 folder=ROOT/('window-'+secrets.token_hex(4))
 folder.mkdir(mode=0o700)
 return folder

def make_receipt(folder,status,report=None):
 names={p.name for p in folder.iterdir()}
 if report is not None:save(folder,'case-report.json',core.canon(report))
 data={'schema':'ARDREC-R114-F5-ROOT-FTP-ATTEMPT-RECEIPT-v1',
       'status':status,'source_f4_manifest_sha256':core.F4_MANIFEST_SHA,
       'case_id':core.CASE,'attempt_id':core.ATTEMPT,
       'files_sha256':{p.name:core.sha(read(p)) for p in folder.iterdir() if p.is_file()},
       'a6_admitted':0,'risk_calculated':False,'p8':'NO-GO'}
 save(folder,'receipt.json',core.canon(data))
 print('R114_F5_ROOT_SESSION='+str(folder),flush=True)
 print('R114_F5_ROOT_RECEIPT_SHA256='+core.sha(read(folder/'receipt.json')),flush=True)

def window(bundle):
 need(not (ROOT/'window-attempted.once').exists(),
      'F5_WINDOW_ALREADY_ATTEMPTED_DO_NOT_RETRY')
 folder=create_session()
 opened=False;armed=False;final_deny=False;result=None
 try:
  run_invariants(folder,bundle)
  run('nft_candidate_check',['/usr/sbin/nft','--check','--file','-'],folder,
      stdin=bundle['r34-ftp-only.nft'],timeout=12)
  deny=run('nft_deny_before',['/usr/sbin/nft','-j','-a','list','table',
             'bridge','ardrec_r34_guard'],folder,timeout=12)
  before_doc=json.loads(deny)
  before_rules=[x['rule'] for x in before_doc.get('nftables',[]) if 'rule' in x]
  need(len(before_rules)==4 and
       all(any('drop' in expr for expr in row.get('expr',[])) for row in before_rules) and
       not any(any('accept' in expr for expr in row.get('expr',[])) for row in before_rules),
       'R34_DENY_BEFORE_NOT_EXACTLY_FOUR_DROPS')
  # Durable one-shot marker is placed BEFORE the timer and any binding changes.
  save(ROOT,'window-attempted.once',b'R114_F5_FTP_T01_ONE_PHYSICAL_ATTEMPT\n')
  stem='ardrec-r114-f5-deny-'+secrets.token_hex(6)
  save(folder,'timer-intent.json',core.canon({'stem':stem,'duration':120,
                 'recovery':F6,'case_id':core.CASE,'p8':'NO-GO'}))
  run('timer_arm',['/usr/bin/systemd-run','--system','--unit='+stem,
        '--on-active=120s','--timer-property=AccuracySec=1s',
        '--description=ARDREC F5 FTP only F6 autonomous deny',
        '/usr/bin/python3',F6,'--restore-deny'],folder,timeout=15)
  timer=run('timer_active',['/usr/bin/systemctl','show',stem+'.timer',
        '--no-pager','-p','LoadState','-p','ActiveState','-p','Unit',
        '-p','NextElapseUSecMonotonic'],folder)
  props=dict(x.split('=',1) for x in timer.decode().splitlines() if '=' in x)
  need(props.get('LoadState')=='loaded' and props.get('ActiveState')=='active' and
       props.get('Unit')==stem+'.service' and
       props.get('NextElapseUSecMonotonic') not in ('0','','infinity'),
       'INDEPENDENT_DENY_TIMER_NOT_ARMED')
  armed=True
  swap_start=time.monotonic()
  save(folder,'binding-swap-started.once',b'ONLY_FTP_TWO_BINDINGS\n')
  for role in ('runner-ftp','ftp'):
   need(time.monotonic()-swap_start<60,'SWAP_DEADLINE_EXCEEDED')
   tap=c.ROWS[role][2]
   run('delete_'+role.replace('-','_'),VIRSH+['nwfilter-binding-delete',tap],folder,timeout=8)
   run('create_'+role.replace('-','_'),VIRSH+['nwfilter-binding-create',
       '/var/lib/ardrec/r113-six-deny-guard-v1/'+role.replace('-','_')+'-candidate.xml'],
       folder,timeout=8)
   bxml=run('binding_'+role.replace('-','_'),VIRSH+['nwfilter-binding-dumpxml',tap],folder)
   doc=ET.fromstring(bxml)
   reference=doc.find('.//filterref')
   need(reference is not None and reference.get('filter')==c.name(role) and
        c.name(role).encode() in bxml and tap.encode() in bxml,
        'FTP_BINDING_UNEXPECTED_'+role)
  need(time.monotonic()-swap_start<60,'NOT_ENOUGH_TIMER_MARGIN')
  t=run('timer_last_check',['/usr/bin/systemctl','show',stem+'.timer','--no-pager',
      '-p','ActiveState'],folder)
  need(b'ActiveState=active' in t,'TIMER_INACTIVE_BEFORE_OPEN')
  run('nft_open',['/usr/sbin/nft','-f','-'],folder,
      stdin=bundle['r34-ftp-only.nft'],timeout=10)
  opened=True
  save(folder,'ftp-only-window-open.once',b'R34_FTP_ONLY_4_ACCEPT_4_DROP\n')
  state=run('nft_live',['/usr/sbin/nft','-j','-a','list','table','bridge',
                             'ardrec_r34_guard'],folder)
  audit_live_nft(state)
  one_probe(folder)
 except Exception as exc:
  print('R114_F5_WINDOW_STOP='+type(exc).__name__+':'+str(exc)[:170],flush=True)
  print('R114_F5_PHYSICAL_NO_RETRY=TRUE',flush=True)
 finally:
  try:
   f6('f6_restore_final','--restore-deny',folder)
   f6('f6_attest_final','--attest-deny',folder)
   final_deny=True
  except Exception as exc:
   print('R114_F5_CRITICAL_DENY_NOT_ATTESTED='+type(exc).__name__+':'+str(exc)[:170],flush=True)
   print('R114_F5_BACKUP_TIMER_ARMED='+str(armed).upper(),flush=True)
  if opened and final_deny and (folder/'runner_probe.json').is_file():
   try:
    result=core.classify_attempt(raw_probe=read(folder/'runner_probe.json'),
       qga_raw_status=read(folder/'qga_completion.json'),
       f6_final_raw=read(folder/'f6_attest_final.stdout'),
       f4_manifest_sha=core.F4_MANIFEST_SHA,
       f4_report_sha=core.sha(bundle['f4-report.json']))
   except Exception as exc:
    print('R114_F5_CLASSIFICATION_STOP='+type(exc).__name__+':'+str(exc)[:170],flush=True)
  status=('CLOSED_DENY_FTP_220_A5_ATTEMPT' if result and result['ftp_220_response_observed']
          else 'CLOSED_DENY_FTP_ATTEMPT_UNRESOLVED' if final_deny
          else 'CRITICAL_DENY_UNVERIFIED')
  try:make_receipt(folder,status,result)
  except Exception as exc:print('R114_F5_RECEIPT_ERROR='+str(exc)[:150],flush=True)
  print('R114_F5_FINAL_DENY='+('PASS_SIX_BINDINGS' if final_deny else 'NOT_VERIFIED'),flush=True)
  print('R114_F5_TIMER_ARMED='+str(armed).upper(),flush=True)
  print('R114_F5_A5='+('REAL_FTP_T01_GREETING_OBSERVED' if result and result['ftp_220_response_observed']
                       else 'NO_ACCEPTED_220_PROOF'),flush=True)
  print('R114_F5_A6=ND',flush=True)
  print('R114_F5_P8=NO-GO',flush=True)
 return 0 if status=='CLOSED_DENY_FTP_220_A5_ATTEMPT' else 23

def replay(folder):
 need(folder.parent==ROOT and re.fullmatch('window-[0-9a-f]{8}',folder.name) and
      folder.is_dir() and not folder.is_symlink(),'REPLAY_PATH_INVALID')
 need(folder.stat().st_uid==0 and stat.S_IMODE(folder.stat().st_mode)==0o700,
      'REPLAY_FOLDER_OWNER_MODE_INVALID')
 rraw=read(folder/'receipt.json');event=json.loads(rraw)
 need(event.get('schema')=='ARDREC-R114-F5-ROOT-FTP-ATTEMPT-RECEIPT-v1' and
      event.get('source_f4_manifest_sha256')==core.F4_MANIFEST_SHA and
      event.get('case_id')==core.CASE and event.get('attempt_id')==core.ATTEMPT and
      event.get('a6_admitted')==0 and event.get('risk_calculated') is False and
      event.get('p8')=='NO-GO','REPLAY_RECEIPT_SCOPE_INVALID')
 names={p.name for p in folder.iterdir()}
 need(set(event.get('files_sha256',{}))==names-{'receipt.json'},
      'REPLAY_FILE_SCOPE_INVALID')
 for name,digest in event['files_sha256'].items():
  need(core.sha(read(folder/name))==digest,'REPLAY_FILE_HASH_CHANGED_'+name)
 need(event['status'] in ('CLOSED_DENY_FTP_220_A5_ATTEMPT',
                          'CLOSED_DENY_FTP_ATTEMPT_UNRESOLVED',
                          'CRITICAL_DENY_UNVERIFIED'), 'REPLAY_OUTCOME_UNKNOWN')
 if event['status']=='CLOSED_DENY_FTP_220_A5_ATTEMPT':
  # Check decoded physical QGA, F6 and identical derived A5 report.
  probe=read(folder/'runner_probe.json')
  raw_status=read(folder/'qga_completion.json')
  completed=json.loads(raw_status)['return']
  need(base64.b64decode(completed['out-data'],validate=True)==probe,
       'REPLAY_QGA_BYTES_NOT_SAME')
  bundle=auth_bundle()
  expected=core.classify_attempt(raw_probe=probe,qga_raw_status=raw_status,
     f6_final_raw=read(folder/'f6_attest_final.stdout'),
     f4_manifest_sha=core.F4_MANIFEST_SHA,
     f4_report_sha=core.sha(bundle['f4-report.json']))
  need(expected['ftp_220_response_observed'] is True and
       read(folder/'case-report.json')==core.canon(expected),
       'REPLAY_A5_CASE_FACT_MISMATCH')
  before=json.loads(read(folder/'f6_before.stdout'))
  restore=json.loads(read(folder/'f6_restore_final.stdout'))
  need(before.get('result')=='SIX_BINDING_DENY_ATTESTED' and
       restore.get('result')=='SIX_BINDING_DENY_RESTORED',
       'REPLAY_DENY_CHAIN_INVALID')
  need('ftp-only-window-open.once' in event['files_sha256'] and
       'timer_active.stdout' in event['files_sha256'] and
       'nft_live.stdout' in event['files_sha256'], 'REPLAY_OPEN_TIMELINE_UNVERIFIED')
 print('R114_F5_REPLAY=PASS_ROOT_RECEIPT_BYTE_INTEGRITY')
 print('R114_F5_REPLAY_SOURCE_OUTCOME='+event['status'])
 print('R114_F5_REPLAY_A6=ND')
 print('R114_F5_REPLAY_HOST_COMMANDS=0')
 print('R114_F5_REPLAY_P8=NO-GO')
 return 0

def main():
 os.umask(0o077)
 ap=argparse.ArgumentParser(description=__doc__)
 group=ap.add_mutually_exclusive_group(required=True)
 group.add_argument('--check',action='store_true')
 group.add_argument('--window',action='store_true')
 group.add_argument('--replay',type=Path)
 args=ap.parse_args()
 try:
  bundle=auth_bundle()
  if args.check:
   print('R114_F5_ROOT_BUNDLE=VERIFIED')
   return 0
  if args.window:return window(bundle)
  return replay(args.replay)
 except Exception as exc:
  print('R114_F5_ROOT_STOP='+type(exc).__name__+':'+str(exc)[:170],flush=True)
  print('R114_F5_NO_AUTORETRY=TRUE\nR114_F5_P8=NO-GO',flush=True)
  return 23
if __name__=='__main__':raise SystemExit(main())
