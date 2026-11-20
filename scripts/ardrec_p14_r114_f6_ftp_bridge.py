#!/usr/bin/env python3
"""Create/replay immutable private FTP-T01 A5-to-A6 guarded evidence intake.

`--ingest` requires separate operator consent outside this program. Root access
is restricted to sudo /usr/bin/cat on the fixed historical F5 receipt files.
No guest calls, root scripts, network access or host mutations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path.insert(0,str(REPO/'src'))
from ardrec.coordination import r114_f6_ftp_a5_a6_bridge as f6

class Stop(ValueError):pass
def need(test,msg):
 if not test:raise Stop(msg)
def sha(b):return hashlib.sha256(b).hexdigest()
def private_source(path:Path,owner:int,limit:int=200000):
 need(path.is_file() and not path.is_symlink(),'SOURCE_FILE_INVALID_'+path.name)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and
       stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and
       0<st.st_size<limit,'SOURCE_OWNER_OR_MODE_INVALID_'+path.name)
  data=os.read(fd,limit)
  need(len(data)==st.st_size,'SOURCE_SIZE_CHANGED_'+path.name)
  return data
 finally:os.close(fd)
def read_fixed():
 # Only explicitly enumerated existing root-owned F5 historical files.
 result={}
 for name in f6.ROOT_FILES:
  cmd=['/usr/bin/sudo','-n','/usr/bin/cat',f6.F5_ROOT+'/'+name]
  p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      stdin=subprocess.DEVNULL,timeout=12,check=False)
  need(p.returncode==0 and len(p.stdout)<=200000 and len(p.stdout)>0 and
       len(p.stderr)==0,'ROOT_READ_FAILED_'+name)
  result[name]=p.stdout
 return result

def sources(root_override=None):
 uid=os.getuid()
 if root_override is None:root=read_fixed()
 else:root=root_override
 a={n:private_source(Path(f6.F5C_ROOT)/n,uid) for n in f6.F5C_PINS}
 b={n:private_source(Path(f6.F4_ROOT)/n,uid) for n in f6.F4_FILES}
 return root,a,b

def write_once(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as fp:
  fp.write(data);fp.flush();os.fsync(fp.fileno())
def verified_dir(path,owner):
 need(path.is_dir() and not path.is_symlink(),'DIR_MISSING_OR_SYMLINK')
 st=path.stat()
 need(st.st_uid==owner and stat.S_IMODE(st.st_mode)==0o700,'PRIVATE_DIR_INVALID')
def seal(root,a,b,report,preview):
 base=Path(f6.F6_OUTPUT)
 if not base.exists():
  base.mkdir(mode=0o700,parents=True,exist_ok=False)
 verified_dir(base,os.getuid())
 session=base/('intake-'+secrets.token_hex(4))
 session.mkdir(mode=0o700)
 content={}
 for prefix,group in [('root',root),('f5c',a),('f4',b)]:
  for n,v in sorted(group.items()):content[prefix+'/'+n]=v
 content['report.json']=f6.canon(report)
 content['a6-preview.json']=f6.canon(preview)
 for name,value in content.items():
  parent,name_only=name.split('/') if '/' in name else (None,name)
  if parent:
   folder=session/parent
   folder.mkdir(mode=0o700,exist_ok=True)
   dest=folder/name_only
  else:dest=session/name_only
  write_once(dest,value)
 manifest={'schema':'ARDREC-R114-F6-PRIVATE-A5-A6-EVIDENCE-v1',
   'source_root_receipt_sha256':f6.ROOT_RECEIPT_SHA,
   'source_f5c_replay_sha256':f6.F5C_PINS['replay.log'],
   'files_sha256':{k:sha(v) for k,v in sorted(content.items())},
   'a6_classification':'ND','risk_recalculated':False,'p8':'NO-GO'}
 write_once(session/'manifest.json',f6.canon(manifest))
 os.chmod(session,0o500)
 print('R114_F6_SESSION='+str(session))
 print('R114_F6_MANIFEST_SHA256='+sha(f6.canon(manifest)))
 return session

def _read_session(session):
 uid=os.getuid()
 base=Path(f6.F6_OUTPUT)
 verified_dir(base,uid)
 need(session.parent==base and session.name.startswith('intake-') and
      len(session.name)==15 and session.name[7:].isalnum() and
      session.is_dir() and not session.is_symlink(), 'REPLAY_SESSION_PATH_INVALID')
 st=session.stat()
 need(st.st_uid==uid and stat.S_IMODE(st.st_mode)==0o500,'REPLAY_SESSION_MODE')
 manifest=json.loads(private_source(session/'manifest.json',uid))
 need(manifest.get('schema')=='ARDREC-R114-F6-PRIVATE-A5-A6-EVIDENCE-v1' and
      manifest.get('source_root_receipt_sha256')==f6.ROOT_RECEIPT_SHA and
      manifest.get('source_f5c_replay_sha256')==f6.F5C_PINS['replay.log'] and
      manifest.get('a6_classification')=='ND' and
      manifest.get('risk_recalculated') is False and manifest.get('p8')=='NO-GO',
      'REPLAY_MANIFEST_CONTRACT_INVALID')
 paths={'root/'+n for n in f6.ROOT_FILES}|{'f5c/'+n for n in f6.F5C_PINS}|\
       {'f4/'+n for n in f6.F4_FILES}|{'report.json','a6-preview.json'}
 need(set(manifest.get('files_sha256',{}))==paths,'REPLAY_FILE_SET_CHANGED')
 need({p.name for p in session.iterdir()}=={'root','f5c','f4','report.json',
       'a6-preview.json','manifest.json'},'REPLAY_TOP_LEVEL_SCOPE')
 content={}
 for k in paths:
  p=session/k
  if '/' in k:
   verified_dir(p.parent,uid)
  v=private_source(p,uid)
  need(sha(v)==manifest['files_sha256'][k],'REPLAY_SHA_MISMATCH_'+k)
  content[k]=v
 need({p.name for p in (session/'root').iterdir()}==set(f6.ROOT_FILES) and
      {p.name for p in (session/'f5c').iterdir()}==set(f6.F5C_PINS) and
      {p.name for p in (session/'f4').iterdir()}==set(f6.F4_FILES),
      'REPLAY_SUBDIR_SCOPE')
 root={k.split('/',1)[1]:v for k,v in content.items() if k.startswith('root/')}
 a={k.split('/',1)[1]:v for k,v in content.items() if k.startswith('f5c/')}
 b={k.split('/',1)[1]:v for k,v in content.items() if k.startswith('f4/')}
 report,preview=f6.inspect(root,a,b)
 need(f6.canon(report)==content['report.json'] and
      f6.canon(preview)==content['a6-preview.json'],
      'REPLAY_RECOMPUTATION_DIFFERENT')
 return report,sha(f6.canon(manifest))

def main():
 os.umask(0o077)
 ap=argparse.ArgumentParser()
 g=ap.add_mutually_exclusive_group(required=True)
 g.add_argument('--ingest',action='store_true')
 g.add_argument('--replay',type=Path)
 args=ap.parse_args()
 try:
  need(os.geteuid()!=0,'MUST_RUN_UNPRIVILEGED')
  if args.ingest:
   root,a,b=sources()
   report,preview=f6.inspect(root,a,b)
   path=seal(root,a,b,report,preview)
   print('R114_F6_A5_REAL=PASS_FTP_220_AND_QGA_RECEIPT')
   print('R114_F6_SOURCE_SUPPORTS=3_CANDIDATES_NOT_A6_ADMITTED')
   print('R114_F6_A3_PRECONDITIONS=ND_ALL_FIVE')
   print('R114_F6_A6=ND_DRAFT_CATALOG_AND_A3_GUARDS')
   print('R114_F6_P8=NO-GO')
   return 0
  report,mhash=_read_session(args.replay)
  print('R114_F6_REPLAY=PASS_F5_F5C_F4_P7_AND_A6_PREVIEW')
  print('R114_F6_MANIFEST_SHA256='+mhash)
  print('R114_F6_A5=REAL_FTP_T01_GREETING_ATTESTED')
  print('R114_F6_A6='+report['a6_classification'])
  print('R114_F6_REPLAY_ROOT_COMMANDS=0')
  print('R114_F6_RISK_RECALCULATED=NO')
  print('R114_F6_P8=NO-GO')
  return 0
 except Exception as exc:
  print('R114_F6_STOP='+type(exc).__name__+':'+str(exc)[:160])
  print('R114_F6_NO_AUTORETRY=TRUE\nR114_F6_P8=NO-GO')
  return 23
if __name__=='__main__':raise SystemExit(main())
