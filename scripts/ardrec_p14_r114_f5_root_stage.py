#!/usr/bin/env python3
"""Root-owned, source-authenticated staging for one FTP A5 window only.

No libvirt/nft/systemd writes. This must run only after explicit staging consent.
The old F10R root bundle is read as an already protected source of *data*.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
ORIGINAL=Path('/var/lib/ardrec/r113-f10r-window-v1')
DEST=Path('/var/lib/ardrec/r114-f5-ftp-t01-root-v1')
HEAD='636a6658b908fa1bdde1c095314382f9b9403000'
SCRIPT=REPO/'scripts/ardrec_p14_r114_f5_root_window.py'
CORE=REPO/'src/ardrec/coordination/r114_f5_ftp_case.py'
F4_DIR=Path('/home/cicada/ardrec-lab/r114-f4-ftp-configuration-read-v1/capture-499b62a4')
FILES={'root-window.py','core.py','contract.py','semantic.py',
       'ftp-runner.xml','ftp-target.xml','r34-ftp-only.nft','f4-report.json',
       'f4-manifest.json'}

class Stop(ValueError):pass
def need(ok,why):
 if not ok:raise Stop(why)
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(obj):return (json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def protected(root:Path,filename:str,uid:int=0):
 need(root.is_dir() and not root.is_symlink(),'SOURCE_DIR_INVALID')
 st=root.lstat()
 need(st.st_uid==uid and stat.S_IMODE(st.st_mode)==0o700,'SOURCE_DIR_MODE')
 p=root/filename
 need(p.is_file() and not p.is_symlink(),'SOURCE_FILE_MISSING_'+filename)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  need(stat.S_ISREG(st.st_mode) and st.st_uid==uid and st.st_nlink==1 and
       stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<250000,'SOURCE_FILE_MODE_'+filename)
  raw=os.read(fd,250001)
  need(len(raw)==st.st_size,'SOURCE_FILE_SIZE_CHANGED_'+filename)
  return raw
 finally:os.close(fd)

def select_ftp_nft(original:bytes)->bytes:
 """Restrict signed F8R 12 ACCEPT rules to the 4 rules for FTP only."""
 need(type(original) is bytes,'NFT_SOURCE_TYPE')
 lines=original.splitlines(keepends=True)
 need(len(lines)==17 and lines[0]==b'flush table bridge ardrec_r34_guard\n',
      'NFT_SOURCE_SHAPE_INVALID')
 allows=lines[1:13];drops=lines[13:]
 need(all(b' counter accept\n' in x for x in allows) and
      all(b' counter drop\n' in x for x in drops) and
      all(b'add rule bridge ardrec_r34_guard ' in x for x in allows+drops),
      'NFT_SOURCE_RULES_INVALID')
 selected=[x for x in allows if ((b'iifname "a33d31r" oifname "a33d31t"' in x) or
                                    (b'iifname "a33d31t" oifname "a33d31r"' in x))]
 need(len(selected)==4 and sum(b'ether type arp ' in x for x in selected)==2 and
      sum(b'ip protocol tcp ' in x for x in selected)==2 and
      all((b'10.203.31.1' in x and b'10.203.31.2' in x and
           (b'tcp dport 21 ' in x or b'tcp sport 21 ' in x or b'ether type arp ' in x)) for x in selected),
      'NFT_FTP_PAIR_MISMATCH')
 need(all(b'a33d30' not in x and b'a33d32' not in x for x in selected),
      'NON_FTP_ACCEPT_PRESENT')
 result=lines[0]+b''.join(selected)+b''.join(drops)
 need(len(result)<5000 and result.count(b' counter accept\n')==4 and
      result.count(b' counter drop\n')==4,'NFT_FTP_ONLY_INVALID')
 return result

def git(*args):
 p=subprocess.run(['/usr/bin/git','-c','safe.directory='+str(REPO),'-C',str(REPO),*args],capture_output=True,
                  text=True,stdin=subprocess.DEVNULL,timeout=20,check=False)
 need(p.returncode==0,'GIT_CMD_FAILED_'+args[0]);return p.stdout.strip()

def make_bundle():
 need(os.geteuid()==0,'ROOT_REQUIRED')
 need(git('branch','--show-current')=='feat/p14-r111-r114-real-lab' and
      git('status','--porcelain=v1','-uall')=='' and
      git('rev-parse','HEAD^')==HEAD,'EXPECTED_SIGNED_F5_COMMIT_AFTER_PARENT')
 names=['scripts/ardrec_p14_r114_f5_root_window.py',
        'scripts/ardrec_p14_r114_f5_root_stage.py',
        'src/ardrec/coordination/r114_f5_ftp_case.py']
 for name in names:
  source=REPO/name
  need(source.is_file() and not source.is_symlink(),'REPO_FILE_MISSING_'+name)
  need(subprocess.run(['/usr/bin/git','-c','safe.directory='+str(REPO),'-C',str(REPO),'cat-file','-e','HEAD:'+name],
      stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
      timeout=15).returncode==0,'REPO_FILE_UNTRACKED_'+name)
  version=subprocess.run(['/usr/bin/git','-c','safe.directory='+str(REPO),'-C',str(REPO),'show','HEAD:'+name],
      capture_output=True,stdin=subprocess.DEVNULL,timeout=15,check=True).stdout
  need(version==source.read_bytes(),'REPO_FILE_NOT_SIGNED_'+name)
 need('gpgsig' in git('cat-file','-p','HEAD'),'GIT_COMMIT_HAS_NO_SIGNATURE')
 need(not DEST.exists() and not DEST.is_symlink(),'ROOT_STAGE_ALREADY_EXISTS_NO_RETRY')
 prior=protected(ORIGINAL,'manifest.json')
 m=json.loads(prior)
 need(m.get('schema')=='ARDREC-R113-F10R-ROOT-BUNDLE-v1' and
      m.get('policy_host_pass_hash')=='b336a40851a5723b507449042aed7010729327c57336e90bd1e95251c774870e',
      'F10R_ROOT_SOURCE_MANIFEST_DRIFT')
 need(type(m.get('sha256')) is dict and
      all(sha(protected(ORIGINAL,n))==d for n,d in m['sha256'].items()),
      'F10R_ROOT_SOURCE_HASH_DRIFT')
 f4man=protected(F4_DIR,'manifest.json',uid=REPO.stat().st_uid)
 # F4 is user-owned. Its UID is verified against the signed-repository owner.
 need(sha(f4man)=='a3261fcefb15ef67c5436d74eadc546f3874cef9185d9f89ca22cf6976a31e62',
      'F4_MANIFEST_DRIFT')
 f4report=protected(F4_DIR,'report.json',uid=REPO.stat().st_uid)
 core={}
 exec(compile(CORE.read_bytes(),str(CORE),'exec'),core)
 core['validate_f4_source'](json.loads(f4report),json.loads(f4man),
    manifest_sha=sha(f4man),report_sha=sha(f4report))
 need(json.loads(f4man)['report_sha256']==sha(f4report),'F4_REPORT_HASH_DRIFT')
 original_nft=protected(ORIGINAL,'r34-window-CANDIDATE.nft')
 new_nft=select_ftp_nft(original_nft)
 out={
  'root-window.py':SCRIPT.read_bytes(),
  'core.py':CORE.read_bytes(),
  'contract.py':protected(ORIGINAL,'contract.py'),
  'semantic.py':protected(ORIGINAL,'semantic.py'),
  'ftp-runner.xml':protected(ORIGINAL,'ardrec-r113-runner-ftp-tcp-v1.xml'),
  'ftp-target.xml':protected(ORIGINAL,'ardrec-r113-ftp-tcp-v1.xml'),
  'r34-ftp-only.nft':new_nft,
  'f4-report.json':f4report,
  'f4-manifest.json':f4man,
 }
 need(set(out)==FILES,'ROOT_PAYLOAD_SCOPE_CHANGED')
 DEST.mkdir(mode=0o700)
 for name,content in sorted(out.items()):
  fd=os.open(DEST/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as h:
   h.write(content);h.flush();os.fsync(h.fileno())
 manifest={'schema':'ARDREC-R114-F5-FTP-ROOT-BUNDLE-v1',
     'source_f10r_bundle_manifest_sha256':sha(prior),
     'source_f4_manifest_sha256':sha(f4man),
     'source_f4_report_sha256':sha(f4report),
     'source_git_commit':git('rev-parse','HEAD'),
     'sha256':{k:sha(v) for k,v in sorted(out.items())},
     'allowed_tcp':[{'source':'10.203.31.1','target':'10.203.31.2','port':21}],
     'window_seconds':120,'f6_restore':'/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py',
     'a6_admitted':0,'p8':'NO-GO'}
 fd=os.open(DEST/'manifest.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as h:
  h.write(canonical(manifest));h.flush();os.fsync(h.fileno())
 print('R114_F5_ROOT_STAGE=PASS_'+str(len(out)+1)+'_FILES')
 print('R114_F5_F4_MANIFEST_SHA256='+sha(f4man))
 print('R114_F5_NFT_FTP_ACCEPTS=4')
 print('R114_F5_NFT_DEFAULT_DROPS=4')
 print('R114_F5_ROOT_NETWORK_WRITES=0')
 print('R114_F5_P8=NO-GO')

def main():
 os.umask(0o077)
 try:make_bundle()
 except Exception as e:
  print('R114_F5_ROOT_STAGE_STOP='+type(e).__name__+':'+str(e)[:140]);return 23
 return 0
if __name__=='__main__':raise SystemExit(main())
