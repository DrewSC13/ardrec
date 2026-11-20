#!/usr/bin/env python3
"""R114-F3: replay-verified physical asset anchors and A1-A10 authority barriers.

Reads existing private receipts only. NO sudo, virsh, systemctl, nft, QGA or TCP.
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
import sys

REPO=Path('/home/cicada/Development/GitHub/ardrec')
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r114_f2_family_gap as f2
from ardrec.coordination import r114_f3_asset_anchor as core
from ardrec.coordination import r113_f2_agent_ip_identity as ipcore
import ardrec_p14_r114_f2_family_gap as f2cli
import ardrec_p14_r113_f2_agent_ip_identity as ipcli

ROOT=Path('/home/cicada/ardrec-lab/r114-f3-physical-asset-anchors-v1')
FILES={'report.json','manifest.json'}
F2_DIR=Path(core.MATRIX_RECEIPT)
IDENTITY_DIR=Path(core.IDENTITY_RECEIPT)

class Stop(RuntimeError):pass

def need(ok:bool,why:str)->None:
 if not ok:raise Stop(why)

def private_dir(p:Path)->None:
 need(p.is_dir() and not p.is_symlink(),'PRIVATE_DIRECTORY_MISSING_OR_LINK_'+p.name)
 st=p.stat()
 need(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,
      'PRIVATE_DIRECTORY_OWNER_OR_MODE_'+p.name)

def read(p:Path,limit:int=300000)->bytes:
 need(not p.is_symlink() and p.is_file(),'PRIVATE_FILE_MISSING_OR_LINK_'+p.name)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_nlink==1
       and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=limit,
       'PRIVATE_FILE_OWNER_MODE_SIZE_'+p.name)
  chunks=[];left=st.st_size
  while left:
   buf=os.read(fd,left)
   need(bool(buf),'PRIVATE_FILE_SHORT_READ_'+p.name)
   chunks.append(buf);left-=len(buf)
  need(os.fstat(fd).st_mtime_ns==st.st_mtime_ns,
       'PRIVATE_FILE_CHANGED_DURING_READ_'+p.name)
  return b''.join(chunks)
 finally:os.close(fd)

def write(p:Path,raw:bytes):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as out:
  out.write(raw);out.flush();os.fsync(out.fileno())

def jload(raw:bytes,why:str)->dict:
 try: doc=json.loads(raw)
 except (ValueError,UnicodeError,RecursionError) as e:raise Stop('JSON_INVALID_'+why) from e
 need(type(doc) is dict,'DOCUMENT_NOT_OBJECT_'+why)
 return doc

def sources()->tuple[dict,dict,str,str,str]:
 """Authenticate both receipt chains, re-running existing *offline* verifiers."""
 private_dir(F2_DIR.parent);private_dir(F2_DIR)
 need({p.name for p in F2_DIR.iterdir()}=={'report.json','manifest.json'},
      'F2_MATRIX_FILES_SCOPE_CHANGED')
 matrix_manifest_raw=read(F2_DIR/'manifest.json')
 matrix_report_raw=read(F2_DIR/'report.json')
 need(core.digest(matrix_manifest_raw)==core.F2_MATRIX_MANIFEST_PIN and
      core.digest(matrix_report_raw)==core.F2_MATRIX_REPORT_PIN,
      'F2_MATRIX_RECEIPT_PIN_CHANGED')
 m=jload(matrix_manifest_raw,'f2_matrix_manifest')
 need(matrix_manifest_raw==f2.canonical(m) and
      m.get('schema')=='ARDREC-R114-F2-PRIVATE-REPLAY-v1' and
      m.get('report_sha256')==core.F2_MATRIX_REPORT_PIN and
      m.get('source_manifest_sha256')==f2.F1_MANIFEST_PIN and
      m.get('network_calls')==0 and m.get('root_calls')==0 and
      m.get('new_guest_exec')==0 and m.get('risk_recalculation') is False and
      m.get('p8')=='NO-GO','F2_MATRIX_MANIFEST_AUTHORITY_INVALID')
 matrix=jload(matrix_report_raw,'f2_matrix')
 need(matrix_report_raw==f2.canonical(matrix),'F2_MATRIX_NONCANONICAL')
 f1_report,f1_man_sha,f1_rep_sha=f2cli.source()
 f2.verify(matrix,f1_report,f1_report_sha256=f1_rep_sha,
           f1_manifest_sha256=f1_man_sha)
 need(m['source_report_sha256']==f1_rep_sha and
      m['catalog_sha256']==matrix['source_catalog_sha256'],
      'F2_MATRIX_SOURCE_CHANGED')

 private_dir(IDENTITY_DIR.parent);private_dir(IDENTITY_DIR)
 need({p.name for p in IDENTITY_DIR.iterdir()}=={'identity.json','manifest.json'},
      'R113_F2_PROOF_FILES_CHANGED')
 identity_manifest_raw=read(IDENTITY_DIR/'manifest.json')
 need(core.digest(identity_manifest_raw)==core.R113_F2_IDENTITY_MANIFEST_PIN,
      'R113_F2_QGA_MANIFEST_PIN_CHANGED')
 identity_manifest=jload(identity_manifest_raw,'identity_manifest')
 need(identity_manifest.get('schema')==ipcore.SCHEMA+'-manifest' and
      identity_manifest.get('traffic_authorized') is False and
      identity_manifest.get('protocol_connections')==0 and
      identity_manifest.get('p8_operational')=='NO-GO',
      'R113_F2_QGA_PROOF_AUTHORITY_CHANGED')
 identity_raw=read(IDENTITY_DIR/'identity.json')
 need(identity_manifest.get('files')=={'identity.json':core.digest(identity_raw)},
      'R113_F2_QGA_IDENTITY_HASH_CHANGED')
 identity=jload(identity_raw,'identity')
 core.validate_identity(identity)
 # Reopen original F1 physical capture and reproduce its classification.
 ipcli.verify(IDENTITY_DIR)
 return (matrix,identity,core.digest(matrix_manifest_raw),
         core.digest(identity_manifest_raw),core.digest(matrix_report_raw))

def build()->int:
 need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
 matrix,identity,msha,isha,rsha=sources()
 report=core.make_report(matrix,identity,matrix_manifest_sha256=msha,
                         identity_manifest_sha256=isha,matrix_report_sha256=rsha)
 output=core.canonical(report)
 private_dir(ROOT.parent)
 if not ROOT.exists():ROOT.mkdir(mode=0o700)
 private_dir(ROOT)
 need(not list(ROOT.glob('anchors-*')),'F3_ALREADY_CREATED_NO_RETRY')
 folder=ROOT/('anchors-'+secrets.token_hex(4))
 folder.mkdir(mode=0o700)
 print('R114_F3_SESSION='+str(folder),flush=True)
 try:
  write(folder/'report.json',output)
  manifest={
   'schema':'ARDREC-R114-F3-PRIVATE-REPLAY-v1',
   'source_f2_matrix_manifest_sha256':msha,
   'source_f2_matrix_report_sha256':rsha,
   'source_r113_f2_qga_manifest_sha256':isha,
   'source_catalog_sha256':report['source_catalog_sha256'],
   'report_sha256':core.digest(output),
   'network_calls':0,'new_guest_exec':0,'root_calls':0,
   'a5_starts':0,'a6_admitted':0,'risk_recalculation':False,
   'p8':'NO-GO',
  }
  write(folder/'manifest.json',core.canonical(manifest))
  core.verify(report,matrix,identity,matrix_manifest_sha256=msha,
              identity_manifest_sha256=isha,matrix_report_sha256=rsha)
  print('R114_F3_QGA_IDENTITY=PASS_SIX_MAC_IP_INTERFACES')
  print('R114_F3_PHYSICAL_ASSETS=PASS_3')
  print('R114_F3_PLANNING_CANDIDATES=PASS_29_NO_CASE_ID')
  print('R114_F3_A1_A10=AUTHORITY_BOUNDARIES_NOT_EXECUTED')
  print('R114_F3_A5_ATTEMPTS=0')
  print('R114_F3_A6_CONDITIONS=0_ND')
  print('R114_F3_SMB2=NOT_VERIFIED')
  print('R114_F3_REPORT_SHA256='+core.digest(output))
  print('R114_F3_MANIFEST_SHA256='+core.digest(core.canonical(manifest)))
  print('R114_F3_P8=NO-GO')
 except Exception as e:
  print('R114_F3_STOP='+type(e).__name__+':'+str(e)[:160],flush=True)
  print('R114_F3_INCOMPLETE_NO_AUTORETRY='+str(folder),flush=True)
  return 23
 return 0

def replay(folder:Path)->int:
 need(os.geteuid()!=0,'DO_NOT_RUN_AS_ROOT')
 private_dir(ROOT.parent);private_dir(ROOT);private_dir(folder)
 need(folder.parent==ROOT and re.fullmatch('anchors-[a-f0-9]{8}',folder.name) is not None,
      'REPLAY_FOLDER_INVALID')
 need({p.name for p in folder.iterdir()}==FILES,'REPLAY_FILE_SCOPE_CHANGED')
 mraw=read(folder/'manifest.json');m=jload(mraw,'manifest')
 need(mraw==core.canonical(m) and m.get('schema')=='ARDREC-R114-F3-PRIVATE-REPLAY-v1' and
      m.get('source_f2_matrix_manifest_sha256')==core.F2_MATRIX_MANIFEST_PIN and
      m.get('source_f2_matrix_report_sha256')==core.F2_MATRIX_REPORT_PIN and
      m.get('source_r113_f2_qga_manifest_sha256')==core.R113_F2_IDENTITY_MANIFEST_PIN and
      m.get('network_calls')==0 and m.get('new_guest_exec')==0 and
      m.get('root_calls')==0 and m.get('a5_starts')==0 and
      m.get('a6_admitted')==0 and m.get('risk_recalculation') is False and
      m.get('p8')=='NO-GO', 'REPLAY_MANIFEST_AUTHORITY_INVALID')
 rraw=read(folder/'report.json');r=jload(rraw,'report')
 need(rraw==core.canonical(r) and core.digest(rraw)==m.get('report_sha256'),
      'REPLAY_REPORT_HASH_INVALID')
 matrix,identity,msha,isha,rsha=sources()
 need((msha,isha,rsha)==(core.F2_MATRIX_MANIFEST_PIN,
      core.R113_F2_IDENTITY_MANIFEST_PIN,core.F2_MATRIX_REPORT_PIN) and
      m.get('source_catalog_sha256')==matrix['source_catalog_sha256'],
      'REPLAY_SOURCE_OR_CATALOG_CHANGED')
 core.verify(r,matrix,identity,matrix_manifest_sha256=msha,
             identity_manifest_sha256=isha,matrix_report_sha256=rsha)
 print('R114_F3_REPLAY=PASS_F1_F2_QGA_P7_AND_F6_LINEAGE')
 print('R114_F3_MANIFEST_SHA256='+core.digest(mraw))
 print('R114_F3_ASSETS=3')
 print('R114_F3_CANDIDATES=29_PLAN_ONLY')
 print('R114_F3_A5=NO_START_A6=ND_RISK=UNCOMPUTED')
 print('R114_F3_NEW_NETWORK=0')
 print('R114_F3_P8=NO-GO')
 return 0

def main():
 os.umask(0o077)
 p=argparse.ArgumentParser(description=__doc__)
 g=p.add_mutually_exclusive_group(required=True)
 g.add_argument('--build',action='store_true')
 g.add_argument('--replay',type=Path)
 args=p.parse_args()
 try:return build() if args.build else replay(args.replay)
 except Exception as e:
  print('R114_F3_STOP='+type(e).__name__+':'+str(e)[:190],flush=True)
  print('R114_F3_NO_AUTOMATIC_RETRY=TRUE',flush=True)
  print('R114_F3_P8=NO-GO')
  return 23

if __name__=='__main__':raise SystemExit(main())
