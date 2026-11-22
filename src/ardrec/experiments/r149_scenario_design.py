"""R149: offline 54-unit scenario design; NEVER claims P7 freeze or physical evidence.

Select 54 real service/scenario identities in a private working CSV after external
review. Suggested family distribution is a DRAFT ONLY, not a real selection.
"""
from __future__ import annotations

import csv
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

from ardrec.experiments import r148_paired_register as r148

SCHEMA = 'ARDREC-R149-SCENARIO-DESIGN-v1'
FAMILY_SCHEMA = SCHEMA+'-catalog-checklist'
PROTOS = ('SSH','FTP','SMB')
FIELDS = ('slot_id','protocol','candidate_family','chosen_family','case_id',
          'scenario_id','service_instance_id','variation_reason',
          'scope_authorization_sha256','preregistration_sha256',
          'static_estimate','static_support_sha256')
ENTRY_FIELDS = FIELDS[3:]
MAX_CSV = 262144
MAX_JSON = 524288
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z', re.ASCII)
HEX64 = re.compile(r'[0-9a-f]{64}\Z',re.ASCII)
PLANNING_ONLY = 'DRAFT_SELECTION_UNVERIFIED_NOT_P7_FREEZE'

class Stop(ValueError):
    pass

def need(ok,code):
    if not ok: raise Stop(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(obj):
    return (json.dumps(obj,sort_keys=True,separators=(',',':'),
                       ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def decode(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_JSON,'DOCUMENT_SIZE_INVALID')
    def unique(pairs):
        d={}
        for k,v in pairs:
            need(k not in d,'JSON_DUPLICATE_KEY')
            d[k]=v
        return d
    try:
        obj=json.loads(raw,object_pairs_hook=unique,
                       parse_constant=lambda _:need(False,'JSON_NONFINITE'))
        need(type(obj) is dict and canonical(obj)==raw,'JSON_NOT_CANONICAL')
        return obj
    except (ValueError,UnicodeError,TypeError,OverflowError) as exc:
        raise Stop('DOCUMENT_INVALID') from exc

def sealed(doc):
    need('sha256' not in doc,'DOUBLE_SEAL')
    result=dict(doc);result['sha256']=sha(canonical(doc));return result

def verify_seal(doc):
    need(type(doc) is dict and doc.get('sha256')==sha(canonical(
         {k:v for k,v in doc.items() if k!='sha256'})),'DOCUMENT_SEAL_INVALID')

def catalog_families(catalog_raw):
    need(sha(catalog_raw)=='5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e',
         'CATALOG_PIN_INVALID')
    obj=json.loads(catalog_raw)
    families=obj.get('families')
    need(type(families) is list and len(families)==25,'CATALOG_FAMILIES_INVALID')
    result={p:[] for p in PROTOS}
    for f in families:
        need(type(f) is dict and type(f.get('id')) is str,'CATALOG_FAMILY_INVALID')
        proto=f['id'][:3]
        need(proto in result and f.get('protocol')==proto.lower(),'CATALOG_PROTOCOL_INVALID')
        need(type(f.get('condition_es')) is str and
             type(f.get('minimum_action_es')) is str and
             type(f.get('preconditions')) is list and
             type(f.get('required_supports')) is list,'CATALOG_FIELDS_INVALID')
        need(f['id'] not in [x['id'] for x in result[proto]],'FAMILY_DUPLICATE')
        result[proto].append(f)
    need({p:len(result[p]) for p in PROTOS}==r148.FAMILIES,'CATALOG_COUNTS_INVALID')
    return result

def csv_bytes(rows):
    h=io.StringIO(newline='');w=csv.DictWriter(h,fieldnames=FIELDS,lineterminator='\n',
                                              extrasaction='raise')
    w.writeheader()
    for row in rows:w.writerow(row)
    return h.getvalue().encode('utf-8')

def parse_csv(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_CSV,'CSV_SIZE_INVALID')
    try:
        text=raw.decode('utf-8','strict')
        need('\x00' not in text and '\r' not in text,'CSV_CONTROL_INVALID')
        r=csv.reader(io.StringIO(text,newline=''),strict=True)
        records=list(r)
    except (UnicodeError,csv.Error) as exc:
        raise Stop('CSV_INVALID') from exc
    need(len(records)==55 and tuple(records[0])==FIELDS,'CSV_HEADER_OR_ROWS_INVALID')
    need(all(len(x)==len(FIELDS) for x in records[1:]),'CSV_COLUMNS_INVALID')
    return [dict(zip(FIELDS,line)) for line in records[1:]]

def draft(catalog_raw, protocol, registry):
    audit=r148.validate(protocol,registry,catalog_raw)
    need(audit['statuses']['PLANNED_UNASSIGNED']==54,'REGISTER_NOT_EMPTY')
    fam=catalog_families(catalog_raw)
    rows=[]
    for i,s in enumerate(registry['slots']):
        proto=s['protocol'];fams=fam[proto]
        suggestion=fams[(s['planning_position']-1)%len(fams)]['id']
        rows.append(dict(zip(FIELDS,[s['slot_id'],proto,suggestion]+['']*len(ENTRY_FIELDS))))
    counts={p:{} for p in PROTOS}
    for row in rows:
        p=row['protocol'];f=row['candidate_family']
        counts[p][f]=counts[p].get(f,0)+1
    plan=sealed({'schema':SCHEMA,'r148_protocol_sha256':protocol['sha256'],
         'r148_registry_sha256':registry['sha256'],
         'r148_head':protocol['head'],'catalog_sha256':sha(catalog_raw),
         'slots':54,'candidate_counts':counts,
         'status':PLANNING_ONLY,
         'selection_is_real':False,'physical_evidence_verified':False,
         'independent_rubric_verified':False,'p7':'DRAFT_NOT_FROZEN',
         'p8':'NO-GO','a6':'ND','a9':'NOT_PUBLISHED'})
    checklist=sealed({'schema':FAMILY_SCHEMA,
         'catalog_sha256':sha(catalog_raw),'count':25,
         'families':[{ 'id':f['id'],'protocol':p,
              'condition_es':f['condition_es'],
              'minimum_action_es':f['minimum_action_es'],
              'preconditions':f['preconditions'],
              'required_supports':f['required_supports'],
              'acceptance_supports':f['acceptance_supports'],
              'parameter_slots':f['parameter_slots'],
              'cleanup':f['cleanup']}
             for p in PROTOS for f in fam[p]]})
    return plan,checklist,rows

def _validate_line(idx,row,expected,families):
    need(set(row)==set(FIELDS) and row['slot_id']==expected['slot_id'] and
         row['protocol']==expected['protocol'] and
         row['candidate_family']==expected['candidate_family'],
         'SLOT_OR_PROPOSAL_TAMPERED')
    proto=row['protocol']
    for name in ENTRY_FIELDS:
        val=row[name]
        need(type(val) is str and len(val)<=256 and
             all(ord(ch)>=32 for ch in val), 'ENTRY_CONTROL_OR_SIZE_INVALID')
        # Prevent CSV / spreadsheet formula injection in free text and identifiers.
        need(not val.startswith(('=','+','-','@')),'SPREADSHEET_FORMULA_DENIED')
    chosen=row['chosen_family']
    need(not chosen or chosen in families[proto],'CHOSEN_FAMILY_INVALID')
    for name in ('case_id','scenario_id','service_instance_id'):
        v=row[name];need(not v or ID.fullmatch(v),'IDENTIFIER_INVALID')
    reason=row['variation_reason']
    need(not reason or 8<=len(reason)<=256,'VARIATION_REASON_INVALID')
    for name in ('scope_authorization_sha256','preregistration_sha256','static_support_sha256'):
        v=row[name];need(not v or HEX64.fullmatch(v),'DIGEST_REFERENCE_INVALID')
    val=row['static_estimate']
    if val:
        try:r148._decimal(val)
        except r148.Stop as exc:raise Stop(str(exc)) from exc
    entered=[row[k]!='' for k in ENTRY_FIELDS]
    return 'COMPLETE' if all(entered) else ('PARTIAL' if any(entered) else 'EMPTY')

def validate_selection(plan, checklist, working_raw, catalog_raw, protocol, registry):
    canonical_plan,canonical_checklist,proposed=draft(catalog_raw,protocol,registry)
    verify_seal(plan);verify_seal(checklist)
    need(plan==canonical_plan and checklist==canonical_checklist,
         'PLAN_OR_CATALOG_CHECKLIST_CHANGED')
    rows=parse_csv(working_raw)
    families={p:set(plan['candidate_counts'][p]) for p in PROTOS}
    states={'EMPTY':0,'PARTIAL':0,'COMPLETE':0}
    cases=set();scenarios=set();covered={p:set() for p in PROTOS}
    for idx,(row,expected) in enumerate(zip(rows,proposed)):
        state=_validate_line(idx,row,expected,families)
        states[state]+=1
        if row['case_id']:
            need(row['case_id'] not in cases,'DUPLICATE_CASE_ID')
            cases.add(row['case_id'])
        if row['scenario_id']:
            need(row['scenario_id'] not in scenarios,'DUPLICATE_SCENARIO_ID')
            scenarios.add(row['scenario_id'])
        if state=='COMPLETE':covered[row['protocol']].add(row['chosen_family'])
    result={'schema':SCHEMA+'-read-only-readiness',
      'plan_sha256':plan['sha256'],'working_sha256':sha(working_raw),
      'slots':54,'statuses':states,
      'candidate_family_coverage':sum(len(x) for x in plan['candidate_counts'].values()),
      'complete_family_coverage':{k:len(v) for k,v in covered.items()},
      'readiness':('CANDIDATE_COMPLETE_UNVERIFIED' if states['COMPLETE']==54
                   else 'BLOCKED_INCOMPLETE_CANDIDATES'),
      'physical_observations':0,'p7':'DRAFT_NOT_FROZEN','p8':'NO-GO',
      'a6':'ND','a9':'NOT_PUBLISHED','claim':'NEVER_THESIS_RESULT_OR_AUTHORIZATION'}
    return sealed(result)

def _safe_dir(folder):
    need(isinstance(folder,Path) and folder.is_absolute() and
         '..' not in folder.parts,'PATH_INVALID')
    st=folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and not folder.is_symlink() and
         st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,
         'DIRECTORY_UNSAFE')

def _read(folder,name):
    need(name in ('plan.json','family-checklist.json','family-proposal.csv',
                  'selection-working.csv'),'FILE_NAME_REJECTED')
    fd=os.open(folder/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==os.geteuid() and
             0<st.st_size<=MAX_JSON,'FILE_UNSAFE')
        raw=b''
        while len(raw)<=MAX_JSON:
            p=os.read(fd,65536)
            if not p:break
            raw+=p
        need(len(raw)==st.st_size and len(raw)<=MAX_JSON and
             os.fstat(fd).st_size==st.st_size,'FILE_CHANGED')
        return raw
    finally:os.close(fd)

def _new_file(folder,name,raw):
    need(0<len(raw)<=MAX_JSON,'FILE_BYTES_INVALID')
    fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            fd=-1;out.write(raw);out.flush();os.fsync(out.fileno())
    finally:
        if fd>=0:os.close(fd)

def create(folder,catalog_raw,protocol,registry):
    need(os.geteuid()!=0,'ROOT_FORBIDDEN')
    need(isinstance(folder,Path) and folder.is_absolute() and
         '..' not in folder.parts and not folder.exists() and
         not folder.is_symlink(),'NEW_FOLDER_REQUIRED')
    parent=folder.parent
    pst=parent.lstat()
    need(stat.S_ISDIR(pst.st_mode) and pst.st_uid==os.geteuid() and
         not parent.is_symlink() and not(pst.st_mode&0o022),'PARENT_UNSAFE')
    plan,checklist,rows=draft(catalog_raw,protocol,registry)
    folder.mkdir(mode=0o700)
    _safe_dir(folder)
    _new_file(folder,'plan.json',canonical(plan))
    _new_file(folder,'family-checklist.json',canonical(checklist))
    proposal=csv_bytes(rows)
    _new_file(folder,'family-proposal.csv',proposal)
    _new_file(folder,'selection-working.csv',proposal)
    return read(folder,catalog_raw,protocol,registry)

def read(folder,catalog_raw,protocol,registry):
    _safe_dir(folder)
    plan=decode(_read(folder,'plan.json'))
    checklist=decode(_read(folder,'family-checklist.json'))
    _,_,expected=draft(catalog_raw,protocol,registry)
    need(_read(folder,'family-proposal.csv')==csv_bytes(expected),
         'ORIGINAL_PROPOSAL_CHANGED')
    return validate_selection(plan,checklist,_read(folder,'selection-working.csv'),
                              catalog_raw,protocol,registry)
