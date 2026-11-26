"""R148 — 54 UNASSIGNED slots, safeguarded local register and paired analysis.

All supplied measurements and digest references are UNVERIFIED. This module
cannot attest physical provenance, validate P7 freeze, authorize P8, admit A6,
or publish A9. It cannot send network traffic or start a VM.
"""
from __future__ import annotations

import csv
from decimal import Context, Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat

from ardrec.coordination.r125_integrated_acceptance import coverage as r125_coverage

SCHEMA = 'ARDREC-R148-EXPERIMENT-54-PAIRED-REGISTER-v1'
REGISTRY_SCHEMA = SCHEMA + '-observations'
PROTOCOL_SCHEMA = SCHEMA + '-protocol'
REPORT_SCHEMA = SCHEMA + '-read-only-report'
PROTOCOLS = ('SSH', 'FTP', 'SMB')
COUNTS = {'SSH':18,'FTP':18,'SMB':18}
FAMILIES = {'SSH':8,'FTP':8,'SMB':9}
HEX40 = re.compile(r'[0-9a-f]{40}\Z', re.ASCII)
HEX64 = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z',re.ASCII)
STATUSES = ('PLANNED_UNASSIGNED', 'RECORDED_UNVERIFIED', 'EXCLUDED_UNVERIFIED')
REFS = ('static_freeze_sha256', 'physical_attempt_receipt_sha256',
        'ardrec_a9_receipt_sha256', 'common_evidence_sha256',
        'independent_rubric_receipt_sha256')
VALUES = ('static_estimate', 'ardrec_estimate', 'independent_reference')
MAX_BYTES = 524288

class Stop(ValueError):
    """Stable fail-closed reason."""

def need(ok:bool, reason:str)->None:
    if not ok:
        raise Stop(reason)

def canonical(doc:dict)->bytes:
    need(type(doc) is dict,'DOCUMENT_REQUIRED')
    return (json.dumps(doc,sort_keys=True,separators=(',', ':'),
                       ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')

def digest(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()

def _pairs(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'JSON_DUPLICATE_KEY')
        out[k]=v
    return out

def decode(raw:bytes)->dict:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES,'DOCUMENT_SIZE_INVALID')
    try:
        obj=json.loads(raw,object_pairs_hook=_pairs,
                       parse_constant=lambda _:need(False,'NONFINITE_JSON'))
        need(type(obj) is dict and canonical(obj)==raw,'DOCUMENT_NOT_CANONICAL')
    except (TypeError,ValueError,UnicodeError,OverflowError) as exc:
        raise Stop('DOCUMENT_INVALID') from exc
    return obj

def _seal(doc:dict)->dict:
    need('sha256' not in doc,'DOCUMENT_SEAL_ALREADY_SET')
    out=dict(doc)
    out['sha256']=digest(canonical(doc))
    return out

def _verify_seal(doc:dict, reason='DOCUMENT_SEAL_INVALID')->None:
    need(type(doc) is dict and isinstance(doc.get('sha256'),str),reason)
    need(doc['sha256']==digest(canonical({k:v for k,v in doc.items() if k!='sha256'})),reason)

def _slot(proto:str,position:int)->dict:
    return {'slot_id':f'{proto}-{position:02}', 'protocol':proto,
            'planning_position':position,'scenario_id':None,'case_id':None,
            'family_id':None,'status':'PLANNED_UNASSIGNED',
            'static_estimate':None,'ardrec_estimate':None,
            'independent_reference':None,
            **{k:None for k in REFS},
            'exclusion_reason':None,'exclusion_decision_sha256':None}

def build(catalog_raw:bytes,head:str)->tuple[dict,dict]:
    """Prepare exactly 54 *positions*, using the R125 pinned draft catalog."""
    need(type(head) is str and HEX40.fullmatch(head),'HEAD_INVALID')
    cap=r125_coverage(catalog_raw)
    need(cap['planned_unit_count']==54 and cap['assigned_real_unit_count']==0
         and cap['p7']=='DRAFT_NOT_FROZEN' and cap['p8']=='NO-GO'
         and cap['expected_by_protocol']==COUNTS
         and cap['family_counts_by_protocol']==FAMILIES,
         'R125_COVERAGE_INVALID')
    protocol=_seal({'schema':PROTOCOL_SCHEMA,'head':head,
        'catalog_sha256':digest(catalog_raw),'r125_coverage_sha256':cap['sha256'],
        'planned_total':54,'expected_by_protocol':COUNTS.copy(),
        'p7':'DRAFT_NOT_FROZEN','p8':'NO-GO','pilot':'NOT_COMPLETED',
        'static_freeze_required_before_technical_tests':True,
        'independent_rubric_required':True,
        'sample_replace_on_exclusion':False,
        'analysis':{'pairing':'SAME_SERVICE_SCENARIO',
          'error_metric':'ABSOLUTE_ERROR_AGAINST_INDEPENDENT_REFERENCE',
          'difference':'ABS_STATIC_MINUS_ABS_ARDREC',
          'alternative':'STATIC_ERROR_GREATER_THAN_ARDREC_ERROR',
          'wilcoxon':'EXACT_CONDITIONAL_SIGN_FLIP_MIDRANK',
          'zeros':'RETAIN_ROWS_EXCLUDE_ZERO_FROM_WILCOXON_RANKS',
          'alpha':'0.05','protocol_subgroups':'DESCRIPTIVE_ONLY'}})
    registry=_seal({'schema':REGISTRY_SCHEMA,'protocol_sha256':protocol['sha256'],
        'data_authority':'UNVERIFIED_INPUTS_ONLY',
        'experiment_phase':'BEFORE_PILOT_AND_P7_FREEZE',
        'common_scale':None, 'pilot_receipt_sha256':None,
        'p7_frozen_catalog_sha256':None,
        'rubric_frozen_receipt_sha256':None,
        'preregistration_receipt_sha256':None,
        'slots':[_slot(p,i) for p in PROTOCOLS for i in range(1,19)]})
    validate(protocol,registry,catalog_raw)
    return protocol,registry

def _decimal(value):
    need(type(value) is str and len(value)<=48 and value==value.strip()
         and value!='','DECIMAL_TEXT_REQUIRED')
    try:
        d=Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise Stop('DECIMAL_INVALID') from exc
    need(d.is_finite() and d>=0 and d.adjusted()<=12,'DECIMAL_RANGE_OR_FINITE')
    need(-48 <= d.as_tuple().exponent <= 12, 'DECIMAL_EXPONENT_OUT_OF_RANGE')
    return d

def _digest_or_none(value):
    return value is None or (type(value) is str and HEX64.fullmatch(value))

def validate(protocol:dict, registry:dict,catalog_raw:bytes)->dict:
    """Structural audit. Does NOT authenticate submitted digests or measurements."""
    _verify_seal(protocol,'PROTOCOL_SEAL_INVALID')
    _verify_seal(registry,'REGISTRY_SEAL_INVALID')
    need(protocol.get('schema')==PROTOCOL_SCHEMA and
         type(protocol.get('head')) is str and HEX40.fullmatch(protocol['head']) and
         protocol.get('catalog_sha256')==digest(catalog_raw) and
         protocol.get('planned_total')==54 and
         protocol.get('expected_by_protocol')==COUNTS and
         protocol.get('p7')=='DRAFT_NOT_FROZEN' and protocol.get('p8')=='NO-GO' and
         protocol.get('pilot')=='NOT_COMPLETED' and
         protocol.get('static_freeze_required_before_technical_tests') is True and
         protocol.get('independent_rubric_required') is True and
         protocol.get('sample_replace_on_exclusion') is False,
         'PROTOCOL_FIELDS_INVALID')
    cap=r125_coverage(catalog_raw)
    need(protocol.get('r125_coverage_sha256')==cap['sha256'],
         'PROTOCOL_COVERAGE_CHANGED')
    need(protocol.get('analysis')=={
        'pairing':'SAME_SERVICE_SCENARIO',
        'error_metric':'ABSOLUTE_ERROR_AGAINST_INDEPENDENT_REFERENCE',
        'difference':'ABS_STATIC_MINUS_ABS_ARDREC',
        'alternative':'STATIC_ERROR_GREATER_THAN_ARDREC_ERROR',
        'wilcoxon':'EXACT_CONDITIONAL_SIGN_FLIP_MIDRANK',
        'zeros':'RETAIN_ROWS_EXCLUDE_ZERO_FROM_WILCOXON_RANKS',
        'alpha':'0.05','protocol_subgroups':'DESCRIPTIVE_ONLY'},
         'ANALYSIS_PROTOCOL_MUTATED')
    need(type(registry) is dict and registry.get('schema')==REGISTRY_SCHEMA and
         registry.get('protocol_sha256')==protocol['sha256'] and
         registry.get('data_authority')=='UNVERIFIED_INPUTS_ONLY' and
         registry.get('experiment_phase')=='BEFORE_PILOT_AND_P7_FREEZE',
         'REGISTRY_FIELDS_INVALID')
    keys=set(_slot('SSH',1))
    slots=registry.get('slots')
    need(type(slots) is list and len(slots)==54,'SLOTS_NOT_54')
    families={f['id'] for f in json.loads(catalog_raw)['families']}
    statuses={s:0 for s in STATUSES}
    identities=set();cases=set();scenarios=set()
    for idx,s in enumerate(slots):
        proto=PROTOCOLS[idx//18]
        pos=(idx%18)+1
        need(type(s) is dict and set(s)==keys and
             s['slot_id']==f'{proto}-{pos:02}' and
             s['protocol']==proto and type(s['planning_position']) is int and
             s['planning_position']==pos,'SLOT_IDENTITY_ORDER_INVALID')
        status=s['status'];need(status in STATUSES,'SLOT_STATUS_INVALID')
        statuses[status]+=1
        if status=='PLANNED_UNASSIGNED':
            need(s==_slot(proto,pos),'PLANNED_SLOT_CANNOT_HAVE_DATA')
            continue
        need(type(s['scenario_id']) is str and ID.fullmatch(s['scenario_id']) and
             type(s['case_id']) is str and ID.fullmatch(s['case_id']) and
             type(s['family_id']) is str and s['family_id'] in families and
             s['family_id'].startswith(proto+'-'),
             'RECORDED_CASE_SCENARIO_FAMILY_INVALID')
        need(s['scenario_id'] not in scenarios and s['case_id'] not in cases,
             'DUPLICATE_CASE_OR_SCENARIO')
        scenarios.add(s['scenario_id']); cases.add(s['case_id'])
        if status=='EXCLUDED_UNVERIFIED':
            need(type(s['exclusion_reason']) is str and
                 3<=len(s['exclusion_reason'])<=256 and
                 type(s['exclusion_decision_sha256']) is str and
                 HEX64.fullmatch(s['exclusion_decision_sha256']) and
                 all(s[k] is None for k in VALUES+REFS),
                 'EXCLUSION_RECORD_INCOMPLETE')
        else:
            need(s['exclusion_reason'] is None and
                 s['exclusion_decision_sha256'] is None and
                 all(type(s[k]) is str and HEX64.fullmatch(s[k]) for k in REFS),
                 'MEASUREMENT_REFERENCE_MISSING')
            vals=[_decimal(s[k]) for k in VALUES]
            scale=registry.get('common_scale')
            need(type(scale) is dict and set(scale)=={'lower','upper'},
                 'COMMON_SCALE_REQUIRED')
            low=_decimal(scale['lower']); high=_decimal(scale['upper'])
            need(low<high and all(low<=v<=high for v in vals),
                 'VALUES_OUTSIDE_COMMON_SCALE')
    scale=registry.get('common_scale')
    need(scale is None or (type(scale) is dict and set(scale)=={'lower','upper'}
          and _decimal(scale['lower']) < _decimal(scale['upper'])),
          'COMMON_SCALE_INVALID')
    need(all(_digest_or_none(registry.get(k)) for k in (
        'pilot_receipt_sha256','p7_frozen_catalog_sha256',
        'rubric_frozen_receipt_sha256','preregistration_receipt_sha256')),
        'EXTERNAL_RECEIPT_DIGEST_INVALID')
    # Such digests are user input and may NEVER authorize P7/P8/A6/A9.
    return {'schema':SCHEMA+'-structural-audit',
            'planned':54,'by_protocol':COUNTS.copy(),
            'statuses':statuses,'confirmed_physical_observations':0,
            'independent_reference_attested':False,
            'p7_frozen_verified':False,'p8':'NO-GO',
            'a6':'ND','a9':'NOT_PUBLISHED',
            'authority':'UNVERIFIED_DOCUMENTARY_STRUCTURE_ONLY'}

def _midranks(values:list[Decimal])->list[int]:
    """Rank |difference| with averaged ties; return twice each midrank."""
    order=sorted(range(len(values)),key=lambda i:values[i])
    ranks=[0]*len(values)
    cursor=0
    while cursor<len(order):
        last=cursor+1
        while last<len(order) and values[order[last]]==values[order[cursor]]:
            last+=1
        twice=(cursor+1)+last
        for i in order[cursor:last]:ranks[i]=twice
        cursor=last
    return ranks

def wilcoxon_exact(diffs:list[Decimal])->dict:
    """Exact one-sided sign-flip tail, tie-aware; zeros retained in count.

    Conditional on observed nonzero absolute magnitudes. No normal
    approximation, no p-hacking selection, no continuity correction.
    """
    need(type(diffs) is list and len(diffs)<=54 and
         all(type(x) is Decimal and x.is_finite() for x in diffs),
         'DIFFERENCES_INVALID')
    nonzero=[d for d in diffs if d!=0]
    zero=len(diffs)-len(nonzero)
    n=len(nonzero)
    if n==0:
        return {'n_pairs':len(diffs),'n_nonzero':0,'n_zero':zero,
                'w_plus_twice':None,'w_total_twice':None,
                'p_one_sided_exact':None,'p_fraction':None,
                'decision':'NOT_TESTABLE_ALL_ZERO_OR_NO_PAIRS'}
    ranks=_midranks([x.copy_abs() for x in nonzero])
    observed=sum(w for w,d in zip(ranks,nonzero) if d>0)
    distribution=[0]*(sum(ranks)+1)
    distribution[0]=1
    top=0
    for w in ranks:
        for j in range(top,-1,-1):
            if distribution[j]:distribution[j+w]+=distribution[j]
        top+=w
    total=1<<n
    tail=sum(distribution[observed:])
    fraction=Fraction(tail,total)
    with localcontext(Context(prec=60, rounding=ROUND_HALF_EVEN)):
        probability=Decimal(fraction.numerator)/Decimal(fraction.denominator)
    decision='FAVORS_ARDREC_UNVERIFIED_EXPLORATORY' if probability<Decimal('0.05') else 'NOT_SIGNIFICANT_UNVERIFIED_EXPLORATORY'
    return {'n_pairs':len(diffs),'n_nonzero':n,'n_zero':zero,
            'w_plus_twice':observed,'w_total_twice':sum(ranks),
            'p_one_sided_exact':str(probability),
            'p_fraction':f'{fraction.numerator}/{fraction.denominator}',
            'decision':decision}

def analyze(protocol:dict,registry:dict,catalog_raw:bytes)->dict:
    # 13 integer digits + 48 fractional digits + bounded sums fit exactly.
    with localcontext(Context(prec=80, rounding=ROUND_HALF_EVEN)):
        return _analyze_exact(protocol, registry, catalog_raw)

def _analyze_exact(protocol:dict,registry:dict,catalog_raw:bytes)->dict:
    audit=validate(protocol,registry,catalog_raw)
    selected=[]
    for s in registry['slots']:
        if s['status']=='RECORDED_UNVERIFIED':
            static,ardrec,ref=(_decimal(s[k]) for k in VALUES)
            selected.append({'slot_id':s['slot_id'],'protocol':s['protocol'],
                'static_absolute_error':abs(static-ref),
                'ardrec_absolute_error':abs(ardrec-ref),
                'difference':abs(static-ref)-abs(ardrec-ref)})
    diffs=[row['difference'] for row in selected]
    test=wilcoxon_exact(diffs)
    def decimal_str(d:Decimal)->str:
        return format(d,'f')
    group={}
    for proto in PROTOCOLS:
        rows=[r for r in selected if r['protocol']==proto]
        group[proto]={'recorded_unverified':len(rows),
                      'planned':18}
        if rows:
            n=Decimal(len(rows))
            sum_static=sum((r['static_absolute_error'] for r in rows),Decimal(0))
            sum_ardrec=sum((r['ardrec_absolute_error'] for r in rows),Decimal(0))
            # Means may recur; round only this descriptive presentation.
            with localcontext(Context(prec=28, rounding=ROUND_HALF_EVEN)):
                group[proto]['mean_static_absolute_error']=decimal_str(sum_static/n)
                group[proto]['mean_ardrec_absolute_error']=decimal_str(sum_ardrec/n)
        else:
            group[proto]['mean_static_absolute_error']=None
            group[proto]['mean_ardrec_absolute_error']=None
    out={'schema':REPORT_SCHEMA,'head':protocol['head'],
         'protocol_sha256':protocol['sha256'],'registry_sha256':registry['sha256'],
         'planned':54,'recorded_unverified':len(selected),
         'excluded_unverified':audit['statuses']['EXCLUDED_UNVERIFIED'],
         'unassigned':audit['statuses']['PLANNED_UNASSIGNED'],
         'primary_comparison':test,'by_protocol_descriptive':group,
         'physical_evidence_verified':False,'independent_rubric_verified':False,
         'p7_frozen_verified':False,'a6':'ND','a9':'NOT_PUBLISHED','p8':'NO-GO',
         'claim':'EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT'}
    return _seal(out)

def _private_dir(folder:Path)->None:
    need(folder.is_absolute() and '..' not in folder.parts,'PRIVATE_PATH_INVALID')
    st=folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         stat.S_IMODE(st.st_mode)==0o700 and not folder.is_symlink(),
         'PRIVATE_DIRECTORY_UNSAFE')

def _safe_parent(folder:Path)->None:
    need(folder.is_absolute() and '..' not in folder.parts,'PARENT_PATH_INVALID')
    st=folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         not folder.is_symlink() and not(st.st_mode & 0o022),
         'PARENT_DIRECTORY_UNSAFE')

def _private_file(folder:Path,name:str)->bytes:
    need(name in ('protocol.json','observations.json'),'PRIVATE_FILENAME_REJECTED')
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC
    fd=os.open(folder/name,flags)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_nlink==1 and
             0<st.st_size<=MAX_BYTES,'PRIVATE_FILE_METADATA_INVALID')
        raw=b''
        while len(raw)<=MAX_BYTES:
            part=os.read(fd,65536)
            if not part:break
            raw+=part
        need(0<len(raw)<=MAX_BYTES and len(raw)==st.st_size and
             os.fstat(fd).st_size==st.st_size,'PRIVATE_FILE_CHANGED')
        return raw
    finally:
        os.close(fd)

def _exclusive(folder:Path,name:str,raw:bytes)->None:
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES,'WRITE_BYTES_INVALID')
    fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,'wb') as out:
            fd=-1;out.write(raw);out.flush();os.fsync(out.fileno())
    finally:
        if fd>=0:os.close(fd)

def initialize(folder:Path,catalog_raw:bytes,head:str)->dict:
    """Create one private 0700 study skeleton; never accepts a preexisting target."""
    need(os.geteuid()!=0,'ROOT_FORBIDDEN')
    need(isinstance(folder,Path) and folder.is_absolute() and
         '..' not in folder.parts and not folder.exists() and
         not folder.is_symlink(),'DESTINATION_MUST_BE_NEW')
    _safe_parent(folder.parent)
    protocol,registry=build(catalog_raw,head)
    folder.mkdir(mode=0o700)
    _private_dir(folder)
    try:
        _exclusive(folder,'protocol.json',canonical(protocol))
        _exclusive(folder,'observations.json',canonical(registry))
        readback=read(folder,catalog_raw)
        need(readback[0]==protocol and readback[1]==registry,'READBACK_FAILED')
        return validate(protocol,registry,catalog_raw)
    except Exception:
        # Never erase or rewrite partially created evidence; allow manual audit.
        raise

def read(folder:Path,catalog_raw:bytes)->tuple[dict,dict]:
    _private_dir(folder)
    protocol=decode(_private_file(folder,'protocol.json'))
    registry=decode(_private_file(folder,'observations.json'))
    validate(protocol,registry,catalog_raw)
    return protocol,registry

def export_csv(registry:dict)->bytes:
    """Tabular view of slots; all references remain unverified."""
    names=list(_slot('SSH',1))
    output=io.StringIO(newline='')
    writer=csv.DictWriter(output,fieldnames=names,extrasaction='raise',lineterminator='\n')
    writer.writeheader()
    for slot in registry['slots']:
        writer.writerow({k:slot[k] for k in names})
    return output.getvalue().encode('utf-8')
