"""R129: fail-closed A6/A7/A8/A9/A10 handoff with durable audit replay.

The existing F14 classification is ND until an independent witness verifies
physical FTP source AND support semantics. This implementation refuses to
open DurableStore or fabricate a technical verdict from a 220 greeting.
A9's existing transactional publication API remains the sole authority.
"""
from __future__ import annotations

from pathlib import Path
import os
import stat
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r126_operational_controller as r126
from ardrec.coordination import r128_ftp_pilot as r128
from ardrec.coordination import r127_failure_observer as b6

SCHEMA='ARDREC-R129-FTP-T01-A6-A10-TRANSITIONAL-RECONCILIATION-v1'
ROOT=Path('/home/cicada/ardrec-lab/r129-ftp-a6-a10-audit-v1')

class Stop(ValueError):
    """Fail closed on missing or altered evidence."""


def need(ok: bool, code: str) -> None:
    if not ok: raise Stop(code)


def reconcile(*, intake: dict, case: dict, catalog_raw: bytes) -> dict[str,Any]:
    need(type(intake) is dict and intake.get('schema')==r128.SCHEMA and
         intake.get('sha256')==r126.sha({k:v for k,v in intake.items() if k!='sha256'}) and
         intake.get('a6')=='ND' and intake.get('a9_generation') is None and
         intake.get('p8')=='NO-GO' and
         intake.get('source_bytes_independently_attested') is False and
         intake.get('r127_observation_is_root_authority') is False and
         ((intake.get('r127_observation_sha256') is None and
           intake.get('r127_observation_status') is None) or
          (type(intake.get('r127_observation_sha256')) is str and
           len(intake['r127_observation_sha256'])==64 and
           all(c in '0123456789abcdef' for c in intake['r127_observation_sha256']) and
           intake.get('r127_observation_status') in (
             'SESSION_TIMER_STILL_ACTIVE_NOT_CLOSURE_PROOF',
             'TIMER_ENDED_DENY_OBSERVED_NOT_INDEPENDENT_PROOF'))),
         'R128_SOURCE_NOT_ADMISSIBLE')
    need(type(case) is dict and case.get('schema')==r121.SCHEMA and
         case.get('case_id')==intake['case_id'] and
         case.get('case_key')==intake['case_key'] and
         case.get('a6_classification')=='ND' and
         case.get('a7_confirmed_rf') is None and
         case.get('a8_applied_transition') is None and
         case.get('a9_published_generation') is None,
         'R121_CASE_NOT_CONSERVATIVE')
    try:
        r121.verify(case,catalog_raw)
    except (r121.Stop,ValueError,OSError,TypeError,KeyError) as exc:
        raise Stop('R121_SOURCE_CHANGED') from exc
    # Rebind to F13's original reservation: R121 verifies the source folder.
    need(case['catalog_sha256']==f1.digest(catalog_raw),
         'CASE_CATALOG_DRIFT')
    result={'schema':SCHEMA,'head':intake['head'],
            'family_id':'FTP-T01','case_id':intake['case_id'],
            'case_key':intake['case_key'],
            'intake_sha256':intake['sha256'],'r121_sha256':case['sha256'],
            'r127_observation_candidate_sha256':intake.get('r127_observation_sha256'),
            'r127_observation_is_authoritative':False,
            'a6':'ND','a6_supports_accepted':False,
            'a7_mathematical_interval':[case['a7_lower'],case['a7_upper']],
            'a7_confirmed_rf':None,
            'a8_candidate':case['a8_recommendation'],
            'a8_authoritative_transition':None,
            'a9_global_generation':None,
            'a9_durable_store_opened':False,
            'a10':'REPLAYABLE_PRIVATE_AUDIT_NOT_GLOBAL_GENERATION',
            'p7':'DRAFT','p8':'NO-GO',
            'blockers':['PHYSICAL_FTP_ORIGIN_NOT_INDEPENDENTLY_ADMITTED',
                        'NO_A6_TECHNICAL_TRUTH',
                        'A7_RISK_NOT_CONFIRMED',
                        'A8_TRANSITION_NOT_AUTHORIZED',
                        'A9_PUBLICATION_NOT_AUTHORIZED']}
    result['sha256']=r126.sha(result)
    return result


def validate_replay(report:dict,*,intake:dict,case:dict,catalog_raw:bytes)->bool:
    need(type(report) is dict and report==reconcile(intake=intake,case=case,
                                                    catalog_raw=catalog_raw),
         'A6_A10_REPLAY_CHANGED')
    return True


def store_private(report:dict,*,intake:dict,case:dict,catalog_raw:bytes,
                  root:Path=ROOT,observer_report:dict|None=None)->Path:
    """Store immutable A10 audit. NEVER create/open a global A9 generation."""
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    validate_replay(report,intake=intake,case=case,catalog_raw=catalog_raw)
    need(isinstance(root,Path) and root.is_absolute() and
         not root.is_symlink() and root.parent.is_dir() and
         not root.parent.is_symlink(),'AUDIT_ROOT_INVALID')
    r121._private(root.parent)
    if not root.exists():
        root.mkdir(mode=0o700)
        f13._fsync_directory(root.parent)
    r121._private(root)
    folder=f7._create(root,'audit-')
    files={'report.json':report,'intake.json':intake,'r121.json':case}
    if intake.get('r127_observation_sha256') is not None:
        need(type(observer_report) is dict and
             observer_report.get('sha256')==intake['r127_observation_sha256'] and
             observer_report.get('head')==intake['head'] and
             b6.verify(observer_report),
             'R127_OBSERVER_NOT_REPLAYABLE_FOR_A10')
        files['observer.json']=observer_report
    else:
        need(observer_report is None,'UNREQUESTED_R127_OBSERVER')
    for name,value in files.items():
        f2.exclusive(folder/name,f1.canonical(value))
    manifest={'schema':SCHEMA+'-manifest',
              'entry_sha256':{name:r126.sha(value) for name,value in files.items()},
              'p8':'NO-GO','a9':None,
              'real_source_attested':False}
    f2.exclusive(folder/'manifest.json',f1.canonical(manifest))
    f13._fsync_directory(folder)
    f13._fsync_directory(root)
    return folder


def verify_private(folder:Path,catalog_raw:bytes)->dict:
    need(isinstance(folder,Path) and folder.is_absolute(),
         'AUDIT_DIRECTORY_UNEXPECTED')
    entries={x.name for x in folder.iterdir()}
    base={'report.json','intake.json','r121.json','manifest.json'}
    need(entries in (base,base|{'observer.json'}),
         'AUDIT_DIRECTORY_UNEXPECTED')
    r121._private(folder.parent)
    r121._private(folder)
    def safe_read(name: str) -> bytes:
        p=folder/name
        st=p.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             0<st.st_size<=262144,'AUDIT_FILE_UNSAFE')
        fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            actual=os.fstat(fd)
            need((actual.st_dev,actual.st_ino,actual.st_size,actual.st_uid)==
                 (st.st_dev,st.st_ino,st.st_size,st.st_uid),
                 'AUDIT_RACE')
            raw=os.read(fd,262145)
            need(len(raw)==st.st_size,'AUDIT_SHORT_READ')
            return raw
        finally: os.close(fd)
    docs={name:safe_read(name) for name in sorted(entries)}
    values={name:f1.load(raw) for name,raw in docs.items()}
    need(all(docs[name]==f1.canonical(values[name]) for name in docs),
         'AUDIT_NONCANONICAL')
    manifest=values['manifest.json']
    sources={k:v for k,v in values.items() if k!='manifest.json'}
    if 'observer.json' in values:
        need(b6.verify(values['observer.json']) and
             values['observer.json'].get('sha256')==
             values['intake.json'].get('r127_observation_sha256') and
             values['observer.json'].get('head')==values['intake.json'].get('head'),
             'A10_R127_OBSERVER_NOT_SOURCE_BOUND')
    else:
        need(values['intake.json'].get('r127_observation_sha256') is None,
             'A10_R127_OBSERVER_MISSING')
    need(type(manifest) is dict and set(manifest)=={
         'schema','entry_sha256','p8','a9','real_source_attested'} and
         manifest['schema']==SCHEMA+'-manifest' and
         manifest['p8']=='NO-GO' and manifest['a9'] is None and
         manifest['real_source_attested'] is False and
         manifest['entry_sha256']=={n:r126.sha(v) for n,v in sources.items()},
         'AUDIT_MANIFEST_TAMPERED')
    validate_replay(values['report.json'],intake=values['intake.json'],
                    case=values['r121.json'],catalog_raw=catalog_raw)
    return values['report.json']


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'reuses_r121_exact_risk_and_r58e':True,
            'independent_a6_technical_support':False,
            'authoritative_a8_transition':False,
            'a9_durable_store_publication':False,
            'a10_private_durable_replay':True,
            'r127_b6_observation_candidate_link':True,
            'a7_confirmed_rf':None,'p8':'NO-GO','a9':None}
