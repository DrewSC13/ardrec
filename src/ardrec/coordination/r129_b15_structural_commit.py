"""R129-B15: real native A8/A9 *structural* publication, only with fresh external proof.

This is NOT an experimental risk publication. FTP-T01 proves at most control
connectivity. No Rf is asserted and no synthetic B12 calibration is accepted.
An independently installed, root-owned release and three externally managed
Ed25519 authorities must approve the exact source and one native store HEAD.

The CLI runs only with the immutable /opt vendored package, as the non-root store owner.
It cannot arm R116, start VMs, open traffic or provision root authorities.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r129_b11_independent_a6 as b11
from ardrec.persistence import DurableStore
from ardrec.persistence.codec import StorageError
from ardrec.state import (ServicePhase, Truth, Transition, TransitionContext,
                          GuardFact, InvocationPhase)
import ardrec.persistence as persistence_module
import ardrec.state as state_module

SCHEMA = 'ARDREC-R129-B15-STRUCTURAL-A8-A9-NATIVE-v1'
SOURCE_SCHEMA = SCHEMA+'-root-source'
GRANT_SCHEMA = SCHEMA+'-publication-grant'
REV_SCHEMA = SCHEMA+'-revocation'
TRUST_SCHEMA = SCHEMA+'-trust'
SOURCE_PREFIX = (SOURCE_SCHEMA+'\x00').encode('ascii')
GRANT_PREFIX = (GRANT_SCHEMA+'\x00').encode('ascii')
REV_PREFIX = (REV_SCHEMA+'\x00').encode('ascii')
ROOT = Path('/opt/ardrec/r129-structural-v1')
PUBLISHER = ROOT/'vendor/ardrec/coordination/r129_b15_structural_commit.py'
TRUST = Path('/etc/ardrec-public/r129-structural-trust-v1.json')
REVOCATION = Path('/etc/ardrec-public/r129-structural-revocation-v1.json')
STAGING = Path('/home/cicada/ardrec-lab/r129-structural-staging-v1')
STORE = Path('/home/cicada/ardrec-lab/r129-structural-store-v1')
MAX_ROOT_FILE=16384
MAX_INPUT_FILE=16384
HEX = re.compile(r'[0-9a-f]{64}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
SESSION = re.compile(r'[0-9a-f]{16}\Z')
SOURCE_FIELDS={'schema','head','session','case_id','a6_sha256',
               'b9_receipt_sha256','r127_witness_sha256','origin',
               'technical_scope','root_b9_original_bytes_replayed',
               'root_r127_crash_restoration_verified','observed_at'}
GRANT_FIELDS={'schema','grant_id','head','session','case_id','source_sha256',
              'a6_sha256','record_id','configuration_sha256','store_head_sha256',
              'expected_generation','service_id','installed_publisher_sha256',
              'native_persistence_sha256','native_state_sha256','valid_from',
              'valid_until','action','publication_class','confirmed_rf','p8'}
REV_FIELDS={'schema','grant_sha256','issued_at','valid_until','revoked','reason_code'}

class Stop(ValueError):
    pass

def need(condition,reason):
    if not condition: raise Stop(reason)

def sha(doc): return f1.digest(f1.canonical(doc))

def current(now):
    need(type(now) is datetime and now.tzinfo is not None and now.utcoffset() is not None,
         'UTC_CLOCK_REQUIRED')
    return now.astimezone(timezone.utc)

def instant(value):
    try: return f1._instant(value,'B15_TIMESTAMP').astimezone(timezone.utc)
    except (ValueError,TypeError,f1.Rejected) as exc:
        raise Stop('INVALID_TIMESTAMP') from exc

def exact(value, keys, code):
    need(type(value) is dict and set(value)==keys,code)
    return value

def signer_pair(entry):
    exact(entry,{'key_id','public_key_pem'},'SIGNER_FIELDS')
    need(type(entry['key_id']) is str and f1.ID.fullmatch(entry['key_id']) and
         type(entry['public_key_pem']) is str,'SIGNER_ID')
    try: raw=entry['public_key_pem'].encode('ascii')
    except UnicodeError as exc:raise Stop('SIGNER_PEM_NONASCII') from exc
    need(raw.startswith(b'-----BEGIN PUBLIC KEY-----\n') and
         raw.endswith(b'-----END PUBLIC KEY-----\n') and len(raw)<=1024,
         'SIGNER_PEM')
    return (entry['key_id'],hashlib.sha256(raw).hexdigest())

def trust_check(trust):
    exact(trust,{'schema','source_signer','publication_signer',
                 'revocation_signer','excluded_signer_public_sha256'},'TRUST_FIELDS')
    need(trust['schema']==TRUST_SCHEMA,'TRUST_SCHEMA')
    entries=[trust[k] for k in ('source_signer','publication_signer','revocation_signer')]
    keys=[signer_pair(x) for x in entries]
    need(len({x[0] for x in keys})==3 and len({x[1] for x in keys})==3,
         'SIGNERS_NOT_INDEPENDENT')
    excluded=trust['excluded_signer_public_sha256']
    need(type(excluded) is list and len(excluded)>=5 and len(excluded)==len(set(excluded)) and
         all(type(s) is str and HEX.fullmatch(s) for s in excluded),
         'UPSTREAM_SIGNER_EXCLUSIONS_REQUIRED')
    need(not set(x[1] for x in keys).intersection(excluded),'UPSTREAM_SIGNER_REUSED')
    return entries

def review_signed(*, admission, source, grant, revocation, trust, now):
    """Documentary cryptographic review; cannot by itself publish or prove physical origin."""
    now=current(now)
    need(type(admission) is dict and
         admission.get('schema')==b11.SCHEMA+'-physical-admission' and
         admission.get('sha256')==sha({k:v for k,v in admission.items() if k!='sha256'}) and
         admission.get('a6')=='VERDADERO' and
         admission.get('a6_scope')=='FTP_T01_CONTROL_CONNECTIVITY_ONLY' and
         admission.get('technical_condition')=='FTP_T01_CONTROL_CONNECTION_CONFIRMED' and
         admission.get('root_b9_original_bytes_replayed') is True and
         admission.get('root_r127_crash_restoration_verified') is True and
         admission.get('a7_rf_confirmed') is None and
         admission.get('a8_transition_applied') is None and
         admission.get('a9_generation') is None and
         admission.get('p8')=='NO-GO', 'LIVE_A6_SHAPE_REQUIRED')
    ss=exact(source,{'statement','signer_key_id','signature_b64'},'SOURCE_WRAPPER')
    s=exact(ss['statement'],SOURCE_FIELDS,'SOURCE_FIELDS')
    need(s['schema']==SOURCE_SCHEMA and s['head']==admission['head'] and
         s['session']==admission['session'] and s['case_id']==admission['case_id'] and
         s['a6_sha256']==admission['sha256'] and
         s['r127_witness_sha256']==admission['independent_root_witness_sha256'] and
         type(s['b9_receipt_sha256']) is str and HEX.fullmatch(s['b9_receipt_sha256']) and
         s['root_b9_original_bytes_replayed'] is True and
         s['root_r127_crash_restoration_verified'] is True and
         s['origin']=='INDEPENDENT_ORIGINAL_ROOT_B9_AND_B11_READBACK' and
         s['technical_scope']=='FTP_T01_CONTROL_CONNECTIVITY_ONLY',
         'SOURCE_NOT_BOUND_TO_PHYSICAL_A6')
    need(0<=(now-instant(s['observed_at'])).total_seconds()<=60,
         'SOURCE_OBSERVATION_STALE')
    gg=exact(grant,{'statement','signer_key_id','signature_b64'},'GRANT_WRAPPER')
    g=exact(gg['statement'],GRANT_FIELDS,'GRANT_FIELDS')
    need(g['schema']==GRANT_SCHEMA and type(g['grant_id']) is str and f1.ID.fullmatch(g['grant_id']) and
         g['head']==admission['head']==s['head'] and type(g['head']) is str and SHA.fullmatch(g['head']) and
         g['session']==admission['session']==s['session'] and SESSION.fullmatch(g['session']) and
         g['case_id']==admission['case_id']==s['case_id'] and
         g['source_sha256']==sha(source) and g['a6_sha256']==admission['sha256'] and
         g['service_id']=='FTP_DEV' and g['action']=='STOP_AND_PUBLISH_NATIVE_STRUCTURAL_ONLY' and
         g['publication_class']=='ADMINISTRATIVE_CLOSURE_ONLY' and
         g['confirmed_rf'] is None and g['p8']=='NO-GO' and
         all(type(g[field]) is str and HEX.fullmatch(g[field]) for field in
             ('configuration_sha256','store_head_sha256','installed_publisher_sha256',
              'native_persistence_sha256','native_state_sha256')) and
         type(g['record_id']) is str and f1.ID.fullmatch(g['record_id']) and
         type(g['expected_generation']) is int and 0<=g['expected_generation']<2**63,
         'GRANT_SCOPE_OR_DIGEST_INVALID')
    start,end=instant(g['valid_from']),instant(g['valid_until'])
    need(start<=now<end and 0<(end-start).total_seconds()<=60,
         'GRANT_NOT_CURRENT')
    rr=exact(revocation,{'statement','signer_key_id','signature_b64'},'REVOCATION_WRAPPER')
    r=exact(rr['statement'],REV_FIELDS,'REVOCATION_FIELDS')
    need(r['schema']==REV_SCHEMA and r['grant_sha256']==sha(grant) and
         type(r['revoked']) is bool and r['revoked'] is False and
         type(r['reason_code']) is str and f1.ID.fullmatch(r['reason_code']),
         'REVOCATION_NOT_BOUND_OR_REVOKED')
    start,end=instant(r['issued_at']),instant(r['valid_until'])
    need(start<=now<end and 0<=(now-start).total_seconds()<=30,
         'REVOCATION_NOT_FRESH')
    keys=trust_check(trust)
    for wrapper,payload,key,prefix in (
        (source,s,keys[0],SOURCE_PREFIX),(grant,g,keys[1],GRANT_PREFIX),
        (revocation,r,keys[2],REV_PREFIX)):
        try:f3.verified_signature(wrapper,payload,key,prefix)
        except (f3.Stop,ValueError,TypeError,KeyError) as exc:
            raise Stop('INDEPENDENT_SIGNATURE_REJECTED') from exc
    return {'schema':SCHEMA+'-verified-documentary-grant',
            'head':g['head'],'session':g['session'],'case_id':g['case_id'],
            'record_id':g['record_id'],'service_id':'FTP_DEV',
            'expected_generation':g['expected_generation'],
            'configuration_sha256':g['configuration_sha256'],
            'store_head_sha256':g['store_head_sha256'],
            'publisher_sha256':g['installed_publisher_sha256'],
            'persistence_sha256':g['native_persistence_sha256'],
            'state_sha256':g['native_state_sha256'],
            'grant_sha256':sha(grant),'source_sha256':sha(source),
            'a6_sha256':admission['sha256'],
            'experimental_risk_publication':False,
            'confirmed_rf':None,'p8':'NO-GO'}

def _read_root_public(path):
    need(path in (TRUST,REVOCATION),'POLICY_PATH_NOT_ALLOWLISTED')
    for p in (Path('/'),Path('/etc'),Path('/etc/ardrec-public')):
        st=p.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not(st.st_mode&0o022) and
             not p.is_symlink(),'ROOT_PUBLIC_PARENT_UNTRUSTED')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         stat.S_IMODE(st.st_mode)==0o644 and 0<st.st_size<=MAX_ROOT_FILE,
         'ROOT_PUBLIC_FILE_UNTRUSTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        actual=os.fstat(fd)
        need((actual.st_dev,actual.st_ino,actual.st_uid,actual.st_nlink,
              actual.st_size,actual.st_mtime_ns)==
             (st.st_dev,st.st_ino,st.st_uid,st.st_nlink,st.st_size,st.st_mtime_ns),
             'ROOT_PUBLIC_RACE')
        raw=os.read(fd,MAX_ROOT_FILE+1)
        after=os.fstat(fd)
        need(len(raw)==st.st_size and
             (after.st_ino,after.st_size,after.st_mtime_ns)==
             (actual.st_ino,actual.st_size,actual.st_mtime_ns),
             'ROOT_PUBLIC_CHANGED')
        return f1.load(raw)
    finally:os.close(fd)

def _file_sha_root(path):
    need(path in (PUBLISHER,Path(persistence_module.__file__),Path(state_module.__file__)),
         'RELEASE_FILE_NOT_PINNED')
    need(path.is_relative_to(ROOT) and not path.is_symlink(),
         'APPROVED_CODE_OUTSIDE_BUNDLE')
    for parent in (Path('/'), Path('/opt'), ROOT.parent, ROOT, *list(path.parents)[:-1]):
        st=parent.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
             not (st.st_mode & 0o022) and not parent.is_symlink(),
             'APPROVED_CODE_PARENT_UNTRUSTED')
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
         not(st.st_mode&0o022) and 0<st.st_size<=200000,
         'APPROVED_CODE_UNTRUSTED')
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _installed_grant(verified):
    need(os.geteuid()!=0 and os.geteuid()==pwd.getpwnam('cicada').pw_uid,
         'NONROOT_STORE_OWNER_REQUIRED')
    need(Path(__file__).resolve()==PUBLISHER,'INDEPENDENT_CODE_INSTALL_REQUIRED')
    need(_file_sha_root(PUBLISHER)==verified['publisher_sha256'] and
         _file_sha_root(Path(persistence_module.__file__))==verified['persistence_sha256'] and
         _file_sha_root(Path(state_module.__file__))==verified['state_sha256'],
         'INDEPENDENT_RELEASE_CODE_SHA_MISMATCH')

def _private_doc(name):
    need(name in ('a6.json','source.json','grant.json'), 'STAGING_NAME_INVALID')
    st=STAGING.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         stat.S_IMODE(st.st_mode)==0o700 and not STAGING.is_symlink(),
         'STAGING_DIRECTORY_UNTRUSTED')
    path=STAGING/name
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
         st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         0<st.st_size<=MAX_INPUT_FILE,'STAGING_FILE_UNTRUSTED')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd)
        need((a.st_dev,a.st_ino,a.st_uid,a.st_size,a.st_nlink)==
             (st.st_dev,st.st_ino,st.st_uid,st.st_size,st.st_nlink),
             'STAGING_FILE_RACE')
        raw=os.read(fd,MAX_INPUT_FILE+1)
        need(len(raw)==st.st_size,'STAGING_SHORT_READ')
        return f1.load(raw)
    finally:os.close(fd)

def _ids(verified):
    session=verified['session']
    a6=verified['a6_sha256']
    return {'stage_event':'T10_R129_'+session,
            'publish_event':'A9_R129_'+session,
            'generation_reference':'G_R129_'+session,
            'reason_reference':'A6_'+a6[:48],
            'effect_reference':'R127_'+session}

def _structural_commit(store,verified,refresh):
    """Native write sequence. Called only AFTER installed-code and live policy gates.

    On a crash between stage and publish, replay recognizes the exact stage
    event and can continue, provided fresh signatures are reverified.
    """
    need(callable(refresh),'REVOCATION_REFRESH_REQUIRED')
    ids=_ids(verified)
    state=store.state
    need(state.confirmed.record_id==verified['record_id'] and
         state.confirmed.configuration_sha256==verified['configuration_sha256'] and
         state.authority is Truth.VERDADERO and state.simulation is False and
         state.invocation is InvocationPhase.EN_CURSO and
         state.confirmed.generation in (verified['expected_generation'],
                  verified['expected_generation']+1),
         'STORE_STATE_OR_GENERATION_MISMATCH')
    selected=[s for s in state.services if s.service_scenario_id==verified['service_id']]
    need(len(selected)==1,'STORE_SERVICE_SCOPE')
    service=selected[0]
    if state.confirmed.generation==verified['expected_generation']+1:
        need(state.confirmed.generation_reference==ids['generation_reference'] and
             ids['stage_event'] in state.confirmed.incorporated_events and
             ids['publish_event'] in state.confirmed.incorporated_events and
             service.phase is ServicePhase.DETENIDO and not service.local_trace,
             'RECOVERY_GENERATION_NOT_THIS_GRANT')
        refresh()
        return {'schema':SCHEMA+'-native-structural-publication',
            'record_id':verified['record_id'],'service_id':verified['service_id'],
            'head':verified['head'],'session':verified['session'],
            'generation':state.confirmed.generation,
            'native_store_head_sha256':store.head_sha256,
            'original_a6_sha256':verified['a6_sha256'],
            'source_attestation_sha256':verified['source_sha256'],
            'grant_sha256':verified['grant_sha256'],
            'transition':'DETENER','publication_class':'ADMINISTRATIVE_CLOSURE_ONLY',
            'technical_risk_published':False,'confirmed_rf':None,
            'recovered_existing_commit':True,
            'a6_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY','p8':'NO-GO'}
    need(state.confirmed.generation==verified['expected_generation'],
         'STORE_STATE_OR_GENERATION_MISMATCH')
    already_staged=bool(service.local_trace)
    if already_staged:
        ctx=service.local_trace[-1].context
        need(len(service.local_trace)==1 and service.phase is ServicePhase.DETENIDO and
             service.local_trace[-1].transition is Transition.DETENER and
             ctx.event_reference==ids['stage_event'] and
             ctx.reason_reference==ids['reason_reference'] and
             ctx.stop_cause=='CONTROL' and
             {f.name:f.reference for f in ctx.facts}=={
               'cause_verified':ids['reason_reference'],
               'effect_processable':ids['effect_reference']},
             'STAGED_EVENT_NOT_THIS_GRANT')
    else:
        need(store.head_sha256==verified['store_head_sha256'] and
             service.phase not in (ServicePhase.DETENIDO,ServicePhase.CERRADO) and
             not any(a.pending for a in state.attempts),
             'STORE_STAGING_PRECONDITION')
        ctx=TransitionContext(state.confirmed.record_id,state.execution_id,
               state.confirmed.generation,state.confirmed.configuration_sha256,
               ids['stage_event'],(
                 GuardFact('cause_verified',Truth.VERDADERO,ids['reason_reference']),
                 GuardFact('effect_processable',Truth.VERDADERO,ids['effect_reference'])),
               reason_reference=ids['reason_reference'],stop_cause='CONTROL')
        refresh()
        store.transition(verified['service_id'],Transition.DETENER,ctx)
    refresh()
    outcome=store.publish(expected_generation=verified['expected_generation'],
                          reference=ids['generation_reference'],
                          event=ids['publish_event'])
    need(outcome.confirmed.generation==verified['expected_generation']+1 and
         outcome.confirmed.generation_reference==ids['generation_reference'] and
         ids['stage_event'] in outcome.confirmed.incorporated_events and
         ids['publish_event'] in outcome.confirmed.incorporated_events,
         'NATIVE_GENERATION_NOT_CONFIRMED')
    return {'schema':SCHEMA+'-native-structural-publication',
            'record_id':verified['record_id'],'service_id':verified['service_id'],
            'head':verified['head'],'session':verified['session'],
            'generation':outcome.confirmed.generation,
            'native_store_head_sha256':store.head_sha256,
            'original_a6_sha256':verified['a6_sha256'],
            'source_attestation_sha256':verified['source_sha256'],
            'grant_sha256':verified['grant_sha256'],
            'transition':'DETENER','publication_class':'ADMINISTRATIVE_CLOSURE_ONLY',
            'technical_risk_published':False,'confirmed_rf':None,
            'recovered_existing_commit':False,
            'a6_scope':'FTP_T01_CONTROL_CONNECTIVITY_ONLY','p8':'NO-GO'}

def execute_installed(*,now=None):
    """Only live installed entry; no injectable trust/store/source paths."""
    moment=datetime.now(timezone.utc) if now is None else current(now)
    admission=_private_doc('a6.json')
    source=_private_doc('source.json')
    grant=_private_doc('grant.json')
    trust=_read_root_public(TRUST)
    revoke=_read_root_public(REVOCATION)
    verified=review_signed(admission=admission,source=source,grant=grant,
                           revocation=revoke,trust=trust,now=moment)
    _installed_grant(verified)
    def refresh():
        review_signed(admission=admission,source=source,grant=grant,
                      revocation=_read_root_public(REVOCATION),
                      trust=_read_root_public(TRUST),now=datetime.now(timezone.utc))
        _installed_grant(verified)
    with DurableStore.open(STORE,record_id=verified['record_id'],
                           configuration_sha256=verified['configuration_sha256']) as store:
        receipt=_structural_commit(store,verified,refresh)
    # Reopen and verify native durable replay, including its HEAD anchor.
    with DurableStore.open(STORE,record_id=verified['record_id'],
                           configuration_sha256=verified['configuration_sha256'],
                           expected_head=receipt['native_store_head_sha256']) as reopened:
        need(reopened.state.confirmed.generation==receipt['generation'] and
             reopened.state.confirmed.generation_reference==_ids(verified)['generation_reference'],
             'A10_REOPEN_MISMATCH')
    return receipt

def capabilities():
    return {'schema':SCHEMA+'-capabilities',
            'source_only_unapproved_until_independent_root_bundle':True,
            'native_structural_commit_path_implemented':True,
            'signed_external_source_publication_revocation_required':True,
            'live_original_root_b9_r127_a6_attestation_required':True,
            'fixed_private_user_owned_native_store':str(STORE),
            'fixed_root_owned_public_trust':str(TRUST),
            'experimental_risk_publication_implemented':False,
            'no_synthetic_rf_promotion':True,
            'no_network_actions':True,'root_install_performed':False,
            'a6_without_external_authority':'ND','a9_without_external_authority':None,
            'p8':'NO-GO'}
