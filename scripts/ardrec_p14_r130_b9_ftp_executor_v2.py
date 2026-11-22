#!/usr/bin/env python3
"""R128-B9: root-staged one-session FTP-T01 executor (source-only until signed install).

Separate root-signed traffic authority is required IN ADDITION to B4's
DENY-only grant. F13 journal MUST be spent before the immutable handoff is
sealed by an independent root operator. No shell, no user-supplied commands,
no arbitrary target, no VM start, no retry. Reuses exact SHA-pinned R116-F3
physical FTP helper routines; NEVER calls its historical main/permit review.

Never run --execute-pilot from a mutable source checkout. A signed, root-owned
manifest and independent privileges are required. R116 autonomous DENY is
armed before ANY change; synchronous DENY restore is mandatory on completion.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types

sys.dont_write_bytecode = True

ROOT = Path('/var/lib/ardrec/r128-one-session-v2')
SCRIPT = ROOT / 'root-executor.py'
MANIFEST = ROOT / 'manifest.json'
B4 = Path('/var/lib/ardrec/r126-ftp-session-guard-v1/root-controller.py')
F3 = Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1/root-pilot.py')
TRAFFIC_TRUST = Path('/etc/ardrec/r128-root-traffic-trust-v1.json')
TRAFFIC_REVOCATION = Path('/etc/ardrec/r128-root-traffic-revocation-v1.json')
RELEASE = ROOT / 'release.json'
RELEASE_TRUST = Path('/etc/ardrec/r128-root-release-trust-v1.json')
RELEASE_REVOCATION = Path('/etc/ardrec/r128-root-release-revocation-v1.json')
B4_PIN = 'f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8'
F3_PIN = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
GUARD_PIN = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
SCHEMA = 'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1'
TRUST_SCHEMA = SCHEMA + '-trust'
GRANT_SCHEMA = SCHEMA + '-traffic-grant'
REV_SCHEMA = SCHEMA + '-traffic-revocation'
GRANT_PREFIX = (GRANT_SCHEMA + '\0').encode('ascii')
REV_PREFIX = (REV_SCHEMA + '\0').encode('ascii')
HANDOFF_SCHEMA = 'ARDREC-R128-B9-PREBOUND-F13-ROOT-HANDOFF-v1'
RELEASE_SCHEMA = 'ARDREC-R128-B14-INDEPENDENT-ROOT-RELEASE-v1'
RELEASE_TRUST_SCHEMA = RELEASE_SCHEMA + '-trust'
RELEASE_REV_SCHEMA = RELEASE_SCHEMA + '-revocation'
RELEASE_PREFIX = (RELEASE_SCHEMA + '\x00').encode('ascii')
RELEASE_REV_PREFIX = (RELEASE_REV_SCHEMA + '\x00').encode('ascii')
HEX16 = re.compile(r'[0-9a-f]{16}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
CASE = re.compile(r'FTP-T01-S[0-9]{2}-[0-9]{2}\Z')
STATIC = frozenset({'root-executor.py','manifest.json','release.json','traffic-grant.json',
                    'f13-handoff.json','lock'})
MAX_FILE = 200000

class Stop(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def canon(doc):
    return (json.dumps(doc, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def digest(doc):
    return hashlib.sha256(canon(doc)).hexdigest()


def check_root_dir(path, *, mode=None):
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
         not path.is_symlink() and not(s.st_mode & 0o022),
         'ROOT_DIRECTORY_UNTRUSTED')
    if mode is not None:
        need(stat.S_IMODE(s.st_mode) == mode, 'ROOT_DIRECTORY_MODE')


def read_root(path, *, limit=MAX_FILE):
    need(isinstance(path, Path) and path.is_absolute() and
         not path.is_symlink(), 'ROOT_INPUT_PATH')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
         stat.S_IMODE(s.st_mode) == 0o600 and 0<s.st_size<=limit,
         'ROOT_INPUT_MODE_OR_SIZE')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        need((a.st_dev,a.st_ino,a.st_uid,a.st_size,a.st_nlink)==
             (s.st_dev,s.st_ino,s.st_uid,s.st_size,s.st_nlink), 'ROOT_INPUT_RACE')
        raw = os.read(fd,limit+1)
        b = os.fstat(fd)
        need(len(raw)==s.st_size and
             (a.st_size,a.st_mtime_ns,a.st_ino)==(b.st_size,b.st_mtime_ns,b.st_ino),
             'ROOT_INPUT_CHANGED')
        return raw
    finally:
        os.close(fd)


def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_FILE, 'DOCUMENT_SIZE')
    def nodup(pairs):
        out = {}
        for key,value in pairs:
            need(key not in out,'JSON_DUPLICATE_KEY')
            out[key]=value
        return out
    try:
        doc=json.loads(raw,object_pairs_hook=nodup,
                       parse_constant=lambda _:need(False,'JSON_NONFINITE'))
    except Stop:
        raise
    except (ValueError,TypeError,UnicodeError) as exc:
        raise Stop('DOCUMENT_JSON_INVALID') from exc
    need(type(doc) is dict and canon(doc)==raw,'DOCUMENT_CANONICAL_REQUIRED')
    return doc


def load_pinned(path, expected, module_name):
    """Load only known root-owned source, by SHA, with bytecode disabled."""
    raw=read_root(path)
    need(hashlib.sha256(raw).hexdigest()==expected, 'ROOT_SOURCE_PIN_CHANGED')
    obj=types.ModuleType(module_name)
    obj.__file__=str(path)
    exec(compile(raw,str(path),'exec'),obj.__dict__)
    need(read_root(path)==raw, 'ROOT_SOURCE_CHANGED_DURING_IMPORT')
    return obj


def signed_release(*, auth, manifest, release, trust, revocation, b4docs,
                   boot_id, f8_reference_sha256, traffic_trust, now):
    """Independently signed root bundle release; no self-issued approvals.

    This validates an externally issued statement, NOT the real Git signature
    by itself. A release authority attests its own independent review of the
    named signed source. Every cryptographic key must be distinct from the ten
    operational signers. Recheck current signed revocation before each write.
    """
    now = auth.current(now)
    auth.exact(trust, {'schema', 'release_signer', 'revocation_signer'},
               'RELEASE_TRUST_FIELDS')
    need(trust['schema'] == RELEASE_TRUST_SCHEMA, 'RELEASE_TRUST_SCHEMA')
    upstream = tuple(b4docs[name][key] for name, roles in (
        ('root_trust', ('grant_signer', 'revocation_signer')),
        ('scope_trust', ('scope_signer', 'revocation_signer')),
        ('pilot_trust', ('pilot_signer', 'revocation_signer')),
        ('window_trust', ('window_signer', 'revocation_signer')))
        for key in roles)
    auth.exact(traffic_trust, {'schema','traffic_signer','revocation_signer'},
               'TRAFFIC_TRUST_FIELDS')
    need(traffic_trust['schema'] == TRUST_SCHEMA, 'TRAFFIC_TRUST_SCHEMA')
    keys = (*upstream, traffic_trust['traffic_signer'],
            traffic_trust['revocation_signer'],
            trust['release_signer'], trust['revocation_signer'])
    need(len({k['key_id'] for k in keys}) == len(keys) and
         len({hashlib.sha256(auth.signer(k)).hexdigest() for k in keys}) == len(keys),
         'ROOT_RELEASE_SIGNERS_NOT_DISTINCT')
    stmt = auth.verify(release, trust['release_signer'], RELEASE_PREFIX)
    auth.exact(stmt, {'schema', 'release_id', 'approved_head', 'boot_id',
        'manifest_sha256', 'script_sha256', 'r126_deny_controller_sha256',
        'legacy_f3_sha256', 'guard_sha256', 'f8_reference_sha256',
        'source_commit_signature_verified', 'independent_review',
        'valid_from', 'valid_until', 'action', 'p8'}, 'ROOT_RELEASE_FIELDS')
    need(stmt['schema'] == RELEASE_SCHEMA and
         type(stmt['release_id']) is str and re.fullmatch(r'[A-Za-z0-9_-]{3,80}', stmt['release_id']) and
         stmt['approved_head'] == manifest['approved_head'] and
         stmt['boot_id'] == boot_id and
         stmt['manifest_sha256'] == digest(manifest) and
         stmt['script_sha256'] == manifest['script_sha256'] and
         stmt['r126_deny_controller_sha256'] == B4_PIN and
         stmt['legacy_f3_sha256'] == F3_PIN and
         stmt['guard_sha256'] == GUARD_PIN and
         type(f8_reference_sha256) is str and HEX64.fullmatch(f8_reference_sha256) and
         stmt['f8_reference_sha256'] == f8_reference_sha256 and
         stmt['source_commit_signature_verified'] is True and
         stmt['independent_review'] is True and
         stmt['action'] == 'RELEASE_EXACT_ROOT_BUNDLE_FOR_SINGLE_FTP_T01' and
         stmt['p8'] == 'NO-GO', 'ROOT_RELEASE_SCOPE_INVALID')
    begin, end = auth.at(stmt['valid_from']), auth.at(stmt['valid_until'])
    need(begin <= now < end and 0 < (end-begin).total_seconds() <= 86400,
         'ROOT_RELEASE_NOT_CURRENT')
    auth.verify_revocation(revocation, trust['revocation_signer'],
         RELEASE_REV_PREFIX, RELEASE_REV_SCHEMA, 'release_sha256',
         digest(release), 'release_id', stmt['release_id'], now)
    return {'schema': RELEASE_SCHEMA + '-verified',
            'head': manifest['approved_head'],
            'release_sha256': digest(release),
            'revocation_sha256': digest(revocation),
            'f8_reference_sha256': f8_reference_sha256,
            'root_release_signed': True, 'operational_traffic_granted': False,
            'p8': 'NO-GO'}


def _no_duplicate_pairs(pairs):
    result={}
    for key,value in pairs:
        need(key not in result, 'HISTORICAL_F8_DUPLICATE_KEY')
        result[key]=value
    return result


def root_live_release(*, auth, manifest, b4docs, boot_id, legacy, now=None):
    """Read fixed original root-owned bytes only; never replay editable F8 code."""
    now = datetime.now(timezone.utc) if now is None else now
    # An F8 historical record is traceability only. Current state comes from
    # B4/R116 live physical checks, not from the historical mutable replay.
    f8 = legacy.ROOT / 'authority' / 'ftp-boot-paths.json'
    raw = legacy.safe(f8, limit=8192)
    try:
        reference=json.loads(raw,object_pairs_hook=lambda pairs:
            _no_duplicate_pairs(pairs))
    except (ValueError,TypeError) as exc:
        raise Stop('HISTORICAL_F8_REFERENCE_INVALID') from exc
    need(type(reference) is dict and
         set(reference) == {'schema', 'plan', 'boot'} and
         reference['schema'] == legacy.SCHEMA + '-f8-boot-reference',
         'HISTORICAL_F8_REFERENCE_INVALID')
    traffic_trust = parse(read_root(TRAFFIC_TRUST, limit=8192))
    trust = parse(read_root(RELEASE_TRUST, limit=8192))
    release = parse(read_root(RELEASE, limit=8192))
    revocation = parse(read_root(RELEASE_REVOCATION, limit=8192))
    verdict = signed_release(auth=auth, manifest=manifest, release=release,
        trust=trust, revocation=revocation, b4docs=b4docs,
        boot_id=boot_id, f8_reference_sha256=hashlib.sha256(raw).hexdigest(),
        traffic_trust=traffic_trust,now=now)
    # Root-owned reference + distinct signature: no dynamic Python import
    # from /home/cicada/Development/GitHub/ardrec. F8 is not P8 authority.
    return verdict


def stage():
    need(os.geteuid()==0 and Path(__file__).resolve()==SCRIPT,
         'INDEPENDENT_ROOT_STAGING_REQUIRED')
    for folder in (Path('/'), Path('/var'), Path('/var/lib'),
                   Path('/var/lib/ardrec'), ROOT, Path('/etc'), Path('/etc/ardrec')):
        check_root_dir(folder, mode=0o700 if folder==ROOT else None)
    actual={x.name for x in ROOT.iterdir()}
    need(STATIC<=actual and all(x in STATIC or
         x=='attempt-consumed.once' or
         bool(re.fullmatch(r'pilot-[0-9a-f]{16}',x)) for x in actual),
         'ROOT_STAGE_FILE_SCOPE')
    data=parse(read_root(MANIFEST,limit=12000))
    need(set(data)=={'schema','approved_head','script_sha256',
         'r126_deny_controller_sha256','legacy_f3_sha256','guard_sha256',
         'root_staged_independently','automatic_network','p8'} and
         data['schema']==SCHEMA+'-root-bundle' and
         type(data['approved_head']) is str and HEX40.fullmatch(data['approved_head']) and
         data['script_sha256']==hashlib.sha256(read_root(SCRIPT)).hexdigest() and
         data['r126_deny_controller_sha256']==B4_PIN and
         data['legacy_f3_sha256']==F3_PIN and
         data['guard_sha256']==GUARD_PIN and
         data['root_staged_independently'] is True and
         data['automatic_network'] is False and data['p8']=='NO-GO',
         'ROOT_STAGE_NOT_APPROVED')
    need(hashlib.sha256(read_root(B4)).hexdigest()==B4_PIN and
         hashlib.sha256(read_root(F3)).hexdigest()==F3_PIN,
         'UPSTREAM_ROOT_SOURCE_DRIFT')
    lock=ROOT/'lock'
    need(read_root(lock,limit=256)==b'ARDREC-R128-B9-ROOT-LOCK\n', 'ROOT_LOCK_INVALID')
    return data


def validate_handoff(handoff, *, head, session, b4grant, budget):
    need(type(handoff) is dict and set(handoff)=={
         'schema','head','session','case_id','case_key','assessment_index',
         'attempt_id','contract_sha256','scope_authorization_sha256','window_sha256',
         'reservation_sha256','spent_sha256','budget_sha256','target',
         'once_consumed_without_physical_claim','root_approval_issued','a6','p8','sha256'},
         'F13_HANDOFF_FIELDS')
    need(handoff['schema']==HANDOFF_SCHEMA and
         handoff['head']==head and handoff['session']==session and
         CASE.fullmatch(handoff['case_id']) and
         handoff['case_id']==b4grant['case_id'] and
         handoff['contract_sha256']==b4grant['contract_sha256'] and
         handoff['scope_authorization_sha256']==b4grant['scope_authorization_sha256'] and
         handoff['window_sha256']==b4grant['window_sha256'] and
         handoff['budget_sha256']==digest(budget) and
         handoff['target']=={'ip':'10.203.31.2','port':21} and
         handoff['once_consumed_without_physical_claim'] is True and
         handoff['root_approval_issued'] is False and
         handoff['a6']=='ND' and handoff['p8']=='NO-GO' and
         type(handoff['assessment_index']) is int and
         0<=handoff['assessment_index']<2**31 and
         type(handoff['attempt_id']) is str and
         re.fullmatch(r'ATT_[A-Z0-9_]{1,76}',handoff['attempt_id']) and
         all(type(handoff[k]) is str and HEX64.fullmatch(handoff[k]) for k in
             ('case_key','reservation_sha256','spent_sha256')) and
         handoff['sha256']==digest({k:v for k,v in handoff.items() if k!='sha256'}),
         'F13_HANDOFF_NOT_BOUND')
    return True


def signed_traffic(*, auth_module, grant, trust, revocation,
                   handoff, b4docs, approved_head, boot_id, now):
    """Independent signed traffic grant; B4 DENY-only approval is insufficient."""
    auth=auth_module
    now=auth.current(now)
    auth.exact(trust,{'schema','traffic_signer','revocation_signer'},
               'TRAFFIC_TRUST_FIELDS')
    need(trust['schema']==TRUST_SCHEMA,'TRAFFIC_TRUST_SCHEMA')
    traffic_keys=(trust['traffic_signer'],trust['revocation_signer'])
    members=(b4docs['root_trust']['grant_signer'],
             b4docs['root_trust']['revocation_signer'],
             b4docs['scope_trust']['scope_signer'],
             b4docs['scope_trust']['revocation_signer'],
             b4docs['pilot_trust']['pilot_signer'],
             b4docs['pilot_trust']['revocation_signer'],
             b4docs['window_trust']['window_signer'],
             b4docs['window_trust']['revocation_signer'],
             *traffic_keys)
    need(len(set(x['key_id'] for x in members))==10 and
         len(set(auth.sha(auth.signer(x)) for x in members))==10,
         'TEN_SEPARATE_SIGNERS_REQUIRED')
    stmt=auth.verify(grant,trust['traffic_signer'],GRANT_PREFIX)
    auth.exact(stmt,{'schema','traffic_id','session','case_id','head','boot_id',
                    'f13_handoff_sha256','root_deny_grant_sha256',
                    'window_sha256','budget_sha256','valid_from','valid_until',
                    'action','guest','destination','one_shot',
                    'traffic_pilot_exception_only','a6','p8'},
               'TRAFFIC_GRANT_FIELDS')
    deny=b4docs['grant']['statement']
    need(stmt['schema']==GRANT_SCHEMA and
         type(stmt['traffic_id']) is str and re.fullmatch(r'[A-Za-z0-9_-]{3,80}',stmt['traffic_id']) and
         stmt['session']==deny['session'] and HEX16.fullmatch(stmt['session']) and
         stmt['head']==approved_head==deny['head'] and
         stmt['case_id']==deny['case_id']==handoff['case_id'] and
         stmt['boot_id']==boot_id==deny['boot_id'] and
         stmt['root_deny_grant_sha256']==digest(b4docs['grant']) and
         stmt['f13_handoff_sha256']==digest(handoff) and
         stmt['window_sha256']==deny['window_sha256'] and
         stmt['budget_sha256']==deny['budget_sha256'] and
         stmt['action']=='ONE_FTP_T01_GUEST_GREETING' and
         stmt['guest']=='ardrec-r33-dev-runner' and
         stmt['destination']=={'ip':'10.203.31.2','port':21} and
         stmt['one_shot'] is True and stmt['traffic_pilot_exception_only'] is True and
         stmt['a6']=='ND' and stmt['p8']=='NO-GO',
         'TRAFFIC_SCOPE_MISMATCH')
    begin,end=auth.at(stmt['valid_from']),auth.at(stmt['valid_until'])
    need(begin<end and (end-begin).total_seconds()<=60 and
         begin<=now<end and (end-now).total_seconds()>=46,
         'TRAFFIC_GRANT_NOT_FRESH_OR_TOO_SHORT')
    auth.verify_revocation(revocation,trust['revocation_signer'],REV_PREFIX,
       REV_SCHEMA,'traffic_grant_sha256',digest(grant),
       'traffic_id',stmt['traffic_id'],now)
    return stmt


def preflight(*, manifest, auth, b4docs, handoff,
              traffic_grant, traffic_trust, traffic_revocation,
              now, boot_id, run=None):
    """Injectable pure gate; physical guard is checked, no host mutation."""
    b4=auth
    checked=b4.validate_bundle(b4docs,now=now,
            expected_head=manifest['approved_head'],boot_id=boot_id)
    claim=b4docs['grant']['statement']
    budget=b4docs['traffic_window']['statement']['budget']
    validate_handoff(handoff,head=manifest['approved_head'],
            session=checked['session'],b4grant=claim,budget=budget)
    traffic=signed_traffic(auth_module=b4, grant=traffic_grant,
            trust=traffic_trust,revocation=traffic_revocation,
            handoff=handoff,b4docs=b4docs,
            approved_head=manifest['approved_head'],boot_id=boot_id,now=now)
    need(not (ROOT/'attempt-consumed.once').exists(),
         'ROOT_TRAFFIC_ALREADY_CONSUMED')
    b4.preflight({'approved_head':manifest['approved_head']},b4docs,
                 now=now,boot_id=boot_id,run=b4.host_run if run is None else run)
    return {'schema':SCHEMA+'-preflight','head':manifest['approved_head'],
            'session':checked['session'],'case_id':claim['case_id'],
            'traffic_grant_sha256':digest(traffic_grant),
            'root_deny_grant_sha256':digest(b4docs['grant']),
            'f13_handoff_sha256':digest(handoff),
            'budget':budget,'traffic_permit_until':traffic['valid_until'],
            'host_changes':0,'traffic_opened':False,'a6':'ND','p8':'NO-GO'}


def fresh_gate(*, b4, b4docs, manifest, traffic, trust, revocation,
               handoff, boot_id, session, legacy, policy, monotonic_start):
    """Refresh SIGNED revocation and session timer before each irreversible step."""
    now=datetime.now(timezone.utc)
    live_docs=b4.read_documents()
    need(all(canon(live_docs[key])==canon(b4docs[key]) for key in b4docs),
         'UPSTREAM_SIGNED_DOCUMENT_REPLACED')
    b4.validate_bundle(live_docs,now=now,
             expected_head=manifest['approved_head'],boot_id=boot_id)
    live_traffic=parse(read_root(ROOT/'traffic-grant.json'))
    live_handoff=parse(read_root(ROOT/'f13-handoff.json'))
    need(live_traffic==traffic and live_handoff==handoff,
         'ROOT_SESSION_DOCUMENT_CHANGED')
    # An operator can revoke the signed root release DURING the window.
    root_live_release(auth=b4,manifest=manifest,b4docs=b4docs,
                      boot_id=boot_id,legacy=legacy)
    live_rev=parse(read_root(TRAFFIC_REVOCATION))
    live_trust=parse(read_root(TRAFFIC_TRUST))
    need(live_trust==trust,'ROOT_TRAFFIC_TRUST_CHANGED')
    signed_traffic(auth_module=b4,grant=traffic,trust=trust,
        revocation=live_rev,handoff=handoff,b4docs=b4docs,
        approved_head=manifest['approved_head'],boot_id=boot_id,now=now)
    remaining=policy.timer_remaining(legacy.timer('ardrec-r116-f1-deny-'+session),
              monotonic_seconds=time.monotonic(),
              expected_unit='ardrec-r116-f1-deny-'+session)
    policy.permit_margin(now=now,
         permit_expiry=b4.at(traffic['statement']['valid_until']),
         timer_seconds=remaining)
    need((time.monotonic_ns()-monotonic_start)<45_000_000_000,
         'DENY_BACKUP_MUST_NOT_HAVE_EXPIRED')


def store(folder: Path, name: str, value: dict):
    need(name in ('intent.json','receipt.json') and
         folder.parent==ROOT and re.fullmatch(r'pilot-[0-9a-f]{16}',folder.name),
         'ROOT_RECEIPT_SCOPE')
    body=canon(value)
    need(len(body)<=MAX_FILE,'ROOT_RECEIPT_TOO_LARGE')
    fd=os.open(folder/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(body);f.flush();os.fsync(f.fileno())
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def execute(*, manifest, auth, b4docs, handoff, traffic_grant,
            traffic_trust, traffic_revocation, boot_id, legacy):
    """Physical execution only from immutable independently installed root code."""
    need(os.geteuid()==0 and Path(__file__).resolve()==SCRIPT,
         'IMMUTABLE_EXECUTOR_REQUIRED')
    now=datetime.now(timezone.utc)
    ready=preflight(manifest=manifest,auth=auth,b4docs=b4docs,handoff=handoff,
        traffic_grant=traffic_grant,traffic_trust=traffic_trust,
        traffic_revocation=traffic_revocation,now=now,boot_id=boot_id)
    session=ready['session']
    # R116 F3 legacy code is authenticated as DATA + fixed helper functions.
    # Neither its historically pinned main() nor independent_review() is invoked.
    legacy.staged()
    policy,_,_,_,_=legacy.modules()
    policy.five_one(legacy.root_guard('--check'))
    g114,bundle=legacy.old_ftp_material(policy)
    # Historic F8 Python replay from the mutable Git tree is forbidden.
    # The root-owned F8 reference is attested by B14 signed release at entry.
    guard_legacy=legacy.root_guard_library()
    need(not (legacy.ROOT/legacy.ONE).exists(), 'HISTORICAL_PILOT_ALREADY_SPENT')
    # Durable root-side claim occurs BEFORE arming or enabling any traffic.
    # Distinct B9 claim remains spent even if b4 arm fails/crashes.
    fd=os.open(ROOT/'attempt-consumed.once',
        os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(canon({'schema':SCHEMA+'-claim','session':session,
            'f13_handoff_sha256':digest(handoff),'p8':'NO-GO'}));f.flush();os.fsync(f.fileno())
    dfd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(dfd)
    finally:os.close(dfd)
    folder=ROOT/('pilot-'+session)
    folder.mkdir(mode=0o700)
    store(folder,'intent.json',{'schema':SCHEMA+'-intent',
          'session':session,'head':manifest['approved_head'],
          'f13_handoff_sha256':digest(handoff),
          'root_traffic_grant_sha256':digest(traffic_grant),
          'root_deny_grant_sha256':digest(b4docs['grant']),
          'boot_id':boot_id,'a6':'ND','p8':'NO-GO'})
    armed=False;opened=False;result=None;error=None;restored=False
    start=time.monotonic_ns()
    try:
        arm=auth.arm({'approved_head':manifest['approved_head']},b4docs,
              now=datetime.now(timezone.utc),boot_id=boot_id)
        need(arm['session']==session and arm['timer']['timer_active'] is True,
             'R116_SESSION_TIMER_ARM_FAILED')
        armed=True
        def gate():
            fresh_gate(b4=auth,b4docs=b4docs,manifest=manifest,
                 traffic=traffic_grant,trust=traffic_trust,
                 revocation=traffic_revocation,handoff=handoff,boot_id=boot_id,
                 session=session,legacy=legacy,policy=policy,monotonic_start=start)
        gate()
        legacy.run(('/usr/sbin/nft','--check','--file','-'),
                   input=bundle['r34-ftp-only.nft'],timeout=8)
        _,six=guard_legacy.historical()
        legacy.transition_to_ftp_candidate(guard_legacy,six,policy,gate)
        gate()
        legacy.run(('/usr/sbin/nft','-f','-'),
                   input=bundle['r34-ftp-only.nft'],timeout=8)
        opened=True
        gate()
        g114.audit_live_nft(legacy.run(('/usr/sbin/nft','-j','-a',
                              'list','table','bridge','ardrec_r34_guard')))
        gate()
        # Exactly ONE QGA guest-exec, creating at most one TCP connection.
        result=legacy.execute_one_guest_probe(folder,gate,
                       budget=ready['budget'],case_id=ready['case_id'])
    except Exception as exc:
        error=type(exc).__name__+':'+str(exc)[:120]
    finally:
        if armed or opened or (auth.GUARD.parent/'arm-consumed.once').exists():
            try:
                done=legacy.root_guard('--restore-deny')
                need(done.get('status')=='DENY_RESTORED',
                     'DENY_RESTORE_NOT_CONFIRMED')
                policy.five_one(legacy.root_guard('--check'))
                restored=True
            except Exception as exc:
                error='CRITICAL_DENY_UNVERIFIED:'+type(exc).__name__
        elapsed=time.monotonic_ns()-start
        status=('FTP_GUEST_CANDIDATE_ONLY' if
                result is not None and error is None and restored and
                elapsed<=60_000_000_000 else 'NO_GO_ATTEMPT_CONSUMED')
        receipt={'schema':SCHEMA+'-receipt','session':session,
             'head':manifest['approved_head'],'case_id':ready['case_id'],
             'f13_handoff_sha256':digest(handoff),
             'root_traffic_grant_sha256':digest(traffic_grant),
             'denies_restored_and_verified':restored,
             'timer_armed':armed,'traffic_window_opened':opened,
             'guest_result_sha256':digest(result) if result is not None else None,
             'elapsed_monotonic_ns':elapsed,'result':status,
             'error':error,'a6':'ND','a9':None,'p8':'NO-GO'}
        store(folder,'receipt.json',receipt)
    return receipt


def capabilities():
    return {'schema':SCHEMA+'-capabilities',
        'root_staged_signed_release_required':True,
        'root_release_cryptographically_verified':True,
        'release_revocation_rechecked_during_window':True,
        'no_mutable_historical_f8_replay':True,
        'root_traffic_grant_separate_from_deny_grant':True,
        'ten_distinct_ed25519_signers':True,
        'f13_prebound_spent_before_dispatch':True,
        'one_guest_qga_socket_reader_only':True,
        'reuses_pinned_r116_f3_helpers_not_historical_main':True,
        'r116_autonomous_deny_45s':True,
        'synchronous_deny_restore':True,
        'starts_vms':False,'automatic_network':False,
        'installed_from_this_package':False,
        'pilot_real_execution_proven':False,
        'a6':'ND','a9':None,'p8':'NO-GO'}


def main(argv=None):
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capabilities',action='store_true')
    group.add_argument('--inspect-root',action='store_true')
    group.add_argument('--execute-pilot',action='store_true')
    args=parser.parse_args(argv)
    if args.capabilities:
        print(canon(capabilities()).decode().strip())
        return 0
    try:
        manifest=stage()
        b4=load_pinned(B4,B4_PIN,'ardrec_r126_b4_root')
        b4.protected_root()
        docs=b4.read_documents()
        handoff=parse(read_root(ROOT/'f13-handoff.json'))
        grant=parse(read_root(ROOT/'traffic-grant.json'))
        trust=parse(read_root(TRAFFIC_TRUST))
        revoked=parse(read_root(TRAFFIC_REVOCATION))
        lockfd=os.open(ROOT/'lock',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            boot=b4.read_boot_id()
            legacy=load_pinned(F3,F3_PIN,'ardrec_r116_f3_pinned_helpers')
            legacy.staged()
            root_live_release(auth=b4, manifest=manifest, b4docs=docs,
                              boot_id=boot, legacy=legacy)
            if args.inspect_root:
                result=preflight(manifest=manifest,auth=b4,b4docs=docs,
                    handoff=handoff,traffic_grant=grant,traffic_trust=trust,
                    traffic_revocation=revoked,now=datetime.now(timezone.utc),
                    boot_id=boot)
            else:
                result=execute(manifest=manifest,auth=b4,b4docs=docs,
                    handoff=handoff,traffic_grant=grant,traffic_trust=trust,
                    traffic_revocation=revoked,boot_id=boot,legacy=legacy)
        finally:
            os.close(lockfd)
        print(canon(result).decode().strip(),flush=True)
        return 0 if result.get('result')!='NO_GO_ATTEMPT_CONSUMED' else 23
    except Exception as exc:
        print(canon({'schema':SCHEMA+'-refusal','status':'DENY_NO_RETRY',
                   'reason':type(exc).__name__+':'+str(exc)[:160],
                   'a6':'ND','p8':'NO-GO'}).decode().strip(),file=sys.stderr)
        return 23

if __name__=='__main__':
    raise SystemExit(main())
