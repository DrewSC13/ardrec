"""R168-F2: separate current-HEAD signed release for Runner boot under DENY.

Source/approval/revocation checks only; does not grant network or P8.
The role-specific boot permit and scope signatures remain separate mandatory gates.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os
import stat

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r167_f7d_release_gate as previous

SCHEMA = 'ARDREC-R168-F2-RUNNER-RELEASE-APPROVAL-v1'
REVOKE_SCHEMA = 'ARDREC-R168-F2-RUNNER-RELEASE-REVOCATION-v1'
PREFIX = b'ARDREC-R168-F2-RUNNER-RELEASE-v1\x00'
REVOKE_PREFIX = b'ARDREC-R168-F2-RUNNER-RELEASE-REVOCATION-v1\x00'
MANIFEST = Path('/home/cicada/Development/GitHub/ardrec/lab/operational-controller/r168-f2-runner-source-v1.json')
APPROVAL = Path('/home/cicada/ardrec-lab/r168-f2-runner-release-v1/release.json')
REVOCATION = Path('/etc/ardrec/r168-f2-runner-release-revocation-v1.json')
ROOT_MAX = 8192
MAX_RELEASE_SEC = 900
MAX_REVOCATION_SEC = 90

class Stop(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def digest(obj):
    return f1.digest(f1.canonical(obj))

def root_revocation_bytes(path=REVOCATION):
    need(path == REVOCATION, 'ROOT_REVOCATION_PATH_NOT_ALLOWED')
    for item in (Path('/'), Path('/etc'), Path('/etc/ardrec')):
        st = item.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and
             not (st.st_mode & 0o022) and not item.is_symlink(),
             'ROOT_PARENT_NOT_TRUSTED')
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
         st.st_nlink == 1 and not (st.st_mode & 0o022) and
         0 < st.st_size <= ROOT_MAX and not path.is_symlink(),
         'ROOT_REVOCATION_NOT_TRUSTED')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        live = os.fstat(fd)
        need(live.st_dev == st.st_dev and live.st_ino == st.st_ino and
             live.st_size == st.st_size and live.st_uid == 0 and
             live.st_nlink == 1, 'ROOT_REVOCATION_RACE')
        raw = os.read(fd, ROOT_MAX + 1)
        need(len(raw) == st.st_size, 'ROOT_REVOCATION_READ_SHORT')
        return raw
    finally:
        os.close(fd)

def private_release_bytes(path=APPROVAL):
    need(path == APPROVAL, 'RELEASE_APPROVAL_PATH_NOT_ALLOWED')
    parent = path.parent
    ps = parent.lstat()
    need(stat.S_ISDIR(ps.st_mode) and not parent.is_symlink() and
         ps.st_uid == os.geteuid() and stat.S_IMODE(ps.st_mode) == 0o700,
         'RELEASE_DIR_CUSTODY')
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and not path.is_symlink() and
         st.st_uid == os.geteuid() and st.st_nlink == 1 and
         stat.S_IMODE(st.st_mode) == 0o600 and 0 < st.st_size <= ROOT_MAX,
         'RELEASE_APPROVAL_CUSTODY')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        live = os.fstat(fd)
        need(live.st_dev == st.st_dev and live.st_ino == st.st_ino and
             live.st_size == st.st_size, 'RELEASE_APPROVAL_RACE')
        raw = os.read(fd, ROOT_MAX + 1)
        need(len(raw) == st.st_size, 'RELEASE_APPROVAL_SIZE_CHANGED')
        return raw
    finally:
        os.close(fd)

def source_admission():
    obj = f1.load(MANIFEST.read_bytes())
    need(set(obj) == {'schema','files_sha256','historical_source_sha256',
                      'role','boot_release','traffic_authorized','p8'},
         'SOURCE_MANIFEST_FIELDS')
    need(obj['schema'] == 'ARDREC-R168-F2-RUNNER-SOURCE-v1' and
         obj['role'] == 'runner' and obj['boot_release'] == 'SIGNED_REQUIRED' and
         obj['traffic_authorized'] is False and obj['p8'] == 'NO-GO',
         'SOURCE_MANIFEST_SCOPE')
    sources = {
        'src/ardrec/coordination/r168_f2_runner_ftp_boot.py',
        'src/ardrec/coordination/r168_f2_runner_release_gate.py',
        'scripts/ardrec_p14_r168_f2_runner_ftp.py',
        'lab/tests/test_p14_r168_f2_runner_release.py',
    }
    need(type(obj['files_sha256']) is dict and
         set(obj['files_sha256']) == sources, 'SOURCE_FILE_SET_DRIFT')
    repo = Path('/home/cicada/Development/GitHub/ardrec')
    for name, expected in obj['files_sha256'].items():
        p = repo / name
        need(p.is_file() and not p.is_symlink() and
             type(expected) is str and f1.SHA.fullmatch(expected) and
             f1.digest(p.read_bytes()) == expected,
             'SOURCE_SHA256_DRIFT_' + name)
    return obj['files_sha256']

def require(plan, *, now):
    need(type(now) is datetime and now.tzinfo is not None,
         'UTC_CLOCK_REQUIRED')
    now = now.astimezone(timezone.utc)
    sources = source_admission()
    need(type(plan) is dict and plan.get('role') == 'runner' and
         plan.get('traffic_authorized') is False and
         plan.get('p8') == 'NO-GO' and
         type(plan.get('head')) is str and
         f1.GIT_SHA.fullmatch(plan['head']) and
         type(plan.get('contract_sha256')) is str and
         type(plan.get('authorization_sha256')) is str and
         f1.SHA.fullmatch(plan['contract_sha256']) and
         f1.SHA.fullmatch(plan['authorization_sha256']),
         'RUNNER_RELEASE_PLAN_SCOPE')
    trust = previous.root_policy(previous.RELEASE_TRUST)
    f3.trust_check(trust)
    approval_raw = private_release_bytes()
    need(f1.canonical(f1.load(approval_raw)) == approval_raw,
         'RELEASE_NOT_CANONICAL')
    approval = f1.load(approval_raw)
    f3.exact(approval, {'statement','signer_key_id','signature_b64'},
             'RELEASE_WRAPPER')
    s = approval['statement']
    f3.exact(s, {'schema','release_id','head','role','plan_sha256',
                 'contract_sha256','authorization_sha256','files_sha256',
                 'valid_from','valid_until','action','network_traffic_authorized','p8'},
             'RELEASE_FIELDS')
    need(s['schema'] == SCHEMA and type(s['release_id']) is str and
         f1.ID.fullmatch(s['release_id']) and s['head'] == plan['head'] and
         s['role'] == 'runner' and s['plan_sha256'] == digest(plan) and
         s['contract_sha256'] == plan['contract_sha256'] and
         s['authorization_sha256'] == plan['authorization_sha256'] and
         s['files_sha256'] == sources and
         s['action'] == 'ONE_DENY_BOOT_ONLY' and
         s['network_traffic_authorized'] is False and s['p8'] == 'NO-GO',
         'RUNNER_RELEASE_SCOPE_CHANGED')
    start = f1._instant(s['valid_from'], 'RELEASE_FROM')
    end = f1._instant(s['valid_until'], 'RELEASE_TO')
    need(start <= now < end and 0 < (end-start).total_seconds() <= MAX_RELEASE_SEC,
         'RELEASE_TIME_NOT_CURRENT')
    f3.verified_signature(approval,s,trust['scope_signer'],PREFIX)
    rev_raw = root_revocation_bytes()
    need(f1.canonical(f1.load(rev_raw)) == rev_raw,
         'REVOCATION_NOT_CANONICAL')
    rev = f1.load(rev_raw)
    f3.exact(rev, {'statement','signer_key_id','signature_b64'},
             'RELEASE_REVOCATION_WRAPPER')
    r = rev['statement']
    f3.exact(r, {'schema','release_sha256','release_id','issued_at',
                 'valid_until','revoked','reason_code'},
             'RELEASE_REVOCATION_FIELDS')
    need(r['schema'] == REVOKE_SCHEMA and
         r['release_sha256'] == digest(approval) and
         r['release_id'] == s['release_id'] and
         r['revoked'] is False and
         type(r['reason_code']) is str and
         f1.ID.fullmatch(r['reason_code']),
         'RUNNER_RELEASE_REVOCATION_SCOPE')
    f3.verified_signature(rev,r,trust['revocation_signer'],REVOKE_PREFIX)
    issued = f1._instant(r['issued_at'], 'REVOKE_FROM')
    until = f1._instant(r['valid_until'], 'REVOKE_TO')
    need(issued <= now < until and 0 <= (now-issued).total_seconds() <= MAX_REVOCATION_SEC and
         0 < (until-issued).total_seconds() <= MAX_REVOCATION_SEC,
         'RUNNER_RELEASE_REVOCATION_STALE')
    return {'release_sha256':digest(approval),
            'revocation_sha256':digest(rev),
            'role':'runner','network_traffic_authorized':False,'p8':'NO-GO'}
