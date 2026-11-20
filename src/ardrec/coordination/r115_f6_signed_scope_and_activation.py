"""R115-F6: integrate fresh F5 physical state with root-anchored signed FTP-T01 scope.

Strictly read-only: verifies signed statements and current DENY baseline; outputs
an activation handoff, never a boot lease, traffic grant, A5 execution or A6 fact.
The trust and revocation roots are independently provisioned; the caller cannot
supply an alternative path through this CLI.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f5_lifecycle_readiness as f5

SCHEMA = 'ARDREC-R115-F6-SIGNED-SCOPE-ACTIVATION-HANDOFF-v1'
BASE = 'a652195a544a549dbad6a44120e3d447cf4d4994'
CATALOG = Path(__file__).resolve().parents[3] / 'lab/operational-catalog-v1/catalog.json'
TRUST = Path('/etc/ardrec/r115-ftp-t01-trust-v1.json')
REVOCATION = Path('/etc/ardrec/r115-ftp-t01-revocation-v1.json')
ROOT = Path('/home/cicada/ardrec-lab/r115-f6-signed-scope-v1')
MAX_FRESH_SEC = 120
MAX_REVOCATION_AGE_SEC = 90
MAX_ROOT_FILE = 8192

class Stop(ValueError):
    pass

def need(condition, code):
    if not condition:
        raise Stop(code)

def now_utc():
    return datetime.now(timezone.utc)

def secure_root_file(path: Path) -> bytes:
    """Load fixed root-owned policy file without following symlinks or trusting its name alone."""
    need(path in (TRUST, REVOCATION), 'ROOT_INPUT_NOT_ALLOWLISTED')
    for item in (Path('/'), Path('/etc'), Path('/etc/ardrec')):
        s = item.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and
             not (s.st_mode & 0o022), 'ROOT_POLICY_PARENT_NOT_TRUSTED')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and
         not (s.st_mode & 0o022) and 0 < s.st_size <= MAX_ROOT_FILE,
         'ROOT_POLICY_FILE_NOT_TRUSTED')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        need(stat.S_ISREG(actual.st_mode) and actual.st_dev == s.st_dev and
             actual.st_ino == s.st_ino and actual.st_uid == 0 and
             actual.st_nlink == 1 and actual.st_size == s.st_size,
             'ROOT_POLICY_RACE')
        raw = os.read(fd, MAX_ROOT_FILE + 1)
        need(len(raw) == s.st_size, 'ROOT_POLICY_INCOMPLETE')
        return raw
    finally:
        os.close(fd)

def verify_f5_receipt(folder: Path, *, now=None) -> tuple[dict, dict, int]:
    """Recompute F5 report from original bytes; reject stale/inconsistent receipts."""
    if now is None:
        now = now_utc()
    try:
        originals = {name: f2.private_read(folder/name) for name in
                     ('capture.json', 'report.json', 'manifest.json')}
        manifest = f1.load(originals['manifest.json'])
        need(set(manifest) == {'schema', 'files_sha256', 'scope'} and
             manifest['schema'] == 'ARDREC-R115-F5-RECEIPT-v1' and
             manifest['scope'] == 'READ_ONLY_NO_DISPATCH_NO_AUTHORITY',
             'F5_RECEIPT_MANIFEST')
        need(type(manifest['files_sha256']) is dict and
             set(manifest['files_sha256']) == {'capture.json', 'report.json'},
             'F5_RECEIPT_FILES')
        for name in ('capture.json','report.json'):
            need(manifest['files_sha256'][name] == f1.digest(originals[name]),
                 'F5_RECEIPT_SHA_'+name)
        captured = f1.load(originals['capture.json'])
        report = f1.load(originals['report.json'])
        expected = f5.report(captured)
        need(expected == report and f1.canonical(expected) == originals['report.json'],
             'F5_REPORT_NOT_REPRODUCIBLE')
        moment = f1._instant(captured['end'], 'F5_END')
        lag = (now - moment).total_seconds()
        need(-5 <= lag <= MAX_FRESH_SEC, 'F5_CAPTURE_STALE_OR_FUTURE')
        return captured, expected, round(lag)
    except (OSError, ValueError, KeyError, TypeError, f1.Rejected, f2.Stop, f5.Stop) as exc:
        if isinstance(exc, Stop):
            raise
        raise Stop('F5_RECEIPT_REJECTED_'+type(exc).__name__) from exc

def scope(contract_raw: bytes | None, authorization_raw: bytes | None,
          *, catalog_raw: bytes, now: datetime, root_loader=secure_root_file):
    """Only a fixed root-managed trust + signed recent revocation can establish scope."""
    if contract_raw is None or authorization_raw is None:
        need(contract_raw is None and authorization_raw is None,
             'PARTIAL_SCOPE_INPUT')
        return ('ND','NO_OPERATOR_CONTRACT_AND_SIGNED_AUTHORIZATION',None)
    try:
        c = f1.load(contract_raw)
        f1.validate(c, f1.load(catalog_raw), catalog_raw)
        need(c['source_commit'] == BASE, 'CONTRACT_BASE_MISMATCH')
        auth = f1.load(authorization_raw)
    except (f1.Rejected, ValueError, TypeError, KeyError) as exc:
        raise Stop('INVALID_CONTRACT_OR_AUTHORIZATION_'+type(exc).__name__) from exc
    try:
        trust = f1.load(root_loader(TRUST))
        revoked = f1.load(root_loader(REVOCATION))
    except FileNotFoundError:
        return ('ND','INDEPENDENT_ROOT_TRUST_OR_REVOCATION_NOT_PROVISIONED',None)
    except (OSError, ValueError, f1.Rejected, Stop) as exc:
        return ('ND','ROOT_TRUST_NOT_ATTESTED_'+type(exc).__name__,None)
    try:
        review = f3.auth_review(c,auth,revoked,trust, now=now.isoformat())
        if review['status'] == 'FALSO':
            return ('FALSO','SIGNED_REVOCATION_PRESENT',review['authorization_sha256'])
        issued = f1._instant(revoked['statement']['issued_at'],'REVOCATION_ISSUED')
        until = f1._instant(revoked['statement']['valid_until'],'REVOCATION_UNTIL')
        start = f1._instant(c['valid_from'],'SCOPE_FROM')
        stop = f1._instant(c['valid_until'],'SCOPE_UNTIL')
        age = (now-issued).total_seconds()
        if (review['crypto_verified'] is True and
            review['reason'] == 'CRYPTO_VALID_BUT_HOST_AUTHORITY_NOT_PINNED' and
            0 <= age <= MAX_REVOCATION_AGE_SEC and
            start <= now < min(stop,until)):
            # Approval is a snapshot for THIS handoff, not a reusable A5 grant.
            return ('VERDADERO','SIGNED_SCOPE_ROOT_ANCHORED_AT_REVIEW_ONLY',
                    review['authorization_sha256'])
        return ('ND','SIGNED_SCOPE_OR_REVOCATION_NOT_CURRENT',review['authorization_sha256'])
    except (f3.Stop, f1.Rejected, KeyError, ValueError, TypeError) as exc:
        # Forged/inconsistent signatures are not silently treated as authorization.
        return ('FALSO','SIGNED_AUTHORITY_VALIDATION_FAILED_'+type(exc).__name__,None)

def decision(f5_report: dict, freshness_seconds: int, scope_result):
    need(type(f5_report) is dict and f5_report.get('schema') == f5.REPORT_SCHEMA,
         'INVALID_F5_REPORT')
    state = f5_report['lifecycle_stage']
    need(state in ('OFFLINE_DENY_BASELINE_MATCH', 'RUNNING_SIX_DENY_BINDINGS_MATCH',
                   'DRIFT_NO_GO', 'INCOMPLETE_OR_TRANSITION_NO_GO'), 'INVALID_STAGE')
    s, reason, auth_sha = scope_result
    a3 = dict(f5_report['a3'])
    a3['SCOPE_APPROVED'] = s
    if state == 'DRIFT_NO_GO':
        a3['LAB_ISOLATION_CONFIRMED'] = 'FALSO'
    else:
        a3['LAB_ISOLATION_CONFIRMED'] = 'ND'
    if f5_report['vm_definitions']['ftp'] == 'DRIFT':
        a3['DESTINATION_AUTHORIZED'] = 'FALSO'
    if f5_report['states']['ftp'] == 'OFF' or f5_report['states']['runner'] == 'OFF':
        a3['SERVICE_READY'] = 'FALSO'
    # Destination authorization is not the same as a VM-definition match.
    a3['CLIENT_COMPATIBLE'] = 'ND'
    if state == 'OFFLINE_DENY_BASELINE_MATCH':
        next_gate = 'SEPARATE_BOOT_AUTHORIZATION_R112_F12_THEN_R112_F10'
    elif state == 'RUNNING_SIX_DENY_BINDINGS_MATCH':
        next_gate = 'SEPARATE_P8_WINDOW_PROFILE_CLIENT_AND_SERVICE_ATTESTATION'
    elif state == 'DRIFT_NO_GO':
        next_gate = 'RECONCILE_DENY_POLICY_WITHOUT_DISPATCH'
    else:
        next_gate = 'RECONCILE_LIFECYCLE_WITHOUT_RETRY'
    blockers = [k for k,v in a3.items() if v != 'VERDADERO']
    return {'schema':SCHEMA,'f5_lifecycle_stage':state,
            'f5_capture_age_seconds':freshness_seconds,
            'authority_at_review':s,'authority_reason':reason,
            'authorization_sha256':auth_sha,
            'a3':a3,'blocking_gates':blockers,
            'next_authorized_workflow':next_gate,
            'boot_lease_issued':False,'guests_started':0,
            'traffic_authorized':False,'a5_dispatch':'NO-GO',
            'a6':'ND','p8':'NO-GO','a7_confirmed_rf':None,
            'a9_generation':None,'read_only':True}

def run_review(*, receipt: Path, contract: Path | None = None,
               authorization: Path | None = None, now=None):
    if now is None: now = now_utc()
    captured, report, age = verify_f5_receipt(receipt, now=now)
    cat_raw = CATALOG.read_bytes()
    source = None if contract is None else f2.private_read(contract)
    signed = None if authorization is None else f2.private_read(authorization)
    result = decision(report,age,scope(source,signed,catalog_raw=cat_raw,now=now))
    result['f5_capture_sha256'] = f1.digest(f1.canonical(captured))
    result['catalog_sha256'] = f1.digest(cat_raw)
    return result

def save_private(report, root=ROOT):
    need(os.geteuid()!=0, 'NO_ROOT_SHELL')
    if not root.exists():
        need(root.parent.is_dir() and not root.parent.is_symlink(), 'PRIVATE_PARENT_MISSING')
        root.mkdir(mode=0o700)
    f2.private_parent(root)
    folder = Path(tempfile.mkdtemp(prefix='review-',dir=root))
    raw = f1.canonical(report)
    f2.exclusive(folder/'report.json',raw)
    f2.exclusive(folder/'manifest.json',f1.canonical({
        'schema':'ARDREC-R115-F6-RECEIPT-v1',
        'report_sha256':f1.digest(raw),
        'mode':'READ_ONLY_NO_BOOT_NO_DISPATCH'}))
    return folder

def main(argv=None):
    import argparse
    p=argparse.ArgumentParser(description='R115-F6 signed scope + F5 lifecycle handoff, no execution')
    p.add_argument('--receipt',type=Path,required=True)
    p.add_argument('--contract',type=Path)
    p.add_argument('--authorization',type=Path)
    a=p.parse_args(argv)
    try:
        need(os.geteuid()!=0,'NO_ROOT_SHELL')
        report=run_review(receipt=a.receipt,contract=a.contract,
                          authorization=a.authorization)
        folder=save_private(report)
    except (Stop, f1.Rejected, f2.Stop, f5.Stop, OSError, ValueError) as exc:
        print('R115_F6_STOP='+type(exc).__name__+':'+str(exc))
        return 2
    print('R115_F6_RECEIPT='+str(folder))
    print('R115_F6_STAGE='+report['f5_lifecycle_stage'])
    print('R115_F6_SCOPE='+report['authority_at_review'])
    print('R115_F6_AUTHORITY_REASON='+report['authority_reason'])
    for name in f1.GATES:
        print('R115_F6_A3_'+name+'='+report['a3'][name])
    print('R115_F6_BLOCKERS='+','.join(report['blocking_gates']))
    print('R115_F6_NEXT='+report['next_authorized_workflow'])
    print('R115_F6_DISPATCH=NO-GO')
    print('R115_F6_A6=ND')
    print('R115_F6_P8=NO-GO')
    print('R115_F6_GUEST_STARTS=0')
    print('R115_F6_NETWORK_PROBES=0')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
