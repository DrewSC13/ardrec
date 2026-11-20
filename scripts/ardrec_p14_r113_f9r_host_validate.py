#!/usr/bin/env python3
"""ARDREC R113-F9R corrected ARP XML host policy acceptance preflight, strictly no network admission.

Only checks an existing, hash-replayed F8 candidate via nft --check and
virt-xml-validate, and executes F6 check/attest (read-only). One-time session
receipts; --replay never invokes host commands. Does not mutate Git.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

REPO = Path('/home/cicada/Development/GitHub/ardrec')
PLAN_BASE = Path('/home/cicada/ardrec-lab/r113-f8r-arp-xml-v1')
PLAN = None
BASE = Path('/home/cicada/ardrec-lab/r113-f9r-arp-host-acceptance-v1')
F6 = Path('/var/lib/ardrec/r113-six-deny-guard-v1/root-recover.py')
HEAD = None
BRANCH = 'feat/p14-r111-r114-real-lab'
ROLES = ('runner-ssh', 'ssh', 'runner-ftp', 'ftp', 'runner-smb', 'smb')
NAMES = ('r34-window-CANDIDATE.nft',) + tuple('ardrec-r113-' + r + '-tcp-v1.xml' for r in ROLES)
SCHEMA = 'ARDREC-R113-F9R-CORRECTED-ARP-HOST-CHECK-v1'
TIMEOUT = 30

class Stop(ValueError): pass

def need(value: bool, message: str) -> None:
    if not value: raise Stop(message)

def sha(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def canonical(data: object) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')

def secure_dir(folder: Path) -> None:
    st = folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
         stat.S_IMODE(st.st_mode) == 0o700 and not folder.is_symlink(),
         'PRIVATE_FOLDER_INVALID_' + folder.name)

def secure_file(path: Path, allow_empty: bool = False) -> bytes:
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and not path.is_symlink() and
         st.st_uid == os.geteuid() and st.st_nlink == 1 and
         stat.S_IMODE(st.st_mode) == 0o600 and
         (st.st_size >= 0 if allow_empty else st.st_size > 0) and
         st.st_size < 524288, 'PRIVATE_FILE_INVALID_' + path.name)
    return path.read_bytes()

def save(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def command(folder: Path, name: str, argv: list[str], *, timeout: int = TIMEOUT) -> dict:
    need(name.replace('_', '').replace('-', '').isalnum(), 'COMMAND_LABEL_INVALID')
    try:
        proc = subprocess.run(argv, cwd=REPO, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False, timeout=timeout, close_fds=True)
        rc = proc.returncode
        out, err = proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        rc = 124 if isinstance(exc, subprocess.TimeoutExpired) else 127
        out = exc.stdout or b'' if isinstance(exc, subprocess.TimeoutExpired) else b''
        err = (type(exc).__name__ + ': ' + str(exc)).encode('utf-8', 'replace')[:3500]
    need(len(out) < 524288 and len(err) < 65536, 'COMMAND_OUTPUT_TOO_LARGE_' + name)
    save(folder / (name + '.stdout'), out)
    save(folder / (name + '.stderr'), err)
    print('QUERY_' + name + '_RC=' + str(rc), flush=True)
    print('QUERY_' + name + '_STDOUT_SHA256=' + sha(out), flush=True)
    print('QUERY_' + name + '_STDERR_SHA256=' + sha(err), flush=True)
    if rc != 0:
        # Native validation errors are essential to diagnose host-specific grammar.
        print('QUERY_' + name + '_ERROR=' + err.decode('utf-8', 'replace')[-1800:].replace('\n',' | '), flush=True)
    return {'argv': argv, 'rc': rc, 'stdout_sha256': sha(out),
            'stderr_sha256': sha(err), 'stdout_bytes': len(out), 'stderr_bytes': len(err)}

def repo_clean() -> None:
    need(HEAD is not None and len(HEAD) == 40, 'REQUIRED_PINNED_GIT_HEAD')
    checks = [
        (['git','branch','--show-current'], BRANCH),
        (['git','rev-parse','HEAD'], HEAD),
        (['git','log','-1','--format=%G?'], 'G'),
        (['git','status','--porcelain=v1','-uall'], ''),
    ]
    for argv, expected in checks:
        p = subprocess.run(argv, cwd=REPO, capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, timeout=15, check=False)
        need(p.returncode == 0 and p.stdout.strip() == expected,
             'SIGNED_GIT_PREFLIGHT_FAILED_' + argv[1])

def prep_copies(folder: Path) -> dict[str, str]:
    need(PLAN is not None and PLAN.parent == PLAN_BASE and PLAN.name.startswith('plan-'), 'PLAN_PATH_DRIFT')
    secure_dir(PLAN.parent)
    secure_dir(PLAN)
    # Check original immutable source bytes first, not a local reimplementation.
    meta = json.loads(secure_file(PLAN / 'manifest.json'))
    need(meta.get('schema') == 'ARDREC-R113-F8R-CORRECTED-ARP-OFFLINE-v1' and
         meta.get('safety') == {'policy_installed':False,'traffic_admitted':False,'p8':'NO-GO'} and
         meta.get('rejected_f9_report_sha256') == '5f492ab67002cd6d8ce4d898d09c3c59c3c9551e72c243f6ac41f0e2190ae03d',
         'F8R_POLICY_MANIFEST_INVALID')
    digests = meta.get('sha256')
    need(isinstance(digests, dict) and set(digests) == set(NAMES), 'F8R_FILE_SCOPE_INVALID')
    need({p.name for p in PLAN.iterdir()} == set(NAMES) | {'manifest.json'}, 'F8R_PLAN_DRIFT')
    copied = {}
    for name in NAMES:
        data = secure_file(PLAN / name)
        need(sha(data) == digests[name], 'F8R_HASH_CHANGED_' + name)
        save(folder / name, data)
        copied[name] = sha(data)
    # Retain the exact original policy metadata to reconstruct a detached receipt.
    save(folder / 'f8-manifest.json', secure_file(PLAN / 'manifest.json'))
    return copied

def attest_result(folder: Path, result: dict, label: str, expected: str) -> None:
    need(result['rc'] == 0, 'F6_' + label + '_COMMAND_FAILED')
    content = json.loads(secure_file(folder / (label + '.stdout')))
    need(content.get('result') == expected and content.get('bindings') == 6 and
         content.get('p8') == 'NO-GO', 'F6_' + label + '_NOT_ATTESTED')

def execute() -> int:
    os.umask(0o077)
    repo_clean()
    # Root-owned F6 directory is mode 0700: unprivileged stat is not reliable.
    # Verify its exact root bundle through sudo --check-root-bundle instead.
    # No existing F9 session is ever reused for physical commands.
    if not BASE.exists(): BASE.mkdir(mode=0o700)
    secure_dir(BASE)
    folder = Path(tempfile.mkdtemp(prefix='validation-', dir=BASE))
    secure_dir(folder)
    print('R113_F9R_SESSION=' + str(folder), flush=True)
    results = {}
    errors = []
    try:
        replay = command(folder, 'f8_replay', [str(REPO / '.venv/bin/python'),
                         str(REPO / 'scripts/ardrec_p14_r113_f8r_policy.py'),
                         '--replay', str(PLAN)])
        results['f8_replay'] = replay
        need(replay['rc'] == 0 and b'R113_F8R_POLICY_REPLAY=PASS' in
             secure_file(folder / 'f8_replay.stdout'), 'F8R_REPLAY_FAILED')
        copied = prep_copies(folder)
        print('R113_F9R_F8_POLICY=REPLAY_AND_SHA256_PASS', flush=True)

        check = command(folder, 'f6_root_check',
                        ['/usr/bin/sudo','-n','/usr/bin/python3',str(F6),'--check-root-bundle'])
        results['f6_root_check'] = check
        attest_result(folder, check, 'f6_root_check', 'ROOT_BUNDLE_VERIFIED')

        before = command(folder, 'f6_before',
                         ['/usr/bin/sudo','-n','/usr/bin/python3',str(F6),'--attest-deny'])
        results['f6_before'] = before
        attest_result(folder, before, 'f6_before', 'SIX_BINDING_DENY_ATTESTED')
        print('R113_F9R_DENY_BEFORE=PASS_SIX_BINDINGS', flush=True)

        nft_tool = Path('/usr/sbin/nft')
        need(nft_tool.is_file(), 'NFT_TOOL_NOT_FOUND')
        nft = command(folder, 'nft_check', ['/usr/bin/sudo','-n',str(nft_tool),
                     '--check','--file',str(folder / 'r34-window-CANDIDATE.nft')])
        results['nft_check'] = nft
        if nft['rc'] != 0: errors.append('NFT_CANDIDATE_NOT_ACCEPTED')

        validator = shutil.which('virt-xml-validate')
        if not validator:
            errors.append('LIBVIRT_SCHEMA_VALIDATOR_UNAVAILABLE')
            print('R113_F9R_VIRT_XML_VALIDATE=NOT_INSTALLED', flush=True)
        else:
            print('R113_F9R_VIRT_XML_VALIDATE=' + validator, flush=True)
            for role in ROLES:
                key = 'xml_' + role.replace('-', '_')
                xmlname = 'ardrec-r113-' + role + '-tcp-v1.xml'
                verified = command(folder, key, [validator, str(folder / xmlname), 'nwfilter'])
                results[key] = verified
                if verified['rc'] != 0: errors.append('NWFILTER_NOT_VALID_' + role)

        after = command(folder, 'f6_after',
                        ['/usr/bin/sudo','-n','/usr/bin/python3',str(F6),'--attest-deny'])
        results['f6_after'] = after
        if after['rc'] != 0:
            errors.append('DENY_AFTER_NOT_VERIFIED')
        else:
            try: attest_result(folder, after, 'f6_after', 'SIX_BINDING_DENY_ATTESTED')
            except (Stop, ValueError): errors.append('DENY_AFTER_INVALID')

        report = {
            'schema': SCHEMA, 'git_head': HEAD, 'plan': str(PLAN),
            'f8_manifest_sha256': sha(secure_file(folder / 'f8-manifest.json')),
            'candidate_files_sha256': copied,
            'queries': results, 'host_mutations_requested': 0,
            'nft_check_only': True, 'libvirt_schema_only': True,
            'network_probes': 0, 'protocol_connections': 0, 'p8': 'NO-GO',
            'errors': errors, 'outcome': 'PASS_READONLY_HOST_ACCEPTANCE' if not errors else 'BLOCKED_FIX_POLICY',
            'utc': datetime.now(timezone.utc).isoformat(),
        }
        save(folder / 'report.json', canonical(report))
        print('R113_F9R_MANIFEST_SHA256=' + sha(secure_file(folder / 'report.json')), flush=True)
        print('R113_F9R_NFT_CHECK=' + ('PASS' if nft['rc'] == 0 else 'REJECTED'), flush=True)
        validated_xml = [r for name,r in results.items() if name.startswith('xml_') and r['rc'] == 0]
        print('R113_F9R_XML_VALIDATED=' + str(len(validated_xml)) + '/6', flush=True)
        print('R113_F9R_DENY_AFTER=' + ('PASS' if 'DENY_AFTER_NOT_VERIFIED' not in errors and 'DENY_AFTER_INVALID' not in errors else 'UNVERIFIED'), flush=True)
        print('R113_F9R_RESULT=' + report['outcome'], flush=True)
        print('R113_F9R_FIREWALL_WRITES=0', flush=True)
        print('R113_F9R_LIBVIRT_WRITES=0', flush=True)
        print('R113_F9R_P8=NO-GO', flush=True)
        return 0 if not errors else 23
    except Exception as exc:
        print('R113_F9R_STOP=' + type(exc).__name__ + ':' + str(exc)[:240], flush=True)
        print('R113_F9R_NO_AUTOMATIC_RETRY=TRUE', flush=True)
        print('R113_F9R_SESSION_PRESERVED=' + str(folder), flush=True)
        print('R113_F9R_P8=NO-GO', flush=True)
        return 23

def replay(folder: Path) -> int:
    need(folder.is_absolute() and folder.parent == BASE and
         folder.name.startswith('validation-'), 'REPLAY_PATH_INVALID')
    secure_dir(BASE)
    secure_dir(folder)
    report = json.loads(secure_file(folder / 'report.json'))
    need(report.get('schema') == SCHEMA and report.get('git_head') == HEAD and
         report.get('plan') == str(PLAN) and report.get('host_mutations_requested') == 0 and
         report.get('network_probes') == 0 and report.get('p8') == 'NO-GO', 'REPORT_INVALID')
    need(sha(secure_file(folder / 'f8-manifest.json')) == report['f8_manifest_sha256'],
         'F8R_MANIFEST_CHANGED')
    need(set(report['candidate_files_sha256']) == set(NAMES), 'CANDIDATE_FILES_CHANGED')
    for name, digest in report['candidate_files_sha256'].items():
        need(sha(secure_file(folder / name)) == digest, 'CANDIDATE_HASH_DRIFT_' + name)
    for name, item in report['queries'].items():
        for suffix in ('stdout','stderr'):
            actual = sha(secure_file(folder / (name + '.' + suffix), True))
            need(actual == item[suffix + '_sha256'], 'HOST_PROBE_FILE_CHANGED_' + name)
    expected = {'report.json','f8-manifest.json'} | set(NAMES) | {
        name + '.' + suffix for name in report['queries'] for suffix in ('stdout','stderr')
    }
    need({p.name for p in folder.iterdir()} == expected, 'RECEIPT_SCOPE_CHANGED')
    need(report['outcome'] in ('PASS_READONLY_HOST_ACCEPTANCE','BLOCKED_FIX_POLICY'), 'RECEIPT_OUTCOME_INVALID')
    need((not report['errors']) == (report['outcome'] == 'PASS_READONLY_HOST_ACCEPTANCE'), 'RECEIPT_RESULT_DRIFT')
    print('R113_F9R_REPLAY=PASS_RECEIPT_INTEGRITY', flush=True)
    print('R113_F9R_SOURCE_OUTCOME=' + report['outcome'], flush=True)
    print('R113_F9R_REPORT_SHA256=' + sha(secure_file(folder / 'report.json')), flush=True)
    print('R113_F9R_HOST_COMMANDS=0', flush=True)
    print('R113_F9R_P8=NO-GO', flush=True)
    return 0

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--head', type=str, required=True)
    options = parser.add_mutually_exclusive_group(required=True)
    options.add_argument('--validate-host', action='store_true')
    options.add_argument('--replay', type=Path)
    args = parser.parse_args()
    global PLAN, HEAD
    PLAN, HEAD = args.plan, args.head
    try:
        return execute() if args.validate_host else replay(args.replay)
    except Exception as exc:
        print('R113_F9R_STOP=' + type(exc).__name__ + ':' + str(exc)[:220], flush=True)
        print('R113_F9R_P8=NO-GO', flush=True)
        return 23

if __name__ == '__main__':
    raise SystemExit(main())
