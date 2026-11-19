#!/usr/bin/env python3
"""R113-F2: auditar las seis IP de QGA sin tráfico de red y conservar prueba."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

REPO = Path('/home/cicada/Development/GitHub/ardrec')
ROOT = Path('/home/cicada/ardrec-lab/r113-f2-agent-ip-identity-v1')
BRANCH = 'feat/p14-r111-r114-real-lab'
PARENT = 'b559d85f45008ec6664eafeb2f99baca7add8cba'
sys.path[:0] = [str(REPO/'src'), str(REPO/'scripts')]
from ardrec.coordination import r113_f2_agent_ip_identity as core
import ardrec_p14_r113_f1_network_audit as f1

SCHEMA = core.SCHEMA
FILES = ('identity.json', 'manifest.json')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(',', ':')) + '\n').encode('ascii')

def need(condition, reason):
    core.need(condition, reason)

def ok(*argv):
    p = subprocess.run(argv, cwd=REPO, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=18, check=False)
    need(p.returncode == 0, 'COMMAND_FAILED_'+argv[0])
    return p.stdout.strip()

def private(path: Path):
    need(path.is_dir() and not path.is_symlink(), 'PRIVATE_DIR_INVALID')
    st = path.stat()
    need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
         'PRIVATE_DIR_PERMISSIONS')

def write(path: Path, content):
    raw = canonical(content)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())

def read(path: Path):
    need(path.is_file() and not path.is_symlink(), 'PRIVATE_FILE_NOT_REGULAR')
    st = path.stat()
    need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600,
         'PRIVATE_FILE_PERMISSIONS')
    return json.loads(path.read_bytes())

def source():
    need(Path.cwd().resolve() == REPO, 'REPO_CWD_INVALID')
    need(ok('git', 'branch', '--show-current') == BRANCH, 'WRONG_BRANCH')
    subprocess.run(['git','merge-base','--is-ancestor',PARENT,'HEAD'],cwd=REPO,
                   check=True,timeout=15,capture_output=True)
    need(ok('git', 'log', '-1', '--format=%G?') == 'G', 'UNSIGNED_HEAD')
    need(not ok('git', 'status', '--porcelain=v1', '-uall'), 'WORKTREE_NOT_CLEAN')

def verify(path: Path):
    need(path.is_absolute() and path.parent == ROOT and
         path.name.startswith('proof-'), 'PROOF_SCOPE_INVALID')
    private(ROOT)
    private(path)
    need({entry.name for entry in path.iterdir()} == set(FILES), 'PROOF_FILES_CHANGED')
    classification = read(path/'identity.json')
    manifest = read(path/'manifest.json')
    need(manifest.get('schema') == SCHEMA+'-manifest', 'MANIFEST_INVALID')
    need(manifest.get('files') == {
        'identity.json': digest((path/'identity.json').read_bytes())},
         'PROOF_SHA_INVALID')
    need(manifest.get('p8_operational') == 'NO-GO' and
         manifest.get('traffic_authorized') is False and
         manifest.get('protocol_connections') == 0, 'PROOF_AUTHORITY_DRIFT')
    f1path = Path(manifest['f1_audit'])
    need(f1path.is_absolute() and f1path.parent == f1.ROOT and
         f1path.name.startswith('audit-'), 'F1_PROVENANCE_SCOPE')
    f1.verify(f1path)
    need(digest((f1path/'manifest.json').read_bytes()) ==
         manifest['f1_manifest_sha256'], 'F1_RECEIPT_TAMPERED')
    recomputed = core.verify_classification(read(f1path/'classification.json'))
    need(recomputed == classification, 'IDENTITY_REPLAY_MISMATCH')
    return manifest

def audit():
    source()
    previous = {p.name for p in f1.ROOT.glob('audit-*') if p.is_dir()}
    # F1 realiza exclusivamente consultas y captura F11/R34/VM+QGA con URI normal para agent.
    need(f1.gather() == 0, 'F1_CAPTURE_FAILED')
    new = sorted(p for p in f1.ROOT.glob('audit-*')
                 if p.is_dir() and p.name not in previous)
    need(len(new) == 1, 'EXPECTED_ONE_F1_AUDIT')
    f1folder = new[0]
    f1.verify(f1folder)
    identity = core.verify_classification(read(f1folder/'classification.json'))
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(ROOT)
    folder = Path(tempfile.mkdtemp(prefix='proof-', dir=ROOT))
    private(folder)
    write(folder/'identity.json', identity)
    manifest = {
        'schema': SCHEMA+'-manifest',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source_commit': ok('git','rev-parse','HEAD'),
        'f1_audit': str(f1folder),
        'f1_manifest_sha256': digest((f1folder/'manifest.json').read_bytes()),
        'files': {'identity.json': digest((folder/'identity.json').read_bytes())},
        'traffic_authorized': False,
        'protocol_connections': 0,
        'p8_operational': 'NO-GO',
    }
    write(folder/'manifest.json', manifest)
    verify(folder)
    print('R113_F2_QGA_AGENT=PASS_4_GUESTS')
    print('R113_F2_IP_MAC_CIDR=PASS_6_INTERFACES')
    for role, entries in identity['endpoints'].items():
        for net, entry in entries.items():
            print('R113_F2_'+role.upper()+'_'+net.upper()+'_IP='+entry['ipv4_cidr'])
            print('R113_F2_'+role.upper()+'_'+net.upper()+'_MAC='+entry['mac'])
    print('R113_F2_PROOF='+str(folder))
    print('R113_F2_MANIFEST_SHA256='+digest((folder/'manifest.json').read_bytes()))
    print('R113_F2_PROTOCOLS_TESTED=NO')
    print('R113_F2_TRAFFIC_AUTHORIZED=NO')
    print('R113_F2_P8=NO-GO')
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--audit', action='store_true')
    g.add_argument('--replay', type=Path)
    args = parser.parse_args()
    try:
        source()
        if args.audit:
            return audit()
        verify(args.replay)
        print('R113_F2_REPLAY=PASS')
        print('R113_F2_P8=NO-GO')
        return 0
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print('R113_F2_STOP='+type(exc).__name__+':'+str(exc)[:190])
        print('R113_F2_NO_MUTATION_OR_RETRY=TRUE')
        print('R113_F2_P8=NO-GO')
        return 23

if __name__ == '__main__':
    raise SystemExit(main())
