#!/usr/bin/env python3
"""R118: auditoría de fuente post-merge, sin root, VM ni tráfico.

La verificación criptográfica de linaje requiere un documento fresco firmado
independientemente y confianza establecida por root. Esta CLI no los crea.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

from ardrec.coordination import r118_postmerge_gate as gate
from ardrec.coordination.r118_postmerge_gate import SOURCES, sha, closure_status, Stop

REPO = Path('/home/cicada/Development/GitHub/ardrec')
CLOSURE = Path('lab/operational-controller/r117-f5b-physical-closure-v3.json')
LINEAGE = Path('/var/lib/ardrec/r118-postmerge-source-only/lineage.json')
REVOCATION = Path('/var/lib/ardrec/r118-postmerge-source-only/revocation.json')
APPROVAL_TRUST = Path('/etc/ardrec/r117-authorities-v3/approval-public.pem')
REVOCATION_TRUST = Path('/etc/ardrec/r117-authorities-v3/revocation-public.pem')
APPROVAL_PIN = '304c3409f9d074f2ab68881622de9129ab41ee1e1652e8a0ee102211637159d8'
REVOCATION_PIN = '4c32a558cf5b4c6032234ee91a457f203a8dd3472141a29906d6fb0b775a3509'


def git(*args: str) -> str:
    proc = subprocess.run(['/usr/bin/git', *args], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=12, check=False,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                          cwd=Path.cwd())
    if proc.returncode or len(proc.stdout) > 65536:
        raise Stop('GIT_READ_FAILURE_'+args[0])
    try:
        return proc.stdout.decode('utf-8').strip()
    except UnicodeError as exc:
        raise Stop('GIT_ENCODING') from exc


def inspect(*, repo: Path = REPO) -> dict:
    if Path.cwd().resolve() != repo:
        raise Stop('WRONG_REPOSITORY')
    if git('rev-parse','--show-toplevel') != str(repo):
        raise Stop('WRONG_GIT_ROOT')
    branch = git('branch','--show-current')
    head = git('rev-parse','HEAD')
    clean = git('status','--porcelain=v1','--untracked-files=all') == ''
    signature = git('log','-1','--format=%G?')
    closure = closure_status(CLOSURE.read_bytes())
    hashes = {}
    for relative in SOURCES:
        path = repo / relative
        if not path.is_file() or path.is_symlink():
            hashes[relative] = None
        else:
            hashes[relative] = sha(path.read_bytes())
    reasons = []
    if branch != 'main':
        reasons.append('NON_MAIN_SOURCE_BRANCH')
    if not clean:
        reasons.append('UNCOMMITTED_SOURCE_OR_FILES')
    if signature != 'G':
        reasons.append('HEAD_SIGNATURE_NOT_TRUSTED')
    if head != closure['candidate_head']:
        reasons.append('MAIN_HEAD_DIFFERS_FROM_INSTALLED_CANDIDATE')
    if None in hashes.values():
        reasons.append('R118_OR_HISTORICAL_SOURCE_MISSING')
    reasons.extend(['HOST_F5B_CURRENT_STATE_NOT_READ',
                    'FRESH_INDEPENDENT_SOURCE_LINEAGE_NOT_PRESENT',
                    'BOOT_SCOPE_AND_REVOCATION_NOT_AUTHORIZED',
                    'P8_NO_GO'])
    return {
        'schema': 'ARDREC-R118-POSTMERGE-READINESS-v1',
        'repo': str(repo),
        'branch': branch, 'head': head, 'clean': clean,
        'git_head_signature': signature,
        'candidate_head': closure['candidate_head'],
        'candidate_sha256': closure['candidate_sha256'],
        'closure_sha256': sha(CLOSURE.read_bytes()),
        'source_sha256': hashes,
        'postinstall_host_audit': 'NOT_PERFORMED',
        'source_lineage_signed': False,
        'boot_authorized': False, 'network_authorized': False,
        'p8': 'NO-GO',
        'blockers': reasons,
        'guest_operations': 0, 'network_operations': 0,
        'firewall_operations': 0,
    }


def check_root_lineage(doc: dict) -> dict:
    """Verifica bytes root 0600 (sin crear permisos ni recibos nuevos)."""
    if doc['branch'] != 'main' or not doc['clean'] or doc['git_head_signature'] != 'G':
        raise Stop('UNTRUSTED_WORKTREE_OR_COMMIT')
    from ardrec.coordination.r117_f4_root_release import root_bytes
    try:
        ap = root_bytes(APPROVAL_TRUST, maxsize=4096)
        rp = root_bytes(REVOCATION_TRUST, maxsize=4096)
        if sha(ap) != APPROVAL_PIN or sha(rp) != REVOCATION_PIN:
            raise Stop('ROOT_TRUST_NOT_PINNED')
        report = gate.verify_lineage(
            CLOSURE.read_bytes(), doc['head'],
            {name: (REPO / name).read_bytes() for name in SOURCES},
            root_bytes(LINEAGE, maxsize=16384),
            root_bytes(REVOCATION, maxsize=16384),
            approval_public=ap, revocation_public=rp,
            now=datetime.now(timezone.utc))
    except (OSError, ValueError, KeyError) as exc:
        raise Stop('ROOT_LINEAGE_VERIFICATION_FAILED:'+str(exc)) from exc
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description='R118 auditoría de continuidad SOURCE_ONLY')
    ap.add_argument('--json', action='store_true', help='JSON canónico de sólo lectura')
    ap.add_argument('--verify-root-lineage', action='store_true',
                    help='exige declaraciones frescas firmadas y archivos root 0600, jamás autoriza boot')
    opts = ap.parse_args(argv)
    try:
        doc = inspect()
        if opts.verify_root_lineage:
            doc['verified_lineage'] = check_root_lineage(doc)
            doc['source_lineage_signed'] = True
            doc['blockers'] = [x for x in doc['blockers']
                               if x != 'FRESH_INDEPENDENT_SOURCE_LINEAGE_NOT_PRESENT']
    except (Stop, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print('R118_FAIL='+str(exc), file=sys.stderr)
        return 2
    if opts.json:
        print(json.dumps(doc, sort_keys=True, ensure_ascii=True, separators=(',', ':')))
    else:
        print('ARDREC R118 / AUDITORIA SOURCE_ONLY / SIN ACCIONES FISICAS')
        print('MAIN='+doc['head'])
        print('CANDIDATO_INSTALADO_HISTORICO='+doc['candidate_head'])
        print('REPOSITORIO_LIMPIO='+str(doc['clean']))
        print('FUENTE_FIRMADA_Y_RECONCILIADA='+('SI' if doc['source_lineage_signed'] else 'NO'))
        print('HOST_INSPECCIONADO=NO')
        print('AUTORIZACION_BOOT=NO / TRAFICO=NO / P8=NO-GO')
        print('BLOQUEOS='+','.join(doc['blockers']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
