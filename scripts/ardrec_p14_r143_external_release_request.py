#!/usr/bin/env python3
"""R143: issue a PUBLIC, UNSIGNED review dossier from a clean signed HEAD.

Never installs root files, never signs permits, never starts VMs or traffic.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import sys

REPO = Path('/home/cicada/Development/GitHub/ardrec')
PATCHES = Path('/home/cicada/Development/GitHub/ardrec-patches')
sys.path.insert(0, str(REPO / 'src'))
from ardrec.coordination import r143_root_release_handoff as handoff


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--prepare-readonly', action='store_true', required=True)
    args = ap.parse_args()
    try:
        handoff.need(os.geteuid() != 0, 'ROOT_FORBIDDEN')
        handoff.need(Path.cwd() == REPO, 'REPO_WORKDIR_REQUIRED')
        handoff.need(PATCHES.is_dir() and not PATCHES.is_symlink(), 'PATCHES_INVALID')
        folder = PATCHES / 'ardrec-r143-external-review'
        if not folder.exists() and not folder.is_symlink():
            folder.mkdir(mode=0o700)
        st = folder.lstat()
        handoff.need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
                     and stat.S_IMODE(st.st_mode) == 0o700
                     and not folder.is_symlink(), 'PRIVATE_FOLDER_INVALID')
        doc, sources = handoff.signed_checkout(REPO)
        name = 'ARDREC_R143_PUBLIC_REVIEW_' + doc['source_commit'][:12] + '.zip'
        target = folder / name
        handoff.need(not target.exists() and not target.is_symlink(),
                     'EXISTING_REVIEW_BUNDLE_NO_OVERWRITE')
        sha = handoff.create_public_bundle(request=doc, sources=sources,
                                           destination=target)
        print('R143_REVIEW_BUNDLE=' + str(target))
        print('R143_REVIEW_SHA256=' + sha)
        print('R143_REVIEW_HEAD=' + doc['source_commit'])
        print('R143_REVIEW_TREE=' + doc['source_tree'])
        print('R143_FILES=8_PUBLIC_SOURCES_PLUS_MANIFEST_AND_REQUEST')
        print('R143_DOCUMENTARY_AUTHORITY=NOT_PROVISIONED')
        print('R143_EXTERNAL_INDEPENDENT_AUTHORITY=REQUIRED')
        print('R143_READONLY_REQUEST=PASS')
        print('ROOT_INSTALL=NO VM_STARTS=0 TRAFFIC=0 P8=NO-GO A6=ND A9=NOT_PUBLISHED')
        return 0
    except (handoff.Refusal, OSError, ValueError) as exc:
        print('R143_STOP=' + type(exc).__name__ + ':' + str(exc)[:180])
        return 23


if __name__ == '__main__':
    raise SystemExit(main())
