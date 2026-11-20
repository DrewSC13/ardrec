#!/usr/bin/env python3
"""Read-only root prerequisite inventory; never run as root or stage assets."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from ardrec.coordination import r116_f4_root_inventory as m
REPO=Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--inspect',action='store_true',required=True)
    ap.add_argument('--receipt-dir',type=Path)
    args=ap.parse_args()
    if __import__('os').geteuid()==0:
        print('R116_F4_STOP=ROOT_FORBIDDEN');return 23
    try:
        doc=m.report(repo=REPO)
        if args.receipt_dir:
            dest=args.receipt_dir
            if dest.is_symlink() or dest.exists():raise m.Stop('RECEIPT_DEST_ALREADY_EXISTS')
            if not dest.parent.is_dir() or dest.parent.is_symlink():raise m.Stop('RECEIPT_PARENT_NOT_TRUSTED')
            dest.mkdir(mode=0o700)
            docraw=m.canonical(doc)
            path=dest/'inventory.json'
            fd=__import__('os').open(path,__import__('os').O_WRONLY|__import__('os').O_CREAT|__import__('os').O_EXCL|__import__('os').O_NOFOLLOW,0o600)
            with __import__('os').fdopen(fd,'wb') as out:out.write(docraw);out.flush();__import__('os').fsync(out.fileno())
            print('R116_F4_RECEIPT='+str(dest))
            print('R116_F4_RECEIPT_SHA256='+m.sha(docraw))
        print('R116_F4_SOURCE_PINS='+str(doc['source_pins_verified']))
        for k in sorted(doc['files']):print('R116_F4_FILE_'+k+'='+doc['files'][k])
        for k in sorted(doc['directories']):print('R116_F4_DIR_'+k+'='+doc['directories'][k])
        print('R116_F4_BLOCKERS='+','.join(doc['blockers']))
        print('R116_F4_P7=DRAFT_NOT_CALIBRATED')
        print('R116_F4_A6=ND')
        print('R116_F4_P8=NO-GO')
        print('R116_F4_RESULT=READONLY_INVENTORY_NO_GO')
        return 0
    except (OSError,ValueError,TypeError) as exc:
        print('R116_F4_STOP='+type(exc).__name__+':'+str(exc)[:160]);return 23

if __name__=='__main__':raise SystemExit(main())
