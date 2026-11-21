"""R117-F4 root release acceptance, always deny if separately staged pilot absent.

This is an independent *release* check, not a scope or boot authorization.
Only root-staged, authenticated pilot code can satisfy it; never creates data,
starts guests, opens firewall, or grants P8. F5 will install it separately.
"""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path

RECEIPT=Path('/var/lib/ardrec/r117-f4-boot-release-v1/receipt.json')
PILOT_MANIFEST=Path('/var/lib/ardrec/r117-f4-ftp-pilot-root-v1/manifest.json')
REPO=Path('/home/cicada/Development/GitHub/ardrec')
RELEASE_SCHEMA='ARDREC-R117-F4-BOOT-RELEASE-v1'
PILOT_SCHEMA='ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle'
SRC=('src/ardrec/coordination/r117_f4_controlled_boot.py',
     'src/ardrec/coordination/r117_f4_runner_ftp_boot.py',
     'src/ardrec/coordination/r117_f4_root_release.py')
class Stop(ValueError):pass
def need(ok,code):
    if not ok:raise Stop(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def _dir(path):
    st=path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and
         not(path.is_symlink()) and not(st.st_mode&0o022),
         'RELEASE_UNTRUSTED_DIRECTORY_'+str(path))
def root_bytes(path,maxsize=65536):
    for d in (Path('/'),Path('/var'),Path('/var/lib'),Path('/var/lib/ardrec'),path.parent):_dir(d)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=maxsize,
             'RELEASE_UNTRUSTED_FILE_'+str(path))
        raw=os.read(fd,maxsize+1)
        need(len(raw)==st.st_size,'RELEASE_FILE_RACE')
        return raw
    finally:os.close(fd)
def require_attested_release(head,*,repo=REPO,reader=root_bytes):
    """Fail closed until an independent root staging creates both exact receipts."""
    need(type(head) is str and len(head)==40 and
         all(c in '0123456789abcdef' for c in head),'RELEASE_HEAD_INVALID')
    rec=json.loads(reader(RECEIPT))
    need(type(rec) is dict and set(rec)=={'schema','head','source_sha256',
         'pilot_manifest_sha256','pilot_schema','p8','authorized_to_boot'},
         'RELEASE_RECEIPT_FIELDS')
    need(rec['schema']==RELEASE_SCHEMA and rec['head']==head and
         rec['pilot_schema']==PILOT_SCHEMA and rec['p8']=='NO-GO' and
         rec['authorized_to_boot'] is False and
         type(rec['source_sha256']) is dict and set(rec['source_sha256'])==set(SRC),
         'RELEASE_SCOPE_NOT_CURRENT')
    for source in SRC:
        f=repo/source
        need(f.is_file() and not f.is_symlink() and
             digest(f.read_bytes())==rec['source_sha256'][source],
             'RELEASE_SOURCE_DRIFT_'+source)
    raw=reader(PILOT_MANIFEST)
    need(digest(raw)==rec['pilot_manifest_sha256'],'PILOT_STAGE_MANIFEST_CHANGED')
    pilot=json.loads(raw)
    need(type(pilot) is dict and pilot.get('schema')==PILOT_SCHEMA and
         pilot.get('head')==head and pilot.get('p8')=='NO-GO' and
         pilot.get('a6')=='ND' and pilot.get('network_automatic') is False,
         'PILOT_STAGE_UNTRUSTED')
    return {'schema':RELEASE_SCHEMA+'-attested','head':head,
            'pilot_sha256':digest(raw),'p8':'NO-GO','traffic_authorized':False}
