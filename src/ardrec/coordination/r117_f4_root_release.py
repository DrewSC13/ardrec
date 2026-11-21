"""R117-F4 root release acceptance, always deny if separately staged pilot absent.

This is an independent *release* check, not a scope or boot authorization.
Only root-staged, authenticated pilot code can satisfy it; never creates data,
starts guests, opens firewall, or grants P8. F5 will install it separately.
"""
from __future__ import annotations
import hashlib,json,os,stat,re,subprocess
from datetime import datetime,timezone
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
    for d in reversed(path.parents):
        _dir(d)
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
    receipt_raw=reader(RECEIPT)
    rec=json.loads(receipt_raw)
    need(type(rec) is dict and set(rec)=={'schema','head','source_sha256',
         'pilot_manifest_sha256','pilot_schema','p8','authorized_to_boot'},
         'RELEASE_RECEIPT_FIELDS')
    need(rec['schema']==RELEASE_SCHEMA and rec['head']==head and
         rec['pilot_schema']==PILOT_SCHEMA and rec['p8']=='NO-GO' and
         rec['authorized_to_boot'] is False and
         type(rec['source_sha256']) is dict and set(rec['source_sha256'])==set(SRC),
         'RELEASE_SCOPE_NOT_CURRENT')
    for source in SRC:
        installed=(
            Path('/var/lib/ardrec/r117-f4-ftp-pilot-root-v1')
            / 'runtime' / 'ardrec' / 'coordination'
            / Path(source).name
        )
        need(
            digest(reader(installed))==
                rec['source_sha256'][source],
            'RELEASE_SOURCE_DRIFT_'+source
        )
    raw=reader(PILOT_MANIFEST)
    need(digest(raw)==rec['pilot_manifest_sha256'],'PILOT_STAGE_MANIFEST_CHANGED')
    pilot=json.loads(raw)
    need(type(pilot) is dict and pilot.get('schema')==PILOT_SCHEMA and
         pilot.get('head')==head and pilot.get('p8')=='NO-GO' and
         pilot.get('a6')=='ND' and pilot.get('network_automatic') is False,
         'PILOT_STAGE_UNTRUSTED')
    _closed_transaction(head,receipt_raw,raw,reader)
    return {'schema':RELEASE_SCHEMA+'-attested','head':head,
            'pilot_sha256':digest(raw),'p8':'NO-GO','traffic_authorized':False}


# F5D-F: F4 recognizes only a fully closed, cryptographically approved
# release. A receipt alone is NEVER sufficient for release acceptance.

# R117: historical approval + fresh independent nonrevocation.
# Source-only verification; boot and network remain prohibited.

APPROVAL_PIN='304c3409f9d074f2ab68881622de9129ab41ee1e1652e8a0ee102211637159d8'
REVOCATION_PIN='4c32a558cf5b4c6032234ee91a457f203a8dd3472141a29906d6fb0b775a3509'

REVOCATION=Path(
    '/etc/ardrec/r117-f5b-release-revocation-v1.json'
)
REVOCATION_SIG=Path(
    '/etc/ardrec/r117-f5b-release-revocation-v1.sig'
)
REVOCATION_TRUST=Path('/etc/ardrec/r117-authorities-v3/revocation-public.pem')

REVOCATION_SCHEMA=(
    'ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1'
)
REVOCATION_PREFIX=(
    b'ARDREC-R117-F5D-ROOT-RELEASE-REVOCATION-v1\x00'
)
REVOCATION_FIELDS={
    'schema','head','candidate_sha256',
    'issued_at','valid_until',
    'revoked','authority','p8'
}


def _historical_approval_time(start,end,now):
    """Validate duration without treating an old signature as new."""
    need(
        start<=now
        and start<end
        and 0<(end-start).total_seconds()<=600,
        'RELEASE_HISTORICAL_APPROVAL_TIME_INVALID'
    )


def _fresh_revocation(head,candidate_sha,reader,now):
    """Verify a fresh independent nonrevocation declaration."""
    raw=reader(REVOCATION)
    doc=_strict_document(raw)

    need(
        set(doc)==REVOCATION_FIELDS
        and doc['schema']==REVOCATION_SCHEMA
        and doc['head']==head
        and doc['candidate_sha256']==candidate_sha
        and doc['revoked'] is False
        and doc['p8']=='NO-GO'
        and type(doc['authority']) is str
        and 3<=len(doc['authority'])<=80,
        'RELEASE_REVOCATION_SCOPE_INVALID'
    )

    start=_utc(doc['issued_at'])
    until=_utc(doc['valid_until'])

    need(
        start<=now<until
        and 0<(until-start).total_seconds()<=90,
        'RELEASE_REVOCATION_NOT_FRESH'
    )

    public=reader(REVOCATION_TRUST)

    need(
        digest(public)==REVOCATION_PIN
        and REVOCATION_PIN!=APPROVAL_PIN,
        'RELEASE_REVOCATION_TRUST_PIN_INVALID'
    )

    signature=reader(REVOCATION_SIG)

    _ed25519_verify(
        public,signature,REVOCATION_PREFIX+raw
    )

    return True


ROOT=Path('/var/lib/ardrec')
ACTIVATION=ROOT/'r117-f5b-activation-v1.json'
ACTIVATION_SCHEMA='ARDREC-R117-F5B-ACTIVATION-v1'
APPROVAL=RECEIPT.parent/'approval.json'
APPROVAL_SIG=RECEIPT.parent/'approval.sig'
TRUST=Path('/etc/ardrec/r117-authorities-v3/approval-public.pem')
PREFIX=b'ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1\x00'
TXN_NAME=re.compile(r'\.r117-f5b-transaction-[0-9a-f]{24}\Z')
MARKERS={
    'prepared.once':b'PREPARED_NOT_PUBLISHED\n',
    'pilot-visible.once':b'PILOT_VISIBLE_RELEASE_PENDING\n',
    'release-visible.once':b'RELEASE_VISIBLE_INSPECTION_REQUIRED\n',
}
JOURNAL_FILES=set(MARKERS)|{'intent.json','complete.json'}

def _unique_pairs(pairs):
    result={}
    for key,value in pairs:
        need(key not in result,'TRANSACTION_DUPLICATE_JSON_FIELD')
        result[key]=value
    return result

def _strict_document(raw):
    need(type(raw) is bytes and 0<len(raw)<=8192,
         'TRANSACTION_DOCUMENT_SIZE')
    try:
        obj=json.loads(raw,object_pairs_hook=_unique_pairs,
             parse_constant=lambda _:(_ for _ in ()).throw(
                 Stop('TRANSACTION_NONFINITE_JSON')))
        need(type(obj) is dict,'TRANSACTION_DOCUMENT_NOT_OBJECT')
        canonical=(json.dumps(obj,sort_keys=True,separators=(',',':'),
                   ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
        need(raw==canonical,'TRANSACTION_DOCUMENT_NOT_CANONICAL')
    except (UnicodeError,OverflowError,TypeError,ValueError) as exc:
        raise Stop('TRANSACTION_DOCUMENT_INVALID') from exc
    return obj

def _ed25519_verify(pub, signature, statement):
    """OpenSSL verification through seekable anonymous memory FDs.

    Does not create persistent files or invoke the untrusted checkout.
    """
    need(type(pub) is bytes and 0<len(pub)<=4096 and
         b'BEGIN PUBLIC KEY' in pub and
         type(signature) is bytes and len(signature)==64 and
         type(statement) is bytes and 0<len(statement)<=8192,
         'RELEASE_CRYPTO_INPUT_INVALID')
    need(hasattr(os,'memfd_create'), 'RELEASE_MEMFD_UNAVAILABLE')
    handles=[]
    try:
        for name,raw in (('key',pub),('signature',signature),('message',statement)):
            fd=os.memfd_create('ardrec-f5df-'+name,os.MFD_CLOEXEC)
            handles.append(fd)
            need(os.write(fd,raw)==len(raw),'RELEASE_MEMFD_WRITE_INCOMPLETE')
            os.lseek(fd,0,os.SEEK_SET)
        command=[
            '/usr/bin/openssl','pkeyutl','-verify','-rawin',
            '-pubin','-inkey','/proc/self/fd/'+str(handles[0]),
            '-sigfile','/proc/self/fd/'+str(handles[1]),
            '-in','/proc/self/fd/'+str(handles[2]),
        ]
        result=subprocess.run(command,stdin=subprocess.DEVNULL,
            capture_output=True,timeout=10,check=False,
            pass_fds=tuple(handles),
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        need(result.returncode==0,'RELEASE_ED25519_SIGNATURE_INVALID')
    finally:
        for fd in handles:
            os.close(fd)

def _utc(value):
    need(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',value),
        'RELEASE_APPROVAL_UTC_INVALID')
    try:
        return datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as exc:
        raise Stop('RELEASE_APPROVAL_TIME_INVALID') from exc


def _verify_activation(raw, head, txn_name, intent, complete,
                       receipt_raw, pilot_raw, approval_raw, complete_raw):
    """Recognize only an exact source-only activation.

    This validates release metadata; it never grants boot, traffic
    or broader execution authority.
    """
    activation=_strict_document(raw)
    need(set(activation)=={
        'schema','head','transaction','candidate_sha256',
        'approval_sha256','pilot_manifest_sha256','receipt_sha256',
        'complete_sha256','boot_authorized','network_authorized','p8'
    },'ACTIVATION_FIELDS_INVALID')
    need(
        activation['schema']==ACTIVATION_SCHEMA
        and activation['head']==head
        and activation['transaction']==txn_name
        and TXN_NAME.fullmatch(activation['transaction']) is not None
        and activation['candidate_sha256']==intent['candidate_sha256']
        and activation['approval_sha256']==digest(approval_raw)
        and activation['pilot_manifest_sha256']==digest(pilot_raw)
        and activation['receipt_sha256']==digest(receipt_raw)
        and activation['complete_sha256']==digest(complete_raw)
        and activation['boot_authorized'] is False
        and activation['network_authorized'] is False
        and activation['p8']=='NO-GO',
        'ACTIVATION_NOT_BOUND_TO_CLOSED_RELEASE'
    )
    need(
        complete['pilot_manifest_sha256']==activation['pilot_manifest_sha256']
        and complete['receipt_sha256']==activation['receipt_sha256']
        and intent['approval_sha256']==activation['approval_sha256'],
        'ACTIVATION_JOURNAL_BINDING_INVALID'
    )
    return activation

def _closed_transaction(head, receipt_raw, pilot_raw, reader):
    """Reject incomplete F5B journals before any F4 release acceptance.

    Structural closure plus independent signed INSTALL_SOURCE_ONLY approval.
    This function never authorizes boot or networking.
    """
    _dir(ROOT)
    entries=[name for name in os.listdir(ROOT)
             if name.startswith('.r117-f5b-transaction-')]
    need(len(entries)==1,'RELEASE_TRANSACTION_NOT_UNIQUE')
    name=entries[0]
    need(TXN_NAME.fullmatch(name) is not None,
         'RELEASE_TRANSACTION_NAME_INVALID')
    txn=ROOT/name
    _dir(txn)
    need(stat.S_IMODE(txn.lstat().st_mode)==0o700,
         'RELEASE_TRANSACTION_DIRECTORY_MODE')
    need(set(os.listdir(txn))==JOURNAL_FILES,
         'RELEASE_TRANSACTION_FILES_INVALID')
    for marker,expected in MARKERS.items():
        need(reader(txn/marker)==expected,
             'RELEASE_TRANSACTION_MARKER_INVALID_'+marker)

    intent=_strict_document(reader(txn/'intent.json'))
    complete_raw=reader(txn/'complete.json')
    complete=_strict_document(complete_raw)
    approval_raw=reader(APPROVAL)
    approval=_strict_document(approval_raw)
    signature=reader(APPROVAL_SIG)

    need(set(intent)=={
        'schema','head','candidate_sha256','approval_sha256',
        'status','p8'},'RELEASE_INTENT_FIELDS_CHANGED')
    need(set(complete)=={
        'schema','head','pilot_manifest_sha256','receipt_sha256',
        'approved_install','boot_permit_issued','network_connections',
        'vm_starts','p8'},'RELEASE_COMPLETE_FIELDS_CHANGED')
    need(set(approval)=={
        'schema','head','candidate_sha256','valid_from','valid_until',
        'purpose','authority','p8'},'RELEASE_APPROVAL_FIELDS_CHANGED')
    need(intent['schema']=='ARDREC-R117-F5B-TRANSACTION-v1' and
         intent['head']==head and intent['status']=='SOURCE_INSTALL_ATTEMPT' and
         intent['p8']=='NO-GO' and
         type(intent['candidate_sha256']) is str and
         re.fullmatch('[0-9a-f]{64}',intent['candidate_sha256']) is not None and
         intent['approval_sha256']==digest(approval_raw),
         'RELEASE_INTENT_NOT_AUTHENTIC')
    need(complete['schema']=='ARDREC-R117-F5B-COMPLETE-v1' and
         complete['head']==head and
         complete['pilot_manifest_sha256']==digest(pilot_raw) and
         complete['receipt_sha256']==digest(receipt_raw) and
         complete['approved_install'] is True and
         complete['boot_permit_issued'] is False and
         type(complete['vm_starts']) is int and
         complete['vm_starts']==0 and
         type(complete['network_connections']) is int and
         complete['network_connections']==0 and complete['p8']=='NO-GO',
         'RELEASE_TRANSACTION_NOT_COMPLETE')
    need(approval['schema']=='ARDREC-R117-F5B-ROOT-INSTALL-APPROVAL-v1' and
         approval['head']==head and
         approval['candidate_sha256']==intent['candidate_sha256'] and
         approval['purpose']=='INSTALL_SOURCE_ONLY' and
         approval['p8']=='NO-GO' and
         type(approval['authority']) is str and
         3<=len(approval['authority'])<=80,
         'RELEASE_APPROVAL_SCOPE_INVALID')
    start,end=_utc(approval['valid_from']),_utc(approval['valid_until'])
    now=datetime.now(timezone.utc)

    _historical_approval_time(start,end,now)

    trust=reader(TRUST)
    need(digest(trust)==APPROVAL_PIN,
         'RELEASE_APPROVAL_TRUST_PIN_INVALID')

    _ed25519_verify(trust,signature,PREFIX+approval_raw)

    _fresh_revocation(
        head,intent['candidate_sha256'],reader,now
    )
    _verify_activation(reader(ACTIVATION),head,name,intent,complete,
                       receipt_raw,pilot_raw,approval_raw,complete_raw)
    return True
