"""ARDREC R146: standalone cryptographic installation authorization and durable pair.

Source-only until an EXTERNAL root administrator stages and authenticates the
agent; this module cannot confer independent authority to itself. No sockets,
libvirt, nftables, systemd, FTP or mutable-checkout loading. The install core
supports a real fixed-root caller but tests only disposable private directories.

WARNING: A successful installation permit only authorizes writing B4/B9 bytes;
it does not grant network traffic, physical boot, A6 or P8.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import ctypes

SCHEMA = 'ARDREC-R146-INDEPENDENT-ROOT-INSTALL-v1'
TRUST_SCHEMA = SCHEMA + '-trust'
PERMIT_SCHEMA = SCHEMA + '-permit'
REVOKE_SCHEMA = SCHEMA + '-revocation'
PREFIX = (PERMIT_SCHEMA + '\x00').encode('ascii')
REV_PREFIX = (REVOKE_SCHEMA + '\x00').encode('ascii')
B4_SHA = 'f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8'
B9_SHA = 'c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3'
GUARD_SHA = 'c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7'
F3_SHA = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
B4 = frozenset({'root-controller.py','manifest.json','grant.json','contract.json',
                'scope-authorization.json','pilot-permit.json','traffic-window.json'})
B9 = frozenset({'root-executor.py','manifest.json','release.json',
                'traffic-grant.json','f13-handoff.json','lock'})
DESTINATIONS = ('/var/lib/ardrec/r126-ftp-session-guard-v1',
                '/var/lib/ardrec/r128-one-session-v2')
HEX40 = re.compile('[a-f0-9]{40}\\Z')
HEX64 = re.compile('[a-f0-9]{64}\\Z')
SESSION = re.compile('[a-f0-9]{16}\\Z')
BOOT = re.compile('[a-f0-9-]{36}\\Z')
MAX_TOTAL = 1_000_000

class Refusal(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def parse(raw, limit=200000):
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'DOCUMENT_BYTES_INVALID')
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    try:
        doc = json.loads(raw, object_pairs_hook=pairs,
                         parse_constant=lambda _: need(False,'NONFINITE_JSON'))
    except Refusal:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Refusal('INVALID_JSON') from exc
    need(type(doc) is dict and raw == canonical(doc), 'NONCANONICAL_JSON')
    return doc


def instant(text):
    need(type(text) is str and
         re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', text),
         'DATE_FORMAT_INVALID')
    try:
        return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise Refusal('DATE_VALUE_INVALID') from exc


def current(now):
    need(type(now) is datetime and now.tzinfo is not None and
         now.utcoffset() is not None, 'CLOCK_NOT_AWARE')
    return now.astimezone(timezone.utc)


def validate_payload(payload, head):
    """Exact operational source identity; documentary signatures are a SEPARATE gate."""
    need(type(head) is str and HEX40.fullmatch(head), 'HEAD_INVALID')
    expected = {'B4/' + x for x in B4} | {'B9/' + x for x in B9}
    need(type(payload) is dict and set(payload) == expected, 'PAYLOAD_SCOPE_INVALID')
    need(all(type(data) is bytes and 0 < len(data) <= 200000
             for data in payload.values()) and
         sum(map(len, payload.values())) <= MAX_TOTAL, 'PAYLOAD_SIZE_INVALID')
    need(sha(payload['B4/root-controller.py']) == B4_SHA, 'B4_SOURCE_PIN_INVALID')
    need(sha(payload['B9/root-executor.py']) == B9_SHA, 'B9_SOURCE_PIN_INVALID')
    need(payload['B9/lock'] == b'ARDREC-R128-B9-ROOT-LOCK\n', 'B9_LOCK_INVALID')
    for name, raw in payload.items():
        if name.endswith('.json'):
            parse(raw)
    need(parse(payload['B4/manifest.json']) == {
        'schema':'ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle',
        'script_sha256':B4_SHA, 'guard_sha256':GUARD_SHA,
        'approved_head':head,'deny_only':True,'root_install_independent':True,
    }, 'B4_MANIFEST_INVALID')
    need(parse(payload['B9/manifest.json']) == {
        'schema':'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle',
        'approved_head':head, 'script_sha256':B9_SHA,
        'r126_deny_controller_sha256':B4_SHA,'legacy_f3_sha256':F3_SHA,
        'guard_sha256':GUARD_SHA,'root_staged_independently':True,
        'automatic_network':False,'p8':'NO-GO',
    }, 'B9_MANIFEST_INVALID')
    inventory = {k:sha(v) for k, v in sorted(payload.items())}
    return {'inventory_sha256':sha(canonical(inventory)),'files':inventory,
            'b4':B4_SHA,'b9':B9_SHA,'head':head}


def signer(doc):
    need(type(doc) is dict and set(doc)=={'key_id','public_key_pem'},
         'SIGNER_FIELDS_INVALID')
    need(type(doc['key_id']) is str and 4<=len(doc['key_id'])<=100 and
         re.fullmatch(r'[a-zA-Z0-9_.-]+',doc['key_id']), 'SIGNER_ID_INVALID')
    pem=doc['public_key_pem']
    need(type(pem) is str and len(pem)<400 and
         pem.startswith('-----BEGIN PUBLIC KEY-----\n') and
         pem.endswith('-----END PUBLIC KEY-----\n'), 'PUBLIC_KEY_FORMAT_INVALID')
    return pem.encode('ascii')


def openssl_ed25519(pem, signature, message):
    """Verify without Python third-party root dependencies or secret temp files."""
    need(os.name=='posix' and hasattr(os,'memfd_create'), 'LINUX_MEMFD_REQUIRED')
    fds=[]
    try:
        for label,raw in (('r146-pub',pem),('r146-sig',signature),('r146-msg',message)):
            fd=os.memfd_create(label,flags=os.MFD_CLOEXEC)
            fds.append(fd)
            off=0
            while off<len(raw):
                count=os.write(fd,raw[off:])
                need(count>0,'ANONYMOUS_WRITE_FAILURE')
                off+=count
            os.lseek(fd,0,os.SEEK_SET)
        p=subprocess.run(('/usr/bin/openssl','pkeyutl','-verify','-pubin',
            '-inkey',f'/proc/self/fd/{fds[0]}','-rawin',
            '-in',f'/proc/self/fd/{fds[2]}',
            '-sigfile',f'/proc/self/fd/{fds[1]}'),
            stdin=subprocess.DEVNULL,capture_output=True,check=False,
            close_fds=True,pass_fds=tuple(fds),timeout=5,
            env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        return p.returncode==0 and len(p.stdout)<=1024 and len(p.stderr)<=1024
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Refusal('ED25519_VERIFIER_UNAVAILABLE') from exc
    finally:
        for fd in fds:
            os.close(fd)


def signed(envelope, pub, prefix):
    need(type(envelope) is dict and
         set(envelope)=={'statement','signer_key_id','signature_b64'},
         'SIGNATURE_ENVELOPE_INVALID')
    need(envelope['signer_key_id']==pub['key_id'] and
         type(envelope['signature_b64']) is str and
         type(envelope['statement']) is dict, 'SIGNATURE_SIGNER_INVALID')
    try:
        signature=base64.b64decode(envelope['signature_b64'],validate=True)
    except (ValueError,base64.binascii.Error) as exc:
        raise Refusal('SIGNATURE_BASE64_INVALID') from exc
    need(len(signature)==64,'ED25519_SIGNATURE_LENGTH_INVALID')
    need(openssl_ed25519(signer(pub),signature,prefix+canonical(envelope['statement'])),
         'INVALID_ED25519_SIGNATURE')
    return envelope['statement']


def verified_install_permit(*,trust_raw,permit_raw,revocation_raw,head,tree,
                            inventory_sha256,boot_id,now,agent_bundle_sha256,other_signers=(),other_signer_ids=()):
    """External root install authority. Successful signature != provenance of keys."""
    now=current(now)
    need(type(head) is str and HEX40.fullmatch(head) and
         type(tree) is str and HEX40.fullmatch(tree),'GIT_IDENTITY_INVALID')
    need(type(inventory_sha256) is str and HEX64.fullmatch(inventory_sha256),
         'INVENTORY_SHA_INVALID')
    need(type(agent_bundle_sha256) is str and HEX64.fullmatch(agent_bundle_sha256),
         'AGENT_BUNDLE_SHA_INVALID')
    need(type(boot_id) is str and BOOT.fullmatch(boot_id), 'BOOT_ID_INVALID')
    trust=parse(trust_raw,8192)
    need(set(trust)=={'schema','permit_signer','revocation_signer'} and
         trust['schema']==TRUST_SCHEMA, 'INSTALL_TRUST_SCHEMA_INVALID')
    s1,s2=trust['permit_signer'],trust['revocation_signer']
    p1,p2=signer(s1),signer(s2)
    need(s1['key_id']!=s2['key_id'] and sha(p1)!=sha(p2),
         'INSTALL_SIGNERS_NOT_DISTINCT')
    # The externally provisioned key set is compared against the 12 previously
    # authenticated operational signers; this still cannot prove persons differ.
    need(type(other_signers) in (tuple,list) and
         all(type(x) is str and HEX64.fullmatch(x) for x in other_signers),
         'OPERATIONAL_SIGNER_SET_INVALID')
    need(len(other_signers)==12 and len(other_signers)==len(set(other_signers)) and
         len(other_signer_ids)==12 and len(set(other_signer_ids))==12 and
         all(type(x) is str and x for x in other_signer_ids) and
         s1['key_id'] not in other_signer_ids and s2['key_id'] not in other_signer_ids and
         sha(p1) not in other_signers and sha(p2) not in other_signers,
         'INSTALL_SIGNER_REUSED_FROM_OPERATIONAL')
    permit=parse(permit_raw,16384)
    stmt=signed(permit,s1,PREFIX)
    need(set(stmt)=={'schema','session','head','tree','inventory_sha256',
         'source_b4_sha256','source_b9_sha256','agent_bundle_sha256','action','destinations',
         'boot_id','valid_from','valid_until','network_traffic_authorized',
         'one_shot','p8'}, 'INSTALL_PERMIT_FIELDS_INVALID')
    need(stmt['schema']==PERMIT_SCHEMA and type(stmt['session']) is str and
         SESSION.fullmatch(stmt['session']) and stmt['head']==head and
         stmt['tree']==tree and stmt['inventory_sha256']==inventory_sha256 and
         stmt['source_b4_sha256']==B4_SHA and stmt['source_b9_sha256']==B9_SHA and
         stmt['agent_bundle_sha256']==agent_bundle_sha256 and
         stmt['action']=='INSTALL_B4_B9_ONLY' and
         stmt['destinations']==list(DESTINATIONS) and stmt['boot_id']==boot_id and
         stmt['network_traffic_authorized'] is False and
         stmt['one_shot'] is True and stmt['p8']=='NO-GO',
         'INSTALL_PERMISSION_SCOPE_INVALID')
    start,end=instant(stmt['valid_from']),instant(stmt['valid_until'])
    need(start<end and (end-start).total_seconds()<=600 and
         start<=now<end and (end-now).total_seconds()>=5,
         'INSTALL_WINDOW_EXPIRED_OR_TOO_SHORT')
    rev=parse(revocation_raw,16384)
    rstmt=signed(rev,s2,REV_PREFIX)
    need(set(rstmt)=={'schema','session','permit_sha256','issued_at',
          'valid_until','revoked','reason_code'}, 'INSTALL_REVOCATION_FIELDS_INVALID')
    need(rstmt['schema']==REVOKE_SCHEMA and
         rstmt['session']==stmt['session'] and
         rstmt['permit_sha256']==sha(permit_raw) and
         rstmt['revoked'] is False and type(rstmt['reason_code']) is str,
         'INSTALL_REVOKED_OR_UNBOUND')
    issued,expires=instant(rstmt['issued_at']),instant(rstmt['valid_until'])
    need(issued<=now<expires and 0<=(now-issued).total_seconds()<=30,
         'INSTALL_REVOCATION_NOT_FRESH')
    return {'schema':SCHEMA+'-checked-permit','session':stmt['session'],
            'head':head,'tree':tree,'inventory_sha256':inventory_sha256,
            'agent_bundle_sha256':agent_bundle_sha256,
            'permit_sha256':sha(permit_raw),'revocation_sha256':sha(revocation_raw),
            'boot_id':boot_id,'network_traffic_authorized':False,'p8':'NO-GO'}


def check_folder(folder,owner):
    need(isinstance(folder,Path) and folder.is_absolute() and not folder.is_symlink(),
         'DIRECTORY_PATH_UNSAFE')
    st=folder.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==owner and
         stat.S_IMODE(st.st_mode)==0o700, 'DIRECTORY_METADATA_INVALID')


def read_exact(path,raw,owner):
    need(isinstance(path,Path) and not path.is_symlink(), 'FILE_PATH_UNSAFE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and
             st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
             st.st_size==len(raw), 'FILE_METADATA_INVALID')
        actual=b''
        while len(actual)<len(raw):
            chunk=os.read(fd,len(raw)-len(actual))
            need(chunk,'FILE_SHORT_READ')
            actual+=chunk
        end=os.fstat(fd)
        need((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==
             (end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns) and
             actual==raw, 'FILE_BYTES_CHANGED')
    finally:os.close(fd)


def write_file(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        off=0
        while off<len(raw):
            n=os.write(fd,raw[off:])
            need(n>0,'FILE_WRITE_SHORT')
            off+=n
        os.fsync(fd)
    finally:os.close(fd)


def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def stage_dir(parent,name,content,owner):
    dest=parent/name
    if dest.exists() or dest.is_symlink():
        verify_dir(dest,content,owner)
        return
    dest.mkdir(mode=0o700)
    os.chmod(dest,0o700)
    try:
        for filename,raw in sorted(content.items()):
            need('/' not in filename and filename not in ('','.','..'),
                 'INVALID_ENTRY_NAME')
            write_file(dest/filename,raw)
        fsync_dir(dest)
        fsync_dir(parent)
    except BaseException:
        # Do not delete partial stage, preserving forensic state and no retry.
        raise


def verify_dir(path,content,owner):
    check_folder(path,owner)
    names={x.name for x in path.iterdir()}
    need(names==set(content),'PUBLISHED_FILE_SET_MISMATCH')
    for filename,raw in content.items():
        read_exact(path/filename,raw,owner)


def noreplace(source,dest):
    need(not dest.exists() and not dest.is_symlink(),'DESTINATION_EXISTS_NO_OVERWRITE')
    libc=ctypes.CDLL(None,use_errno=True)
    call=libc.renameat2
    call.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    call.restype=ctypes.c_int
    ret=call(-100,os.fsencode(source),-100,os.fsencode(dest),1)
    if ret:
        err=ctypes.get_errno()
        raise OSError(err,os.strerror(err),str(dest))


def transact(*,state_dir,root_parent,payload,head,tree,boot_id,authorize,
             install_evidence,fail=None):
    """Durable 2-destination publication. External authorizer MUST check live
    root-owned signatures before each mutation; this function does not authenticate
    its caller and is not exposed as a mutable-checkout root CLI.
    """
    need(fail in (None,'after_journal','before_b4','after_b4',
                  'before_b9','after_b9','before_receipt'), 'UNKNOWN_FAULT')
    owner=os.geteuid()
    check_folder(state_dir,owner)
    need(isinstance(root_parent,Path) and root_parent.is_absolute() and
         not root_parent.is_symlink(),'DESTINATION_PARENT_UNSAFE')
    root_st=root_parent.lstat()
    need(stat.S_ISDIR(root_st.st_mode) and root_st.st_uid==owner and
         not(root_st.st_mode&0o022),'DESTINATION_PARENT_METADATA_INVALID')
    need(root_st.st_dev==state_dir.stat().st_dev,'DESTINATION_MUST_BE_SAME_FS')
    source=validate_payload(payload,head)
    need(type(tree) is str and HEX40.fullmatch(tree),'TREE_INVALID')
    need(type(boot_id) is str and BOOT.fullmatch(boot_id),'BOOT_ID_INVALID')
    need(type(install_evidence) is dict and set(install_evidence)=={
         'permit_sha256','agent_bundle_sha256','release_sha256',
         'initial_revocation_sha256'} and
         all(type(x) is str and HEX64.fullmatch(x)
             for x in install_evidence.values()),'SIGNED_INSTALL_EVIDENCE_INVALID')
    expected={
        'b4':root_parent/Path(DESTINATIONS[0]).name,
        'b9':root_parent/Path(DESTINATIONS[1]).name,
    }
    b4={k[3:]:v for k,v in payload.items() if k.startswith('B4/')}
    b9={k[3:]:v for k,v in payload.items() if k.startswith('B9/')}
    plan={'schema':SCHEMA+'-install-plan','head':head,'tree':tree,
          'boot_id':boot_id,'inventory_sha256':source['inventory_sha256'],
          'b4_target':str(expected['b4']),'b9_target':str(expected['b9']),
          'install_evidence':dict(install_evidence),
          'traffic':False,'p8':'NO-GO'}
    journal_raw=canonical(plan)
    receipt_raw=canonical({'schema':SCHEMA+'-installed-receipt',
         'plan_sha256':sha(journal_raw),'inventory_sha256':source['inventory_sha256'],
         'head':head,'tree':tree,'boot_id':boot_id,
         'install_evidence':dict(install_evidence),
         'root_bytes_readback':True,'network_traffic_authorized':False,'p8':'NO-GO'})
    lock_path=state_dir/'install.lock'
    fd=os.open(lock_path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid==owner and st.st_nlink==1 and
             stat.S_IMODE(st.st_mode)==0o600 and st.st_size==0,
             'INSTALL_LOCK_UNSAFE')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise Refusal('CONCURRENT_INSTALL') from exc
        need({p.name for p in state_dir.iterdir()} <= {
             'install.lock','install.json','receipt.json','pending-b4','pending-b9'},
             'INSTALL_JOURNAL_SCOPE_DRIFT')
        journal=state_dir/'install.json'
        receipt=state_dir/'receipt.json'
        if journal.exists() or journal.is_symlink():
            read_exact(journal,journal_raw,owner)
        else:
            need(not any(x.exists() or x.is_symlink() for x in expected.values()) and
                 not receipt.exists() and not receipt.is_symlink(),
                 'PREEXISTING_SOURCE_WITHOUT_JOURNAL')
            need(authorize('before_journal',plan) is True, 'AUTHORIZATION_BEFORE_JOURNAL')
            write_file(journal,journal_raw)
            fsync_dir(state_dir)
        if receipt.exists() or receipt.is_symlink():
            for key,contents in (('b4',b4),('b9',b9)):
                verify_dir(expected[key],contents,owner)
            read_exact(receipt,receipt_raw,owner)
            return {'status':'ALREADY_INSTALLED_VERIFIED','receipt_sha256':sha(receipt_raw)}
        if expected['b9'].exists() or expected['b9'].is_symlink():
            need(expected['b4'].is_dir() and not expected['b4'].is_symlink(),
                 'B9_PRESENT_WITHOUT_B4')
        for key,contents in (('b4',b4),('b9',b9)):
            if expected[key].exists() or expected[key].is_symlink():
                verify_dir(expected[key],contents,owner)
            else:
                stage_dir(state_dir,'pending-'+key,contents,owner)
        if fail=='after_journal':raise Refusal('INJECTED_AFTER_JOURNAL')
        for key,contents in (('b4',b4),('b9',b9)):
            if not expected[key].exists() and not expected[key].is_symlink():
                need(authorize('before_'+key,plan) is True,
                     'AUTHORIZATION_BEFORE_'+key.upper())
                if fail=='before_'+key:raise Refusal('INJECTED_BEFORE_'+key.upper())
                noreplace(state_dir/('pending-'+key),expected[key])
                fsync_dir(root_parent)
                fsync_dir(state_dir)
            verify_dir(expected[key],contents,owner)
            if fail=='after_'+key:raise Refusal('INJECTED_AFTER_'+key.upper())
        need(authorize('before_receipt',plan) is True,
             'AUTHORIZATION_BEFORE_RECEIPT')
        if fail=='before_receipt':raise Refusal('INJECTED_BEFORE_RECEIPT')
        write_file(receipt,receipt_raw)
        fsync_dir(state_dir)
        read_exact(receipt,receipt_raw,owner)
        return {'status':'INSTALLED_B4_B9_VERIFIED','receipt_sha256':sha(receipt_raw)}
    finally:os.close(fd)


def capabilities():
    return {'schema':SCHEMA+'-capabilities','bootstrap_external_root_required':True,
            'standalone_signer_verification':True,'revocation_fresh_seconds':30,
            'permit_window_max_seconds':600,'final_destinations':list(DESTINATIONS),
            'recovery_reconciles_b4_b9':True,'root_install_run_from_checkout':False,
            'no_root_authority_synthesized':True,'network_traffic_authorized':False,
            'a6':'ND','p8':'NO-GO'}
