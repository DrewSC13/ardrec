"""R141: restrictive, read-only root-input acquisition for later independent review.

This code deliberately DOES NOT issue installation permission. Its source may be
reviewed for independent deployment, but must never be imported from a mutable
checkout by a privileged agent. The only current supported execution is an
unprivileged, private test fixture; privileged deployment remains NO-GO.

The reader uses Linux dirfd + O_NOFOLLOW and fstat checks, rather than relying
on Path.resolve() or an unchecked pre-read lstat. Returned bytes remain
UNTRUSTED until the R139 Ed25519/semantics review, and origin of the trust
anchors must be established by an external root authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = 'ARDREC-R141-ROOT-MATERIAL-READONLY-v1'
B4_SHA = 'f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8'
B9_SHA = 'c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3'
B4_FILES = frozenset(('manifest.json', 'root-controller.py', 'grant.json',
                      'contract.json', 'scope-authorization.json',
                      'pilot-permit.json', 'traffic-window.json'))
B9_FILES = frozenset(('root-executor.py', 'manifest.json', 'release.json',
                      'traffic-grant.json', 'f13-handoff.json', 'lock'))
POLICY = {
    'root_trust': 'etc/ardrec/r126-root-session-trust-v1.json',
    'root_revocation': 'etc/ardrec/r126-root-session-revocation-v1.json',
    'scope_trust': 'etc/ardrec/r126-ftp-t01-scope-trust-v2.json',
    'scope_revocation': 'etc/ardrec/r126-ftp-t01-scope-revocation-v2.json',
    'pilot_trust': 'etc/ardrec/r115-p7-pilot-trust-v1.json',
    'pilot_revocation': 'etc/ardrec/r115-p7-pilot-revocation-v1.json',
    'window_trust': 'etc/ardrec/r115-p8-trust-v1.json',
    'window_revocation': 'etc/ardrec/r115-p8-revocation-v1.json',
    'traffic_trust': 'etc/ardrec/r128-root-traffic-trust-v1.json',
    'traffic_revocation': 'etc/ardrec/r128-root-traffic-revocation-v1.json',
    'release_trust': 'etc/ardrec/r128-root-release-trust-v1.json',
    'release_revocation': 'etc/ardrec/r128-root-release-revocation-v1.json',
}
BOOT_REFERENCE = 'var/lib/ardrec/r116-f3-ftp-pilot-root-v1/authority/ftp-boot-paths.json'
DROP = 'var/lib/ardrec/r134-source-drop-v1'
INDEPENDENT_AGENT = Path('/opt/ardrec/r141-gate-v1/reader.py')
MAX_FILE = 200000
MAX_TOTAL = 1_000_000
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
_DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILEFLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class Refusal(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, 'DOCUMENT_SIZE')
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'JSON_DUPLICATE_KEY')
            result[name] = value
        return result
    try:
        doc = json.loads(raw, object_pairs_hook=pairs,
                         parse_constant=lambda _: need(False, 'JSON_NONFINITE'))
    except Refusal:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Refusal('JSON_INVALID') from exc
    need(type(doc) is dict and canonical(doc) == raw, 'JSON_NONCANONICAL')
    return doc


def components(path):
    need(type(path) is str and path and not path.startswith('/')
         and len(path) <= 320, 'RELATIVE_PATH_INVALID')
    pieces = path.split('/')
    need(all(x not in ('', '.', '..') and '\x00' not in x
             and re.fullmatch(r'[A-Za-z0-9_.-]+', x) for x in pieces),
         'PATH_COMPONENT_INVALID')
    return pieces


def metadata(fd, *, owner, folder=False, strict=False):
    st = os.fstat(fd)
    need(st.st_uid == owner, 'FILE_OWNER_INVALID')
    if folder:
        need(stat.S_ISDIR(st.st_mode) and not (st.st_mode & 0o022),
             'DIRECTORY_METADATA_INVALID')
        if strict:
            need(stat.S_IMODE(st.st_mode) == 0o700,
                 'DIRECTORY_NOT_PRIVATE')
    else:
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
             and stat.S_IMODE(st.st_mode) == 0o600
             and 0 < st.st_size <= MAX_FILE,
             'FILE_METADATA_INVALID')
    return st


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid,
            st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


class LockedTree:
    """Descriptor-relative source reader; NEVER an authority for root install.

    The test-only root may be a private folder owned by the unprivileged user.
    Validation of that folder does NOT prove external root trust. A future
    privileged agent must hard-code root=/ and owner=0, attest its own installed
    binary separately and verify all policy and signed release documents.
    """
    def __init__(self, root: Path, *, owner: int, system_root=False):
        need(isinstance(root, Path) and root.is_absolute(), 'ROOT_PATH_INVALID')
        need(type(owner) is int and owner >= 0, 'OWNER_INVALID')
        need(type(system_root) is bool, 'SYSTEM_ROOT_FLAG_INVALID')
        if system_root:
            need(root == Path('/') and owner == 0 and os.geteuid() == 0,
                 'PRIVILEGED_ROOT_SCOPE_INVALID')
        else:
            need(root != Path('/'), 'SYSTEM_ROOT_REQUIRES_PRIVILEGED_MODE')
        self.root = root
        self.owner = owner
        self.system_root = system_root
        self.fd = -1

    def __enter__(self):
        need(not self.root.is_symlink(), 'ROOT_SYMLINK_DENIED')
        fd = os.open(self.root, _DIRFLAGS)
        try:
            metadata(fd, owner=self.owner, folder=True, strict=not self.system_root)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def __exit__(self, *_):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _directory(self, path):
        need(self.fd >= 0, 'READER_CLOSED')
        cur = os.dup(self.fd)
        try:
            for part in components(path):
                new = os.open(part, _DIRFLAGS, dir_fd=cur)
                try:
                    metadata(new, owner=self.owner, folder=True)
                except BaseException:
                    os.close(new)
                    raise
                os.close(cur)
                cur = new
            return cur
        except BaseException:
            os.close(cur)
            raise

    def entries(self, path):
        fd = self._directory(path)
        try:
            return set(os.listdir(fd))
        finally:
            os.close(fd)

    def read(self, path, *, strict_parent=False):
        bits = components(path)
        need(len(bits) >= 2, 'FILE_PATH_UNSCOPED')
        fd = self._directory('/'.join(bits[:-1]))
        try:
            if strict_parent:
                metadata(fd, owner=self.owner, folder=True, strict=True)
            h = os.open(bits[-1], _FILEFLAGS, dir_fd=fd)
            try:
                a = metadata(h, owner=self.owner, folder=False)
                data = bytearray()
                while len(data) <= a.st_size:
                    chunk = os.read(h, a.st_size + 1 - len(data))
                    if not chunk:
                        break
                    data.extend(chunk)
                b = metadata(h, owner=self.owner, folder=False)
                # Check the directory entry still names the opened inode.
                # An fd-only read could otherwise accept an entry replaced
                # while the original (now unlinked) descriptor stays valid.
                now = os.stat(bits[-1], dir_fd=fd, follow_symlinks=False)
                need(_identity(a) == _identity(b) and
                     _identity(a) == _identity(now) and
                     len(data) == a.st_size, 'FILE_CHANGED_DURING_READ')
                return bytes(data)
            finally:
                os.close(h)
        finally:
            os.close(fd)


def _check_payload(reader: LockedTree):
    fd = reader._directory(DROP)
    try:
        metadata(fd, owner=reader.owner, folder=True, strict=True)
    finally:
        os.close(fd)
    # R134's candidate drop includes a documentary approval. Its content is
    # collected but NEVER treated as root authority (R139 is a separate gate).
    need(reader.entries(DROP) == {'B4', 'B9', 'approval.json'},
         'DROP_ENTRIES_UNEXPECTED')
    need(reader.entries(DROP + '/B4') == B4_FILES, 'B4_ENTRIES_UNEXPECTED')
    need(reader.entries(DROP + '/B9') == B9_FILES, 'B9_ENTRIES_UNEXPECTED')
    payload = {}
    for folder, names in (('B4', B4_FILES), ('B9', B9_FILES)):
        for name in sorted(names):
            payload[folder + '/' + name] = reader.read(
                DROP + '/' + folder + '/' + name, strict_parent=True)
    need(digest(payload['B4/root-controller.py']) == B4_SHA,
         'B4_SOURCE_PIN_MISMATCH')
    need(digest(payload['B9/root-executor.py']) == B9_SHA,
         'B9_SOURCE_PIN_MISMATCH')
    need(payload['B9/lock'] == b'ARDREC-R128-B9-ROOT-LOCK\n',
         'B9_LOCK_INVALID')
    for name, raw in payload.items():
        if name.endswith('.json'):
            parse(raw)
    approval_raw = reader.read(DROP + '/approval.json', strict_parent=True)
    parse(approval_raw)
    return payload, approval_raw


def capture(reader: LockedTree, *, include_policies=True):
    """Collect exact bytes, no signatures checked, NEVER approve installation."""
    need(isinstance(reader, LockedTree) and reader.fd >= 0, 'READER_REQUIRED')
    payload, approval_raw = _check_payload(reader)
    external = {}
    if include_policies:
        for key, path in sorted(POLICY.items()):
            external[key] = reader.read(path)
        external['f8_reference'] = reader.read(BOOT_REFERENCE)
        for raw in external.values():
            parse(raw)
    sizes = (sum(map(len, payload.values())) +
             sum(map(len, external.values())) + len(approval_raw))
    need(sizes <= MAX_TOTAL, 'TOTAL_BYTES_EXCEEDED')
    receipt = {
        'schema': SCHEMA + '-receipt',
        'content_sha256': digest(canonical({
            'payload': {k: digest(v) for k, v in sorted(payload.items())},
            'external': {k: digest(v) for k, v in sorted(external.items())},
        })),
        'payload_count': len(payload),
        'external_count': len(external),
        'documentary_approval_sha256': digest(approval_raw),
        'documentary_approval_is_authority': False,
        'filesystem_metadata_checked': True,
        'trust_anchor_provisioned_independently': False,
        'ed25519_review_complete': False,
        'git_commit_signature_independently_verified': False,
        'f8_boot_receipt_physically_attested': False,
        'root_install_authorized': False,
        'root_install_executed': False,
        'traffic_enabled': False,
        'p8': 'NO-GO',
    }
    return {'payload': payload, 'external': external,
            'approval_raw': approval_raw, 'receipt': receipt}


def inspect_release_input(*, reader: LockedTree, head: str):
    """Pure read-and-validate for downstream R139; no authority escalation."""
    need(type(head) is str and HEX40.fullmatch(head), 'HEAD_INVALID')
    observed = capture(reader)
    # Existing R135 and R139 must still validate V2 manifests, ten operational
    # signers, two release signers, boot ID and freshness. Do not claim it here.
    observed['receipt']['source_head_claimed'] = head
    return observed


def fixed_root_readonly():
    """Not callable from a repo checkout; only a separately staged root agent.

    The exact installed code and external trust provenance still require an
    out-of-band authenticated release; this function has no install callback.
    """
    need(os.geteuid() == 0 and Path(__file__).absolute() == INDEPENDENT_AGENT
         and not Path(__file__).is_symlink(),
         'INDEPENDENT_PRIVILEGED_AGENT_REQUIRED')
    with LockedTree(Path('/'), owner=0, system_root=True) as reader:
        return capture(reader)


def capabilities():
    return {
        'schema': SCHEMA + '-capabilities',
        'linux_openat_nofollow_reader': True,
        'file_owner_mode_link_size_and_race_checks': True,
        'fixed_operational_input_path_map': True,
        'checks_sha_pinned_b4_b9': True,
        'input_bytes_remain_untrusted': True,
        'independent_agent_installed': False,
        'root_install_authorized': False,
        'root_install_available': False,
        'traffic_enabled': False,
        'a6': 'ND', 'a9': None, 'p8': 'NO-GO',
    }
