#!/usr/bin/env python3
"""ARDREC R55.5 root-owned, deny-only recovery program.

NOT an installer or an authorization to open traffic. The executable and
bundle must be copied to a root-owned, mode-0700 directory in a later
independently approved maintenance operation. It cannot read a user-supplied
bundle path, and it has no 'allow', 'open', or 'switch-filter' command.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

BUNDLE = Path('/var/lib/ardrec/r555-deny-guard')
SCHEMA = 'ardrec-r555-deny-only-root-bundle-v1'
RESTORE = 'r34-deny-restore.nft'
ROLE_FILES = {
    'ssh': ('a33d30t', 'ssh-original.xml', 'ssh-candidate.xml'),
    'runner': ('a33d30r', 'runner-original.xml', 'runner-candidate.xml'),
}
TABLE = 'ardrec_r34_guard'
TAPS = {'a33d30r','a33d30t','a33d31r','a33d31t','a33d32r','a33d32t'}
DENY = 'ardrec-r33-block-until-containment'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
ALLOWED_COMMANDS = ('/usr/sbin/nft','/usr/bin/virsh')
MAX_OUTPUT = 262144

class RecoveryError(RuntimeError):
    pass

def need(ok, why):
    if not ok:
        raise RecoveryError(why)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pairs(items):
    doc = {}
    for name, value in items:
        need(name not in doc, 'json_duplicate_key')
        doc[name] = value
    return doc

def read_json(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False,'nonfinite_json'))

def safe_root_file(path, owner_uid):
    need(path.parent == BUNDLE and path.name in
         {'manifest.json', RESTORE, 'root-recover.py',
          'ssh-original.xml', 'ssh-candidate.xml',
          'runner-original.xml','runner-candidate.xml'},
         'unapproved_root_file_path')
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == owner_uid and s.st_nlink == 1 and
         stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= 262144,
         'root_file_owner_or_mode_invalid_' + path.name)
    return path.read_bytes()

def root_bundle():
    need(os.geteuid() == 0, 'root_required')
    return verify_staged(expected_uid=0)

def verify_staged(*, expected_uid):
    # Testability does NOT relax root_bundle(): physical execution always
    # requires UID=0, fixed BUNDLE path and the exact staged executable.
    need(Path(__file__).resolve() == BUNDLE / 'root-recover.py',
         'root_executable_must_be_staged_copy')
    for part in (BUNDLE, *BUNDLE.parents):
        need(not part.is_symlink(), 'root_path_symlink')
    st = BUNDLE.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == expected_uid and
         stat.S_IMODE(st.st_mode) == 0o700, 'root_bundle_directory_invalid')
    # All ancestors must be root-owned and not group/other writable.
    for parent in BUNDLE.parents:
        s = parent.lstat()
        need(s.st_uid in (0, expected_uid) and not (s.st_mode & 0o022),
             'root_bundle_ancestor_writable')
    expected = {'manifest.json', RESTORE, 'root-recover.py',
                'ssh-original.xml', 'ssh-candidate.xml',
                'runner-original.xml', 'runner-candidate.xml'}
    need({p.name for p in BUNDLE.iterdir()} == expected,
         'root_bundle_extra_files_or_missing')
    raw = {name:safe_root_file(BUNDLE / name,expected_uid) for name in expected}
    doc = read_json(raw['manifest.json'])
    need(type(doc) is dict and doc.get('schema') == SCHEMA and
         doc.get('source_main') == '1866af3a4f0ceb64b92f39a924ef00eacf56b169' and
         doc.get('p8_operational') == 'NO-GO' and
         doc.get('permission') == 'DENY_ONLY_RESTORATION' and
         doc.get('traffic_allowed') is False and
         type(doc.get('sha256')) is dict and
         set(doc['sha256']) == expected - {'manifest.json'},
         'root_manifest_invalid')
    for name in expected - {'manifest.json'}:
        need(doc['sha256'][name] == sha(raw[name]),
             'root_bundle_hash_mismatch_' + name)
    need(doc['sha256']['root-recover.py'] == sha(Path(__file__).read_bytes()),
         'executed_code_not_bundle_copy')
    need(b'counter accept' not in raw[RESTORE] and
         b'flush ruleset' not in raw[RESTORE] and
         b'delete table' not in raw[RESTORE] and
         raw[RESTORE].startswith(b'flush table bridge ardrec_r34_guard\n') and
         raw[RESTORE].count(b'counter drop') == 4,
         'restore_policy_not_deny_only')
    for role, (tap, original, candidate) in ROLE_FILES.items():
        verify_binding(raw[original],role,False)
        verify_binding(raw[candidate],role,True)
    return raw

def verify_binding(raw, role, candidate):
    need(role in ROLE_FILES and type(raw) is bytes and
         0 < len(raw) <= 16384 and b'<!' not in raw,
         'binding_data_invalid')
    root = ET.fromstring(raw)
    tap = ROLE_FILES[role][0]
    mac = '52:54:00:ad:30:02' if role == 'ssh' else '52:54:00:ad:30:01'
    name = 'ardrec-r33-dev-' + role
    offered = ('ardrec-r45-ssh-icmp-candidate' if role == 'ssh'
               else 'ardrec-r45-runner-icmp-candidate')
    need(root.tag == 'filterbinding' and not root.attrib and
         [x.tag for x in root] == ['owner','portdev','mac','filterref','backend'],
         'binding_topology_invalid_' + role)
    owner, port, mac_elem, filt, backend = list(root)
    need(not owner.attrib and [x.tag for x in owner] == ['name','uuid'] and
         owner.findtext('name') == name and
         re.fullmatch('[0-9a-fA-F-]{36}',owner.findtext('uuid','')) is not None and
         port.attrib == {'name':tap} and mac_elem.attrib == {'address':mac} and
         filt.attrib == {'filter':offered if candidate else DENY} and
         len(filt) == 1 and filt[0].tag == 'parameter' and
         filt[0].attrib == {'name':'MAC','value':mac} and len(filt[0]) == 0 and
         backend.attrib == {'name':'iptables'} and len(backend) == 0,
         'binding_identity_invalid_' + role)
    return root

def structurally_equal(a,b):
    def walk(x):
        return (x.tag,tuple(sorted(x.attrib.items())),
                (x.text or '').strip(),tuple(walk(c) for c in x))
    return walk(ET.fromstring(a)) == walk(ET.fromstring(b))

def host(argv, *, input_bytes=None, timeout=45):
    need(type(argv) is list and len(argv) >= 3,
         'unapproved_privileged_command')
    nft_allowed = argv in (
        ['/usr/sbin/nft','-f','-'],
        ['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]
    )
    binding_allowed = False
    if argv[:3] == ['/usr/bin/virsh','-c','qemu:///system']:
        for role, (tap, original, candidate) in ROLE_FILES.items():
            binding_allowed |= argv in (
                ['/usr/bin/virsh','-c','qemu:///system',
                 'nwfilter-binding-dumpxml',tap],
                ['/usr/bin/virsh','-c','qemu:///system',
                 'nwfilter-binding-delete',tap],
                ['/usr/bin/virsh','-c','qemu:///system',
                 'nwfilter-binding-create',str(BUNDLE/original)],
            )
    need(nft_allowed or binding_allowed, 'unapproved_privileged_command')
    if argv == ['/usr/sbin/nft','-f','-']:
        need(type(input_bytes) is bytes and
             b'counter accept' not in input_bytes,
             'nft_input_not_deny_only')
    else:
        need(input_bytes is None, 'unexpected_host_input')
    cp = subprocess.run(argv, input=input_bytes,
        stdin=subprocess.DEVNULL if input_bytes is None else None,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
        timeout=timeout,close_fds=True,env=ENV)
    need(cp.returncode == 0 and len(cp.stdout) <= MAX_OUTPUT and
         len(cp.stderr) <= 16000,
         'host_command_failed_'+argv[0].split('/')[-1]+'_'+str(cp.returncode))
    return cp.stdout

def verify_deny_live(raw):
    data = read_json(raw)
    need(type(data) is dict and set(data) == {'nftables'} and
         type(data['nftables']) is list, 'nft_readback_json_shape')
    rows = [next(iter(row.items())) for row in data['nftables']
            if type(row) is dict and len(row) == 1 and 'metainfo' not in row]
    need(len(rows) == 8, 'nft_readback_object_count')
    tables = [v for k,v in rows if k == 'table']
    chains = [v for k,v in rows if k == 'chain']
    rules = [v for k,v in rows if k == 'rule']
    need(len(tables) == 1 and len(chains) == 3 and len(rules) == 4 and
         tables[0].get('family') == 'bridge' and
         tables[0].get('name') == TABLE,
         'nft_readback_table_scope')
    names = set()
    for c in chains:
        need(c.get('name') in ('input','output','forward') and
             c.get('name') not in names and c.get('hook') == c.get('name') and
             c.get('type') == 'filter' and c.get('policy') == 'accept' and
             type(c.get('prio')) is int and c.get('prio') == -200,
             'nft_readback_chain_scope')
        names.add(c['name'])
    need(names == {'input','output','forward'},'nft_readback_chain_set')
    seen=set()
    for rule in rules:
        need(rule.get('family') == 'bridge' and rule.get('table') == TABLE and
             rule.get('chain') in names and
             type(rule.get('expr')) is list and len(rule['expr']) == 3,
             'nft_readback_rule_structure')
        match,counter,verdict = rule['expr']
        need(verdict == {'drop':None} and set(match) == {'match'} and
             set(counter) == {'counter'} and
             set(counter['counter']) == {'packets','bytes'} and
             all(type(n) is int and n >= 0 for n in counter['counter'].values()),
             'nft_readback_rule_not_deny')
        expr=match['match']
        need(type(expr) is dict and set(expr)=={'left','op','right'} and
             expr.get('op')=='==' and
             expr['left'].get('meta',{}).get('key') in ('iifname','oifname') and
             set(expr['right'].get('set',[]))==TAPS and
             len(expr['right']['set'])==len(TAPS),
             'nft_readback_match_scope')
        identity=(rule['chain'],expr['left']['meta']['key'])
        need(identity in {('input','iifname'),('output','oifname'),
                          ('forward','iifname'),('forward','oifname')} and
             identity not in seen,'nft_readback_rule_duplicates')
        seen.add(identity)
    need(len(seen)==4,'nft_readback_rule_set')

@contextmanager
def recovery_lock():
    """Serialize privileged recovery with future operator on root manifest inode."""
    fd = os.open(BUNDLE / 'manifest.json', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RecoveryError('exclusive_recovery_lock_busy') from exc
        yield
    finally:
        os.close(fd)

def recover(*, check_only=False):
    raw=root_bundle()
    if check_only:
        return {'result':'ROOT_BUNDLE_VERIFIED_READONLY','writes':0,
                'physical_recovery_tested':False,'p8_operational':'NO-GO'}
    with recovery_lock():
        return _recover_deny(raw)

def _recover_deny(raw):
    events=[]
    # FIRST operation is atomic, scoped deny restoration. No readback mismatch
    # may prevent this first denial attempt. The stage is root-owned and pinned.
    host(['/usr/sbin/nft','-f','-'], input_bytes=raw[RESTORE])
    events.append('nft_restore_attempt_succeeded')
    verify_deny_live(host(['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]))
    events.append('nft_deny_readback_verified')
    for role,(tap,old,candidate) in ROLE_FILES.items():
        cmd=['/usr/bin/virsh','-c','qemu:///system']
        try:
            current=host(cmd+['nwfilter-binding-dumpxml',tap])
        except (OSError,subprocess.TimeoutExpired,RecoveryError):
            # Never delete an unknown binding. R34 remains in deny mode.
            raise RecoveryError('binding_readback_unavailable_'+role)
        if structurally_equal(current,raw[old]):
            events.append('binding_already_original_'+role)
            continue
        need(structurally_equal(current,raw[candidate]),
             'unexpected_binding_blocked_under_r34_deny_'+role)
        # From here, only authenticated candidate is eligible for replacement.
        host(cmd+['nwfilter-binding-delete',tap])
        events.append('binding_candidate_removed_'+role)
        host(cmd+['nwfilter-binding-create',str(BUNDLE/old)])
        events.append('binding_original_created_'+role)
        now=host(cmd+['nwfilter-binding-dumpxml',tap])
        need(structurally_equal(now,raw[old]),
             'binding_restore_readback_failed_'+role)
    verify_deny_live(host(['/usr/sbin/nft','-j','-a','list','table','bridge',TABLE]))
    return {'result':'DENY_RESTORATION_READBACK_PASS',
            'events':events,'bindings_restored_or_original':True,
            'packets_injected':False,'p8_operational':'NO-GO',
            'service_acceptance':False}

def main(argv=None):
    ap=argparse.ArgumentParser()
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-root-bundle',action='store_true')
    group.add_argument('--restore-deny',action='store_true')
    a=ap.parse_args(argv)
    try:
        doc=recover(check_only=a.check_root_bundle)
        print(json.dumps(doc,sort_keys=True,separators=(',',':')))
        return 0
    except Exception as error:
        print(json.dumps({'result':'RECOVERY_REVIEW_REQUIRED_NO_GO',
                          'error':type(error).__name__+':'+str(error)[:160],
                          'p8_operational':'NO-GO'},sort_keys=True),file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
