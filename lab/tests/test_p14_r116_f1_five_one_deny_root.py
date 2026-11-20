"""R116-F1: bounded root guardian policy/IO mock tests; no actual host operations."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO=Path(__file__).resolve().parents[2]
SCRIPT=REPO/'scripts/ardrec_p14_r116_f1_root_deny_guard.py'
STAGER=REPO/'scripts/ardrec_p14_r116_f1_root_stage.py'
MANIFEST=REPO/'lab/operational-controller/r116-f1-root-bundle.json'
spec=importlib.util.spec_from_file_location('r116_f1_root_guard',SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

ROLES={
    'runner_ssh':('runner','ssh','a33d30r','52:54:00:ad:30:01'),
    'ssh':('ssh','ssh','a33d30t','52:54:00:ad:30:02'),
    'runner_ftp':('runner','ftp','a33d31r','52:54:00:ad:31:01'),
    'ftp':('ftp','ftp','a33d31t','52:54:00:ad:31:02'),
    'runner_smb':('runner','smb','a33d32r','52:54:00:ad:32:01'),
    'smb':('smb','smb','a33d32t','52:54:00:ad:32:02'),
}

class Six:
    ROLES=ROLES
    def verify_nft(self,raw):
        if raw != b'DENY_NFT':raise ValueError('NOT_DENY')
    def present(self,raw,tap):
        return tap in raw.decode().splitlines()[1:]
    def verify_domain(self,domain,key,original):
        if domain != ('XML_'+ROLES[key][0]).encode():
            raise ValueError('DOMAIN_DRIFT')
    def xml_equal(self,a,b):return a==b

def baseline():return {x:'OFF' for x in m.VM}
def live():return {'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'}

class Host:
    def __init__(self,states=None,bindings=None,nft=b'DENY_NFT',fail=None):
        self.states=baseline() if states is None else dict(states)
        self.bindings={} if bindings is None else dict(bindings)
        self.nft=nft
        self.fail=fail
        self.commands=[]
    def __call__(self,cmd,*,payload=None,timeout=12):
        tup=tuple(cmd)
        self.commands.append((tup,payload))
        if self.fail is not None and tup==self.fail:raise m.Stop('HOST_FAILED')
        if tup==('/usr/sbin/nft','-f','-'):
            if payload!=b'RESTORE_NFT':raise ValueError('WRONG_RESTORE_PAYLOAD')
            self.nft=b'DENY_NFT';return b''
        if tup==m.NFT:return self.nft
        if tup[:3]==m.VIRSH:
            op=tup[3]
            if op=='domstate':
                v=tup[4].removeprefix('ardrec-r33-dev-')
                return b'running\n' if self.states[v]=='RUNNING' else b'shut off\n'
            if op=='nwfilter-binding-list':
                taps=[ROLES[key][2] for key in self.bindings]
                return ('Port\n'+'\n'.join(taps)+'\n').encode()
            if op=='dumpxml':
                return ('XML_'+tup[4].removeprefix('ardrec-r33-dev-')).encode()
            if op=='nwfilter-binding-dumpxml':
                for key,(*_,tap,mac) in ROLES.items():
                    if tap==tup[4]:return self.bindings[key]
                raise ValueError('TAP_UNKNOWN')
            if op=='nwfilter-binding-delete':
                key=next(k for k,v in ROLES.items() if v[2]==tup[4])
                self.bindings.pop(key);return b''
            if op=='nwfilter-binding-create':
                key=Path(tup[4]).name.removesuffix('-original.xml')
                self.bindings[key]=('O_'+key).encode();return b''
        if tup[0]=='/usr/bin/systemd-run':return b'Created transient timer\n'
        if tup[:2]==('/usr/bin/systemctl','show'):
            name=tup[2].removesuffix('.timer')
            return (f'LoadState=loaded\nActiveState=active\n'
                    f'Unit={name}.service\nNextElapseUSecMonotonic=100000\n').encode()
        raise AssertionError('UNEXPECTED_COMMAND_'+repr(tup))

BUNDLE={'r34-deny-restore.nft':b'RESTORE_NFT'}
for key in ROLES:
    BUNDLE[key+'-original.xml']=('O_'+key).encode()
    BUNDLE[key+'-candidate.xml']=('C_'+key).encode()

def active_bindings(states=None):
    p=m.lifecycle(live() if states is None else states)
    return {x:('O_'+x).encode() for x in p['active']}

class Source(unittest.TestCase):
    def test_manifest_matches_script_exact(self):
        doc=json.loads(MANIFEST.read_bytes())
        self.assertEqual(doc['guard_sha256'],hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        self.assertEqual(doc['helper_sha256'],m.HELPER_SHA)
        self.assertEqual(doc['window_seconds'],60)
        self.assertIs(doc['opens_ports'],False)
        self.assertEqual(doc['p8'],'NO-GO')
    def test_entrypoints_exist(self):
        self.assertTrue(STAGER.is_file())
        self.assertTrue(SCRIPT.is_file())
    def test_capabilities_no_root(self):
        self.assertEqual(m.main(['--capabilities']),0)
    def test_nonstaged_check_rejected(self):
        self.assertEqual(m.main(['--check']),23)

class Lifecycle(unittest.TestCase):
    def test_offline(self):
        p=m.lifecycle(baseline());self.assertEqual((p['active_count'],p['absent_count']),(0,6))
    def test_ssh(self):
        p=m.lifecycle({'ssh':'RUNNING','runner':'OFF','ftp':'OFF','smb':'OFF'})
        self.assertEqual((p['active_count'],p['absent_count']),(1,5))
    def test_ssh_runner(self):
        p=m.lifecycle({'ssh':'RUNNING','runner':'RUNNING','ftp':'OFF','smb':'OFF'})
        self.assertEqual((p['active_count'],p['absent_count']),(4,2))
    def test_ftp_five_one(self):
        p=m.lifecycle(live())
        self.assertEqual((p['active_count'],p['absent_count']),(5,1))
        self.assertIn('runner_smb',p['active'])
        self.assertEqual(p['absent'],('smb',))
        self.assertFalse(p['allow_traffic'])
    def test_smb_on_rejected(self):
        a=live();a['smb']='RUNNING'
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_ftp_without_runner_rejected(self):
        a=baseline();a['ftp']='RUNNING'
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_runner_without_ssh_rejected(self):
        a=baseline();a['runner']='RUNNING'
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_ssh_without_ftp_is_legal(self):
        a=baseline();a['ssh']='RUNNING'
        self.assertEqual(m.lifecycle(a)['active_count'],1)
    def test_ambiguous_vm_state_rejected(self):
        a=live();a['ftp']='PAUSED'
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_missing_vm_rejected(self):
        a=live();del a['ftp']
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_unknown_vm_rejected(self):
        a=live();a['other']='OFF'
        with self.assertRaises(m.Stop):m.lifecycle(a)
    def test_parser_localized(self):
        self.assertEqual(m.state(b'apagado\n'),'OFF')
        self.assertEqual(m.state(b'ejecutando\n'),'RUNNING')
    def test_parser_invalid(self):
        with self.assertRaises(m.Stop):m.state(b'unknown')

class ReadOnly(unittest.TestCase):
    def test_live_match(self):
        h=Host(live(),active_bindings())
        r=m.check_deny(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(r['policy']['active_count'],5)
        self.assertEqual(r['host_writes'],0)
        self.assertFalse(any(x[0][0]=='/usr/sbin/nft' and '-f' in x[0] for x in h.commands))
    def test_offline_match(self):
        h=Host()
        r=m.check_deny(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(r['policy']['active_count'],0)
    def test_candidate_not_accepted_as_deny(self):
        b=active_bindings();b['ftp']=b'C_ftp'
        with self.assertRaises(m.Stop):m.check_deny(f6=Six(),bundle=BUNDLE,host=Host(live(),b))
    def test_unknown_binding_while_smb_off(self):
        b=active_bindings();b['smb']=b'O_smb'
        with self.assertRaises(m.Stop):m.check_deny(f6=Six(),bundle=BUNDLE,host=Host(live(),b))
    def test_missing_active_binding(self):
        b=active_bindings();del b['ftp']
        with self.assertRaises(m.Stop):m.check_deny(f6=Six(),bundle=BUNDLE,host=Host(live(),b))
    def test_nft_not_deny(self):
        with self.assertRaises(ValueError):
            m.check_deny(f6=Six(),bundle=BUNDLE,host=Host(live(),active_bindings(),b'ALLOW'))

class Restore(unittest.TestCase):
    def test_restores_known_candidate_with_nft_first(self):
        b=active_bindings();b['ftp']=b'C_ftp';b['runner_ftp']=b'C_runner_ftp'
        h=Host(live(),b,nft=b'ALLOW')
        r=m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(r['status'],'DENY_RESTORED')
        self.assertEqual(h.commands[0][0],('/usr/sbin/nft','-f','-'))
        self.assertEqual(h.nft,b'DENY_NFT')
        self.assertEqual(h.bindings,active_bindings())
        self.assertFalse(any(b'accept' in str(x).encode().lower() for x in h.commands))
    def test_absent_offline_not_created(self):
        h=Host()
        m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(h.bindings,{})
        self.assertEqual(h.commands[0][0],('/usr/sbin/nft','-f','-'))
    def test_unexpected_unknown_binding_fails_closed(self):
        b=active_bindings();b['ftp']=b'UNKNOWN'
        h=Host(live(),b,nft=b'ALLOW')
        with self.assertRaisesRegex(m.Stop,'UNKNOWN_BINDING'):
            m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(h.nft,b'DENY_NFT')
        self.assertEqual(h.bindings['ftp'],b'UNKNOWN')
        self.assertFalse(any(c[0][3]=='nwfilter-binding-delete' for c in h.commands if len(c[0])>3))
    def test_unexpected_vm_still_nft_first(self):
        a=live();a['smb']='RUNNING'
        h=Host(a,active_bindings(),nft=b'ALLOW')
        with self.assertRaises(m.Stop):m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(h.nft,b'DENY_NFT')
    def test_missing_running_binding_rebuilt_once(self):
        b=active_bindings();del b['ftp']
        h=Host(live(),b,nft=b'ALLOW')
        r=m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(h.bindings['ftp'],b'O_ftp')
        self.assertEqual(r['status'],'DENY_RESTORED')
        self.assertEqual(sum(c[0][3]=='nwfilter-binding-create' for c in h.commands if len(c[0])>3),1)
    def test_nft_restore_command_failure_no_virsh(self):
        h=Host(live(),active_bindings(),nft=b'ALLOW',fail=('/usr/sbin/nft','-f','-'))
        with self.assertRaises(m.Stop):m.restore(f6=Six(),bundle=BUNDLE,host=h)
        self.assertEqual(len(h.commands),1)
    def test_post_restore_nft_tamper_rejected(self):
        class Broken(Host):
            def __call__(self,cmd,**kw):
                if tuple(cmd)==m.NFT:return b'ALLOW'
                return super().__call__(cmd,**kw)
        with self.assertRaises(ValueError):
            m.restore(f6=Six(),bundle=BUNDLE,host=Broken(live(),active_bindings()))

class Timer(unittest.TestCase):
    def test_arm_one_shot_then_refuses_retry(self):
        with tempfile.TemporaryDirectory() as td:
            h=Host(live(),active_bindings())
            with patch.object(m,'ROOT',Path(td)):
                r=m.arm('1'*16,f6=Six(),bundle=BUNDLE,host=h)
                self.assertTrue(r['timer_verified'])
                self.assertTrue((Path(td)/m.MARKER).exists())
                self.assertEqual(r['duration_seconds'],60)
                with self.assertRaisesRegex(m.Stop,'ALREADY_CONSUMED'):
                    m.arm('2'*16,f6=Six(),bundle=BUNDLE,host=h)
            units=[x for x in h.commands if x[0][0]=='/usr/bin/systemd-run']
            self.assertEqual(len(units),1)
            self.assertIn('--on-active=45s',units[0][0])
            self.assertNotIn('--restore-deny',str(h.commands[:-2]))
    def test_arm_offline_rejected_before_marker(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,'ROOT',Path(td)):
                with self.assertRaisesRegex(m.Stop,'FIVE_ONE_STAGE_REQUIRED'):
                    m.arm('1'*16,f6=Six(),bundle=BUNDLE,host=Host())
                self.assertFalse((Path(td)/m.MARKER).exists())
    def test_bad_session_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            with patch.object(m,'ROOT',Path(td)):
                with self.assertRaisesRegex(m.Stop,'SESSION_ID_INVALID'):
                    m.arm('not-a-session',f6=Six(),bundle=BUNDLE,host=Host(live(),active_bindings()))
    def test_timer_failure_consumes_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            h=Host(live(),active_bindings())
            def failure(cmd,*,payload=None,timeout=12):
                if cmd[0]=='/usr/bin/systemd-run':raise m.Stop('SYSTEMD_NOT_AVAILABLE')
                return h(cmd,payload=payload,timeout=timeout)
            with patch.object(m,'ROOT',Path(td)):
                with self.assertRaises(m.Stop):
                    m.arm('b'*16,f6=Six(),bundle=BUNDLE,host=failure)
                self.assertTrue((Path(td)/m.MARKER).exists())
                with self.assertRaisesRegex(m.Stop,'ALREADY_CONSUMED'):
                    m.arm('c'*16,f6=Six(),bundle=BUNDLE,host=h)
    def test_timer_inactive_rejected_consumes(self):
        with tempfile.TemporaryDirectory() as td:
            class BadTimer(Host):
                def __call__(self,cmd,**kw):
                    if cmd[:2]==('/usr/bin/systemctl','show'):
                        return b'LoadState=loaded\nActiveState=inactive\n'
                    return super().__call__(cmd,**kw)
            with patch.object(m,'ROOT',Path(td)):
                with self.assertRaisesRegex(m.Stop,'AUTONOMOUS_TIMER_NOT_CONFIRMED'):
                    m.arm('a'*16,f6=Six(),bundle=BUNDLE,
                          host=BadTimer(live(),active_bindings()))
                self.assertTrue((Path(td)/m.MARKER).exists())

if __name__=='__main__':unittest.main()
