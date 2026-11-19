"""R113-F3T: regresión adversarial de captura SSH sin nueva ejecución."""
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(BASE/'src'),str(BASE/'scripts')]
from ardrec.coordination import r113_f3_guest_listeners as core
import ardrec_p14_r113_f3t_recover_listener as recovery

REAL_SS=('LISTEN 0      4096   127.0.0.53%lo:53   0.0.0.0:*\n'
         'LISTEN 0      4096   0.0.0.0:5355   0.0.0.0:*\n'
         'LISTEN 0      4096   127.0.0.54:53   0.0.0.0:*\n'
         'LISTEN 0      128    0.0.0.0:22    0.0.0.0:*\n')

def capture(role,port,txt=None):
    if txt is None:txt=f'LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:*\n'
    return {'role':role,'command':['/usr/bin/ss','-H','-ltn4'],
            'start':{'return':{'pid':101}},
            'completion':{'return':{'exited':True,'exitcode':0,
                'out-data':base64.b64encode(txt.encode()).decode(),
                'err-data':''}}}

class ParseScopeTests(unittest.TestCase):
    def classify(self,role,text):
        c=capture(role,{'ssh':22,'ftp':21,'smb':445}[role],text)
        return recovery.classify_capture(role,c)
    def test_actual_scoped_dns_line(self):
        self.assertEqual(core.listening_sockets(REAL_SS.encode())[0],
                         {'address':'127.0.0.53','port':53})
    def test_actual_lab_ssh_listener(self):
        result=self.classify('ssh',REAL_SS)
        self.assertEqual(result['local_listener_state'],'LISTENING_ON_LAB_IPV4')
        self.assertEqual(result['bound_ipv4'],['0.0.0.0'])
        self.assertEqual(result['observed_ipv4_socket_count'],4)
        self.assertFalse(result['network_reachability_proven'])
    def test_no_claim_when_only_loopback(self):
        self.assertEqual(self.classify('ftp','LISTEN 0 128 127.0.0.53%lo:21 *:*\n')['local_listener_state'],
                         'LISTENING_ONLY_ON_OTHER_IPV4')
    def test_real_target_address(self):
        self.assertEqual(self.classify('ftp','LISTEN 0 128 10.203.31.2%ens3:21 *:*\n')['local_listener_state'],
                         'LISTENING_ON_LAB_IPV4')
    def test_reject_scoped_wildcard(self):
        with self.assertRaises(core.GuardError):
            self.classify('ssh','LISTEN 0 128 *%ens3:22 *:*\n')
    def test_reject_double_scope(self):
        with self.assertRaises(core.GuardError):
            self.classify('ssh','LISTEN 0 128 127.0.0.53%lo%ens3:22 *:*\n')
    def test_reject_missing_scope(self):
        with self.assertRaises(core.GuardError):
            self.classify('ssh','LISTEN 0 128 127.0.0.53%:22 *:*\n')
    def test_reject_invalid_scope_char(self):
        with self.assertRaises(core.GuardError):
            self.classify('ssh','LISTEN 0 128 127.0.0.53%$(cmd):22 *:*\n')
    def test_reject_ipv6_even_with_scope(self):
        with self.assertRaises(core.GuardError):
            self.classify('ssh','LISTEN 0 128 fe80::1%eth0:22 *:*\n')
    def test_no_listener_not_a_positive(self):
        self.assertEqual(self.classify('smb',REAL_SS)['local_listener_state'],
                         'NO_LISTENER_AT_EXPECTED_PORT')
    def test_nonzero_guest_exit_rejected(self):
        bad=capture('ftp',21);bad['completion']['return']['exitcode']=1
        with self.assertRaises(core.GuardError):recovery.classify_capture('ftp',bad)
    def test_stderr_rejected(self):
        bad=capture('ftp',21);bad['completion']['return']['err-data']='YQ=='
        with self.assertRaises(core.GuardError):recovery.classify_capture('ftp',bad)
    def test_wrong_command_rejected(self):
        bad=capture('ftp',21);bad['command']=['/usr/bin/nmap']
        with self.assertRaises(core.GuardError):recovery.classify_capture('ftp',bad)
    def test_verify_ssh_source_mode_exists(self):
        text=(BASE/'scripts/ardrec_p14_r113_f3t_recover_listener.py').read_text()
        self.assertIn("--verify-ssh-source",text)
        self.assertIn("R113_F3T_GUEST_EXECUTIONS=0",text)
    def test_no_second_ssh_exec_in_source(self):
        text=(BASE/'scripts/ardrec_p14_r113_f3t_recover_listener.py').read_text()
        self.assertEqual(recovery.ROLES,('ftp','smb'))
        self.assertIn("for role in ROLES:",text)
        self.assertIn("recover_ssh()",text)
        self.assertNotIn("qga('ssh'",text)
        self.assertNotIn('virsh start',text)
        self.assertNotIn('nft add',text)
    def test_capture_persisted_before_classify(self):
        text=(BASE/'scripts/ardrec_p14_r113_f3t_recover_listener.py').read_text()
        self.assertLess(text.index("put(folder/('capture-'+role+'.json')"),
                        text.index("classified[role]=classify_capture"))

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ardrec-f3t-unit-')
        base=Path(self.temp.name)
        base.chmod(0o700)
        self.previous=base/'f3r'/'inspect-9nl15krt'
        self.previous.parent.mkdir(mode=0o700)
        self.previous.mkdir(mode=0o700)
        self.root=base/'f3t'
        self.root.mkdir(mode=0o700)
        self.fingerprint={'fingerprint_sha256':'test-f3-original'}
        values={
            'agent_preflight.json':{'agents':'ok'},
            'before.json':{'snapshot':'old'},
            'intent.json':{'scope':['ssh','ftp','smb'],'p8_operational':'NO-GO',
                           'previous_incident':self.fingerprint},
            'started-ssh.once':{},
            'capture-ssh.json':capture('ssh',22,REAL_SS),
        }
        for name,contents in values.items():
            if name=='started-ssh.once':
                contents={'role':'ssh','intent_sha256':recovery.sha(recovery.canon(values['intent.json']))}
            recovery.put(self.previous/name,contents)
        self.original_hashes={name:recovery.sha((self.previous/name).read_bytes()) for name in values}
        self.stack=ExitStack()
        self.stack.enter_context(patch.object(recovery,'PREVIOUS',self.previous))
        self.stack.enter_context(patch.object(recovery,'ROOT',self.root))
        self.stack.enter_context(patch.object(recovery,'PREVIOUS_HASHES',self.original_hashes))
        self.stack.enter_context(patch.object(recovery,'SSH_STDOUT_HASH',
                       recovery.sha(REAL_SS.encode())))
        self.stack.enter_context(patch.object(recovery.f3,'previous_incident',
                        return_value=self.fingerprint))
        self.stack.enter_context(patch.object(recovery.f3,'origin',return_value=None))
    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()
    def test_original_ssh_capture_reused(self):
        ref,listener=recovery.recover_ssh()
        self.assertEqual(ref['source_sha256'],self.original_hashes['capture-ssh.json'])
        self.assertEqual(listener['local_listener_state'],'LISTENING_ON_LAB_IPV4')
    def test_original_tamper_refused(self):
        path=self.previous/'capture-ssh.json'
        path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaises(core.GuardError):recovery.recover_ssh()
    def test_original_marker_tamper_refused(self):
        path=self.previous/'started-ssh.once'
        path.write_text('{}\n')
        with self.assertRaises(core.GuardError):recovery.recover_ssh()
    def test_missing_incident_file_refused(self):
        (self.previous/'before.json').unlink()
        with self.assertRaises(core.GuardError):recovery.recover_ssh()
    def test_intent_prior_fingerprint_refused(self):
        self.stack.enter_context(patch.object(recovery.f3,'previous_incident',
                             return_value={'fingerprint_sha256':'changed'}))
        with self.assertRaises(core.GuardError):recovery.recover_ssh()
    def test_two_guest_mocked_and_replay(self):
        starts=[]
        def qga(role,req):
            op=req['execute']
            self.assertIn(role,('ftp','smb'))
            if op=='guest-info':
                return {'return':{'supported_commands':[
                    {'name':'guest-exec','enabled':True},
                    {'name':'guest-exec-status','enabled':True}]}}
            if op=='guest-exec':
                starts.append(role)
                return {'return':{'pid':101}}
            if op=='guest-exec-status':
                return capture(role,21 if role=='ftp' else 445)['completion']
            raise AssertionError('UNKNOWN_OPERATION')
        self.stack.enter_context(patch.object(recovery.f3,'parent',return_value=None))
        self.stack.enter_context(patch.object(recovery.f3,'live',return_value={'stable':'deny'}))
        self.stack.enter_context(patch.object(recovery.f3,'endpoints',return_value={'verified':'six'}))
        self.stack.enter_context(patch.object(recovery.f3,'qga',side_effect=qga))
        self.assertEqual(recovery.inspect(),0)
        self.assertEqual(starts,['ftp','smb'])
        files=list(self.root.glob('recover-*'))
        self.assertEqual(len(files),1)
        result=recovery.verify(files[0])
        self.assertEqual(set(result),{'ssh','ftp','smb'})
        self.assertEqual(result['ftp']['local_listener_state'],'LISTENING_ON_LAB_IPV4')
        self.assertEqual(result['smb']['local_listener_state'],'LISTENING_ON_LAB_IPV4')
        self.assertEqual(result['ssh']['local_listener_state'],'LISTENING_ON_LAB_IPV4')
        self.assertTrue((files[0]/'manifest.json').exists())
    def test_replay_rejects_capture_tamper(self):
        self.test_two_guest_mocked_and_replay()
        file=next(self.root.glob('recover-*'))/'capture-ftp.json'
        file.write_bytes(file.read_bytes()+b'\n')
        with self.assertRaises(core.GuardError):recovery.verify(file.parent)
    def test_readonly_replay_has_no_qga(self):
        self.assertIn('f3.origin()',recovery.verify.__code__.co_names if False else
                      (BASE/'scripts/ardrec_p14_r113_f3t_recover_listener.py').read_text())
        self.assertFalse('qga' in recovery.verify.__code__.co_names)

if __name__=='__main__':unittest.main()
