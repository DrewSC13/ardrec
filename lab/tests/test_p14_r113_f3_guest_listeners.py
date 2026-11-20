"""R113-F3: pruebas locales, sin VM, red, qga ni firewall."""
import base64
import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ardrec.coordination import r113_f3_guest_listeners as core


def wrapped(text, *, exitcode=0, err='', command=None):
    return {
        'pid':101, 'status':exitcode,
        'command':['/usr/bin/ss','-H','-ltn4'] if command is None else command,
        'stdout_b64':base64.b64encode(text.encode()).decode(),
        'stderr_b64':base64.b64encode(err.encode()).decode(),
    }

class F3Tests(unittest.TestCase):
    def test_guest_info_enabled(self):
        self.assertTrue(core.agent_info({'return':{'supported_commands':[
            {'name':'guest-exec','enabled':True},
            {'name':'guest-exec-status','enabled':True}]}}))
    def test_guest_info_denies_disabled(self):
        with self.assertRaises(core.GuardError):
            core.agent_info({'return':{'supported_commands':[
                {'name':'guest-exec','enabled':False},
                {'name':'guest-exec-status','enabled':True}]}})
    def test_guest_info_denies_duplicate(self):
        with self.assertRaises(core.GuardError):
            core.agent_info({'return':{'supported_commands':[
                {'name':'guest-exec','enabled':True},
                {'name':'guest-exec','enabled':True},
                {'name':'guest-exec-status','enabled':True}]}})
    def test_pid_valid(self):
        self.assertEqual(core.started({'return':{'pid':123}}),123)
    def test_pid_bool_denied(self):
        with self.assertRaises(core.GuardError): core.started({'return':{'pid':True}})
    def test_status_running(self):
        self.assertEqual(core.status({'return':{'exited':False}}), (False,None,None,None))
    def test_status_base64_invalid(self):
        with self.assertRaises(core.GuardError):
            core.status({'return':{'exited':True,'exitcode':0,'out-data':'%'}})
    def test_ssh_listener_wildcard(self):
        v = core.classify('ssh',wrapped('LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\n'))
        self.assertEqual(v['local_listener_state'],'LISTENING_ON_LAB_IPV4')
        self.assertFalse(v['network_reachability_proven'])
    def test_ftp_listener_exact(self):
        v = core.classify('ftp',wrapped('LISTEN 0 128 10.203.31.2:21 0.0.0.0:*\n'))
        self.assertEqual(v['local_listener_state'],'LISTENING_ON_LAB_IPV4')
    def test_smb_listener_exact(self):
        v = core.classify('smb',wrapped('LISTEN 0 128 10.203.32.2:445 0.0.0.0:*\n'))
        self.assertEqual(v['local_listener_state'],'LISTENING_ON_LAB_IPV4')
    def test_loopback_not_reachable(self):
        v = core.classify('ssh',wrapped('LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n'))
        self.assertEqual(v['local_listener_state'],'LISTENING_ONLY_ON_OTHER_IPV4')
    def test_port_not_listening(self):
        v = core.classify('ftp',wrapped('LISTEN 0 128 0.0.0.0:990 0.0.0.0:*\n'))
        self.assertEqual(v['local_listener_state'],'NO_LISTENER_AT_EXPECTED_PORT')
    def test_invalid_command_denied(self):
        with self.assertRaises(core.GuardError):
            core.classify('ssh',wrapped('',command=['/bin/sh','-c','echo']))
    def test_nonzero_exit_denied(self):
        with self.assertRaises(core.GuardError):
            core.classify('smb',wrapped('',exitcode=127))
    def test_error_output_denied(self):
        with self.assertRaises(core.GuardError):
            core.classify('ssh',wrapped('',err='permission denied'))
    def test_invalid_address_denied(self):
        with self.assertRaises(core.GuardError):
            core.classify('ssh',wrapped('LISTEN 0 128 bad:22 0.0.0.0:*\n'))
    def test_ipv6_not_misclassified(self):
        with self.assertRaises(core.GuardError):
            core.classify('ssh',wrapped('LISTEN 0 128 [::]:22 [::]:*\n'))
    def test_invalid_role(self):
        with self.assertRaises(core.GuardError): core.classify('runner',wrapped(''))
    def test_no_service_implied_from_socket(self):
        value=core.classify('ssh',wrapped('LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'))
        self.assertFalse(value['service_identity_proven'])
        self.assertFalse(value['protocol_connection_attempted'])
