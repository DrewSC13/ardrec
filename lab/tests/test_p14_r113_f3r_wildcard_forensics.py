"""R113-F3R: formatos ss IPv4 y captura previa a clasificación; sin QGA."""
import base64
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT / 'src'))
from ardrec.coordination import r113_f3_guest_listeners as core

SCRIPT = ROOT / 'scripts/ardrec_p14_r113_f3_guest_listeners.py'

def sample(role, text):
    return core.classify(role, {
        'pid':101, 'status':0, 'command':['/usr/bin/ss','-H','-ltn4'],
        'stdout_b64':base64.b64encode(text.encode('utf-8')).decode('ascii'),
        'stderr_b64':''})

class WildcardForensicsTests(unittest.TestCase):
    def test_ssh_ipv4_wildcard_star(self):
        self.assertEqual(sample('ssh','LISTEN 0 128 *:22 *:*\n')['local_listener_state'],
                         'LISTENING_ON_LAB_IPV4')
    def test_ftp_ipv4_wildcard_star(self):
        self.assertEqual(sample('ftp','LISTEN 0 128 *:21 *:*\n')['local_listener_state'],
                         'LISTENING_ON_LAB_IPV4')
    def test_smb_ipv4_wildcard_star(self):
        self.assertEqual(sample('smb','LISTEN 0 128 *:445 *:*\n')['local_listener_state'],
                         'LISTENING_ON_LAB_IPV4')
    def test_star_normalized_as_ipv4_wildcard(self):
        self.assertEqual(core.listening_sockets(b'LISTEN 0 128 *:22 *:*\n')[0]['address'],
                         '0.0.0.0')
    def test_known_ip_still_valid(self):
        self.assertEqual(sample('ssh','LISTEN 0 128 10.203.30.2:22 0.0.0.0:*\n')['local_listener_state'],
                         'LISTENING_ON_LAB_IPV4')
    def test_loopback_not_lab_listener(self):
        self.assertEqual(sample('ssh','LISTEN 0 128 127.0.0.1:22 *:*\n')['local_listener_state'],
                         'LISTENING_ONLY_ON_OTHER_IPV4')
    def test_ipv6_wildcard_rejected(self):
        with self.assertRaises(core.GuardError):
            sample('ssh','LISTEN 0 128 [::]:22 [::]:*\n')
    def test_scope_suffix_rejected(self):
        with self.assertRaises(core.GuardError):
            sample('ssh','LISTEN 0 128 *%ens3:22 *:*\n')
    def test_garbage_not_accepted(self):
        with self.assertRaises(core.GuardError):
            sample('ssh','LISTEN 0 128 any:22 *:*\n')
    def test_no_service_reachability_claim(self):
        value=sample('ssh','LISTEN 0 128 *:22 *:*\n')
        self.assertFalse(value['network_reachability_proven'])
        self.assertFalse(value['service_identity_proven'])
    def test_capture_written_before_classify(self):
        raw=SCRIPT.read_text()
        self.assertLess(raw.index("put(folder/('capture-'+role+'.json')"),
                        raw.index('status=core.classify(role,result)'))
    def test_incident_preserved_and_linked(self):
        raw=SCRIPT.read_text()
        self.assertIn("INCIDENT = ROOT / 'inspect-gccubwyi'",raw)
        self.assertIn('previous_incident_fingerprint',raw)
        self.assertNotIn("rmtree(",raw)
        self.assertNotIn("virsh destroy",raw)
    def test_reply_replay_validation(self):
        raw=SCRIPT.read_text()
        self.assertIn("CAPTURE_RESULT_DRIFT_",raw)
        self.assertIn("CAPTURE_PID_DRIFT_",raw)
        self.assertIn("PREVIOUS_INCIDENT_FILE_SCOPE_DRIFT",raw)
