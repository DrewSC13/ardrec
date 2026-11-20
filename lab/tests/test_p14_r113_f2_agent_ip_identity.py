"""R113-F2 pruebas de identidad real, sin interacción física con las VM."""
from __future__ import annotations
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r113_f2_agent_ip_identity as core


def example():
    return {
        'agent_ip_discovery': 'CANDIDATES_AVAILABLE',
        'R34': 'DENY_PRESERVED',
        'F11': 'HOOK_AND_FILTER_VERIFIED',
        'traffic_authorized': False, 'protocol_connections': 0,
        'p8_operational': 'NO-GO',
        'guest_states': dict.fromkeys(core.EXPECTED, 'RUNNING'),
        'networks': dict.fromkeys(core.BRIDGES, 'ACTIVE_DENY'),
        'guest_network_inventory': {
            role: {
                'agent_rc': 0, 'agent_verified_available': True,
                'interfaces': [{'network': 'ardrec-r33-dev-net-'+net,'mac':mac}
                               for net,(mac,_) in targets.items()],
                'agent_ipv4_ipv6_candidates': {net:[cidr]
                             for net,(_,cidr) in targets.items()},
            } for role,targets in core.EXPECTED.items()
        },
    }

class IdentityTests(unittest.TestCase):
    def setUp(self): self.item = example()
    def require_failure(self, keyword):
        with self.assertRaisesRegex(core.IdentityError, keyword):
            core.verify_classification(self.item)
    def test_real_exact_topology(self):
        result = core.verify_classification(self.item)
        self.assertEqual(result['verified_interface_count'],6)
        self.assertEqual(result['verified_network_count'],3)
        self.assertEqual(result['endpoints']['runner']['smb']['ipv4_cidr'],'10.203.32.1/28')
        self.assertFalse(result['services_tested'])
        self.assertFalse(result['traffic_authorized'])
    def test_ip_drift_denied(self):
        self.item['guest_network_inventory']['ftp']['agent_ipv4_ipv6_candidates']['ftp']=['10.203.31.3/28']
        self.require_failure('IP_NOT_EXACT_ftp_ftp')
    def test_extra_ip_denied(self):
        self.item['guest_network_inventory']['ssh']['agent_ipv4_ipv6_candidates']['ssh'].append('10.203.30.3/28')
        self.require_failure('IP_NOT_EXACT_ssh_ssh')
    def test_mac_drift_denied(self):
        self.item['guest_network_inventory']['runner']['interfaces'][1]['mac']='52:54:00:ff:ff:ff'
        self.require_failure('NIC_MAC_DRIFT_runner_ftp')
    def test_nic_missing_denied(self):
        self.item['guest_network_inventory']['runner']['interfaces'].pop()
        self.require_failure('NIC_COUNT_DRIFT_runner')
    def test_unrelated_network_denied(self):
        self.item['guest_network_inventory']['runner']['interfaces'][1]['network']='virbr0'
        self.require_failure('NIC_NETWORK_UNRECOGNIZED_runner')
    def test_agent_readonly_error_denied(self):
        self.item['guest_network_inventory']['smb']['agent_rc']=1
        self.require_failure('AGENT_RESULT_INVALID_smb')
    def test_incomplete_agent_denied(self):
        self.item['agent_ip_discovery']='INCOMPLETE'
        self.require_failure('AGENT_NOT_AVAILABLE')
    def test_r34_drift_denied(self):
        self.item['R34']='UNKNOWN'
        self.require_failure('R34_NOT_DENY')
    def test_p8_fraud_denied(self):
        self.item['p8_operational']='GO'
        self.require_failure('P8_NOT_NO_GO')
    def test_traffic_claim_denied(self):
        self.item['traffic_authorized']=True
        self.require_failure('TRAFFIC_STATUS_DRIFT')
    def test_guest_state_drift_denied(self):
        self.item['guest_states']['runner']='SHUTOFF'
        self.require_failure('GUEST_STATES_DRIFT')
    def test_unknown_guest_denied(self):
        self.item['guest_network_inventory']['rogue']={}
        self.require_failure('GUEST_SCOPE_CHANGED')
    def test_bridge_absence_denied(self):
        del self.item['networks']['ftp']
        self.require_failure('NETWORK_STATES_DRIFT')
    def test_invalid_classification_denied(self):
        self.item=[]
        self.require_failure('CLASSIFICATION_NOT_OBJECT')

if __name__=='__main__': unittest.main()

class SourceSafetyTests(unittest.TestCase):
    def test_agent_query_uses_standard_connection_only(self):
        source = (ROOT/'scripts/ardrec_p14_r113_f1_network_audit.py').read_text()
        self.assertIn("'agent': cmd('virsh', '-c', 'qemu:///system', 'domifaddr', name, '--source', 'agent', timeout=12)",source)
        self.assertNotIn("'agent': cmd(*common, 'domifaddr'",source)
    def test_other_libvirt_reads_still_readonly(self):
        source = (ROOT/'scripts/ardrec_p14_r113_f1_network_audit.py').read_text()
        self.assertIn("common = ('virsh', '--readonly', '-c', 'qemu:///system')",source)
        self.assertIn("'live_xml': cmd(*common, 'dumpxml', name)",source)
        self.assertIn("'domiflist': cmd(*common, 'domiflist', name)",source)
        self.assertNotIn('virsh start',source)
