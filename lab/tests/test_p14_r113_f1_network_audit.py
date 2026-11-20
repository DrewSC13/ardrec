"""R113-F1: controles unitarios, no acreditan observaciones del laboratorio."""
import json
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.coordination import r113_f1_network_audit as m


def capture(text='', rc=0):
    return {'rc': rc, 'stdout': text, 'stderr': '', 'timeout': False,
            'truncated': False}


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.mac = {'ssh': '52:54:00:ab:00:01', 'ftp': '52:54:00:ab:00:02',
                    'smb': '52:54:00:ab:00:03'}
        self.snapshot = {'snapshot': {'summary': {'domain_inventory': {
            role: {'interfaces': [
                {'network': 'ardrec-r33-dev-net-'+network,
                 'mac': self.mac[network]}
                for network in (m.NETWORKS if role == 'runner' else (role,))
            ]} for role in m.ROLES
        }}}}
        self.guest = {
            role: {'live_xml': capture('<domain/>'),
                   'agent': capture('''Name MAC address Protocol Address
vnet1 52:54:00:ab:00:01 ipv4 10.33.0.10/24
vnet2 52:54:00:ab:00:02 ipv4 10.33.1.10/24
vnet3 52:54:00:ab:00:03 ipv4 10.33.2.10/24'''),
                   'domiflist': capture('interfaces')}
            for role in m.ROLES
        }
        self.bridges = {
            role: {'link': capture(json.dumps([{'ifname': bridge}])),
                   'addresses': capture('[]')}
            for role,bridge in m.BRIDGES.items()
        }
        self.called = []
        self.f10 = SimpleNamespace(audited=lambda *a,**kw:self.called.append('audit'))
        self.nic = SimpleNamespace(validate_domain=lambda *a:self.called.append('nic'))
        self.f9 = SimpleNamespace(live_runner=lambda *a:self.called.append('runner'))

    def classify(self):
        return m.classify_live(self.snapshot,self.guest,self.bridges,
            f10=self.f10, legacy=object(),f4=object(),nic=self.nic,f9=self.f9)

    def test_four_guests_three_bridges(self):
        result = self.classify()
        self.assertEqual(set(result['guest_states']), set(m.ROLES))
        self.assertEqual(set(result['networks']), set(m.NETWORKS))
        self.assertEqual(self.called.count('audit'),1)
        self.assertEqual(self.called.count('runner'),1)
        self.assertEqual(self.called.count('nic'),3)

    def test_ip_candidates_are_informational(self):
        result = self.classify()
        self.assertEqual(result['agent_ip_discovery'],'CANDIDATES_AVAILABLE')
        self.assertEqual(result['traffic_authorized'],False)
        self.assertEqual(result['protocol_connections'],0)
        self.assertEqual(result['p8_operational'],'NO-GO')

    def test_agent_unavailable_does_not_invent_ip(self):
        self.guest['ftp']['agent']=capture('',rc=1)
        result = self.classify()
        self.assertEqual(result['agent_ip_discovery'],'INCOMPLETE')
        self.assertEqual(result['guest_network_inventory']['ftp']['agent_ipv4_ipv6_candidates'],{'ftp':[]})

    def test_missing_bridge_denied(self):
        del self.bridges['ftp']
        with self.assertRaisesRegex(ValueError,'BRIDGE_INVENTORY_SCOPE'):
            self.classify()

    def test_renamed_bridge_denied(self):
        self.bridges['smb']['link']=capture('[{"ifname":"virbr0"}]')
        with self.assertRaisesRegex(ValueError,'BRIDGE_IFNAME_CHANGED_smb'):
            self.classify()

    def test_live_xml_failed_denied(self):
        self.guest['ssh']['live_xml']=capture(rc=1)
        with self.assertRaisesRegex(ValueError,'LIVE_XML_UNAVAILABLE_ssh'):
            self.classify()

    def test_inventory_interface_removed_denied(self):
        self.snapshot['snapshot']['summary']['domain_inventory']['runner']['interfaces'].pop()
        with self.assertRaisesRegex(ValueError,'INTERFACE_COUNT_CHANGED_runner'):
            self.classify()

    def test_agent_mac_not_matching_excluded(self):
        parsed=m.agent_addresses('tapx 52:54:00:ff:ff:ff ipv4 10.0.0.3/24',
                                 {'ssh':self.mac['ssh']})
        self.assertEqual(parsed,{'ssh':[]})

    def test_agent_public_and_loopback_excluded(self):
        mac=self.mac['ssh']
        lines='\n'.join(f'tapx {mac} ipv4 {ip}' for ip in
                        ('8.8.8.8/24','127.0.0.1/8','169.254.1.1/16'))
        self.assertEqual(m.agent_addresses(lines,{'ssh':mac}),{'ssh':[]})

    def test_agent_duplicate_address_deduplicated(self):
        line=f'tapx {self.mac["ssh"]} ipv4 10.33.0.10/24'
        self.assertEqual(m.agent_addresses(line+'\n'+line,{'ssh':self.mac['ssh']}),
                         {'ssh':['10.33.0.10/24']})

    def test_agent_wrong_ip_family_rejected(self):
        line=f'tapx {self.mac["ssh"]} ipv6 10.33.0.10/24'
        self.assertEqual(m.agent_addresses(line,{'ssh':self.mac['ssh']}),{'ssh':[]})

    def test_agent_oversized_rejected(self):
        with self.assertRaisesRegex(ValueError,'AGENT_OUTPUT_INVALID'):
            m.agent_addresses('a'*30000,{'ssh':self.mac['ssh']})

    def test_capture_timeout_rejected(self):
        x=capture('<xml/>'); x['timeout']=True
        self.assertFalse(m.valid_capture(x))

if __name__=='__main__': unittest.main()
