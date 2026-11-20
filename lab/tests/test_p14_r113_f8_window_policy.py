"""F8 offline policy contract: never imports live-connection modules or runs host commands."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r113_f8_window_policy as g
from ardrec.coordination import r113_f6_six_binding_guard as f6

class F8Contract(unittest.TestCase):
    def test_three_pairs(self):self.assertEqual(set(g.PAIRS),{'ssh','ftp','smb'})
    def test_six_roles(self):self.assertEqual(len(f6.ROLES),6)
    def test_exact_targets(self):
        self.assertEqual([(g.PAIRS[k][-2],g.PAIRS[k][-1]) for k in ('ssh','ftp','smb')],
                         [('10.203.30.2',22),('10.203.31.2',21),('10.203.32.2',445)])
    def test_unique_nics(self):
        names=[item for pair in g.PAIRS.values() for item in pair[:2]]
        self.assertEqual(len(names),len(set(names)))
    def test_unique_ips(self):
        names=[item for pair in g.PAIRS.values() for item in pair[4:6]]
        self.assertEqual(len(names),len(set(names)))
    def test_role_names_match_f6(self):
        self.assertEqual(set(g.filter_name(k) for k in f6.ROLES),{
            'ardrec-r113-'+k.replace('_','-')+'-tcp-v1' for k in f6.ROLES})
    def test_xml_all_six_valid(self):
        for key in f6.ROLES:self.assertTrue(g.validate_filter(g.filter_xml(key),key))
    def test_xml_each_has_two_arp_two_tcp_one_drop(self):
        for key in f6.ROLES:
            children=list(ET.fromstring(g.filter_xml(key)))
            self.assertEqual([c[0].tag for c in children],['arp','arp','tcp','tcp','all'])
    def test_xml_no_ipv6_or_related(self):
        for key in f6.ROLES:
            raw=g.filter_xml(key)
            self.assertNotIn(b'ipv6',raw.lower());self.assertNotIn(b'RELATED',raw)
    def test_xml_no_ftp_data(self):
        for key in ('runner_ftp','ftp'):
            raw=g.filter_xml(key)
            self.assertNotIn(b"'20'",raw)
    def test_xml_source_mac_pinned(self):
        for key,(_,network,_,mac) in f6.ROLES.items():
            root=ET.fromstring(g.filter_xml(key))
            self.assertEqual(root[0][0].get('srcmacaddr'),mac)
    def test_runner_initiation_only(self):
        for key in ('runner_ssh','runner_ftp','runner_smb'):
            rules=list(ET.fromstring(g.filter_xml(key)))
            self.assertEqual(rules[2].get('direction'),'out')
            self.assertEqual(rules[2][0].get('state'),'NEW,ESTABLISHED')
            self.assertEqual(rules[3].get('direction'),'in')
            self.assertEqual(rules[3][0].get('state'),'ESTABLISHED')
    def test_target_return_only(self):
        for key in ('ssh','ftp','smb'):
            rules=list(ET.fromstring(g.filter_xml(key)))
            self.assertEqual(rules[2].get('direction'),'in')
            self.assertEqual(rules[3].get('direction'),'out')
            self.assertEqual(rules[3][0].get('state'),'ESTABLISHED')
    def test_xml_final_drop(self):
        for key in f6.ROLES:
            root=ET.fromstring(g.filter_xml(key))
            self.assertEqual(root[-1].attrib['action'],'drop')
            self.assertEqual(root[-1].attrib['direction'],'inout')
    def test_xml_ip_tamper_rejected(self):
        raw=g.filter_xml('ssh').replace(b'10.203.30.2',b'10.203.30.3')
        with self.assertRaises(g.PolicyError):g.validate_filter(raw,'ssh')
    def test_xml_extra_allow_rejected(self):
        raw=g.filter_xml('ftp').replace(b'</filter>',b"<rule action='accept' direction='out'><ip/></rule></filter>")
        with self.assertRaises(g.PolicyError):g.validate_filter(raw,'ftp')
    def test_xml_wrong_role_rejected(self):
        with self.assertRaises(g.PolicyError):g.validate_filter(g.filter_xml('smb'),'runner_smb')
    def test_xml_entity_rejected(self):
        with self.assertRaises(g.PolicyError):g.validate_filter(b'<!ENTITY poison "yes">','ssh')
    def test_nft_12_accepts_4_drops(self):
        raw=g.nft_script()
        self.assertEqual(raw.count(b'counter accept'),12)
        self.assertEqual(raw.count(b'counter drop'),4)
    def test_nft_only_forward_accept(self):
        rows=g.nft_script().decode().splitlines()
        for line in rows:
            if 'counter accept' in line:self.assertIn(' forward ',line)
    def test_nft_denies_host(self):
        lines=g.nft_script().decode().splitlines()
        self.assertTrue(any(' input iifname {' in x and x.endswith('counter drop') for x in lines))
        self.assertTrue(any(' output oifname {' in x and x.endswith('counter drop') for x in lines))
    def test_nft_no_global_flush(self):self.assertNotIn(b'flush ruleset',g.nft_script())
    def test_nft_no_dns_or_icmp(self):
        raw=g.nft_script()
        self.assertNotIn(b'udp',raw);self.assertNotIn(b'icmp',raw)
    def test_nft_replays_deterministically(self):self.assertEqual(g.nft_script(),g.nft_script())
    def test_closure_sha_pin(self):self.assertEqual(len(g.F7E_MANIFEST_SHA256),64)
    def test_no_guest_exec(self):
        import inspect
        raw=inspect.getsource(g)
        self.assertNotIn('qemu-agent-command',raw)
        self.assertNotIn('guest-exec',raw)
    def test_no_live_host_calls(self):
        import inspect
        raw=inspect.getsource(g)
        self.assertNotIn('subprocess.run',raw)
        self.assertNotIn('systemd-run',raw)
    @staticmethod
    def fake_closure():
        return g.canonical({
            'schema':'ARDREC-R113-F7E-HISTORICAL-FORENSIC-CLOSURE-v1',
            'f7_physical_recovery_reconciled':True,
            'f7_original_replay_completed':False,
            'six_binding_deny_after':'SIX_BINDING_DENY_ATTESTED',
            'network_traffic_authorized':False,
        })
    def test_prepare_f8_with_authenticated_inputs(self):
        closure=self.fake_closure()
        with patch.object(f6,'check_f5',return_value=True), patch.object(g,'F7E_MANIFEST_SHA256',g.sha(closure)):
            result=g.prepare({},closure)
        self.assertEqual(len(result),8)
        self.assertEqual(result['r34-window-CANDIDATE.nft'],g.nft_script())
        self.assertTrue(json.loads(result['manifest.json'])['policy_not_deployed'])
    def test_prepare_deterministic(self):
        closure=self.fake_closure()
        with patch.object(f6,'check_f5',return_value=True), patch.object(g,'F7E_MANIFEST_SHA256',g.sha(closure)):
            self.assertEqual(g.prepare({},closure),g.prepare({},closure))
    def test_manifest_sha256_all_policy_files(self):
        closure=self.fake_closure()
        with patch.object(f6,'check_f5',return_value=True), patch.object(g,'F7E_MANIFEST_SHA256',g.sha(closure)):
            result=g.prepare({},closure)
        doc=json.loads(result['manifest.json'])
        self.assertEqual(set(doc['sha256']),set(result)-{'manifest.json'})
        for key,digest in doc['sha256'].items():self.assertEqual(g.sha(result[key]),digest)
    def test_closure_change_rejected(self):
        closure=self.fake_closure()
        with patch.object(f6,'check_f5',return_value=True):
            with self.assertRaises(g.PolicyError):g.prepare({},closure)
    def test_prepare_never_marks_live(self):
        closure=self.fake_closure()
        with patch.object(f6,'check_f5',return_value=True), patch.object(g,'F7E_MANIFEST_SHA256',g.sha(closure)):
            doc=json.loads(g.prepare({},closure)['manifest.json'])
        self.assertTrue(doc['window_not_opened']);self.assertEqual(doc['protocol_connections'],0)
    def test_prepare_rejects_bad_closure(self):
        with self.assertRaises((g.PolicyError,f6.GuardError)):
            g.prepare({},b'{}')
    def test_prepare_rejects_missing_source(self):
        with patch.object(f6,'check_f5',return_value=True):
            with self.assertRaises(g.PolicyError):g.prepare({},b'{}')

if __name__=='__main__':unittest.main()
