"""R55.3 adversarial offline fixtures: all scenarios deny operational P8."""
from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from ardrec.coordination import r553_transition_guard as g

UUID='11111111-2222-4333-8444-555555555555'


def binding(role, *, candidate):
    name,tap,mac,ip,offered=g.GUESTS[role]
    root=ET.Element('filterbinding')
    owner=ET.SubElement(root,'owner')
    ET.SubElement(owner,'name').text=name
    ET.SubElement(owner,'uuid').text=UUID
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    ref=ET.SubElement(root,'filterref',{'filter':offered if candidate else g.DENY})
    ET.SubElement(ref,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'


def fixture():
    files={'nft-arp-icmp-NOT-AUTHORIZED.nft':g.expected_nft(allow=True),
           'nft-deny-restore-NOT-EXECUTED.nft':g.expected_nft(allow=False),
           'commands.json':b'[]\n'}
    for role in g.GUESTS:
        files[role+'-binding-original.xml']=binding(role,candidate=False)
        files[role+'-binding-candidate.xml']=binding(role,candidate=True)
    report={
       'schema':'ardrec-r552-f1-transition-plan-v1',
       'source_commit':g.SOURCE_HEAD,
       'r551_sha256':g.R551_SHA256,
       'd1_sha256':g.D1_SHA256,
       'status':'TRANSITION_CANDIDATES_VERIFIED_OFFLINE_ONLY',
       'bindings':{
           role:{'original_sha256':g.digest(files[role+'-binding-original.xml']),
                 'candidate_sha256':g.digest(files[role+'-binding-candidate.xml']),
                 'parameter':{'name':'MAC','value':g.GUESTS[role][2]},
                 'backend':'iptables'}
           for role in g.GUESTS
       },
       'nft_candidate_sha256':g.digest(files['nft-arp-icmp-NOT-AUTHORIZED.nft']),
       'nft_restore_sha256':g.digest(files['nft-deny-restore-NOT-EXECUTED.nft']),
       'xml_schema_validation':True,'nft_syntax_validation':True,
       'guest_traffic_generated':False,'host_mutations':0,
       'restoration_executed':False,'operational_dispatch':False,
       'p8_operational':'NO-GO',
    }
    files['plan.json']=g.canonical(report)
    return files


class TestR553Guard(unittest.TestCase):
    def setUp(self):
        self.f=fixture()

    def test_exact_candidate_has_four_allow_and_four_drop(self):
        raw=g.expected_nft(allow=True)
        self.assertEqual(raw.count(b'counter accept'),4)
        self.assertEqual(raw.count(b'counter drop'),4)
        self.assertNotIn(b'flush ruleset',raw)
        self.assertNotIn(b'10.203.31.',raw)

    def test_original_restore_is_deny_only(self):
        self.assertEqual(g.expected_nft(allow=False).count(b'counter accept'),0)
        self.assertEqual(g.expected_nft(allow=False).count(b'counter drop'),4)

    def test_valid_plan(self):
        self.assertEqual(g.verify_plan(self.f)['status'],
                         'TRANSITION_CANDIDATES_VERIFIED_OFFLINE_ONLY')

    def test_both_bindings_keep_exact_mac_parameter(self):
        for role in g.GUESTS:
            old=g.binding_identity(self.f[role+'-binding-original.xml'],role=role,candidate=False)
            new=g.binding_identity(self.f[role+'-binding-candidate.xml'],role=role,candidate=True)
            self.assertEqual(old,new)

    def mutate(self,role,which,fn):
        path=role+'-binding-'+which+'.xml'
        root=ET.fromstring(self.f[path])
        fn(root)
        self.f[path]=ET.tostring(root)
        with self.assertRaises(g.TransitionGuardError):
            g.verify_plan(self.f)

    def test_reject_extra_backend(self):
        self.mutate('ssh','original',lambda root: root.find('backend').set('name','nftables'))

    def test_reject_absent_backend(self):
        self.mutate('runner','candidate',lambda root: root.remove(root.find('backend')))

    def test_reject_mac_parameter_drift(self):
        self.mutate('ssh','candidate',lambda root: root.find('filterref/parameter').set('value','de:ad:be:ef:00:00'))

    def test_reject_ip_parameter_instead_of_mac(self):
        self.mutate('runner','original',lambda root: root.find('filterref/parameter').set('name','IP'))

    def test_reject_extra_filter_parameter(self):
        self.mutate('runner','original',lambda root: ET.SubElement(root.find('filterref'),'parameter',{'name':'IP','value':'0.0.0.0'}))

    def test_reject_wrong_owner(self):
        self.mutate('ssh','original',lambda root: setattr(root.find('owner/name'),'text','foreign-vm'))

    def test_reject_wrong_tap(self):
        self.mutate('runner','candidate',lambda root: root.find('portdev').set('name','a33d31r'))

    def test_reject_extra_xml_node(self):
        self.mutate('ssh','original',lambda root: ET.SubElement(root,'something'))

    def test_reject_restoration_with_allow(self):
        self.f['nft-deny-restore-NOT-EXECUTED.nft'] = g.expected_nft(allow=True)
        with self.assertRaisesRegex(g.TransitionGuardError,'nft_policy_not_exact'):
            g.verify_plan(self.f)

    def test_reject_candidate_tcp(self):
        self.f['nft-arp-icmp-NOT-AUTHORIZED.nft'] += b'add rule bridge ardrec_r34_guard forward tcp dport 22 accept\n'
        with self.assertRaisesRegex(g.TransitionGuardError,'nft_policy_not_exact'):
            g.verify_plan(self.f)

    def test_reject_generic_flush(self):
        self.f['nft-arp-icmp-NOT-AUTHORIZED.nft'] = b'flush ruleset\n'
        with self.assertRaisesRegex(g.TransitionGuardError,'nft_policy_not_exact'):
            g.verify_plan(self.f)

    def test_reject_false_operational_authority(self):
        report=g.parse_json(self.f['plan.json'])
        report['operational_dispatch']=True
        self.f['plan.json']=g.canonical(report)
        with self.assertRaisesRegex(g.TransitionGuardError,'plan_semantics_invalid'):
            g.verify_plan(self.f)

    def test_reject_p8_go(self):
        report=g.parse_json(self.f['plan.json'])
        report['p8_operational']='GO'
        self.f['plan.json']=g.canonical(report)
        with self.assertRaisesRegex(g.TransitionGuardError,'plan_semantics_invalid'):
            g.verify_plan(self.f)

    def test_gate_fails_without_independent_watchdog(self):
        with self.assertRaisesRegex(g.TransitionGuardError,'independent_watchdog_missing'):
            g.simulate(gate_verified=False)

    def test_only_model_can_simulate_with_watchdog(self):
        report=g.simulate(gate_verified=True)
        self.assertEqual(report['status'],'DRY_RUN_COMPLETE_NO_GO')
        self.assertFalse(report['physical_write'])
        self.assertFalse(report['restoration_tested'])

    def test_injected_faults_always_no_go(self):
        for fault in g.STAGES:
            with self.subTest(fault=fault):
                report=g.simulate(gate_verified=True,fault_at=fault)
                self.assertEqual(report['status'],'REVIEW_REQUIRED_NO_GO')
                self.assertFalse(report['physical_write'])
                self.assertEqual(report['p8_operational'],'NO-GO')

    def test_bad_fault_label_fails_closed(self):
        with self.assertRaises(g.TransitionGuardError):
            g.simulate(gate_verified=True,fault_at='ALLOW_EVERYTHING')

    def test_report_requires_physical_recovery(self):
        report=g.plan_contract(self.f)
        self.assertFalse(report['watchdog_armed'])
        self.assertFalse(report['physical_rollback_tested'])
        self.assertIn('independent_verified_watchdog_or_kernel_expiry',
                      report['mandatory_for_physical_operation'])

    def create_private(self, path):
        path.mkdir(mode=0o700)
        self.f['SHA256SUMS'] = ''.join(
            f'{g.digest(raw)}  {name}\n' for name,raw in sorted(self.f.items())
        ).encode('ascii')
        for filename,raw in self.f.items():
            p=path/filename
            p.write_bytes(raw)
            p.chmod(0o600)

    def test_receipt_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'r552-test'
            self.create_private(path)
            with patch.object(g,'PLAN_SHA256',g.digest(self.f['plan.json'])):
                files=g.verify_private_receipt(path)
                self.assertEqual(files['plan.json'],self.f['plan.json'])

    def test_receipt_tamper_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'r552-test'
            self.create_private(path)
            (path/'ssh-binding-original.xml').write_bytes(b'INVALID')
            with patch.object(g,'PLAN_SHA256',g.digest(self.f['plan.json'])):
                with self.assertRaises(g.TransitionGuardError):
                    g.verify_private_receipt(path)

    def test_receipt_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'r552-test'
            self.create_private(path)
            p=path/'ssh-binding-original.xml'
            p.unlink()
            p.symlink_to(path/'ssh-binding-candidate.xml')
            with patch.object(g,'PLAN_SHA256',g.digest(self.f['plan.json'])):
                with self.assertRaises(g.TransitionGuardError):
                    g.verify_private_receipt(path)

    def test_duplicate_json_keys_refused(self):
        with self.assertRaisesRegex(g.TransitionGuardError,'duplicate_json_key'):
            g.parse_json(b'{"a":1,"a":2}')


if __name__ == '__main__':
    unittest.main()
