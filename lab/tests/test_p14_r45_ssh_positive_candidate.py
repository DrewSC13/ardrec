"""R45 offline deterministic candidates, negative space, protections and receipts."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import stat
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

from ardrec.coordination import r45_ssh_positive_candidate as r45

class R45OfflineTests(unittest.TestCase):
    def test_source_guard(self):
        r45.source_guard()
    def test_source_drift_blocked(self):
        with mock.patch.object(r45.r33,'DENY_FILTER','other'):
            with self.assertRaises(r45.CandidateError):r45.source_guard()
    def test_scope_constants(self):
        self.assertEqual(r45.SOURCE_IP,'10.203.30.2')
        self.assertEqual(r45.DEST_IP,'10.203.30.1')
    def test_xml_both(self):
        for b in (False,True):
            with self.subTest(runner=b):
                raw=r45.filter_candidate(runner=b)
                r45.check_filter(raw,runner=b)
    def test_xml_exact_arp(self):
        for b in (False,True):
            doc=ET.fromstring(r45.filter_candidate(runner=b))
            for rule in doc.findall('rule')[:2]:
                attrs=rule[0].attrib
                self.assertIn(attrs['arpsrcipaddr'],(r45.SOURCE_IP,r45.DEST_IP))
                self.assertIn(attrs['arpdstipaddr'],(r45.SOURCE_IP,r45.DEST_IP))
                self.assertIn(attrs['opcode'],('Request','Reply'))
    def test_xml_icmp_only(self):
        for b in (False,True):
            doc=ET.fromstring(r45.filter_candidate(runner=b))
            self.assertEqual(sorted(r[0].attrib['type'] for r in doc.findall('rule')[2:4]),['0','8'])
            self.assertTrue(all(r[0].attrib['code']=='0' for r in doc.findall('rule')[2:4]))
    def test_xml_terminal_drop(self):
        doc=ET.fromstring(r45.filter_candidate(runner=False))
        self.assertEqual(doc.findall('rule')[-1].attrib['action'],'drop')
        self.assertEqual(doc.findall('rule')[-1][0].tag,'all')
    def test_no_tcp_udp_ipv6_accept(self):
        for b in (False,True):
            root=ET.fromstring(r45.filter_candidate(runner=b))
            self.assertFalse(any(n.tag in ('tcp','udp','ipv6','icmpv6') for n in root.iter()))
    def test_icmp_schema_forbids_destination_mac_attribute(self):
        # libvirt nwfilter.rng: icmp -> srcmac-attribute, not common-l2-attributes.
        for runner in (False, True):
            root=ET.fromstring(r45.filter_candidate(runner=runner))
            for rule in root.findall('rule')[2:4]:
                self.assertEqual(rule[0].tag,'icmp')
                self.assertNotIn('dstmacaddr',rule[0].attrib)
                self.assertIn('srcmacaddr',rule[0].attrib)
                self.assertIn('srcipaddr',rule[0].attrib)
                self.assertIn('dstipaddr',rule[0].attrib)

    def test_reject_reintroduced_invalid_destination_mac(self):
        for runner in (False,True):
            root=ET.fromstring(r45.filter_candidate(runner=runner))
            root.findall('rule')[2][0].set('dstmacaddr','52:54:00:ad:30:01')
            with self.assertRaisesRegex(r45.CandidateError,'filter_protocol_attributes_invalid'):
                r45.check_filter(ET.tostring(root),runner=runner)

    def test_reject_widened_icmp_destination(self):
        for runner in (False,True):
            root=ET.fromstring(r45.filter_candidate(runner=runner))
            root.findall('rule')[3][0].set('dstipaddr','10.203.30.99')
            with self.assertRaisesRegex(r45.CandidateError,'filter_protocol_attributes_invalid'):
                r45.check_filter(ET.tostring(root),runner=runner)

    @unittest.skipUnless(shutil.which('virt-xml-validate'),
                         'host libvirt virt-xml-validate is unavailable')
    def test_generated_filters_pass_real_libvirt_schema(self):
        # No libvirt writes: validate file against host Relax-NG only.
        binary=shutil.which('virt-xml-validate')
        with tempfile.TemporaryDirectory(prefix='ardrec-r45-xml-') as directory:
            for runner in (False,True):
                with self.subTest(runner=runner):
                    path=Path(directory)/('runner.xml' if runner else 'ssh.xml')
                    path.write_bytes(r45.filter_candidate(runner=runner))
                    completed=subprocess.run([binary,str(path),'nwfilter'],
                              stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=12,check=False)
                    self.assertEqual(completed.returncode,0,
                       (completed.stdout+completed.stderr).decode('utf-8','replace'))

    def test_distinct_filters(self):
        self.assertNotEqual(r45.FILTER_RUNNER,r45.FILTER_SSH)
        self.assertNotEqual(r45.FILTER_RUNNER,r45.r33.DENY_FILTER)
    def test_domain_ssh(self):
        r45.check_domain(r45.domain_candidate(runner=False),runner=False)
    def test_domain_runner_ssh_only(self):
        root=ET.fromstring(r45.domain_candidate(runner=True))
        self.assertEqual(len(root.findall('devices/interface')),1)
        self.assertEqual(root.find('devices/interface/source').attrib['network'],r45.r33.NETWORK_PREFIX+'ssh')
    def test_domain_does_not_change_disk(self):
        orig=ET.fromstring(r45.r33.render_xml(r45.r33.R32_RECEIPT_FILE_SHA256)['domain-runner.xml'])
        candidate=ET.fromstring(r45.domain_candidate(runner=True))
        self.assertEqual(orig.find('devices/disk/source').attrib,candidate.find('devices/disk/source').attrib)
        self.assertEqual(orig.findtext('uuid'),candidate.findtext('uuid'))
    def test_nft_candidate_new_table(self):
        nft=r45.nft_candidate()
        self.assertIn(b'ardrec_r45_syntax_only',nft)
        self.assertNotIn(b'table bridge ardrec_r34_guard',nft)
    def test_nft_all_deny_fallback(self):
        nft=r45.nft_candidate()
        self.assertEqual(nft.count(b'counter accept'),4)
        self.assertEqual(nft.count(b'counter drop'),4)
    def test_nft_does_not_add_unapproved_ip(self):
        nft=r45.nft_candidate()
        for forbidden in (b'8.8.8.8',b'0.0.0.0/0',b'10.203.31.',b'10.203.32.',b'flush ruleset'):
            self.assertNotIn(forbidden,nft)
    def test_nft_preserves_other_taps_drop(self):
        nft=r45.nft_candidate()
        self.assertIn(b'a33d31r',nft)
        self.assertIn(b'a33d32t',nft)
    def test_all_files_deterministic(self):
        self.assertEqual(r45.build_files(),r45.build_files())
    def test_file_count(self):
        self.assertEqual(set(r45.build_files()),set(r45.FILES))
    def test_report_no_go(self):
        doc=json.loads(r45.build_files()['r45_candidate.json'])
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertFalse(doc['vm_started'])
        self.assertFalse(doc['existing_filter_modified'])
        self.assertFalse(doc['existing_nft_guard_modified'])
        self.assertFalse(doc['isolation_proven'])
    def test_report_source_pin(self):
        doc=json.loads(r45.build_files()['r45_candidate.json'])
        self.assertEqual(doc['source_main'],r45.BASE)
    def test_report_digests(self):
        doc=json.loads(r45.build_files()['r45_candidate.json'])
        self.assertEqual(doc['sha256'],r45.sha(r45.canon({k:v for k,v in doc.items() if k!='sha256'})))
    def test_private_write_and_verify(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p);root.chmod(0o700)
            path=root/'new'
            a=r45.prepare(path)
            b=r45.verify_directory(path)
            self.assertEqual(a,b)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o700)
    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p);root.chmod(0o700)
            r45.prepare(root/'new')
            with self.assertRaises(r45.CandidateError):r45.prepare(root/'new')
    def test_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p);root.chmod(0o700); d=root/'new'
            r45.prepare(d)
            (d/'ssh-nwfilter-candidate.xml').write_bytes(b'tampered')
            with self.assertRaises(r45.CandidateError):r45.verify_directory(d)
    def test_world_writable_parent_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p);root.chmod(0o777)
            try:
                with self.assertRaises(r45.CandidateError):r45.prepare(root/'new')
            finally:root.chmod(0o700)
    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as p:
            root=Path(p);root.chmod(0o700)
            (root/'alias').symlink_to(root,target_is_directory=True)
            with self.assertRaises(r45.CandidateError):r45.prepare(root/'alias'/'new')

if __name__=='__main__':unittest.main()
