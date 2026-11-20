"""R113-F8R: immutable ARP Relax NG correction contract and forensic provenance."""
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r113_f8r_arp_correction as fixed
from ardrec.coordination import r113_f8_window_policy as old

ROLES=tuple(old.f6.ROLES)


def sources():
    original={old.filter_name(r)+'.xml':old.filter_xml(r) for r in ROLES}
    original['r34-window-CANDIDATE.nft']=old.nft_script()
    meta={'schema':old.SCHEMA,'policy_not_deployed':True,'window_not_opened':True,
          'p8':'NO-GO','f5_manifest_sha256':old.f6.F5_DIGEST,
          'f7e_manifest_sha256':old.F7E_MANIFEST_SHA256,
          'sha256':{k:old.sha(v) for k,v in original.items()}}
    original['manifest.json']=old.canonical(meta)
    report={'schema':'ARDREC-R113-F9-HOST-CHECK-v1','outcome':'BLOCKED_FIX_POLICY',
            'nft_check_only':True,'libvirt_schema_only':True,
            'network_probes':0,'protocol_connections':0,'p8':'NO-GO',
            'f8_manifest_sha256':old.sha(original['manifest.json']),
            'candidate_files_sha256':meta['sha256'],
            'queries': {'nft_check':{'rc':0},'f6_before':{'rc':0},'f6_after':{'rc':0},
                        **{'xml_'+r.replace('-','_'):{'rc':3} for r in
                           ('runner-ssh','ssh','runner-ftp','ftp','runner-smb','smb')}}}
    return original,old.canonical(report)


class F8RContract(unittest.TestCase):
    def test_01_six_roles(self):self.assertEqual(len(ROLES),6)
    def test_02_all_six_correct(self):
        for role in ROLES:self.assertTrue(fixed.check_fixed_xml(fixed.fixed_xml(role),role))
    def test_03_arp_correct_fields(self):
        for role in ROLES:
            root=ET.fromstring(fixed.fixed_xml(role))
            for rule in root[:2]:
                self.assertEqual(set(rule[0].attrib),
                                 {'srcmacaddr','arpsrcipaddr','arpdstipaddr'})
    def test_04_twelve_fixed(self):
        self.assertEqual(sum(fixed.fixed_xml(r).count(b'arpsrcipaddr=') for r in ROLES),12)
    def test_05_exact_old_mac_preserved(self):
        for role in ROLES:
            a=ET.fromstring(old.filter_xml(role));b=ET.fromstring(fixed.fixed_xml(role))
            for i in range(2):self.assertEqual(a[i][0].get('srcmacaddr'),b[i][0].get('srcmacaddr'))
    def test_06_tcp_bytes_effective_unchanged(self):
        for role in ROLES:
            a=ET.fromstring(old.filter_xml(role));b=ET.fromstring(fixed.fixed_xml(role))
            for i in (2,3,4):self.assertEqual(ET.tostring(a[i]),ET.tostring(b[i]))
    def test_07_old_plan_is_immutable(self):
        for role in ROLES:
            original=old.filter_xml(role)
            fixed.fixed_xml(role,original)
            self.assertEqual(original,old.filter_xml(role))
    def test_08_no_new_accept(self):
        for role in ROLES:
            oldrules=ET.fromstring(old.filter_xml(role))
            newrules=ET.fromstring(fixed.fixed_xml(role))
            self.assertEqual([r.attrib for r in oldrules],[r.attrib for r in newrules])
    def test_09_bad_extra_allow_rejected(self):
        x=fixed.fixed_xml('ssh').replace(b'</filter>',
             b'<rule action="accept" direction="in"><ip/></rule></filter>')
        with self.assertRaises(old.PolicyError):fixed.check_fixed_xml(x,'ssh')
    def test_10_invalid_arp_field_rejected(self):
        x=fixed.fixed_xml('ssh').replace(b'arpsrcipaddr',b'srcipaddr')
        with self.assertRaises(old.PolicyError):fixed.check_fixed_xml(x,'ssh')
    def test_11_cross_role_rejected(self):
        with self.assertRaises(old.PolicyError):
            fixed.check_fixed_xml(fixed.fixed_xml('ftp'),'runner_ftp')
    def test_12_old_xml_rejected_for_new_policy(self):
        with self.assertRaises(old.PolicyError):fixed.check_fixed_xml(old.filter_xml('ssh'),'ssh')
    def test_13_original_nft_unchanged(self):
        oldplan,report=sources()
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            policy=fixed.prepare(oldplan,report)
        self.assertEqual(policy['r34-window-CANDIDATE.nft'],oldplan['r34-window-CANDIDATE.nft'])
    def test_14_manifest_exact_file_hashes(self):
        oldplan,report=sources()
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            policy=fixed.prepare(oldplan,report)
        meta=json.loads(policy['manifest.json'])
        self.assertEqual(set(meta['sha256']),set(policy)-{'manifest.json'})
        for name,sha in meta['sha256'].items():self.assertEqual(sha,old.sha(policy[name]))
    def test_15_manifest_forensic_links(self):
        oldplan,report=sources()
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            meta=json.loads(fixed.prepare(oldplan,report)['manifest.json'])
        self.assertEqual(meta['original_f8_manifest_sha256'],old.sha(oldplan['manifest.json']))
        self.assertEqual(meta['rejected_f9_report_sha256'],old.sha(report))
    def test_16_original_f8_tamper_rejected(self):
        oldplan,report=sources()
        oldplan[old.filter_name('ssh')+'.xml']=b'BAD'
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            with self.assertRaises(old.PolicyError):fixed.prepare(oldplan,report)
    def test_17_f9_report_tamper_rejected(self):
        oldplan,report=sources()
        with self.assertRaises(old.PolicyError):fixed.prepare(oldplan,report+b' ')
    def test_18_f9_success_misreported_rejected(self):
        oldplan,report=sources()
        doc=json.loads(report);doc['outcome']='PASS_READONLY_HOST_ACCEPTANCE'
        report=old.canonical(doc)
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            with self.assertRaises(old.PolicyError):fixed.prepare(oldplan,report)
    def test_19_zero_host_commands(self):
        raw=inspect.getsource(fixed)
        for prohibited in ('subprocess.run','systemd-run','virsh','qemu-agent-command',
                           'nft -f', 'nwfilter-define'):
            self.assertNotIn(prohibited,raw)
    def test_20_offline_safety_flags(self):
        oldplan,report=sources()
        with patch.object(fixed,'F9_REPORT_SHA',old.sha(report)):
            meta=json.loads(fixed.prepare(oldplan,report)['manifest.json'])
        self.assertEqual(meta['safety'],{'policy_installed':False,'traffic_admitted':False,'p8':'NO-GO'})

if __name__=='__main__':unittest.main()
