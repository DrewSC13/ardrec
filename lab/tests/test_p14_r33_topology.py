"""R33 isolated tests, including source receipt and filesystem behavior."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r33_offline_topology as t


def fixture_r32():
    data={
        'schema':t.SOURCE_SCHEMA,'mode':'EXPLICIT_STORAGE_STAGING',
        'host':'Prometheus','stage_directory':t.R32_STAGE,
        'stage_status':'FOUR_NEW_COW_OVERLAYS_VERIFIED_NOT_STARTED',
        'new_overlays_created':4,'storage_prepared':True,
        'stage_directory_created':True,'failure_code':None,
        'source_images_mutated':False,'source_r31_file_sha256':'a'*64,
        'source_r31_report_sha256':'b'*64,
        'p8_operational':'NO-GO','experimental_validation':'NOT_RUN',
        'final_risk':None,'published_generation':None,
        'vm_started':False,'network_created':False,'guest_checked':False,
        'operational_dispatch':False,'can_restore':False,
        'restoration_performed':False,'technical_truth_accredited':False,
        'roles':[],'new_assets':[],
    }
    for role in t.ROLES:
        path=f'{t.R32_STAGE}/{role}-runtime.qcow2'
        parent=f'{t.PARENT_ROOT}/{role}-runtime.qcow2'
        size=t.RESOURCE[role]['disk_gib'] * 1024**3
        data['roles'].append({'role':role,'new_overlay':path,'parent_overlay':parent,
            'source_base':f'{t.BASE_ROOT}/{role}-base.qcow2',
            'virtual_size':size,'parent_overlay_sha256':'c'*64,
            'source_base_sha256':'d'*64})
        data['new_assets'].append({'role':role,'path':path,
            'backing_filename':parent,'virtual_size':size,'sha256':'e'*64})
    sign(data)
    return data


def sign(data):
    data['sha256']=t.digest(t.canon({k:v for k,v in data.items() if k!='sha256'}))


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.src=fixture_r32()

    def test_synthetic_receipt_contract(self):
        self.assertTrue(t.verify_r32(self.src))

    def test_source_mutation_digest_failure(self):
        self.src['new_overlays_created']=3
        with self.assertRaisesRegex(t.TopologyError,'digest'):
            t.verify_r32(self.src)

    def test_rehashed_source_authority_rejected(self):
        self.src['p8_operational']='GO';sign(self.src)
        with self.assertRaisesRegex(t.TopologyError,'false_authority'):
            t.verify_r32(self.src)

    def test_incomplete_staging_rejected(self):
        self.src['storage_prepared']=False;sign(self.src)
        with self.assertRaises(t.TopologyError):
            t.verify_r32(self.src)

    def test_role_mismatch_rejected(self):
        self.src['new_assets'][2]['role']='other';sign(self.src)
        with self.assertRaises(t.TopologyError):
            t.verify_r32(self.src)

    def test_foreign_disk_rejected(self):
        self.src['new_assets'][0]['path']='/tmp/ssh-runtime.qcow2';sign(self.src)
        with self.assertRaises(t.TopologyError):
            t.verify_r32(self.src)

    def test_wrong_backing_rejected(self):
        self.src['new_assets'][1]['backing_filename']='/tmp/ftp.qcow2';sign(self.src)
        with self.assertRaises(t.TopologyError):
            t.verify_r32(self.src)

    def test_duplicate_source_key_rejected(self):
        with self.assertRaises(t.TopologyError):
            t._unique_pairs([('x',1),('x',2)])

    def test_only_pinned_source_file_sha_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            f=Path(directory)/'r32_staging.json'
            f.write_bytes(t.canon(self.src)+b'\n');f.chmod(0o600)
            with self.assertRaisesRegex(t.TopologyError,'source_hash_pin'):
                t.read_r32(f,'0'*64)

    def test_actual_source_file_hash_binding_simulation(self):
        with tempfile.TemporaryDirectory() as directory:
            f=Path(directory)/'r32_staging.json'
            f.write_bytes(t.canon(self.src)+b'\n');f.chmod(0o600)
            sha=t.digest(f.read_bytes())
            with mock.patch.object(t,'R32_RECEIPT_FILE_SHA256',sha):
                doc,got=t.read_r32(f,sha)
                self.assertEqual(doc,self.src)
                self.assertEqual(got,sha)

    def test_symlink_source_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            f=Path(directory)/'real'
            f.write_bytes(t.canon(self.src)+b'\n');f.chmod(0o600)
            link=Path(directory)/'r32_staging.json';link.symlink_to(f)
            sha=t.digest(f.read_bytes())
            with mock.patch.object(t,'R32_RECEIPT_FILE_SHA256',sha):
                with self.assertRaises(t.TopologyError):
                    t.read_r32(link,sha)

    def test_generate_exact_seven_xml(self):
        files=t.render_xml('b'*64)
        self.assertEqual(len(files),7)
        self.assertEqual(set(files),{*(f'network-{x}.xml' for x in ('ssh','ftp','smb')),
            *(f'domain-{x}.xml' for x in t.ROLES)})
        self.assertTrue(t.validate_xml(files))

    def test_xml_deterministic(self):
        self.assertEqual(t.render_xml('b'*64),t.render_xml('b'*64))

    def test_new_uuid_unique_and_stable(self):
        files=t.render_xml('b'*64)
        uuids=[ET.fromstring(v).findtext('uuid') for v in files.values()]
        self.assertEqual(len(uuids),len(set(uuids)))
        self.assertTrue(all(x==str(__import__('uuid').UUID(x)) for x in uuids))

    def test_no_network_forward_ip_or_dhcp(self):
        files=t.render_xml('b'*64)
        for role in ('ssh','ftp','smb'):
            root=ET.fromstring(files[f'network-{role}.xml'])
            self.assertIsNone(root.find('forward'))
            self.assertIsNone(root.find('ip'))
            self.assertIsNone(root.find('dhcp'))
            self.assertEqual(root.find('dns').attrib,{'enable':'no'})
            self.assertEqual(root.attrib,{'ipv6':'no'})

    def test_all_guest_nics_have_unresolved_filter(self):
        files=t.render_xml('b'*64)
        for role in t.ROLES:
            root=ET.fromstring(files[f'domain-{role}.xml'])
            ifaces=root.findall('devices/interface')
            self.assertEqual(len(ifaces),len(t.RESOURCE[role]['nics']))
            for i in ifaces:
                self.assertEqual(i.find('filterref').get('filter'),t.DENY_FILTER)

    def test_all_disks_reference_r32_not_v4_v6(self):
        for role in t.ROLES:
            root=ET.fromstring(t.render_xml('b'*64)[f'domain-{role}.xml'])
            disk=root.find('devices/disk/source')
            self.assertEqual(disk.get('file'),f'{t.R32_STAGE}/{role}-runtime.qcow2')

    def test_original_mac_cpu_memory_preserved(self):
        for role, cfg in t.RESOURCE.items():
            root=ET.fromstring(t.render_xml('b'*64)[f'domain-{role}.xml'])
            self.assertEqual(root.findtext('memory'),str(cfg['ram_mib']))
            self.assertEqual(root.findtext('vcpu'),str(cfg['vcpus']))
            self.assertEqual([i.find('mac').get('address') for i in root.findall('devices/interface')],
                [row[2] for row in cfg['nics']])

    def test_disallowed_gpu_graphics_hostdevices_absent(self):
        for role in t.ROLES:
            root=ET.fromstring(t.render_xml('b'*64)[f'domain-{role}.xml'])
            for tag in ('graphics','hostdev','filesystem','redirdev','vsock'):
                self.assertFalse(root.findall('devices/'+tag))

    def test_xml_missing_filter_fails_validation(self):
        files=t.render_xml('b'*64)
        val=files['domain-ssh.xml'].replace(b'<filterref filter="'+t.DENY_FILTER.encode()+b'" />',b'')
        files['domain-ssh.xml']=val
        with self.assertRaises(t.TopologyError):
            t.validate_xml(files)

    def test_xml_foreign_mac_fails_validation(self):
        files=t.render_xml('b'*64)
        files['domain-runner.xml']=files['domain-runner.xml'].replace(
            b'52:54:00:ad:30:01', b'52:54:00:ad:30:99')
        with self.assertRaises(t.TopologyError):
            t.validate_xml(files)

    def test_plan_bytes_stable_and_no_host_activity(self):
        with mock.patch('subprocess.run',side_effect=AssertionError('UNEXPECTED_PROCESS')):
            a=t.make_report(self.src,t.R32_RECEIPT_FILE_SHA256)
            b=t.make_report(self.src,t.R32_RECEIPT_FILE_SHA256)
        self.assertEqual(t.canon(a),t.canon(b))
        self.assertTrue(t.verify_report(a))
        self.assertEqual(a['mode'],'PLAN_ONLY')
        self.assertFalse(a['vm_started'])
        self.assertFalse(a['libvirt_definitions_created'])

    def test_rehashed_false_claim_rejected(self):
        report=t.make_report(self.src,t.R32_RECEIPT_FILE_SHA256)
        report['operational_dispatch']=True;sign(report)
        with self.assertRaises(t.TopologyError):
            t.verify_report(report)

    def test_plan_receipt_must_pin_source(self):
        with self.assertRaises(t.TopologyError):
            t.make_report(self.src,'a'*64)

    def test_write_seven_xml_plus_receipt(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/'private';root.mkdir(mode=0o700)
            report=t.prepare_xml(root,self.src,t.R32_RECEIPT_FILE_SHA256)
            self.assertEqual(len(list(root.iterdir())),8)
            self.assertTrue(t.verify_report(report))
            self.assertEqual(report['mode'],'XML_PREPARED_ONLY')
            for item in report['files']:
                f=root/item['filename']
                self.assertEqual(t.digest(f.read_bytes()),item['sha256'])
                self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
            self.assertEqual(json.loads((root/'r33_topology_receipt.json').read_text()),report)
            self.assertFalse(report['network_started'])

    def test_repeated_write_rejected_preserves_files(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/'private';root.mkdir(mode=0o700)
            t.prepare_xml(root,self.src,t.R32_RECEIPT_FILE_SHA256)
            old={p.name:p.read_bytes() for p in root.iterdir()}
            with self.assertRaises(t.TopologyError):
                t.prepare_xml(root,self.src,t.R32_RECEIPT_FILE_SHA256)
            self.assertEqual(old,{p.name:p.read_bytes() for p in root.iterdir()})

    def test_world_access_directory_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/'private';root.mkdir(mode=0o700)
            root.chmod(0o755)
            with self.assertRaises(t.TopologyError):
                t.prepare_xml(root,self.src,t.R32_RECEIPT_FILE_SHA256)

    def test_symlink_output_directory_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            original=Path(parent)/'private';original.mkdir(mode=0o700)
            link=Path(parent)/'link';link.symlink_to(original)
            with self.assertRaises(t.TopologyError):
                t.prepare_xml(link,self.src,t.R32_RECEIPT_FILE_SHA256)

    def test_existing_file_rejected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as parent:
            root=Path(parent)/'private';root.mkdir(mode=0o700)
            (root/'domain-ssh.xml').write_text('OLD')
            with self.assertRaises(t.TopologyError):
                t.prepare_xml(root,self.src,t.R32_RECEIPT_FILE_SHA256)
            self.assertEqual((root/'domain-ssh.xml').read_text(),'OLD')

    def test_cross_directory_prepared_receipt_deterministic(self):
        with tempfile.TemporaryDirectory() as parent:
            dirs=[]
            for n in ('first','second'):
                p=Path(parent)/n;p.mkdir(mode=0o700)
                t.prepare_xml(p,self.src,t.R32_RECEIPT_FILE_SHA256)
                dirs.append(p)
            self.assertEqual((dirs[0]/'r33_topology_receipt.json').read_bytes(),
                             (dirs[1]/'r33_topology_receipt.json').read_bytes())


if __name__=='__main__':
    unittest.main()
