"""Adversarial tests: F3 never sends traffic or grants A5/A6/P8."""
from __future__ import annotations

import base64
import copy
from datetime import timedelta
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_f3_f11_authority as m
from ardrec.coordination import r115_f2_a3_current_sources as f2
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r112_runner_nic_definition as nic
from ardrec.coordination import r112_f4_isolated_networks as net4
from ardrec.coordination import r113_f6_six_binding_guard as six
from test_p14_r115_f2_a3_current_sources import (
    snapshot as f2snapshot, outputs, xml_vm, contract as f1contract, BASE,
)


def net_info(role):
    return ('Name: ardrec-r33-dev-net-'+role+'\nUUID: '+net4.UUIDS[role]+
            '\nActive: no\nPersistent: yes\nAutostart: no\nBridge: '+
            nic.BRIDGES[role]+'\n').encode()


def net_xml(role):
    return ('<network><name>ardrec-r33-dev-net-'+role+'</name><bridge name="'+
            nic.BRIDGES[role]+'"/><dns enable="no"/></network>').encode()


def extra_data():
    return {'ssh_xml':xml_vm('ssh'),'smb_xml':xml_vm('smb'),
            'ssh_net_xml':net_xml('ssh'),'smb_net_xml':net_xml('smb'),
            'ssh_net_info':net_info('ssh'),'smb_net_info':net_info('smb'),
            'nwfilter_xml':('<filter name="'+nic.FILTER+'"><rule action="drop" '
                            'direction="inout"><all/></rule></filter>').encode(),
            'f11_hook_hash':(six.R34_HOOK+'  '+str(m.HOOK)+'\n').encode(),
            'boot_deny':b'LoadState=loaded\nActiveState=active\n'}


def capture(extra=None, baseline=None, failure=None):
    extra = extra_data() if extra is None else extra
    failure = {} if failure is None else failure
    entries={}
    for name in m.COMMANDS:
        raw=extra.get(name,b'')
        entries[name]={'rc':failure.get(name,0),'timed_out':False,
                       'truncated':False,'started_at':f2.iso(BASE),
                       'completed_at':f2.iso(BASE),
                       'stdout_b64':base64.b64encode(raw).decode('ascii'),
                       'stderr_b64':''}
    return {'schema':m.CAPTURE,'captured_at':f2.iso(BASE),
            'started_at':f2.iso(BASE),
            'source_kind':'LOCAL_READONLY_COMMANDS_NOT_AUTHORITY',
            'f2_snapshot':f2snapshot({**outputs(), 'ftp_net_xml':net_xml('ftp')}) if baseline is None else baseline,
            'extra':entries}


def replace_output(doc,key,value):
    s=copy.deepcopy(doc)
    if key in s['extra']:
        s['extra'][key]['stdout_b64']=base64.b64encode(value).decode()
    else:
        s['f2_snapshot']['commands'][key]['stdout_b64']=base64.b64encode(value).decode()
    return s


def keypair(folder, tag):
    priv=folder/(tag+'.pem')
    pub=folder/(tag+'.pub.pem')
    subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','Ed25519',
                    '-out',str(priv)],check=True,capture_output=True)
    subprocess.run(['/usr/bin/openssl','pkey','-in',str(priv),
                    '-pubout','-out',str(pub)],check=True,capture_output=True)
    return priv,pub.read_text()


def seal(statement,private,key_id,prefix,folder,tag):
    msg=folder/(tag+'.msg')
    sig=folder/(tag+'.sig')
    msg.write_bytes(m.signed_bytes(statement,prefix))
    subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-inkey',str(private),
                    '-rawin','-in',str(msg),'-out',str(sig)],
                   check=True,capture_output=True)
    return {'statement':statement,'signer_key_id':key_id,
            'signature_b64':base64.b64encode(sig.read_bytes()).decode()}


def signed_set(folder, *, revoked=False):
    c=f1contract()
    p1,pub1=keypair(folder,'a')
    p2,pub2=keypair(folder,'b')
    s={'schema':m.AUTH_SCHEMA,'authorization_id':'FTP-T01-DEV-F3',
       'case_id':c['case_id'],'family_id':c['family_id'],'stage':c['stage'],
       'valid_from':c['valid_from'],'valid_until':c['valid_until'],
       'target':c['target'],'client_sha256':c['client']['sha256'],
       'profile_sha256':c['profile']['sha256'],
       'catalog_sha256':c['catalog_sha256'],'limits':c['limits']}
    a=seal(s,p1,'operator_key_F3',m.PREFIX_AUTH,folder,'auth')
    c['authority']['sha256']=m.sha(m.canonical(a))
    rev={'schema':m.REVOCATION_SCHEMA,'authorization_sha256':m.sha(m.canonical(a)),
         'authorization_id':s['authorization_id'],
         'issued_at':'2026-11-20T11:30:00Z',
         'valid_until':'2026-11-20T12:30:00Z',
         'revoked':revoked,'reason_code':'NONE_SIGNED' if not revoked else 'REVOKED'}
    r=seal(rev,p2,'reviewer_key_F3',m.PREFIX_REVOKE,folder,'revoke')
    policy={'schema':m.TRUST_SCHEMA,
            'scope_signer':{'key_id':'operator_key_F3','public_key_pem':pub1},
            'revocation_signer':{'key_id':'reviewer_key_F3','public_key_pem':pub2}}
    return c,a,r,policy


class ReadonlyF11Tests(unittest.TestCase):
    def test_01_healthy_definitions_still_no_go(self):
        r=m.report(capture())
        self.assertEqual(r['source_checks']['six_vm_nic_definitions'],'MATCH')
        self.assertEqual(r['source_checks']['three_network_definitions'],'MATCH')
        self.assertEqual(r['source_checks']['three_network_runtime'],'MATCH')
        self.assertEqual(r['source_checks']['nwfilter_deny'],'MATCH')
        self.assertEqual(r['source_checks']['f11_hook'],'MATCH')
        self.assertEqual(r['source_checks']['r34_nft'],'MATCH')
        self.assertEqual(r['a3_status']['SERVICE_READY'],'FALSO')
        self.assertEqual(r['dispatch_decision'],'NO-GO')
        self.assertFalse(r['six_runtime_bindings_attested'])
        self.assertFalse(r['effective_isolation_attested'])

    def test_02_six_drift_becomes_false(self):
        c=replace_output(capture(),'ssh_xml',xml_vm('ssh').replace(
            b'a33d30t',b'a33d99t'))
        r=m.report(c)
        self.assertEqual(r['source_checks']['six_vm_nic_definitions'],'DRIFT')
        self.assertEqual(r['a3_status']['DESTINATION_AUTHORIZED'],'FALSO')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')

    def test_03_unreadable_ssh_xml_is_nd(self):
        r=m.report(capture(failure={'ssh_xml':1}))
        self.assertEqual(r['source_checks']['six_vm_nic_definitions'],'ND')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'ND')

    def test_04_one_extra_network_fails(self):
        c=replace_output(capture(),'ssh_net_xml',b'<network><name>ardrec-r33-dev-net-ssh</name><forward mode="nat"/></network>')
        self.assertEqual(m.report(c)['source_checks']['three_network_definitions'],'DRIFT')

    def test_05_missing_nwfilter_is_nd(self):
        self.assertEqual(m.report(capture(failure={'nwfilter_xml':2}))['source_checks']['nwfilter_deny'],'ND')

    def test_06_permissive_nwfilter_is_drift(self):
        c=replace_output(capture(),'nwfilter_xml',extra_data()['nwfilter_xml'].replace(b'action="drop"',b'action="accept"'))
        self.assertEqual(m.report(c)['source_checks']['nwfilter_deny'],'DRIFT')

    def test_07_f11_hook_changed_fails(self):
        c=replace_output(capture(),'f11_hook_hash',b'0'*64+b'  '+str(m.HOOK).encode()+b'\n')
        self.assertEqual(m.report(c)['source_checks']['f11_hook'],'DRIFT')

    def test_08_rootboot_not_active_fails(self):
        c=replace_output(capture(),'boot_deny',b'LoadState=loaded\nActiveState=inactive\n')
        self.assertEqual(m.report(c)['source_checks']['r34_boot_deny'],'DRIFT')

    def test_09_no_nft_permission_is_nd_not_go(self):
        b=f2snapshot({**outputs(), 'ftp_net_xml':net_xml('ftp')})
        b['commands']['nft_r34']['rc']=1
        r=m.report(capture(baseline=b))
        self.assertEqual(r['source_checks']['r34_nft'],'ND')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'ND')

    def test_10_bad_dns_network_fails(self):
        c=replace_output(capture(),'smb_net_xml',net_xml('smb').replace(b'enable="no"',b'enable="yes"'))
        self.assertEqual(m.report(c)['source_checks']['three_network_definitions'],'DRIFT')

    def test_11_timeout_is_nd(self):
        c=capture();c['extra']['smb_xml']['timed_out']=True
        self.assertEqual(m.report(c)['source_checks']['six_vm_nic_definitions'],'ND')

    def test_12_dtd_is_drift(self):
        c=replace_output(capture(),'ssh_xml',b'<!DOCTYPE domain [<!ENTITY x SYSTEM "file:///etc/passwd">]><domain>&x;</domain>')
        self.assertEqual(m.report(c)['source_checks']['six_vm_nic_definitions'],'DRIFT')

    def test_13_duplicate_schema_fields_dont_validate(self):
        c=capture(); c['extra']['fake']={}
        with self.assertRaises(m.Stop):m.report(c)

    def test_14_snapshot_not_living_permission(self):
        r=m.report(capture())
        self.assertEqual(r['authority_review']['status'],'ND')
        self.assertEqual(r['a6_classification'],'ND')
        self.assertIsNone(r['a9_published_generation'])
        self.assertFalse(r['a5_executable'])

    def test_15a_legacy_hook_hash_must_not_count_as_current(self):
        old=nic.HOST_HOOK_PIN
        c=replace_output(capture(),'f11_hook_hash',(old+'  '+str(m.HOOK)+'\n').encode())
        self.assertEqual(m.report(c)['source_checks']['f11_hook'],'DRIFT')

    def test_15_missing_command_returns_nd(self):
        c=capture(failure={'ssh_net_info':1})
        self.assertEqual(m.report(c)['source_checks']['three_network_runtime'],'ND')


class SignedAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='r115-f3-test-')
        cls.folder=Path(cls.tmp.name)
        cls.data=signed_set(cls.folder)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_16_signed_declaration_not_operational_authority(self):
        c,a,r,t=self.data
        d=m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')
        self.assertEqual(d['status'],'ND')
        self.assertTrue(d['crypto_verified'])
        self.assertFalse(d['host_trust_anchored'])

    def test_17_tampered_signature_rejected(self):
        c,a,r,t=copy.deepcopy(self.data)
        a['signature_b64']=base64.b64encode(b'Q'*64).decode()
        c['authority']['sha256']=m.sha(m.canonical(a))
        with self.assertRaises(m.Stop):m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')

    def test_18_tampered_authorization_rejected(self):
        c,a,r,t=copy.deepcopy(self.data)
        a['statement']['target']['port']=22
        c['authority']['sha256']=m.sha(m.canonical(a))
        with self.assertRaises(m.Stop):m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')

    def test_19_revoked_signed_document_is_false(self):
        c,a,r,t=signed_set(self.folder,revoked=True)
        self.assertEqual(m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')['status'],'FALSO')
        out=m.report(capture(),authority={'contract':c,'authorization':a,
                                         'revocation':r,'trust':t})
        self.assertEqual(out['a3_status']['SCOPE_APPROVED'],'FALSO')
        self.assertEqual(out['dispatch_decision'],'NO-GO')

    def test_20_stale_revocation_is_nd(self):
        c,a,r,t=self.data
        d=m.auth_review(c,a,r,t,now='2026-11-20T12:31:00Z')
        self.assertEqual(d['status'],'ND')

    def test_21_reused_key_is_rejected(self):
        c,a,r,t=copy.deepcopy(self.data)
        t['revocation_signer']['public_key_pem']=t['scope_signer']['public_key_pem']
        with self.assertRaises(m.Stop):m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')

    def test_22_bad_revocation_signature_rejected(self):
        c,a,r,t=copy.deepcopy(self.data)
        r['signature_b64']=base64.b64encode(b'R'*64).decode()
        with self.assertRaises(m.Stop):m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')

    def test_23_revocation_other_case_rejected(self):
        c,a,r,t=copy.deepcopy(self.data)
        r['statement']['authorization_id']='FTP-OTHER'
        with self.assertRaises(m.Stop):m.auth_review(c,a,r,t,now='2026-11-20T12:00:00Z')

    def test_24_bundle_absent_remains_nd(self):
        r=m.report(capture())
        self.assertEqual(r['authority_review']['reason'],'INDEPENDENT_SIGNATURES_AND_TRUST_NOT_SUPPLIED')

    def test_25_fresh_signed_bundle_never_go(self):
        c,a,r,t=self.data
        out=m.report(capture(),authority={'contract':c,'authorization':a,
                                         'revocation':r,'trust':t})
        self.assertTrue(out['authority_review']['crypto_verified'])
        self.assertEqual(out['a3_status']['SCOPE_APPROVED'],'ND')
        self.assertEqual(out['dispatch_decision'],'NO-GO')


if __name__=='__main__':unittest.main()
