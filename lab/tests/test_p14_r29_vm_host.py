"""R29: pruebas sin libvirt/VM real; entradas de subprocess simuladas."""
from __future__ import annotations

from pathlib import Path
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.vm_host_preflight import (
    collect, read_profile, read_historical_evidence, verify_report,
    _domain_xml, VMPreflightError, canonical)

PROFILE=ROOT/'lab/p14-r29-vm-preflight-v1/expected.json'
EVIDENCE=ROOT/'lab/services-v1/evidence.json'
DOMAIN_UUID='123e4567-e89b-12d3-a456-426614174000'
XML=f'''<domain type="kvm"><name>ardrec-dev-ssh</name><uuid>{DOMAIN_UUID}</uuid>
<devices><interface type="network"><source network="ardrec-dev-ssh"/>
<mac address="52:54:00:ad:30:02"/></interface></devices></domain>'''


class FakeVirsh:
    def __init__(self, answers=None, failing=None):
        self.answers=answers if answers is not None else {
            ('list','--all','--name'):'', ('net-list','--all','--name'):''}
        self.failing=failing
        self.calls=[]

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        assert argv[:4] == ['virsh','--readonly','--connect','qemu:///system']
        assert 'sudo' not in argv and 'start' not in argv and 'destroy' not in argv
        assert kw['timeout']==5 and kw['close_fds'] is True
        assert kw['env']['LC_ALL']=='C'
        cmd=tuple(argv[4:])
        data=self.answers.get(cmd)
        return subprocess.CompletedProcess(argv, 1 if data is None or cmd==self.failing else 0,
                                           b'' if data is None else data.encode(), b'private-error')


class R29PreflightTests(unittest.TestCase):
    def test_historical_profile_has_four_distinct_roles(self):
        p,sha=read_profile(PROFILE)
        self.assertEqual([x['role'] for x in p['roles']],['ssh','ftp','smb','runner'])
        self.assertEqual(len(sha),64)

    def test_historical_evidence_is_not_current_state(self):
        info=read_historical_evidence(EVIDENCE)
        self.assertEqual(info['historical_cleanup'],'RECORDED_PASS_NOT_CURRENT')

    def test_historical_mode_runs_no_process(self):
        fake=FakeVirsh()
        r=collect(PROFILE,EVIDENCE,observe=False,runner=fake)
        self.assertEqual(fake.calls,[])
        self.assertEqual(r['summary'],'HISTORICAL_ONLY_NOT_CURRENT')
        self.assertFalse(r['host_metadata_observed'])

    def test_expected_cleanup_absence_by_names(self):
        fake=FakeVirsh()
        r=collect(PROFILE,EVIDENCE,observe=True,runner=fake)
        self.assertTrue(verify_report(r))
        self.assertEqual(len(fake.calls),2)
        self.assertEqual(r['summary'],'NO_NAMED_ARDREC_DOMAINS_OR_NETWORKS_IN_LIBVIRT_LIST')
        self.assertTrue(all(x['state']=='ABSENT_FROM_LIBVIRT_LIST' for x in r['roles']))

    def test_net_residuals_are_not_accepted_as_clean(self):
        f=FakeVirsh({('list','--all','--name'):'',
                     ('net-list','--all','--name'):'ardrec-dev-ssh\n'})
        r=collect(PROFILE,EVIDENCE,observe=True,runner=f)
        self.assertEqual(r['summary'],'ARDREC_DOMAINS_OR_NETWORKS_PRESENT_REVIEW_REQUIRED')
        self.assertEqual(r['ardrec_networks_listed'],['ardrec-dev-ssh'])

    def test_unrecognized_domain_is_reported_not_executed(self):
        f=FakeVirsh({('list','--all','--name'):'ardrec-shadow\n',
                     ('net-list','--all','--name'):''})
        r=collect(PROFILE,EVIDENCE,observe=True,runner=f)
        self.assertIn('ardrec-shadow',r['unrecognized_ardrec_domains'])
        self.assertEqual(len(f.calls),2)

    def test_domain_xml_identity_and_layout_checked(self):
        f=FakeVirsh({('list','--all','--name'):'ardrec-dev-ssh\n',
                     ('net-list','--all','--name'):'',
                     ('domuuid','ardrec-dev-ssh'):DOMAIN_UUID+'\n',
                     ('domstate','ardrec-dev-ssh'):'shut off\n',
                     ('dumpxml','--inactive','ardrec-dev-ssh'):XML})
        r=collect(PROFILE,EVIDENCE,observe=True,runner=f)
        ssh=r['roles'][0]
        self.assertTrue(ssh['layout_matches_historical'])
        self.assertEqual(ssh['state'],'PRESENT_SHUT_OFF')
        self.assertEqual(len(f.calls),5)
        self.assertFalse(r['identity_accredited'])

    def test_layout_drift_not_silently_accepted(self):
        wrong=XML.replace('52:54:00:ad:30:02','52:54:00:ad:30:ff')
        f=FakeVirsh({('list','--all','--name'):'ardrec-dev-ssh\n',
                     ('net-list','--all','--name'):'',
                     ('domuuid','ardrec-dev-ssh'):DOMAIN_UUID,
                     ('domstate','ardrec-dev-ssh'):'running',
                     ('dumpxml','--inactive','ardrec-dev-ssh'):wrong})
        r=collect(PROFILE,EVIDENCE,observe=True,runner=f)
        self.assertFalse(r['roles'][0]['layout_matches_historical'])
        self.assertFalse(r['technical_truth_accredited'])

    def test_reject_xml_identity_mismatch(self):
        with self.assertRaises(VMPreflightError):
            _domain_xml(XML.replace(DOMAIN_UUID,'123e4567-e89b-12d3-a456-426614174001'),
                        'ardrec-dev-ssh',[{'network':'ardrec-dev-ssh',
                            'mac':'52:54:00:ad:30:02'}],DOMAIN_UUID)

    def test_reject_xml_entity(self):
        with self.assertRaises(VMPreflightError):
            _domain_xml('<!DOCTYPE foo [<!ENTITY x "xx">]>'+XML,'ardrec-dev-ssh',[],DOMAIN_UUID)

    def test_reject_libvirt_command_failure(self):
        f=FakeVirsh(failing=('list','--all','--name'))
        with self.assertRaisesRegex(VMPreflightError,'virsh_readonly_query_failed'):
            collect(PROFILE,EVIDENCE,observe=True,runner=f)

    def test_reject_duplicate_profile_keys(self):
        with tempfile.TemporaryDirectory() as d:
            raw=PROFILE.read_text()
            raw=raw.replace('"schema":','"schema":"bad", "schema":',1)
            p=Path(d)/'duplicate.json';p.write_text(raw)
            with self.assertRaises(VMPreflightError):read_profile(p)

    def test_symlink_profile_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'link.json';p.symlink_to(PROFILE)
            with self.assertRaises(VMPreflightError):read_profile(p)

    def test_invalid_endpoint_rejected(self):
        p=json.loads(PROFILE.read_text())
        p['roles'][0]['ip']='8.8.8.8'
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'expected.json';f.write_text(json.dumps(p))
            with self.assertRaises(VMPreflightError):read_profile(f)

    def test_replay_stable_historical_bytes(self):
        a=collect(PROFILE,EVIDENCE,observe=False)
        b=collect(PROFILE,EVIDENCE,observe=False)
        self.assertEqual(canonical(a),canonical(b))
        self.assertEqual(a['sha256'],b['sha256'])

    def test_tamper_rejected_even_with_same_digest(self):
        r=collect(PROFILE,EVIDENCE,observe=False)
        r=copy.deepcopy(r);r['vm_network_probes']=True
        r['sha256']=hashlib.sha256(canonical({k:v for k,v in r.items() if k!='sha256'})).hexdigest()
        with self.assertRaisesRegex(VMPreflightError,'false_operational_claim'):
            verify_report(r)

    def test_no_vm_dispatch_or_risk(self):
        r=collect(PROFILE,EVIDENCE,observe=True,runner=FakeVirsh())
        self.assertFalse(r['operational_dispatch'])
        self.assertFalse(r['guest_checks_executed'])
        self.assertIsNone(r['final_risk'])
        self.assertIsNone(r['published_generation'])
        self.assertEqual(r['p8_operational'],'NO-GO')


class R29ViewTests(unittest.TestCase):
    def test_vm_panel_contains_current_vs_historical_labels(self):
        from ardrec.coordination.vm_preflight_view import vm_lines
        r=collect(PROFILE,EVIDENCE,observe=False)
        lines=vm_lines(r,80)
        self.assertIn('HIST:', '\n'.join(lines))
        self.assertIn('HISTORICAL_ONLY', '\n'.join(lines))
        self.assertIn('NO-GO', '\n'.join(lines))

    def test_vm_panel_requires_verified_receipt(self):
        from ardrec.coordination.vm_preflight_view import vm_lines
        r=collect(PROFILE,EVIDENCE,observe=False)
        r['summary']='FAKE_OPERATIONAL_PASS'
        with self.assertRaises(VMPreflightError):vm_lines(r)


if __name__=='__main__':unittest.main()
