"""R50-A bounded read-only QGA inspection and immutable receipt tests."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from ardrec.coordination import r50_guest_pair_inventory as r50


def specimen(role:str='ssh',*,ip=None,prefix=r50.EXPECTED_PREFIX,mac=None, extra=False, extra_ip=False):
    wanted=r50.ROLES[role]
    ip=ip or wanted[2];mac=mac or wanted[1]
    items=[{'name':'lo','ip-addresses':[{'ip-address-type':'ipv4',
                   'ip-address':'127.0.0.1','prefix':8}]},
           {'name':'ens3','hardware-address':mac,
            'ip-addresses':[{'ip-address-type':'ipv4','ip-address':ip,'prefix':prefix}]}]
    if extra:
        items.append({'name':'enp2s0','hardware-address':'52:54:00:aa:bb:cc',
                      'ip-addresses':[]})
    if extra_ip:
        items[1]['ip-addresses'].append({'ip-address-type':'ipv4',
                         'ip-address':'10.203.30.250','prefix':24})
    return json.dumps({'return':items}).encode()


def plan():
    return {'schema':r50.SCHEMA,'source_main':r50.BASE_MAIN,
            'mode':'HOST_QGA_READONLY_PREFLIGHT',
            'r49_boot_sha256':r50.R49_BOOT_PIN,
            'r49_definition_sha256':r50.R49_DEFINE_PIN,
            'domains':[r50.ROLES[r][0] for r in ('ssh','runner')],
            'qga_contacted':False,'guest_commands_executed':False,
            'vm_or_network_modified':False,'packets_injected':False,
            'isolation_proven':False,'operational_dispatch':False,
            'p8_operational':'NO-GO'}


def query(role,request):
    if request=={'execute':'guest-ping'}:
        return b'{"return":{}}'
    return specimen(role)


class GuestPairTests(unittest.TestCase):
    def test_ssh_expected(self):
        self.assertEqual(r50.summarize(specimen('ssh'),'ssh')['status'],
                         'EXPECTED_IP_MAC_OBSERVED_NO_GO')

    def test_runner_expected(self):
        self.assertEqual(r50.summarize(specimen('runner'),'runner')['status'],
                         'EXPECTED_IP_MAC_OBSERVED_NO_GO')

    def test_absent_ip_is_review(self):
        d=json.loads(specimen())
        d['return'][1]['ip-addresses']=[]
        self.assertIn('REVIEW',r50.summarize(json.dumps(d).encode(),'ssh')['status'])

    def test_wrong_ip_is_review(self):
        self.assertIn('REVIEW',r50.summarize(specimen(ip='10.203.30.99'),'ssh')['status'])

    def test_explicit_old_24_prefix_is_review(self):
        self.assertIn('REVIEW',r50.summarize(specimen(prefix=24),'ssh')['status'])

    def test_expected_prefix_is_exact_R421(self):
        self.assertEqual(r50.EXPECTED_PREFIX,28)
        self.assertEqual(r50.r421.PROBE_SOURCE,r50.r45.SOURCE_IP)
        self.assertEqual(r50.r421.PROBE_TARGET,r50.r45.DEST_IP)

    def test_wrong_prefix_is_review(self):
        self.assertIn('REVIEW',r50.summarize(specimen(prefix=16),'ssh')['status'])

    def test_other_nic_is_review(self):
        self.assertIn('REVIEW',r50.summarize(specimen(extra=True),'ssh')['status'])

    def test_multiple_ipv4_is_review(self):
        self.assertIn('REVIEW',r50.summarize(specimen(extra_ip=True),'ssh')['status'])

    def test_mac_missing_is_review(self):
        d=json.loads(specimen()); del d['return'][1]['hardware-address']
        self.assertIn('REVIEW',r50.summarize(json.dumps(d).encode(),'ssh')['status'])

    def test_duplicate_nic_names_rejected(self):
        d=json.loads(specimen());d['return'][0]['name']='ens3'
        with self.assertRaisesRegex(r50.R50Error,'name_invalid'):
            r50.summarize(json.dumps(d).encode(),'ssh')

    def test_bad_mac_rejected(self):
        d=json.loads(specimen());d['return'][1]['hardware-address']='00:bad'
        with self.assertRaisesRegex(r50.R50Error,'mac_invalid'):
            r50.summarize(json.dumps(d).encode(),'ssh')

    def test_malformed_json_rejected(self):
        with self.assertRaises(r50.R50Error):r50.reply(b'{!}','interfaces')

    def test_duplicate_json_field_rejected(self):
        with self.assertRaisesRegex(r50.R50Error,'duplicate_json_key'):
            r50.reply(b'{"return":[],"return":[]}', 'interfaces')

    def test_qga_nonfinite_rejected(self):
        with self.assertRaises(r50.R50Error):r50.reply(b'{"return":NaN}', 'interfaces')

    def test_qga_excess_rejected(self):
        with self.assertRaisesRegex(r50.R50Error,'size'):
            r50.reply(b'a'*(r50.MAX_RAW+1),'interfaces')

    def test_unknown_response_rejected(self):
        with self.assertRaisesRegex(r50.R50Error,'error_or_unknown'):
            r50.reply(b'{"error":{"class":"GenericError"}}','interfaces')

    def test_ping_requires_empty_return_object(self):
        with self.assertRaisesRegex(r50.R50Error,'ping_unexpected'):
            r50.reply(b'{"return":[1]}','ping')

    def test_bad_ipv4_rejected(self):
        d=json.loads(specimen());d['return'][1]['ip-addresses'][0]['ip-address']='300.2.3.4'
        with self.assertRaisesRegex(r50.R50Error,'ipv4_invalid'):
            r50.summarize(json.dumps(d).encode(),'ssh')

    def test_qga_allowlist_rejects_guest_exec(self):
        with self.assertRaisesRegex(r50.R50Error,'request_not_readonly'):
            r50.qga('ssh',{'execute':'guest-exec','arguments':{'path':'/bin/sh'}},run=lambda *a,**k:None)

    def test_qga_correct_fixed_command(self):
        calls=[]
        def fake(argv,**kwargs):
            calls.append((argv,kwargs));return SimpleNamespace(returncode=0,stdout=b'{"return":{}}',stderr=b'')
        self.assertEqual(r50.reply(r50.qga('ssh',{'execute':'guest-ping'},run=fake),'ping'),{})
        self.assertEqual(calls[0][0][:4],['/usr/bin/sudo','-n','--','/usr/bin/virsh'])
        self.assertNotIn('shell',calls[0][1])
        self.assertNotIn('guest-exec',str(calls[0][0]))
        self.assertEqual(calls[0][0][-3:-1],['--timeout','5'])

    def test_qga_oserror_fail_closed(self):
        def fake(*args,**kwargs):raise OSError('no agent')
        with self.assertRaisesRegex(r50.R50Error,'command_unavailable'):
            r50.qga('ssh',{'execute':'guest-ping'},run=fake)

    def test_preflight_physical_pin(self):
        with patch.object(r50.r49,'verify_boot',return_value={
            'sha256':r50.R49_BOOT_PIN,'defined_receipt_sha256':r50.R49_DEFINE_PIN}):
            self.assertEqual(r50.preflight({k:Path("/unused") for k in ("r45","r46","r47","r48","definition","boot")})['mode'],'HOST_QGA_READONLY_PREFLIGHT')

    def test_preflight_rejects_wrong_physical_sha(self):
        with patch.object(r50.r49,'verify_boot',return_value={
            'sha256':'0'*64,'defined_receipt_sha256':r50.R49_DEFINE_PIN}):
            with self.assertRaisesRegex(r50.R50Error,'mismatch'):
                r50.preflight({k:Path("/unused") for k in ("r45","r46","r47","r48","definition","boot")})

    def _case(self):
        t=tempfile.TemporaryDirectory()
        parent=Path(t.name)/'private';parent.mkdir(mode=0o700)
        root=parent/'r50a-guest-pair-20261115T043000Z-123'
        return t,root

    def test_private_collision_rejected(self):
        t,root=self._case()
        with t:
            root.mkdir(mode=0o700)
            with self.assertRaisesRegex(r50.R50Error,'collision_or_missing'):
                r50.capture({},root,check=lambda d:plan(),query=query)

    def test_capture_and_verify(self):
        t,root=self._case()
        with t:
            doc=r50.capture({},root,check=lambda d:plan(),query=query)
            self.assertEqual(doc['status'],'GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO')
            self.assertEqual(doc['schema'],r50.SCHEMA_V2)
            self.assertEqual(doc['expected_ipv4_prefix'],28)
            self.assertEqual(r50.verify({},root,check=lambda d:plan())['sha256'],doc['sha256'])
            self.assertEqual({x.name for x in root.iterdir()},
                 {r50.INTENT,r50.REPORT,r50.SUMS,*r50.RAW.values()})

    def test_capture_review_is_not_a_pass(self):
        t,root=self._case()
        def wrong(role,req):
            return (specimen(role,ip='10.203.30.99') if role=='runner'
                    and req=={'execute':'guest-network-get-interfaces'} else query(role,req))
        with t:
            d=r50.capture({},root,check=lambda _:plan(),query=wrong)
            self.assertEqual(d['status'],'GUEST_PAIR_CONFIG_REVIEW_NO_GO')
            self.assertFalse(d['isolation_proven'])

    def test_capture_partial_fail_preserves_intent(self):
        t,root=self._case()
        def bad(role,req):
            if role=='runner':raise r50.R50Error('simulated_agent_unavailable')
            return query(role,req)
        with t:
            with self.assertRaisesRegex(r50.R50Error,'INCOMPLETE_NO_RETRY'):
                r50.capture({},root,check=lambda _:plan(),query=bad)
            self.assertEqual({x.name for x in root.iterdir()},
                     {r50.INTENT,r50.RAW['ssh'],r50.FAILURE,r50.SUMS})

    def test_bad_qga_reply_preserves_fail_file(self):
        t,root=self._case()
        with t:
            with self.assertRaisesRegex(r50.R50Error,'INCOMPLETE_NO_RETRY'):
                r50.capture({},root,check=lambda _:plan(),query=lambda r,q:b'{}')
            self.assertTrue((root/r50.FAILURE).is_file())

    def test_verify_tampered_raw_rejected(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda _:plan(),query=query)
            (root/r50.RAW['ssh']).write_bytes(b'{"return":[]}')
            with self.assertRaisesRegex(r50.R50Error,'receipt_hash_mismatch'):
                r50.verify({},root,check=lambda _:plan())

    def test_verify_live_host_drift_rejected(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda _:plan(),query=query)
            def drift(_):
                x=plan();x['r49_definition_sha256']='a'*64;return x
            with self.assertRaisesRegex(r50.R50Error,'live_host_no_longer_matches'):
                r50.verify({},root,check=drift)


    @staticmethod
    def _convert_synthetic_to_legacy(root):
        p=root/r50.REPORT
        doc=json.loads(p.read_bytes())
        doc['schema']=r50.SCHEMA
        doc.pop('expected_ipv4_prefix')
        doc['roles']={role:r50.summarize((root/r50.RAW[role]).read_bytes(),role,
                                         expected_prefix=r50.LEGACY_PREFIX)
                      for role in ('ssh','runner')}
        doc['status']='GUEST_PAIR_CONFIG_REVIEW_NO_GO'
        doc.pop('sha256')
        doc['sha256']=r50.sha(r50.canon(doc))
        p.write_bytes(r50.canon(doc)+b'\n')
        (root/r50.SUMS).write_text(''.join(
            f'{r50.sha((root/n).read_bytes())}  {n}\n'
            for n in sorted((root/r50.INTENT,r50.REPORT,*r50.RAW.values()) )
        ) if False else ''.join(
            f'{r50.sha((root/n).read_bytes())}  {n}\n'
            for n in sorted([r50.INTENT,r50.REPORT,*r50.RAW.values()])
        ))
        return doc

    def test_old_v1_receipt_still_verifies_as_review(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            self.assertEqual(r50.verify({},root,check=lambda d:plan())['sha256'],
                             historical['sha256'])
            self.assertEqual(historical['status'],'GUEST_PAIR_CONFIG_REVIEW_NO_GO')

    def test_reconciliation_preserves_legacy_and_never_calls_qga(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            out=root.parent/'r50a-prefix-review-20261115T050000Z-123'
            old_bytes={n:(root/n).read_bytes() for n in
                       [r50.INTENT,r50.REPORT,r50.SUMS,*r50.RAW.values()]}
            with patch.object(r50,'HIST_PHYSICAL_PIN',historical['sha256']), \
                 patch.object(r50,'host_check',side_effect=AssertionError('no host')), \
                 patch.object(r50,'qga',side_effect=AssertionError('no QGA')):
                report=r50.reconcile_prefix({},root,out)
                self.assertEqual(report['corrected_criterion_prefix'],28)
                self.assertEqual(report['historical_status'],'GUEST_PAIR_CONFIG_REVIEW_NO_GO')
                self.assertEqual(report['corrected_result'],'GUEST_PAIR_EXPECTED_IP_MAC_OBSERVED_NO_GO')
                self.assertFalse(report['new_guest_qga_queries'])
                self.assertEqual(r50.verify_prefix_reconciliation({},root,out)['sha256'],
                                 report['sha256'])
            self.assertEqual(old_bytes,{n:(root/n).read_bytes() for n in old_bytes})

    def test_historical_offline_preflight_is_exact_not_trusted_from_file(self):
        self.assertEqual(r50.historical_expected_intent_offline(),plan())

    def test_historical_offline_verification_no_nft_or_qga(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            with patch.object(r50,'HIST_PHYSICAL_PIN',historical['sha256']), \
                 patch.object(r50,'host_check',side_effect=AssertionError('host nft unavailable')), \
                 patch.object(r50,'qga',side_effect=AssertionError('unexpected QGA')):
                self.assertEqual(r50.verify_historical_offline(root)['sha256'],historical['sha256'])

    def test_reconciliation_verification_no_live_host_dependency(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            rec=root.parent/'r50a-prefix-review-20261115T050001Z-123'
            with patch.object(r50,'HIST_PHYSICAL_PIN',historical['sha256']), \
                 patch.object(r50,'host_check',side_effect=AssertionError('host nft unavailable')), \
                 patch.object(r50,'qga',side_effect=AssertionError('unexpected QGA')):
                result=r50.reconcile_prefix({},root,rec)
                self.assertEqual(r50.verify_prefix_reconciliation({},root,rec)['sha256'],result['sha256'])

    def test_offline_rejects_tampered_source_and_recomputed_sums(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            with patch.object(r50,'HIST_PHYSICAL_PIN',historical['sha256']):
                self.assertEqual(r50.verify_historical_offline(root)['sha256'],historical['sha256'])
                path=root/r50.REPORT
                doc=json.loads(path.read_bytes());doc['host_policy_modified']=True
                doc['sha256']=r50.sha(r50.canon({k:v for k,v in doc.items() if k!='sha256'}))
                path.write_bytes(r50.canon(doc)+b'\n')
                (root/r50.SUMS).write_text(''.join(
                    f'{r50.sha((root/n).read_bytes())}  {n}\n'
                    for n in sorted([r50.INTENT,r50.REPORT,*r50.RAW.values()])))
                with self.assertRaisesRegex(r50.R50Error,'receipt_report_invalid'):
                    r50.verify_historical_offline(root)

    def test_reconciliation_rejects_unrelated_ip_mismatch(self):
        t,root=self._case()
        with t:
            def wrong(role,req):
                return (specimen(role,ip='10.203.30.99') if role=='runner' and
                        req=={'execute':'guest-network-get-interfaces'} else query(role,req))
            r50.capture({},root,check=lambda d:plan(),query=wrong)
            historical=self._convert_synthetic_to_legacy(root)
            with patch.object(r50,'HIST_PHYSICAL_PIN',historical['sha256']):
                with self.assertRaisesRegex(r50.R50Error,'not_just_a_prefix_discrepancy'):
                    r50._reconcile_doc(historical,root,r50._timestamp())

    def test_reconciliation_wrong_historical_hash_rejected(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            historical=self._convert_synthetic_to_legacy(root)
            with self.assertRaisesRegex(r50.R50Error,'pin_or_status_invalid'):
                r50._reconcile_doc(historical,root,r50._timestamp())

    def test_unknown_schema_is_fail_closed(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda d:plan(),query=query)
            doc=json.loads((root/r50.REPORT).read_bytes())
            doc['schema']='wrong'
            (root/r50.REPORT).write_bytes(r50.canon(doc)+b'\n')
            (root/r50.SUMS).write_text(''.join(
                f'{r50.sha((root/n).read_bytes())}  {n}\n'
                for n in sorted([r50.INTENT,r50.REPORT,*r50.RAW.values()])))
            with self.assertRaisesRegex(r50.R50Error,'receipt_schema_invalid'):
                r50.verify({},root,check=lambda d:plan())

    def test_verify_no_guest_qga_reprobe(self):
        t,root=self._case()
        with t:
            r50.capture({},root,check=lambda _:plan(),query=query)
            with patch.object(r50,'qga',side_effect=AssertionError('QGA should not run')):
                self.assertEqual(r50.verify({},root,check=lambda _:plan())['p8_operational'],'NO-GO')

if __name__=='__main__':unittest.main()
