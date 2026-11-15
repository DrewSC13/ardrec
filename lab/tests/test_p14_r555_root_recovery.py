"""R55.5 offline/adversarial tests. NO nft/virsh/systemd are executed."""
from __future__ import annotations
import hashlib
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from ardrec.coordination import r555_recovery_contract as c

ROOT = Path(__file__).resolve().parents[2]
FILE=ROOT/'scripts/ardrec_p14_r555_root_recover.py'
spec=importlib.util.spec_from_file_location('ardrec_r555_root_recover',FILE)
h=importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
UUID='11111111-2222-4333-8444-555555555555'

def binding(role, candidate=False):
    tap,_,_=h.ROLE_FILES[role]
    mac='52:54:00:ad:30:02' if role=='ssh' else '52:54:00:ad:30:01'
    root=ET.Element('filterbinding')
    owner=ET.SubElement(root,'owner')
    ET.SubElement(owner,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(owner,'uuid').text=UUID
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    ref=ET.SubElement(root,'filterref',{'filter':
        ('ardrec-r45-ssh-icmp-candidate' if role=='ssh' else
         'ardrec-r45-runner-icmp-candidate') if candidate else h.DENY})
    ET.SubElement(ref,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'

def restore():
    taps=', '.join('"'+x+'"' for x in sorted(h.TAPS))
    lines=[f'flush table bridge {h.TABLE}']
    for chain,key in [('input','iifname'),('output','oifname'),
                       ('forward','iifname'),('forward','oifname')]:
        lines.append(f'add rule bridge {h.TABLE} {chain} {key} {{ {taps} }} counter drop')
    return ('\n'.join(lines)+'\n').encode('ascii')

def fake_payloads():
    return {h.RESTORE:restore(),
            'ssh-original.xml':binding('ssh'),
            'ssh-candidate.xml':binding('ssh',True),
            'runner-original.xml':binding('runner'),
            'runner-candidate.xml':binding('runner',True),
            'root-recover.py':FILE.read_bytes()}

def nft_readback():
    rows=[{'table':{'family':'bridge','name':h.TABLE}}]
    for name in ('input','output','forward'):
        rows.append({'chain':{'family':'bridge','table':h.TABLE,
                  'name':name,'hook':name,'type':'filter','prio':-200,'policy':'accept'}})
    for chain,key in [('input','iifname'),('output','oifname'),('forward','iifname'),('forward','oifname')]:
        rows.append({'rule':{'family':'bridge','table':h.TABLE,'chain':chain,
             'expr':[{'match':{'left':{'meta':{'key':key}},'op':'==',
                               'right':{'set':sorted(h.TAPS)}}},
                     {'counter':{'packets':0,'bytes':0}}, {'drop':None}]}})
    return json.dumps({'nftables':rows}).encode()

class Contract(unittest.TestCase):
    def test_source_main_fixed(self): self.assertEqual(c.SOURCE_MAIN,'1866af3a4f0ceb64b92f39a924ef00eacf56b169')
    def test_no_opening_mode_in_root_helper(self):
        raw=FILE.read_text()
        self.assertNotIn("group.add_argument('--allow'",raw)
        self.assertNotIn("group.add_argument('--open'",raw)
        self.assertIn("--restore-deny",raw)
    def test_exact_payload_inventory(self): self.assertEqual(len(c.PAYLOADS),6)
    def test_contract_always_no_go(self):
        obj=c.obligations(); self.assertEqual(obj['p8_operational'],'NO-GO')
        self.assertFalse(obj['recovery_executed'])
        self.assertFalse(obj['systemd_system_timer_armed'])
    def test_watchdog_fixed_system_manager_and_helper(self):
        unit='ardrec-r555-deny-watch-20261115T164500Z-6543'
        args=c.watchdog_argv(unit,45)
        self.assertIn('--system',args)
        self.assertNotIn('--user',args)
        self.assertEqual(args[-2:], [c.ROOT_HELPER,'--restore-deny'])
        c.verify_timer_argv(args,unit,45)
    def test_watchdog_tamper_denied(self):
        unit='ardrec-r555-deny-watch-20261115T164500Z-6543'
        args=c.watchdog_argv(unit,45)
        args[-1]='--check-root-bundle'
        with self.assertRaisesRegex(c.R555Error,'watchdog_command_changed'):
            c.verify_timer_argv(args,unit,45)
    def test_timer_no_host_address(self):
        args=c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-6543',45)
        self.assertNotIn('10.203',str(args))
    def test_no_shell_in_argv(self):
        args=c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-6543',45)
        self.assertNotIn('/bin/sh',args)
    def test_invalid_unit_semicolon(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('x;id',45)
    def test_invalid_unit_newline(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-1\n',45)
    def test_invalid_unit_zero_pid(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-0',45)
    def test_invalid_unit_wrong_prefix(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r554-deny-watch-20261115T164500Z-1',45)
    def test_invalid_time_0(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-1',0)
    def test_invalid_time_181(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-1',181)
    def test_invalid_time_bool(self):
        with self.assertRaises(c.R555Error): c.watchdog_argv('ardrec-r555-deny-watch-20261115T164500Z-1',True)
    def test_prepare_missing_source_refused(self):
        with self.assertRaises(c.R555Error): c.prepare({},FILE.read_bytes())
    def test_prepare_mismatched_source_refused(self):
        with self.assertRaises(c.R555Error): c.prepare({'plan.json':b'{}'},FILE.read_bytes())

class RootGuard(unittest.TestCase):
    def test_binding_ssh_original(self): h.verify_binding(binding('ssh'),'ssh',False)
    def test_binding_runner_original(self): h.verify_binding(binding('runner'),'runner',False)
    def test_binding_ssh_candidate(self): h.verify_binding(binding('ssh',True),'ssh',True)
    def test_binding_runner_candidate(self): h.verify_binding(binding('runner',True),'runner',True)
    def _mutated(self,role,what):
        root=ET.fromstring(binding(role))
        if what=='owner': root.find('owner/name').text='another'
        elif what=='mac': root.find('mac').set('address','00:00:00:00:00:00')
        elif what=='tap': root.find('portdev').set('name','wrong')
        elif what=='backend': root.find('backend').set('name','nftables')
        elif what=='filter': root.find('filterref').set('filter','accept')
        elif what=='extra': ET.SubElement(root,'extra')
        elif what=='parameter': root.find('filterref/parameter').set('value','bad')
        return ET.tostring(root)
    def test_bad_owner(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('ssh','owner'),'ssh',False)
    def test_bad_mac(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('ssh','mac'),'ssh',False)
    def test_bad_tap(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('ssh','tap'),'ssh',False)
    def test_bad_backend(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('runner','backend'),'runner',False)
    def test_bad_filter(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('runner','filter'),'runner',False)
    def test_extra_xml(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('ssh','extra'),'ssh',False)
    def test_mac_parameter_drift(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(self._mutated('runner','parameter'),'runner',False)
    def test_candidate_not_original(self):
        with self.assertRaises(h.RecoveryError): h.verify_binding(binding('ssh',True),'ssh',False)
    def test_xml_whitespace_normalizes(self):
        root=ET.fromstring(binding('ssh'));ET.indent(root)
        self.assertTrue(h.structurally_equal(binding('ssh'),ET.tostring(root)))
    def test_nft_deny_readback_pass(self): h.verify_deny_live(nft_readback())
    def test_nft_reject_accept(self):
        doc=json.loads(nft_readback());doc['nftables'][-1]['rule']['expr'][-1]={'accept':None}
        with self.assertRaises(h.RecoveryError): h.verify_deny_live(json.dumps(doc).encode())
    def test_nft_reject_extra_rule(self):
        doc=json.loads(nft_readback());doc['nftables'].append(doc['nftables'][-1])
        with self.assertRaises(h.RecoveryError): h.verify_deny_live(json.dumps(doc).encode())
    def test_nft_reject_wrong_tap(self):
        doc=json.loads(nft_readback());doc['nftables'][-1]['rule']['expr'][0]['match']['right']['set'][0]='bad'
        with self.assertRaises(h.RecoveryError): h.verify_deny_live(json.dumps(doc).encode())
    def test_nft_reject_priority_drift(self):
        doc=json.loads(nft_readback());doc['nftables'][1]['chain']['prio']=-199
        with self.assertRaises(h.RecoveryError): h.verify_deny_live(json.dumps(doc).encode())
    def test_nft_reject_duplicate_key(self):
        with self.assertRaises(h.RecoveryError): h.verify_deny_live(b'{"nftables":[],"nftables":[]}')
    def test_root_recover_denies_nonroot(self):
        with patch.object(h.os,'geteuid',return_value=1000):
            with self.assertRaisesRegex(h.RecoveryError,'root_required'): h.root_bundle()
    def test_host_rejects_arbitrary_command(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/bin/bash','-c','id'])
    def test_host_rejects_open_nft(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/sbin/nft','add','rule','...','accept'])
    def test_host_rejects_virsh_start(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/bin/virsh','-c','qemu:///system','start','test'])
    def test_host_rejects_network_start(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/bin/virsh','-c','qemu:///system','net-start','test'])
    def test_host_rejects_unrecognized_binding_target(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/bin/virsh','-c','qemu:///system',
                    'nwfilter-binding-delete','external-tap'])
    def test_host_rejects_untrusted_binding_xml(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/bin/virsh','-c','qemu:///system',
                    'nwfilter-binding-create','/tmp/untrusted.xml'])
    def test_host_rejects_unrestricted_nft_script(self):
        with self.assertRaisesRegex(h.RecoveryError,'nft_input_not_deny_only'):
            h.host(['/usr/sbin/nft','-f','-'],input_bytes=b'counter accept')
    def test_host_rejects_extra_nft_file(self):
        with self.assertRaisesRegex(h.RecoveryError,'unapproved_privileged_command'):
            h.host(['/usr/sbin/nft','-f','/tmp/evil'])

class Faults(unittest.TestCase):
    def setUp(self): self.payloads=fake_payloads();self.calls=[]
    def fake_host(self,argv,*,input_bytes=None,timeout=45):
        self.calls.append(tuple(argv))
        if argv[0]=='/usr/sbin/nft':
            if '-f' in argv:
                self.assertEqual(input_bytes,self.payloads[h.RESTORE])
                return b''
            return nft_readback()
        action=argv[3]
        role='ssh' if argv[-1]=='a33d30t' else 'runner'
        if action=='nwfilter-binding-dumpxml': return binding(role)
        return b''
    def test_check_only_zero_host_mutations(self):
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=self.fake_host):
            doc=h.recover(check_only=True)
        self.assertEqual(self.calls,[])
        self.assertEqual(doc['writes'],0)
    def test_original_bindings_restoration_starts_nft(self):
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=self.fake_host):
            doc=h.recover()
        self.assertEqual(self.calls[0],('/usr/sbin/nft','-f','-'))
        self.assertTrue(doc['bindings_restored_or_original'])
        self.assertFalse(any('nwfilter-binding-delete' in x for x in self.calls))
    def test_candidate_restored_after_deny_first(self):
        def fake(argv,*,input_bytes=None,timeout=45):
            self.calls.append(tuple(argv))
            if argv[0]=='/usr/sbin/nft': return b'' if '-f' in argv else nft_readback()
            if argv[3]=='nwfilter-binding-dumpxml':
                role='ssh' if argv[-1]=='a33d30t' else 'runner'
                num=sum(len(x)>3 and x[3]=='nwfilter-binding-delete' for x in self.calls)
                return binding(role, candidate= num==0 and role=='ssh')
            return b''
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=fake):
            doc=h.recover()
        self.assertIn('binding_candidate_removed_ssh',doc['events'])
        self.assertEqual(self.calls[0],('/usr/sbin/nft','-f','-'))
        self.assertEqual(sum(x[3]=='nwfilter-binding-delete' for x in self.calls if x[0]=='/usr/bin/virsh'),1)
    def test_unrecognized_binding_preserves_nft_and_no_delete(self):
        def fake(argv,*,input_bytes=None,timeout=45):
            self.calls.append(tuple(argv))
            if argv[0]=='/usr/sbin/nft': return b'' if '-f' in argv else nft_readback()
            if argv[3]=='nwfilter-binding-dumpxml': return b'<filterbinding/>'
            return b''
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=fake):
            with self.assertRaisesRegex(h.RecoveryError,'unexpected_binding_blocked'):
                h.recover()
        self.assertEqual(self.calls[0],('/usr/sbin/nft','-f','-'))
        self.assertFalse(any('nwfilter-binding-delete' in x for x in self.calls))
    def test_nft_write_failure_no_binding_mutation(self):
        def fake(argv,*,input_bytes=None,timeout=45):
            self.calls.append(tuple(argv)); raise h.RecoveryError('nft_fail')
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=fake):
            with self.assertRaisesRegex(h.RecoveryError,'nft_fail'): h.recover()
        self.assertEqual(self.calls,[('/usr/sbin/nft','-f','-')])
    def test_nft_readback_failure_no_binding_mutation(self):
        def fake(argv,*,input_bytes=None,timeout=45):
            self.calls.append(tuple(argv))
            return b'' if '-f' in argv else b'{"nftables":[]}'
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=fake):
            with self.assertRaises(h.RecoveryError): h.recover()
        self.assertEqual(len(self.calls),2)
    def test_create_failure_retains_r34_deny(self):
        def fake(argv,*,input_bytes=None,timeout=45):
            self.calls.append(tuple(argv))
            if argv[0]=='/usr/sbin/nft': return b'' if '-f' in argv else nft_readback()
            if argv[3]=='nwfilter-binding-dumpxml': return binding('ssh',True)
            if argv[3]=='nwfilter-binding-create': raise h.RecoveryError('failed_create')
            return b''
        with patch.object(h,'root_bundle',return_value=self.payloads),patch.object(h,'recovery_lock',return_value=nullcontext()),patch.object(h,'host',side_effect=fake):
            with self.assertRaisesRegex(h.RecoveryError,'failed_create'): h.recover()
        self.assertEqual(self.calls[0],('/usr/sbin/nft','-f','-'))
    def test_cannot_auto_start_vms(self):
        self.assertNotIn('virsh start',FILE.read_text())
        self.assertNotIn('net-start',FILE.read_text())

if __name__=='__main__': unittest.main()

class IntegrationBundle(unittest.TestCase):
    def valid_files(self):
        # Reuses the committed, independently audited R55.3 synthetic fixture.
        from test_p14_r553_transition_guard import fixture
        blobs=fixture()
        blobs['SHA256SUMS']=(''.join(c.sha(raw)+'  '+name+'\n' for name,raw in sorted(blobs.items()))).encode('ascii')
        return blobs
    def test_pure_full_bundle_generation(self):
        files=self.valid_files()
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            bundle=c.prepare(files,FILE.read_bytes())
        self.assertEqual(len(bundle),7)
        self.assertEqual(set(bundle),set(c.PAYLOADS)|{'manifest.json'})
        doc=json.loads(bundle['manifest.json'])
        self.assertFalse(doc['traffic_allowed'])
        self.assertEqual(doc['permission'],'DENY_ONLY_RESTORATION')
        self.assertEqual(doc['sha256']['root-recover.py'],c.sha(FILE.read_bytes()))
        self.assertEqual(bundle['r34-deny-restore.nft'],files['nft-deny-restore-NOT-EXECUTED.nft'])
    def test_full_bundle_rejects_modified_helper(self):
        files=self.valid_files()
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            with self.assertRaises(c.R555Error):
                c.prepare(files,b'python untrusted')
    def test_full_bundle_rejects_unknown_files(self):
        files=self.valid_files()
        files['malicious.sh']=b'bad'
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            with self.assertRaises(c.R555Error): c.prepare(files,FILE.read_bytes())
    def test_full_bundle_rejects_policy_widening(self):
        files=self.valid_files()
        files['nft-deny-restore-NOT-EXECUTED.nft']+=b'counter accept\n'
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            with self.assertRaises(Exception): c.prepare(files,FILE.read_bytes())
    def test_staged_root_bundle_owner_and_hashes(self):
        files=self.valid_files()
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            bundle=c.prepare(files,FILE.read_bytes())
        with tempfile.TemporaryDirectory(dir=(Path('/root') if h.os.geteuid()==0 else Path.home()),prefix='r555-contract-') as tmp:
            folder=Path(tmp)/'guard'
            folder.mkdir(mode=0o700);folder.chmod(0o700)
            for name,blob in bundle.items():
                p=folder/name; p.write_bytes(blob);p.chmod(0o600)
            with patch.object(h,'BUNDLE',folder),patch.object(h,'__file__',str(folder/'root-recover.py')):
                loaded=h.verify_staged(expected_uid=h.os.getuid())
            self.assertEqual(loaded['r34-deny-restore.nft'],bundle['r34-deny-restore.nft'])
    def test_staged_root_bundle_tampering_refused(self):
        files=self.valid_files()
        with patch.object(c,'PLAN_SHA',c.sha(files['plan.json'])):
            bundle=c.prepare(files,FILE.read_bytes())
        with tempfile.TemporaryDirectory(dir=(Path('/root') if h.os.geteuid()==0 else Path.home()),prefix='r555-contract-') as tmp:
            folder=Path(tmp)/'guard';folder.mkdir(mode=0o700);folder.chmod(0o700);folder.chmod(0o700)
            for name,blob in bundle.items():
                p=folder/name;p.write_bytes(blob);p.chmod(0o600)
            (folder/'r34-deny-restore.nft').write_bytes(bundle['r34-deny-restore.nft']+b'# tamper\n')
            with patch.object(h,'BUNDLE',folder),patch.object(h,'__file__',str(folder/'root-recover.py')):
                with self.assertRaisesRegex(h.RecoveryError,'root_bundle_hash_mismatch'):
                    h.verify_staged(expected_uid=h.os.getuid())
    def test_staged_root_executable_wrong_path_refused(self):
        with patch.object(h,'BUNDLE',Path('/root/unused-r555-guard')):
            with self.assertRaisesRegex(h.RecoveryError,'root_executable_must_be_staged_copy'):
                h.verify_staged(expected_uid=h.os.getuid())
