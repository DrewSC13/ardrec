"""R55.8 offline/adversarial deny-only recovery tests; all host interactions mocked."""
from __future__ import annotations
from contextlib import nullcontext, redirect_stderr
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import io
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from ardrec.coordination import r558_recovery_contract as g
from ardrec.coordination import r553_transition_guard as r553

ROOT=Path(__file__).resolve().parents[2]
FILE=ROOT/'scripts/ardrec_p14_r558_root_recover.py'
spec=importlib.util.spec_from_file_location('ardrec_r558_root',FILE)
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
UUID='11111111-2222-4333-8444-555555555555'


def binding(role, candidate=False):
    tap = h.ROLE_FILES[role][0]
    mac='52:54:00:ad:30:02' if role=='ssh' else '52:54:00:ad:30:01'
    name='ardrec-r33-dev-'+role
    root=ET.Element('filterbinding')
    own=ET.SubElement(root,'owner')
    ET.SubElement(own,'name').text=name
    ET.SubElement(own,'uuid').text=UUID
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    filt=('ardrec-r45-ssh-icmp-candidate' if role=='ssh' else
          'ardrec-r45-runner-icmp-candidate') if candidate else h.DENY
    ref=ET.SubElement(root,'filterref',{'filter':filt})
    ET.SubElement(ref,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'


def domain(role):
    tap=h.ROLE_FILES[role][0]
    mac='52:54:00:ad:30:02' if role=='ssh' else '52:54:00:ad:30:01'
    root=ET.Element('domain',{'type':'kvm','id':'8'})
    ET.SubElement(root,'name').text='ardrec-r33-dev-'+role
    ET.SubElement(root,'uuid').text=UUID
    devices=ET.SubElement(root,'devices')
    nic=ET.SubElement(devices,'interface',{'type':'network'})
    ET.SubElement(nic,'mac',{'address':mac})
    ET.SubElement(nic,'source',{'network':'ardrec-r33-dev-net-ssh'})
    ET.SubElement(nic,'target',{'dev':tap})
    return ET.tostring(root,encoding='utf-8')


def prepared():
    return {
        'ssh-original.xml':binding('ssh'),
        'ssh-candidate.xml':binding('ssh',True),
        'runner-original.xml':binding('runner'),
        'runner-candidate.xml':binding('runner',True),
        'r34-deny-restore.nft':r553.expected_nft(allow=False),
        'root-recover.py':FILE.read_bytes(),
    }


def live_nft():
    rows=[{'table':{'family':'bridge','name':h.TABLE}}]
    for chain in ('input','output','forward'):
        rows.append({'chain':{'family':'bridge','table':h.TABLE,'name':chain,
             'hook':chain,'type':'filter','prio':-200,'policy':'accept'}})
    for chain,key in [('input','iifname'),('output','oifname'),
                      ('forward','iifname'),('forward','oifname')]:
        rows.append({'rule':{'family':'bridge','table':h.TABLE,'chain':chain,
           'expr':[{'match':{'left':{'meta':{'key':key}},'op':'==',
                  'right':{'set':sorted(h.TAPS)}}},
                  {'counter':{'packets':0,'bytes':0}},{'drop':None}]}})
    return json.dumps({'nftables':rows}).encode()


def fake_binding_list(present=()):
    return ('Port dev            Filter\n--------------------------------\n'+
            ''.join(tap+'    any-filter\n' for tap in present)).encode()


class HostFixture:
    def __init__(self,states=None):
        self.states=dict(states or {'ssh':'original','runner':'original'})
        self.calls=[]
        self.fault=None
    def host(self,args,*,input_bytes=None,timeout=45):
        self.calls.append((list(args),input_bytes))
        if self.fault and self.fault(args):
            raise h.RecoveryError('mock_injected_fault')
        if args[:1]==['/usr/sbin/nft']:
            return b'' if '-f' in args else live_nft()
        verb=args[3]
        if verb=='nwfilter-binding-list':
            return fake_binding_list(
                h.ROLE_FILES[role][0] for role,state in self.states.items()
                if state != 'missing')
        if verb=='dumpxml':
            return domain(args[4].removeprefix('ardrec-r33-dev-'))
        if verb=='nwfilter-binding-dumpxml':
            role=next(r for r,info in h.ROLE_FILES.items() if info[0]==args[4])
            state=self.states[role]
            if state=='missing':raise h.RecoveryError('binding_absent')
            return binding(role,state=='candidate') if state!='unknown' else b'<filterbinding></filterbinding>'
        if verb=='nwfilter-binding-delete':
            role=next(r for r,info in h.ROLE_FILES.items() if info[0]==args[4])
            self.states[role]='missing'
            return b''
        if verb=='nwfilter-binding-create':
            role=next(r for r in h.ROLE_FILES if args[4].endswith(r+'-original.xml'))
            if self.states[role]!='missing':
                raise h.RecoveryError('create_collision')
            self.states[role]='original'
            return b''
        raise AssertionError('Unexpected mocked argv: '+repr(args))


class ContractTests(unittest.TestCase):
    def test_helper_sha_matches(self):self.assertEqual(g.sha(FILE.read_bytes()),g.HELPER_SHA)
    def test_fixed_root_path(self):self.assertEqual(str(g.DEST),'/var/lib/ardrec/r558-deny-guard')
    def test_helper_no_external_root_path(self):self.assertNotIn('--bundle-dir',FILE.read_text())
    def test_helper_no_allow_mode(self):self.assertNotIn("group.add_argument('--open'",FILE.read_text())
    def test_helper_no_allow_exec(self):self.assertNotIn("group.add_argument('--allow'",FILE.read_text())
    def test_helper_no_systemd_exec(self):self.assertNotIn('systemd-run',FILE.read_text())
    def test_helper_no_shell_exec(self):self.assertNotIn('shell=True',FILE.read_text())
    def test_helper_staged_schema(self):self.assertEqual(h.SCHEMA,g.SCHEMA)
    def test_source_main(self):self.assertEqual(g.BASE,'04dc845983ffe53925498c47e142b3924319bf1c')
    def test_p8_no_go(self):self.assertEqual(g.obligations()['p8_operational'],'NO-GO')
    def test_r557_good(self):
        d={'schema':'ardrec-r557-f1-physical-deny-v1','status':'PHYSICAL_DENY_AND_TIMER_PASS_NO_GO',
          'physical_deny_verified':True,'timer_armed':True,'timer_fired_verified':True,
          'worker_killed':True,'traffic_opened':False,'p8_operational':'NO-GO'}
        g.attest_r557(d)
    def test_r557_all_essential_flags_rejected(self):
        d={'schema':'ardrec-r557-f1-physical-deny-v1','status':'PHYSICAL_DENY_AND_TIMER_PASS_NO_GO',
          'physical_deny_verified':True,'timer_armed':True,'timer_fired_verified':True,
          'worker_killed':True,'traffic_opened':False,'p8_operational':'NO-GO'}
        for k in d:
            v=d.copy();v[k]=('changed' if isinstance(v[k],str) else not v[k])
            with self.subTest(k=k),self.assertRaises(g.R558Error):g.attest_r557(v)
    def test_prepare_requires_plan_inventory(self):
        with self.assertRaises(g.R558Error):g.prepare({},FILE.read_bytes())
    def test_prepare_rejects_wrong_helper(self):
        with self.assertRaises(g.R558Error):g.prepare({'plan.json':b'fake'},b'bad')
    def test_stage_cmds_exact_9(self):
        src=Path('/home/cicada/ardrec-lab/r58-root-recovery/r558-prepared-20261115T190010Z-1234')
        commands=g.stage_commands(src)
        self.assertEqual(len(commands),9)
        self.assertTrue(all(c[0]=='/usr/bin/install' for c in commands))
        self.assertFalse(any('r555-deny-guard' in str(c) for c in commands))
        self.assertTrue(all('--allow' not in c for c in commands))
    def test_stage_cmds_invalid_source(self):
        for p in ('/tmp/r558-prepared-20261115T190010Z-1234',
                  '/home/cicada/ardrec-lab/r58-root-recovery/../r558-prepared-20261115T190010Z-1234',
                  '/home/cicada/ardrec-lab/r58-root-recovery/not-staged',
                  '/home/cicada/ardrec-lab/r58-root-recovery/r558-prepared-20261115T190010Z-0'):
            with self.subTest(path=p),self.assertRaises(g.R558Error):g.stage_commands(Path(p))
    def test_no_payload_alias(self):
        self.assertEqual(g.FILES,frozenset(('root-recover.py','r34-deny-restore.nft',
             'ssh-original.xml','ssh-candidate.xml','runner-original.xml',
             'runner-candidate.xml','manifest.json')))


class RecoveryTests(unittest.TestCase):
    def test_original_binding_is_valid(self):h.verify_binding(binding('ssh'),'ssh',False)
    def test_candidate_binding_is_valid(self):h.verify_binding(binding('runner',True),'runner',True)
    def test_valid_live_identity_ssh(self):h.verify_live_owner_domain(domain('ssh'),binding('ssh'))
    def test_valid_live_identity_runner(self):h.verify_live_owner_domain(domain('runner'),binding('runner'))
    def test_invalid_live_identity_each_field(self):
        for key,change in (
            ('uuid',lambda e: setattr(e.find('uuid'),'text','00000000-0000-0000-0000-000000000000')),
            ('name',lambda e: setattr(e.find('name'),'text','other')),
            ('type',lambda e: e.set('type','lxc')),
            ('mac',lambda e: e.find('./devices/interface/mac').set('address','00:00:00:00:00:00')),
            ('source',lambda e: e.find('./devices/interface/source').set('network','default')),
            ('target',lambda e: e.find('./devices/interface/target').set('dev','other')),
        ):
            e=ET.fromstring(domain('ssh'));change(e)
            with self.subTest(key=key),self.assertRaises(h.RecoveryError):
                h.verify_live_owner_domain(ET.tostring(e),binding('ssh'))
    def test_duplicate_tap_rejected(self):
        e=ET.fromstring(domain('ssh')); e.find('devices').append(e.find('./devices/interface'))
        with self.assertRaises(h.RecoveryError):h.verify_live_owner_domain(ET.tostring(e),binding('ssh'))
    def test_doctype_rejected(self):
        with self.assertRaises(h.RecoveryError):
            h.verify_live_owner_domain(b'<!DOCTYPE domain>'+domain('ssh'),binding('ssh'))
    def test_binding_list_empty(self):self.assertFalse(h.binding_present(fake_binding_list(), 'a33d30t'))
    def test_binding_list_present(self):self.assertTrue(h.binding_present(fake_binding_list(['a33d30t']),'a33d30t'))
    def test_binding_list_other(self):self.assertFalse(h.binding_present(fake_binding_list(['a33d30r']),'a33d30t'))
    def test_binding_list_duplicate_rejected(self):
        with self.assertRaises(h.RecoveryError):h.binding_present(fake_binding_list(['a33d30r','a33d30r']),'a33d30r')
    def test_binding_list_no_header_rejected(self):
        with self.assertRaises(h.RecoveryError):h.binding_present(b'a33d30t','a33d30t')
    def test_binding_list_invalid_bytes_rejected(self):
        with self.assertRaises(h.RecoveryError):h.binding_present(b'\xff\xfe','a33d30t')
    def test_binding_list_invalid_tokens_rejected(self):
        with self.assertRaises(h.RecoveryError):h.binding_present(b'Port dev\na;b filter\n','a33d30t')
    def test_recovery_no_binding_changes(self):
        f=HostFixture();events=[]
        with patch.object(h,'host',f.host):
            h.recover_one_binding(prepared(),'ssh',events)
        self.assertEqual(events,['binding_already_original_ssh'])
        self.assertFalse(any('nwfilter-binding-delete' in args for args,_ in f.calls))
    def test_recover_missing_ssh(self):
        f=HostFixture({'ssh':'missing','runner':'original'});events=[]
        with patch.object(h,'host',f.host):h.recover_one_binding(prepared(),'ssh',events)
        self.assertEqual(f.states['ssh'],'original')
        self.assertEqual(events,['binding_missing_under_r34_deny_ssh','binding_original_created_ssh'])
    def test_recover_missing_runner(self):
        f=HostFixture({'ssh':'original','runner':'missing'});events=[]
        with patch.object(h,'host',f.host):h.recover_one_binding(prepared(),'runner',events)
        self.assertEqual(f.states['runner'],'original')
    def test_recover_candidate(self):
        f=HostFixture({'ssh':'candidate','runner':'original'});events=[]
        with patch.object(h,'host',f.host):h.recover_one_binding(prepared(),'ssh',events)
        self.assertEqual(f.states['ssh'],'original')
        self.assertIn('binding_candidate_removed_ssh',events)
    def test_unknown_binding_preserved(self):
        f=HostFixture({'ssh':'unknown','runner':'original'});events=[]
        with patch.object(h,'host',f.host), self.assertRaises(h.RecoveryError):
            h.recover_one_binding(prepared(),'ssh',events)
        self.assertEqual(f.states['ssh'],'unknown')
    def test_failed_dumpxml_never_assumed_missing(self):
        f=HostFixture();f.fault=lambda args: 'nwfilter-binding-dumpxml' in args
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h.recover_one_binding(prepared(),'ssh',[])
        self.assertEqual(f.states['ssh'],'original')
    def test_failed_binding_list_no_mutation(self):
        f=HostFixture();f.fault=lambda args:'nwfilter-binding-list' in args
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h.recover_one_binding(prepared(),'ssh',[])
        self.assertEqual(f.states['ssh'],'original')
    def test_failed_create_is_partial(self):
        f=HostFixture({'ssh':'candidate','runner':'original'})
        f.fault=lambda args:'nwfilter-binding-create' in args
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h.recover_one_binding(prepared(),'ssh',[])
        self.assertEqual(f.states['ssh'],'missing')
    def test_second_recovery_repairs_after_create_failure(self):
        f=HostFixture({'ssh':'candidate','runner':'original'})
        f.fault=lambda args:'nwfilter-binding-create' in args
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h.recover_one_binding(prepared(),'ssh',[])
        f.fault=None
        with patch.object(h,'host',f.host):h.recover_one_binding(prepared(),'ssh',[])
        self.assertEqual(f.states['ssh'],'original')
    def test_nft_first_before_bindings(self):
        f=HostFixture({'ssh':'candidate','runner':'missing'})
        with patch.object(h,'host',f.host):
            doc=h._recover_deny(prepared())
        self.assertEqual(doc['result'],'DENY_RESTORATION_READBACK_PASS')
        self.assertEqual(f.calls[0][0],['/usr/sbin/nft','-f','-'])
        self.assertEqual(f.states,{'ssh':'original','runner':'original'})
    def test_nft_failed_no_libvirt_mutation(self):
        f=HostFixture({'ssh':'candidate','runner':'missing'})
        f.fault=lambda args: args==['/usr/sbin/nft','-f','-']
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h._recover_deny(prepared())
        self.assertEqual(len(f.calls),1)
    def test_unknown_binding_under_deny(self):
        f=HostFixture({'ssh':'unknown','runner':'original'})
        with patch.object(h,'host',f.host),self.assertRaises(h.RecoveryError):
            h._recover_deny(prepared())
        self.assertEqual(f.calls[0][0],['/usr/sbin/nft','-f','-'])
        self.assertFalse(any('nwfilter-binding-delete' in a for a,_ in f.calls))
    def test_nft_readback_rejected(self):
        doc=json.loads(live_nft());doc['nftables'].append({'rule':{'family':'bridge'}})
        with self.assertRaises(h.RecoveryError):h.verify_deny_live(json.dumps(doc).encode())
    def test_root_required(self):
        with patch.object(h.os,'geteuid',return_value=1000),self.assertRaises(h.RecoveryError):h.root_bundle()
    def test_root_only_helper_root_path(self):
        self.assertEqual(h.BUNDLE,g.DEST)
    def test_root_helper_cli_no_allow(self):
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):h.main(['--allow-traffic'])


if __name__ == '__main__':unittest.main()
