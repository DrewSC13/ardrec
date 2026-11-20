"""R112 real-host plan: pure adversarial tests. No libvirt host calls."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'), str(ROOT/'scripts')]
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_runner_nic_definition as cli


def vm_xml(role, configured=False):
    root=ET.Element('domain',{'type':'kvm'})
    ET.SubElement(root,'name').text='ardrec-r33-dev-'+role
    devices=ET.SubElement(root,'devices')
    disk=ET.SubElement(devices,'disk',{'type':'file','device':'disk'})
    ET.SubElement(disk,'source',{'file':'/var/lib/libvirt/images/ardrec-dev-point4-r32/'+role+'-runtime.qcow2'})
    for proto,mac,tap in r112.NIC[role]+(r112.ADDED if role=='runner' and configured else []):
        i=ET.SubElement(devices,'interface',{'type':'network'})
        ET.SubElement(i,'mac',{'address':mac})
        ET.SubElement(i,'source',{'network':r112.NETPREFIX+proto})
        ET.SubElement(i,'target',{'dev':tap})
        ET.SubElement(i,'model',{'type':'virtio'})
        ET.SubElement(i,'filterref',{'filter':r112.FILTER})
    return ET.tostring(root,encoding='unicode')


def net_xml(proto):
    return f'<network ipv6="no"><name>{r112.NETPREFIX+proto}</name><bridge name="{r112.BRIDGES[proto]}"/><dns enable="no"/></network>'


def r34_json():
    rules=[]
    for c in ('input','output','forward','forward'):
        rules.append({'rule':{'family':'bridge','table':'ardrec_r34_guard','chain':c,
                              'handle':len(rules)+1,
                              'expr':[{'counter':{'packets':4,'bytes':200}}, {'drop':None}]}})
    return json.dumps({'nftables':rules})


def record(configured=False):
    probes={key:{'rc':0,'timeout':False,'stdout':'','stderr':'','truncated':False}
            for key in legacy.command_list()}
    for role in r112.NIC:
        probes[f'vm-{role}-state']['stdout']='apagado\n'
        probes[f'vm-{role}-inactive-xml']['stdout']=vm_xml(role,configured)
        probes[f'vm-{role}-block']['stdout']='Target Source\nvda /var/lib/libvirt/images/...\n'
    for role in r112.BRIDGES:
        probes[f'net-{role}-xml']['stdout']=net_xml(role)
        probes[f'net-{role}-info']['stdout']='Activa: no\n'
    for key in ('libvirt-daemon','f11-boot-unit','f11-watchdog-timer'):
        probes[key]['stdout']='LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n'
    probes['f11-watchdog-unit']['stdout']='LoadState=loaded\nActiveState=inactive\nSubState=dead\n'
    probes['f11-hook-hash']['stdout']=r112.HOST_HOOK_PIN+'  /etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny\n'
    probes['f11-hook-stat']['stdout']='0:0 755 100 /etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny'
    probes['r34-nft']['stdout']=r34_json()
    probes['deny-nwfilter-xml']['stdout']=(f'<filter name="{r112.FILTER}">'
        '<rule action="drop" direction="inout"><all/></rule></filter>')
    d={'schema':legacy.SCHEMA,'commands':{k:list(v) for k,v in legacy.command_list().items()},
       'probes':probes}
    d['summary']=legacy.summarize(probes)
    return d


class R112DefinitionTests(unittest.TestCase):
    def test_exact_two_nics_added(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s)
        self.assertEqual(len(ET.fromstring(c).findall('devices/interface')),3)
        r112.validate_candidate(s,c)

    def test_reversible_exact_non_nic_xml(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s)
        self.assertTrue(r112.normalized_xml(s))
        r112.validate_candidate(s,c)

    def test_guest_hostdev_rejected(self):
        root=ET.fromstring(vm_xml('runner'))
        ET.SubElement(root.find('devices'),'hostdev')
        with self.assertRaises(r112.AdmissionError):
            r112.make_candidate(ET.tostring(root,encoding='unicode'))

    def test_added_extra_interface_rejected(self):
        s=vm_xml('runner')
        root=ET.fromstring(r112.make_candidate(s))
        ET.SubElement(root.find('devices'),'interface',{'type':'bridge'})
        with self.assertRaises(r112.AdmissionError):
            r112.validate_candidate(s,ET.tostring(root,encoding='unicode'))

    def test_unauthorized_domain_change_rejected(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s).replace('</domain>','<metadata>changed</metadata></domain>')
        with self.assertRaises(r112.AdmissionError):
            r112.validate_candidate(s,c)

    def test_changed_ftp_mac_rejected(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s).replace('52:54:00:ad:31:01','52:54:00:ad:31:03')
        with self.assertRaises(r112.AdmissionError):
            r112.validate_candidate(s,c)

    def test_changed_smb_tap_rejected(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s).replace('a33d32r','a33d33r')
        with self.assertRaises(r112.AdmissionError):
            r112.validate_candidate(s,c)

    def test_missing_filter_denied(self):
        s=vm_xml('runner')
        c=r112.make_candidate(s).replace('ardrec-r33-block-until-containment','something-else')
        with self.assertRaises(r112.AdmissionError):
            r112.validate_candidate(s,c)

    def test_real_style_localized_offline_snapshot(self):
        d=record()
        checked=r112.audit(d,legacy)
        self.assertTrue(checked['all_shutoff'])
        self.assertEqual(checked['runner_nics'],1)

    def test_post_definition_snapshot_checked(self):
        before,after=record(),record(True)
        r112.snapshot_equivalent(before,after,legacy,after_definition=True)

    def test_changed_f11_hook_denied(self):
        d=record()
        d['probes']['f11-hook-hash']['stdout']='0'*64+'  /path'
        d['summary']=legacy.summarize(d['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.audit(d,legacy)

    def test_vm_start_denied(self):
        d=record()
        d['probes']['vm-ssh-state']['stdout']='ejecutando\n'
        d['summary']=legacy.summarize(d['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.audit(d,legacy)

    def test_drop_rule_removed_denied(self):
        d=record()
        nft=json.loads(d['probes']['r34-nft']['stdout'])
        nft['nftables'].pop()
        d['probes']['r34-nft']['stdout']=json.dumps(nft)
        d['summary']=legacy.summarize(d['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.audit(d,legacy)

    def test_network_nating_denied(self):
        d=record()
        d['probes']['net-ftp-xml']['stdout']=net_xml('ftp').replace('<dns','<forward mode="nat"/><dns')
        d['summary']=legacy.summarize(d['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.audit(d,legacy)

    def test_nft_counter_changes_are_permitted(self):
        a,b=record(),record()
        nft=json.loads(b['probes']['r34-nft']['stdout'])
        nft['nftables'][0]['rule']['expr'][0]['counter']['packets']=201
        b['probes']['r34-nft']['stdout']=json.dumps(nft)
        b['summary']=legacy.summarize(b['probes'])
        r112.snapshot_equivalent(a,b,legacy,after_definition=False)

    def test_nft_rule_change_not_permitted(self):
        a,b=record(),record()
        nft=json.loads(b['probes']['r34-nft']['stdout'])
        nft['nftables'][0]['rule']['expr'].append({'accept':None})
        b['probes']['r34-nft']['stdout']=json.dumps(nft)
        b['summary']=legacy.summarize(b['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.snapshot_equivalent(a,b,legacy,after_definition=False)

    def test_other_guest_config_change_denied(self):
        a,b=record(),record(True)
        b['probes']['vm-ssh-inactive-xml']['stdout'] += '\n<!-- altered -->'
        b['summary']=legacy.summarize(b['probes'])
        with self.assertRaises(r112.AdmissionError):
            r112.snapshot_equivalent(a,b,legacy,after_definition=True)

    def test_private_plan_replay_and_physical_define(self):
        with TemporaryDirectory(prefix='r112-real-preflight-') as d:
            base=Path(d)
            original=record()
            after=record(True)
            with patch.object(cli,'ROOT',base), patch.object(cli,'git_source'), \
                 patch.object(cli,'verified_history',return_value={}), \
                 patch.object(cli,'capture',side_effect=[original,original,after]), \
                 patch.object(cli.legacy,'run',return_value={
                     'rc':0,'timeout':False,'stdout':'Domain defined from test',
                     'stderr':'','truncated':False}) as mutator:
                self.assertEqual(cli.plan(base/'old',base/'reconciled'),0)
                plan_dir=next(base.glob('plan-*'))
                doc,_=cli.verify_plan(plan_dir)
                self.assertEqual(doc['before_runner_nics'],1)
                self.assertEqual(mutator.call_count,0)
                self.assertEqual(cli.perform(plan_dir),0)
                result_dir=next(base.glob('apply-*'))
                self.assertTrue(cli.verify_physical(plan_dir,result_dir))
                self.assertEqual(mutator.call_count,1)
                self.assertEqual(mutator.call_args.args[0][:5],
                                 ('sudo','-n','virsh','-c','qemu:///system'))
                self.assertTrue((plan_dir/'apply.once').exists())

    def test_restoration_reverts_exact_original(self):
        with TemporaryDirectory(prefix='r112-restore-') as d:
            base=Path(d)
            before=record()
            configured=record(True)
            with patch.object(cli,'ROOT',base), patch.object(cli,'git_source'), \
                 patch.object(cli,'verified_history',return_value={}), \
                 patch.object(cli,'capture',side_effect=[before,before,configured,configured,before]), \
                 patch.object(cli.legacy,'run',return_value={
                     'rc':0,'timeout':False,'stdout':'Domain defined',
                     'stderr':'','truncated':False}) as mutator:
                cli.plan(base/'old',base/'reconciled')
                plan_dir=next(base.glob('plan-*'))
                cli.perform(plan_dir)
                self.assertEqual(cli.perform(plan_dir,restore=True),0)
                restored=next(base.glob('restore-*'))
                self.assertTrue(cli.verify_physical(plan_dir,restored))
                self.assertEqual(mutator.call_count,2)

    def test_libvirt_define_failure_preserves_intent_without_retry(self):
        with TemporaryDirectory(prefix='r112-uncertain-') as d:
            base=Path(d)
            before=record()
            with patch.object(cli,'ROOT',base), patch.object(cli,'git_source'), \
                 patch.object(cli,'verified_history',return_value={}), \
                 patch.object(cli,'capture',side_effect=[before,before]), \
                 patch.object(cli.legacy,'run',return_value={
                     'rc':1,'timeout':False,'stdout':'',
                     'stderr':'permission','truncated':False}) as mutator:
                cli.plan(base/'old',base/'reconciled')
                plan_dir=next(base.glob('plan-*'))
                with self.assertRaisesRegex(ValueError,'LIBVIRT_DEFINE_UNCERTAIN_OR_FAILED'):
                    cli.perform(plan_dir)
                self.assertTrue((plan_dir/'apply.once').exists())
                attempt=next(base.glob('apply-*'))
                self.assertEqual({p.name for p in attempt.iterdir()},
                                 {'intent.json','define-result.json'})
                self.assertEqual(mutator.call_count,1)

    def test_no_host_actions_in_engine(self):
        text=(ROOT/'src/ardrec/coordination/r112_runner_nic_definition.py').read_text()
        self.assertNotIn('subprocess',text)
        self.assertNotIn('virsh start',text)
        self.assertNotIn('net-start',text)

    def test_physical_command_allowlist_one_define_only(self):
        script=(ROOT/'scripts/ardrec_p14_r112_runner_nic_definition.py').read_text()
        self.assertEqual(script.count("'define',"),1)
        self.assertNotIn('virsh start',script)
        self.assertNotIn('nft -f',script)


if __name__ == '__main__': unittest.main()
