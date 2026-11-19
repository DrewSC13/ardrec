"""R112-F2: fail-closed checks on real-readonly F11/VM measurements.

Unit fixtures only test the parser; Prometheus performs the actual host capture.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]

from ardrec.coordination import r112_f11_live_readiness as core
from ardrec.coordination import r112_runner_nic_definition as r112
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f11_live_readiness as cli
from test_p14_r112_runner_nic_definition import record

P = 'a'*64
R = 'b'*64
H = '8d46223ee39fb66305c40c24cdf7e0ce0078ce88'


def unit_reads():
    states = {
        'libvirtd.service':'active',
        'ardrec-r34-boot-deny.service':'active',
        'ardrec-r34-deny-watchdog.service':'inactive',
        'ardrec-r34-deny-watchdog.timer':'active',
    }
    out = {}
    for unit,state in states.items():
        fields = 'LoadState=loaded\nActiveState='+state+'\nSubState=dead\n'
        if unit == 'libvirtd.service':
            fields += 'Requires=ardrec-r34-boot-deny.service\nAfter=ardrec-r34-boot-deny.service\n'
        out[unit] = {'rc':0,'stdout':fields,'stderr':'','timeout':False,'truncated':False}
    return out


def report(snapshot=None,units=None):
    return core.build(record(configured=True) if snapshot is None else snapshot,
                      unit_reads() if units is None else units,legacy,
                      plan_sha256=P,applied_receipt_sha256=R,source_head=H)


class R112F2Tests(unittest.TestCase):
    def test_spanish_network_inactive(self):
        self.assertEqual(core.network_active('Nombre: x\nActiva: no\nAutoinicio: no\n'),'INACTIVE')

    def test_english_network_active(self):
        self.assertEqual(core.network_active('Name: x\nActive: yes\n'),'ACTIVE')

    def test_unknown_network_state_remains_unknown(self):
        self.assertEqual(core.network_active('Nombre: x\nActiva: desconocido\n'),'UNKNOWN')
        self.assertEqual(core.network_active('Name: x\n'),'UNKNOWN')
        self.assertEqual(core.network_active('Active: yes\nActive: no\n'),'UNKNOWN')

    def test_exact_real_topology_reconciled(self):
        x=report()
        self.assertEqual(x['runner_inactive_nics'],3)
        self.assertTrue(x['all_four_vms_shutoff'])
        self.assertEqual(x['network_states_observed'],{'ssh':'INACTIVE','ftp':'INACTIVE','smb':'INACTIVE'})
        self.assertEqual(x['f11_root_hook_sha256'],core.F11_HOOK)

    def test_true_boot_gate_remains_deny(self):
        x=report()
        self.assertTrue(x['f11_boot_hook_denies_r33'])
        self.assertEqual(x['operational_admission'],'BLOCKED_F11_EXPLICIT_ALLOW_NOT_IMPLEMENTED')
        self.assertEqual(x['p8_operational'],'NO-GO')
        self.assertEqual(x['real_protocol_observations'],0)

    def test_current_service_state_not_continuous_watchdog_proof(self):
        x=report()
        self.assertEqual(x['f11_watchdog_service_state'],'inactive')
        self.assertTrue(x['f11_timer_active'])
        self.assertFalse(x['f11_independent_watchdog_attested_by_this_report'])
        self.assertFalse(x['f11_first_boot_attested_by_this_report'])

    def test_all_technical_results_unaccredited(self):
        x=report()
        self.assertFalse(x['operational_dispatch'])
        self.assertEqual(x['a5_operational_starts'],0)
        self.assertEqual(x['a6_classification'],'ND')
        self.assertIsNone(x['a7_confirmed_rf'])
        self.assertEqual(x['a9_published_generations'],0)
        self.assertEqual(x['vm_starts_this_step'],0)
        self.assertEqual(x['physical_changes_this_step'],0)

    def test_runner_missing_ftp_smb_rejected(self):
        with self.assertRaises(ValueError):
            report(snapshot=record(configured=False))

    def test_changed_hook_rejected(self):
        s=record(configured=True)
        s['probes']['f11-hook-hash']['stdout']='0'*64+' /hook'
        s['summary']=legacy.summarize(s['probes'])
        with self.assertRaises(ValueError):
            report(snapshot=s)

    def test_running_guest_rejected(self):
        s=record(configured=True)
        s['probes']['vm-smb-state']['stdout']='RUNNING\n'
        s['summary']=legacy.summarize(s['probes'])
        with self.assertRaises(ValueError):
            report(snapshot=s)

    def test_nft_deny_change_rejected(self):
        s=record(configured=True)
        s['probes']['r34-nft']['stdout']='{"nftables":[]}'
        s['summary']=legacy.summarize(s['probes'])
        with self.assertRaises(ValueError):
            report(snapshot=s)

    def test_missing_boot_unit_rejected(self):
        u=unit_reads()
        u['ardrec-r34-boot-deny.service']['stdout']='LoadState=loaded\nActiveState=inactive\n'
        with self.assertRaises(ValueError):
            report(units=u)

    def test_missing_watchdog_timer_rejected(self):
        u=unit_reads()
        u['ardrec-r34-deny-watchdog.timer']['stdout']='LoadState=loaded\nActiveState=inactive\n'
        with self.assertRaises(ValueError):
            report(units=u)

    def test_duplicate_unit_property_rejected(self):
        u=unit_reads()
        u['libvirtd.service']['stdout']+='ActiveState=active\n'
        with self.assertRaises(ValueError):
            report(units=u)

    def test_timeout_cannot_be_hidden(self):
        u=unit_reads()
        u['libvirtd.service']['timeout']=True
        with self.assertRaises(ValueError):
            report(units=u)

    def test_version_and_source_hash_bound(self):
        x=report()
        self.assertTrue(core.verify(x,record(configured=True),unit_reads(),legacy,
                      plan_sha256=P,applied_receipt_sha256=R,source_head=H))
        tampered=deepcopy(x)
        tampered['r112_plan_sha256']='c'*64
        tampered['sha256']=core.sha(core.canonical({k:v for k,v in tampered.items() if k!='sha256'}))
        with self.assertRaises(ValueError):
            core.verify(tampered,record(configured=True),unit_reads(),legacy,
                        plan_sha256=P,applied_receipt_sha256=R,source_head=H)

    def test_private_replay_and_extra_file_denial(self):
        with TemporaryDirectory(prefix='r112-f2-') as temp:
            root=Path(temp)
            s=record(configured=True)
            u=unit_reads()
            x=report(snapshot=s,units=u)
            with patch.object(cli,'ROOT',root):
                directory, manifest=cli.store(s,u,x,plan_sha=P,receipt_sha=R)
                self.assertEqual((x,manifest),cli.verify_private(directory,plan_sha=P,receipt_sha=R))
                (directory/'unexpected').write_text('rogue')
                with self.assertRaises(ValueError):
                    cli.verify_private(directory,plan_sha=P,receipt_sha=R)

    def test_private_bytes_tamper_rejected(self):
        with TemporaryDirectory(prefix='r112-f2-') as temp:
            root=Path(temp)
            s,u=record(configured=True),unit_reads()
            x=report(snapshot=s,units=u)
            with patch.object(cli,'ROOT',root):
                directory,_=cli.store(s,u,x,plan_sha=P,receipt_sha=R)
                p=directory/'readiness.json'
                p.write_bytes(p.read_bytes().replace(b'NO-GO',b'GOXXX'))
                with self.assertRaises(ValueError):
                    cli.verify_private(directory,plan_sha=P,receipt_sha=R)

    def test_only_readonly_systemctl_commands(self):
        commands=cli.unit_commands()
        self.assertEqual(set(commands),set(core.EXTRA_UNITS))
        self.assertEqual(len(commands),4)
        self.assertTrue(all(c[:2]==('systemctl','show') for c in commands.values()))
        self.assertTrue(all(c.count('--property=LoadState')==1 for c in commands.values()))

    def test_no_vm_start_or_host_mutation_in_f2(self):
        cli_text=(REPO/'scripts/ardrec_p14_r112_f11_live_readiness.py').read_text()
        self.assertNotIn('net-start',cli_text)
        self.assertNotIn("'define'",cli_text)
        self.assertNotIn('nft -f',cli_text)
        self.assertNotIn('sudo -n virsh',cli_text)
        self.assertNotIn('systemctl restart',cli_text)
        self.assertNotIn('subprocess',cli_text)


if __name__=='__main__':
    unittest.main()
