"""R111-F1: immutable real-receipt reinterpretation and fail-closed controls."""
from __future__ import annotations

from copy import deepcopy
import unittest

import ardrec_p14_r111_legacy_host_snapshot as legacy
from ardrec.coordination import r111_real_host_reconciliation as engine


class R111PhysicalReconciliationTests(unittest.TestCase):
    @staticmethod
    def probes():
        data = {key: {'rc': 0, 'timeout': False, 'truncated': False,
                      'stdout': '', 'stderr': ''}
                for key in legacy.command_list()}
        for role in legacy.ROLES:
            data[f'vm-{role}-state']['stdout'] = 'Apagado\n'
            nets = (role,) if role != 'runner' else ('ssh',)
            xml = ['<domain><name>ardrec-r33-dev-'+role+'</name><devices><disk/>']
            for net in nets:
                xml.append('<interface><source network="ardrec-r33-dev-net-'+net+'"/>'
                           '<filterref filter="ardrec-r33-block-until-containment"/></interface>')
            xml.append('</devices></domain>')
            data[f'vm-{role}-inactive-xml']['stdout'] = ''.join(xml)
        for net in legacy.NETWORKS:
            data[f'net-{net}-info']['stdout'] = 'Nombre: n\nActivo: no\n'
            data[f'net-{net}-xml']['stdout'] = (
                '<network><name>ardrec-r33-dev-net-'+net+'</name>'
                '<bridge name="br33"/><dns enable="no"/></network>')
        data['deny-nwfilter-xml']['stdout'] = (
            '<filter name="ardrec-r33-block-until-containment">'
            '<rule action="drop" direction="inout"/></filter>')
        data['r34-nft']['stdout'] = ('{"nftables":[' + ','.join('{"rule":{}}' for _ in range(4)) + ']}')
        for key in ('libvirt-daemon','f11-boot-unit','f11-watchdog-unit','f11-watchdog-timer'):
            data[key]['stdout'] = 'LoadState=loaded\nActiveState=active\n'
        data['f11-hook-hash']['stdout'] = 'a'*64 + '  /etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny\n'
        return data

    def sample(self):
        probes = self.probes()
        return {'schema': legacy.SCHEMA,
                'commands': {k: list(v) for k,v in legacy.command_list().items()},
                'probes': probes, 'summary': legacy.summarize(probes)}

    def test_spanish_apagado_is_off(self):
        self.assertEqual(engine.normalize_state('Apagado\n'), 'SHUTOFF')
        self.assertEqual(engine.normalize_state('SHUT OFF\n'), 'SHUTOFF')
        self.assertEqual(engine.normalize_state('shutoff'), 'SHUTOFF')

    def test_unknown_states_never_promoted(self):
        for state in ('EN EJECUCIÓN', 'RUNNING', 'Pausado', '', 'APAGÁNDOSE', None):
            self.assertEqual(engine.normalize_state(state), 'UNKNOWN')

    def test_exact_four_locale_false_positives_removed(self):
        record = self.sample()
        original_findings = record['summary']['readiness_findings']
        self.assertEqual(len(original_findings), 5)
        result = engine.build(record, 'f'*64, legacy.summarize)
        self.assertEqual(len(result['reclassified_locale_findings']), 4)
        self.assertEqual(result['remaining_findings'], ['VM_RUNNER_NIC_TOPOLOGY_INCOMPLETE'])
        self.assertEqual(result['domain_states_normalized'], {k:'SHUTOFF' for k in legacy.ROLES})
        self.assertTrue(result['all_four_domains_shutoff_at_snapshot'])
        self.assertEqual(record['summary']['readiness_findings'], original_findings)

    def test_both_missing_runner_nics_identified(self):
        result = engine.build(self.sample(), 'f'*64, legacy.summarize)
        self.assertEqual(result['runner_networks_missing'],
                         ['ardrec-r33-dev-net-ftp','ardrec-r33-dev-net-smb'])

    def test_network_state_parsed_without_assuming_bridge_active(self):
        result = engine.build(self.sample(), 'f'*64, legacy.summarize)
        self.assertEqual(result['network_active_at_snapshot'], {k:'NO' for k in legacy.NETWORKS})
        self.assertEqual(engine.network_active('Name: xyz\n'), 'UNKNOWN')
        self.assertEqual(engine.network_active('Active: yes\n'), 'YES')
        self.assertEqual(engine.network_active('Activo: sí\n'), 'YES')

    def test_bad_original_summary_rejected(self):
        doc = self.sample()
        doc['summary']['readiness_findings'] = []
        with self.assertRaises(engine.ReconciliationError):
            engine.build(doc, 'f'*64, legacy.summarize)

    def test_probe_failure_rejected(self):
        doc = self.sample()
        doc['probes']['vm-ssh-state']['rc'] = 1
        doc['summary'] = legacy.summarize(doc['probes'])
        with self.assertRaises(engine.ReconciliationError):
            engine.build(doc, 'f'*64, legacy.summarize)

    def test_later_running_vm_not_labeled_off(self):
        doc = self.sample()
        doc['probes']['vm-ssh-state']['stdout'] = 'running\n'
        doc['summary'] = legacy.summarize(doc['probes'])
        result = engine.build(doc, 'f'*64, legacy.summarize)
        self.assertFalse(result['all_four_domains_shutoff_at_snapshot'])
        self.assertIn('VM_SSH_NOT_CONFIRMED_SHUTOFF', result['remaining_findings'])
        self.assertEqual(result['domain_states_normalized']['ssh'], 'UNKNOWN')

    def test_reproducible_and_rehashed_tamper_rejected(self):
        doc = self.sample()
        report = engine.build(doc, 'f'*64, legacy.summarize)
        self.assertTrue(engine.verify_report(report, doc, 'f'*64, legacy.summarize))
        self.assertEqual(report, engine.build(deepcopy(doc), 'f'*64, legacy.summarize))
        modified = deepcopy(report)
        modified['remaining_findings'] = []
        modified['sha256'] = engine.sha(engine.canonical({k:v for k,v in modified.items() if k != 'sha256'}))
        with self.assertRaises(engine.ReconciliationError):
            engine.verify_report(modified, doc, 'f'*64, legacy.summarize)

    def test_no_operational_authority(self):
        report = engine.build(self.sample(), 'f'*64, legacy.summarize)
        self.assertFalse(report['f11_positive_admission'])
        self.assertFalse(report['isolation_enforcement_independently_proven'])
        self.assertEqual(report['vm_starts'], 0)
        self.assertEqual(report['protocol_connections'], 0)
        self.assertEqual(report['a6_classification'], 'ND')
        self.assertEqual(report['p8_operational'], 'NO-GO')
        self.assertFalse(report['snapshot_is_current_host_state'])

    def test_original_legacy_inventories_29_read_only_operations(self):
        commands = legacy.command_list()
        self.assertEqual(len(commands), 29)
        for cmd in commands.values():
            self.assertIn(cmd[0], ('virsh','systemctl','sudo'))
            for forbidden in ('start','stop','destroy','define','apply','-f'):
                self.assertNotIn(forbidden, cmd)
            if cmd[0] == 'virsh':
                self.assertEqual(cmd[1:4], ('--readonly', '-c','qemu:///system'))


if __name__ == '__main__':
    unittest.main()
