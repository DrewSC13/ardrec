"""R35 source chain, deny-first deployment and inactive-state safety tests."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'lab' / 'tests'))
from ardrec.coordination import r33_offline_topology as t33
from ardrec.coordination import r34_containment as t34
from ardrec.coordination import r35_inactive_deployment as t
from test_p14_r33_topology import fixture_r32


BINARIES = {
    'sudo': '/usr/bin/sudo', 'nft': '/usr/sbin/nft', 'ip': '/usr/sbin/ip',
    'virsh': '/usr/bin/virsh', 'qemu-img': '/usr/bin/qemu-img',
    'stat': '/usr/bin/stat', 'sha256sum': '/usr/bin/sha256sum',
    'virt-xml-validate': '/usr/bin/virt-xml-validate',
}


class FakeHostRunner:
    def __init__(self, r32, root, *, collision=None, fail_at=None, drift_after_preflight=False, late_collision=None, late_interface=False,
                 late_active_network=False, late_active_domain=False):
        self.r32 = r32
        self.root = root
        self.collision = collision
        self.fail_at = fail_at
        self.drift_after_preflight = drift_after_preflight
        self.late_collision = late_collision
        self.late_interface = late_interface
        self.late_active_network = late_active_network
        self.late_active_domain = late_active_domain
        self.hash_calls = {}
        self.calls = []
        self.nft_installed = False
        self.filter_defined = False
        self.networks_defined = []
        self.domains_defined = []
        self.xml = t33.render_xml(t33.R32_RECEIPT_FILE_SHA256)
        self.policy = t34.policy_files()
        self.hashes = {}
        self.infos = {}
        for row, asset in zip(r32['roles'], r32['new_assets']):
            role = row['role']
            self.hashes[row['source_base']] = row['source_base_sha256']
            self.hashes[row['parent_overlay']] = row['parent_overlay_sha256']
            self.hashes[row['new_overlay']] = asset['sha256']
            size = row['virtual_size']
            self.infos[row['source_base']] = {'format': 'qcow2', 'virtual-size': size}
            self.infos[row['parent_overlay']] = {
                'format': 'qcow2', 'virtual-size': size,
                'backing-filename': row['source_base'],
                'backing-filename-format': 'qcow2'}
            self.infos[row['new_overlay']] = {
                'format': 'qcow2', 'virtual-size': size,
                'backing-filename': row['parent_overlay'],
                'backing-filename-format': 'qcow2'}

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.fail_at and self.fail_at in argv:
            return mock.Mock(returncode=1, stdout=b'', stderr=b'forced failure')
        cmd = argv
        if cmd[0] == '/usr/bin/sudo':
            cmd = cmd[3:]
        if cmd[0] == '/usr/bin/stat':
            if cmd[1:] == ['--version']:
                data = b'stat (GNU coreutils) 9.5\n'
            else:
                path = cmd[-1]
                if path in ('/var', '/var/lib', '/var/lib/libvirt', '/var/lib/libvirt/images'):
                    data = b'directory|0|0|1|755|4096|1|1|1\n'
                elif path == t33.R32_STAGE:
                    data = b'directory|0|64055|1|750|4096|2|1|1\n'
                elif path.endswith('-base.qcow2'):
                    data = b'regular file|0|0|1|444|128|3|1|1\n'
                elif path.endswith('runtime.qcow2') and path.startswith(t33.PARENT_ROOT + '/'):
                    data = b'regular file|64055|64055|1|600|128|4|1|1\n'
                elif path.endswith('runtime.qcow2') and path.startswith(t33.R32_STAGE + '/'):
                    data = b'regular file|64055|64055|1|600|128|5|1|1\n'
                else:
                    raise AssertionError('unexpected stat path: ' + path)
        elif cmd[0] == '/usr/bin/sha256sum':
            path = cmd[-1]
            self.hash_calls[path] = self.hash_calls.get(path, 0) + 1
            digest = self.hashes[path]
            if self.drift_after_preflight and self.hash_calls[path] >= 2:
                digest = '0' * 64
            data = (digest + ' *' + path + '\n').encode()
        elif cmd[0] == '/usr/bin/qemu-img':
            path = cmd[-1]
            data = json.dumps(self.infos[path]).encode()
        elif cmd[0] == '/usr/sbin/nft':
            if cmd[1:] == ['-j', 'list', 'tables']:
                rows = []
                if self.collision == 'nft' or self.nft_installed:
                    rows.append({'table': {'family': 'bridge', 'name': t.NFT_TABLE}})
                data = json.dumps({'nftables': rows}).encode()
            elif cmd[1:] == ['-c', '-f', '-']:
                data = b''
            elif cmd[1:] == ['-f', '-']:
                self.nft_installed = True
                data = b''
            elif cmd[1:] == ['list', 'table', 'bridge', t.NFT_TABLE]:
                source = self.policy['bridge-deny.nft'].decode()
                data = source.replace('counter drop', 'counter packets 0 bytes 0 drop').encode()
            else:
                raise AssertionError('unexpected nft command: ' + repr(cmd))
        elif cmd[0] == '/usr/sbin/ip':
            if self.late_interface and self.networks_defined:
                data = b'[{"ifname":"lo"},{"ifname":"a33d30t"}]'
            else:
                data = b'[{"ifname":"lo"}]'
        elif cmd[0] == '/usr/bin/virt-xml-validate':
            data = b'validates\n'
        elif cmd[0] == '/usr/bin/virsh':
            if cmd[1:4] == ['--readonly', '-c', 'qemu:///system']:
                args = cmd[4:]
            elif cmd[1:3] == ['-c', 'qemu:///system']:
                args = cmd[3:]
            else:
                raise AssertionError('unexpected virsh connection: ' + repr(cmd))
            verb = args[0]
            if verb in ('list', 'net-list', 'nwfilter-list'):
                if self.late_active_domain and self.domains_defined and args == ['list', '--name']:
                    data = (self.domains_defined[0] + '\n').encode()
                elif (self.collision == 'domain' or
                    (self.late_collision == 'domain' and self.networks_defined)) and args == ['list', '--all', '--name']:
                    data = b'ardrec-r33-dev-ssh\n'
                elif self.late_active_network and self.networks_defined and args == ['net-list', '--name']:
                    data = (self.networks_defined[0] + '\n').encode()
                elif (self.collision == 'network' or
                      (self.late_collision == 'network' and self.nft_installed)) and args == ['net-list', '--all', '--name']:
                    data = b'ardrec-r33-dev-net-ssh\n'
                elif (self.collision == 'filter' or
                      (self.late_collision == 'filter' and self.nft_installed)) and args == ['nwfilter-list', '--name']:
                    data = (t.FILTER_NAME + '\n').encode()
                elif args == ['list', '--all', '--name'] and self.domains_defined:
                    data = ('\n'.join(self.domains_defined) + '\n').encode()
                elif args == ['net-list', '--all', '--name'] and self.networks_defined:
                    data = ('\n'.join(self.networks_defined) + '\n').encode()
                elif args == ['nwfilter-list', '--name'] and self.filter_defined:
                    data = (t.FILTER_NAME + '\n').encode()
                else:
                    data = b''
            elif verb == 'nwfilter-dumpxml':
                data = self.policy['nwfilter-deny.xml']
            elif verb == 'net-dumpxml':
                name = args[1]
                role = name.removeprefix(t33.NETWORK_PREFIX)
                data = self.xml[f'network-{role}.xml']
            elif verb == 'net-info':
                data = b'Name: test\nActive: no\nAutostart: no\n'
            elif verb == 'dumpxml':
                name = args[1]
                role = name.removeprefix(t33.DOMAIN_PREFIX)
                data = self.xml[f'domain-{role}.xml']
            elif verb == 'domstate':
                data = b'shut off\n'
            elif verb == 'dominfo':
                data = b'Autostart: disable\n'
            elif verb == 'nwfilter-define':
                self.filter_defined = True
                data = b''
            elif verb == 'net-define':
                name = Path(args[1]).name.removeprefix('network-').removesuffix('.xml')
                self.networks_defined.append(t33.NETWORK_PREFIX + name)
                data = b''
            elif verb == 'define':
                name = Path(args[2]).name.removeprefix('domain-').removesuffix('.xml')
                self.domains_defined.append(t33.DOMAIN_PREFIX + name)
                data = b''
            else:
                raise AssertionError('unexpected virsh verb: ' + repr(args))
        else:
            raise AssertionError('unexpected command: ' + repr(cmd))
        return mock.Mock(returncode=0, stdout=data, stderr=b'')


class R35Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.r32 = fixture_r32()
        self.r33 = t33.make_report(self.r32, t33.R32_RECEIPT_FILE_SHA256, prepared=True)
        self.r34 = t34.report(self.r33, prepared=True)
        self.xml = t33.render_xml(t33.R32_RECEIPT_FILE_SHA256)
        self.policy = t34.policy_files()
        (self.root / t.R33_DIR).mkdir(mode=0o700)
        (self.root / t.R34_DIR).mkdir(mode=0o700)
        for name, raw in self.xml.items():
            (self.root / t.R33_DIR / name).write_bytes(raw)
        for name, raw in self.policy.items():
            (self.root / t.R34_DIR / name).write_bytes(raw)
        self.bundle = {'root': self.root, 'r32': self.r32,
                       'r33': self.r33, 'r34': self.r34,
                       'attestation': {'sha256': 'a' * 64}}
        self.preflight = {'sha256': 'b' * 64}

    def host(self, **options):
        fake = FakeHostRunner(self.r32, self.root, **options)
        host = t.Host(runner=fake, which=lambda name: BINARIES.get(name))
        return host, fake

    def test_source_archive_pin_and_inventory_are_exact(self):
        self.assertEqual(len(t.EXPECTED_MEMBERS), 24)
        self.assertEqual(t.ARCHIVE_SHA256,
                         '58e7cf2f59dd97cab948c190d637b6ff8ee8f67b45400769fe0d97a9e8f2ea36')
        self.assertEqual(t.TAPS, ('a33d30r', 'a33d30t', 'a33d31r',
                                  'a33d31t', 'a33d32r', 'a33d32t'))

    def test_nft_dump_accepts_only_the_r34_scoped_table(self):
        expected = self.policy['bridge-deny.nft']
        actual = expected.decode().replace('counter drop',
                                            'counter packets 0 bytes 0 drop').encode()
        t._verify_nft_dump(actual, expected)

    def test_nft_dump_rejects_extra_rule(self):
        expected = self.policy['bridge-deny.nft']
        bad = expected + b'\nflush ruleset\n'
        with self.assertRaises(t.R35Error):
            t._verify_nft_dump(bad, expected)

    def test_all_three_network_xml_bindings_are_exact(self):
        for role in t33.NET_BRIDGE:
            name = f'network-{role}.xml'
            t._verify_network_dump(self.xml[name], self.xml[name], role)

    def test_all_four_domain_xml_bindings_are_exact(self):
        for role in t33.ROLES:
            name = f'domain-{role}.xml'
            t._verify_domain_dump(self.xml[name], self.xml[name], role)

    def test_domain_xml_wrong_filter_is_rejected(self):
        raw = self.xml['domain-ssh.xml'].replace(
            t.FILTER_NAME.encode(), b'wrong-filter-name')
        with self.assertRaises(t.R35Error):
            t._xml_semantic(raw, 'domain', 'ssh')

    def test_filter_is_deny_all(self):
        t34.verify_filter(self.policy['nwfilter-deny.xml'])
        bad = self.policy['nwfilter-deny.xml'].replace(b'action="drop"', b'action="accept"')
        with self.assertRaises(ValueError):
            t34.verify_filter(bad)

    def test_stat_parser_is_strict(self):
        parsed = t._parse_stat(b'regular file|64055|64055|1|600|99|5|1|1\n')
        self.assertEqual(parsed['uid'], 64055)
        self.assertEqual(parsed['mode'], 0o600)
        with self.assertRaises(t.R35Error):
            t._parse_stat(b'regular file|x|0|1|600|99|5|1|1\n')

    def test_sha256sum_parser_binds_exact_path(self):
        path = '/var/lib/libvirt/images/ardrec-dev-point4-r32/ssh-runtime.qcow2'
        digest = 'a' * 64
        self.assertEqual(t._parse_hash((digest + ' *' + path + '\n').encode(), path), digest)
        with self.assertRaises(t.R35Error):
            t._parse_hash((digest + ' */tmp/other.qcow2\n').encode(), path)

    def test_qcow_info_checks_backing_chain(self):
        t._verify_qcow_info(json.dumps({'format': 'qcow2', 'virtual-size': 8192}).encode(),
                            virtual_size=8192, backing=None)
        with self.assertRaises(t.R35Error):
            t._verify_qcow_info(json.dumps({'format': 'qcow2', 'virtual-size': 8192,
                                           'backing-filename': '/tmp/wrong'}).encode(),
                                virtual_size=8192, backing='/var/lib/right')

    def test_network_must_be_inactive_and_not_autostart(self):
        t._verify_inactive_info(b'Name: net\nActive: no\nAutostart: no\n', kind='network')
        with self.assertRaises(t.R35Error):
            t._verify_inactive_info(b'Name: net\nActive: yes\nAutostart: no\n', kind='network')

    def test_domain_must_be_shut_off_and_autostart_disabled(self):
        t._verify_inactive_info(b'shut off\n', kind='domain')
        t._verify_domain_autostart(b'Autostart: disable\n')
        with self.assertRaises(t.R35Error):
            t._verify_domain_autostart(b'Autostart: enable\n')

    def test_readonly_host_preflight_passes_with_exact_fake_assets(self):
        _, fake = self.host()
        report, returned_host = t.host_preflight(self.bundle, runner=fake,
                                                  which=lambda name: BINARIES.get(name))
        self.assertTrue(t.verify_host_report(report))
        self.assertEqual(report['qcow2_assets_verified'], 12)
        self.assertFalse(report['firewall_modified'])
        self.assertFalse(report['vm_started'])
        self.assertFalse(any('define' in call[0] or 'start' in call[0]
                             for call in fake.calls))

    def test_preflight_rejects_existing_network_collision(self):
        _, fake = self.host(collision='network')
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake, which=lambda name: BINARIES.get(name))
        self.assertFalse(fake.nft_installed)

    def test_preflight_rejects_existing_nft_table_collision(self):
        _, fake = self.host(collision='nft')
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake, which=lambda name: BINARIES.get(name))
        self.assertFalse(fake.nft_installed)

    def test_host_command_boundary_rejects_start_and_flush(self):
        host, _ = self.host()
        with self.assertRaises(t.R35Error):
            host.virsh_write(['start', 'ardrec-r33-dev-ssh'])
        with self.assertRaises(t.R35Error):
            host.sudo([host.bin['nft'], 'flush', 'ruleset'])
        with self.assertRaises(t.R35Error):
            host.sudo([host.bin['virsh'], '-c', 'qemu:///system',
                       'start', 'ardrec-r33-dev-ssh'])

    def test_activation_guard_rejects_any_start_command(self):
        with self.assertRaises(t.R35Error):
            t._check_activation_absent([{'argv': ['/usr/bin/virsh', 'start', 'vm']}])
        with self.assertRaises(t.R35Error):
            t._check_activation_absent([{'argv': ['/usr/bin/sudo', '-n', '--',
                                                    '/usr/sbin/nft', 'flush', 'ruleset']}])

    def test_preflight_report_cannot_claim_mutation(self):
        _, fake = self.host()
        report, _ = t.host_preflight(self.bundle, runner=fake,
                                      which=lambda name: BINARIES.get(name))
        report['vm_started'] = True
        report['sha256'] = t.sha(t.canon({k: v for k, v in report.items() if k != 'sha256'}))
        with self.assertRaises(t.R35Error):
            t.verify_host_report(report)

    def test_preflight_only_deployment_report_has_no_install_claim(self):
        report = t.deployment_report(self.bundle, self.preflight,
                                     status='PREFLIGHT_PASS_NOT_INSTALLED')
        self.assertTrue(t.verify_deployment_report(report))
        self.assertFalse(report['nft_table_installed'])
        self.assertFalse(report['nwfilter_defined'])
        self.assertEqual(report['networks_defined'], [])
        self.assertEqual(report['domains_defined'], [])

    def test_success_report_requires_all_three_networks_and_four_domains(self):
        report = t.deployment_report(
            self.bundle, self.preflight, status='DEPLOYMENT_COMPLETE_INACTIVE',
            nft_installed=True, filter_defined=True, filter_verified=True, networks_defined=list(t.NETWORKS),
            domains_defined=list(t.DOMAINS), networks_inactive=list(t.NETWORKS),
            domains_shut_off=list(t.DOMAINS), autostart_disabled=True,
            storage_revalidated=True, collision_rechecks=True,
            interfaces_absent_before_domains=True, table_verified=True, interfaces_absent_after=True)
        self.assertTrue(t.verify_deployment_report(report))
        report['vm_started'] = True
        report['sha256'] = t.sha(t.canon({k: v for k, v in report.items() if k != 'sha256'}))
        with self.assertRaises(t.R35Error):
            t.verify_deployment_report(report)

    def test_success_claim_rejects_missing_domain(self):
        with self.assertRaises(t.R35Error):
            t.deployment_report(
                self.bundle, self.preflight, status='DEPLOYMENT_COMPLETE_INACTIVE',
                nft_installed=True, filter_defined=True, filter_verified=True, networks_defined=list(t.NETWORKS),
                domains_defined=list(t.DOMAINS[:-1]), networks_inactive=list(t.NETWORKS),
                domains_shut_off=list(t.DOMAINS), autostart_disabled=True,
                storage_revalidated=True, collision_rechecks=True,
            interfaces_absent_before_domains=True, table_verified=True, interfaces_absent_after=True)

    def test_fake_end_to_end_defines_only_inactive_resources(self):
        host, fake = self.host()
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'DEPLOYMENT_COMPLETE_INACTIVE')
        self.assertEqual(set(result['networks_defined']), set(t.NETWORKS))
        self.assertEqual(set(result['domains_defined']), set(t.DOMAINS))
        self.assertTrue(result['nft_table_verified'])
        self.assertTrue(result['nwfilter_verified'])
        self.assertTrue(result['autostart_disabled_verified'])
        self.assertTrue(result['qcow2_revalidated_before_domain_definition'])
        self.assertTrue(result['libvirt_collisions_rechecked_before_each_definition'])
        self.assertTrue(result['tap_and_bridge_names_absent_before_domain_definition'])
        self.assertFalse(result['network_started'])
        self.assertFalse(result['vm_started'])
        verbs = [token for call, _ in fake.calls for token in call]
        self.assertNotIn('start', verbs)
        self.assertNotIn('net-start', verbs)
        self.assertNotIn('autostart', verbs)
        self.assertNotIn('flush', verbs)

    def test_partial_failure_is_not_rolled_back_or_promoted(self):
        host, fake = self.host(fail_at='nwfilter-define')
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertTrue(result['nft_table_installed'])
        self.assertFalse(result['nwfilter_defined'])
        self.assertFalse(result['vm_started'])
        self.assertEqual(result['p8_operational'], 'NO-GO')



    def test_late_active_network_is_reported_and_not_stopped(self):
        _, fake = self.host(late_active_network=True)
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(result['active_networks_observed'], [t.NETWORKS[0]])
        self.assertFalse(result['network_started'])
        self.assertFalse(result['activation_commands_invoked'])
        self.assertEqual(result['p8_operational'], 'NO-GO')

    def test_late_active_domain_is_reported_and_not_stopped(self):
        _, fake = self.host(late_active_domain=True)
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(result['active_domains_observed'], [t.DOMAINS[0]])
        self.assertFalse(result['vm_started'])
        self.assertFalse(result['activation_commands_invoked'])
        self.assertEqual(result['p8_operational'], 'NO-GO')

    def test_late_libvirt_name_collision_blocks_domain_definitions(self):
        _, fake = self.host(late_collision='domain')
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(set(result['networks_defined']), set(t.NETWORKS))
        self.assertEqual(result['domains_defined'], [])
        self.assertFalse(result['vm_started'])

    def test_late_tap_collision_blocks_domain_definitions(self):
        _, fake = self.host(late_interface=True)
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(set(result['networks_defined']), set(t.NETWORKS))
        self.assertEqual(result['domains_defined'], [])
        self.assertFalse(result['vm_started'])

    def test_qcow2_drift_after_network_definition_blocks_all_domains(self):
        _, fake = self.host(drift_after_preflight=True)
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda name: BINARIES.get(name))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertTrue(result['nft_table_installed'])
        self.assertTrue(result['nwfilter_defined'])
        self.assertEqual(set(result['networks_defined']), set(t.NETWORKS))
        self.assertEqual(result['domains_defined'], [])
        self.assertFalse(result['vm_started'])
        self.assertEqual(result['p8_operational'], 'NO-GO')


if __name__ == '__main__':
    unittest.main()
