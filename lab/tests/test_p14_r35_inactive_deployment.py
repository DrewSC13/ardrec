"""R35 source chain, deny-first deployment and inactive-state safety tests."""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
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


def nft_json_fixture(*, corrupt: str | None = None) -> bytes:
    """Equivalent to /usr/sbin/nft -j -a list table bridge ardrec_r34_guard."""
    data = [{'metainfo': {'version': '1.1.0'}},
            {'table': {'family': 'bridge', 'name': t.NFT_TABLE, 'handle': 12}}]
    for i, name in enumerate(('input', 'output', 'forward')):
        data.append({'chain': {'family': 'bridge', 'table': t.NFT_TABLE,
                   'name': name, 'handle': i + 1, 'type': 'filter',
                   'hook': name, 'prio': -200, 'policy': 'accept'}})
    for i, (chain, direction) in enumerate((
        ('input', 'iifname'), ('output', 'oifname'),
        ('forward', 'iifname'), ('forward', 'oifname'),
    )):
        data.append({'rule': {'family': 'bridge', 'table': t.NFT_TABLE,
            'chain': chain, 'handle': 5 + i * 2,
            'expr': [{'match': {'left': {'meta': {'key': direction}},
                               'op': '==', 'right': {'set': list(t.TAPS)}}},
                     {'counter': {'packets': 0, 'bytes': 0}}, {'drop': None}]}})
    if corrupt == 'priority': data[2]['chain']['prio'] = -199
    if corrupt == 'extra_rule': data.append(data[-1])
    if corrupt == 'accept': data[-1]['rule']['expr'][-1] = {'accept': None}
    if corrupt == 'interfaces': data[-1]['rule']['expr'][0]['match']['right']['set'][-1]='other-tap'
    if corrupt == 'chain_policy': data[2]['chain']['policy']='drop'
    if corrupt == 'wrong_hook': data[2]['chain']['hook']='output'
    if corrupt == 'duplicate_rule': data[-1] = data[-2]
    if corrupt == 'extra_expression': data[-1]['rule']['expr'].insert(1, {'log': {'prefix':'bad'}})
    return json.dumps({'nftables': data}, sort_keys=True).encode('ascii')


class FakeHostRunner:
    def __init__(self, r32, root, *, collision=None, fail_at=None, drift_after_preflight=False, late_collision=None, late_interface=False,
                 late_active_network=False, late_active_domain=False, nft_corrupt=None,
                 normalized_network=False):
        self.r32 = r32
        self.root = root
        self.collision = collision
        self.fail_at = fail_at
        self.drift_after_preflight = drift_after_preflight
        self.late_collision = late_collision
        self.late_interface = late_interface
        self.late_active_network = late_active_network
        self.late_active_domain = late_active_domain
        self.nft_corrupt = nft_corrupt
        self.normalized_network = normalized_network
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
            elif cmd[1:] == ['-j', '-a', 'list', 'table', 'bridge', t.NFT_TABLE]:
                data = nft_json_fixture(corrupt=self.nft_corrupt)
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
                elif args == ['nwfilter-list']:
                    affected = (self.collision in ('filter', 'filter_uuid') or
                                (self.late_collision == 'filter' and self.nft_installed) or
                                self.filter_defined)
                    data = b' UUID  Name\n----------------------------------------\n'
                    if affected:
                        ident = ET.fromstring(self.policy['nwfilter-deny.xml']).findtext('uuid')
                        name = ('other-filter' if self.collision == 'filter_uuid'
                                else t.FILTER_NAME)
                        data += f' {ident}  {name}\n'.encode('ascii')
                elif args == ['net-list', '--all', '--uuid'] and self.networks_defined:
                    data = ('\n'.join(ET.fromstring(self.xml[f'network-{n.removeprefix(t33.NETWORK_PREFIX)}.xml']).findtext('uuid') for n in self.networks_defined) + '\n').encode()
                elif args == ['list', '--all', '--uuid'] and self.domains_defined:
                    data = ('\n'.join(ET.fromstring(self.xml[f'domain-{n.removeprefix(t33.DOMAIN_PREFIX)}.xml']).findtext('uuid') for n in self.domains_defined) + '\n').encode()
                elif args == ['list', '--all', '--name'] and self.domains_defined:
                    data = ('\n'.join(self.domains_defined) + '\n').encode()
                elif args == ['net-list', '--all', '--name'] and self.networks_defined:
                    data = ('\n'.join(self.networks_defined) + '\n').encode()
                else:
                    data = b''
            elif verb == 'nwfilter-dumpxml':
                data = self.policy['nwfilter-deny.xml']
            elif verb == 'net-dumpxml':
                name = args[1]
                role = name.removeprefix(t33.NETWORK_PREFIX)
                data = self.xml[f'network-{role}.xml']
                if self.normalized_network:
                    root = ET.fromstring(data)
                    root.attrib.pop('ipv6', None)
                    addr = {'ssh':t.SSH_BRIDGE_MAC_R353, 'ftp':'52:54:00:12:34:56',
                            'smb':'52:54:00:65:43:21'}[role]
                    bridge = root.find('bridge')
                    mac = ET.Element('mac', {'address':addr})
                    root.insert(list(root).index(bridge) + 1, mac)
                    data = ET.tostring(root, encoding='utf-8')
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

    def test_nwfilter_inventory_real_virsh_table(self):
        empty = b' UUID    Name\n--------------------------------------\n'
        self.assertEqual(t._nwfilter_inventory(empty), (set(), set()))
        full = (empty +
                b' 1A2B3C4D-0000-1111-2222-123456789abc  clean-traffic\n')
        names, uuids = t._nwfilter_inventory(full)
        self.assertEqual(names, {'clean-traffic'})
        self.assertEqual(uuids, {'1a2b3c4d-0000-1111-2222-123456789abc'})

    def test_nwfilter_inventory_rejects_malformed_and_duplicates(self):
        head = b' UUID  Name\n------------------------\n'
        for raw in (b'', b'unknown\n',
                    head+b'invalid-uuid filter\n',
                    head+b'00000000-0000-0000-0000-000000000001 name other\n',
                    head+(b'00000000-0000-0000-0000-000000000001 same\n'*2)):
            with self.subTest(raw=raw):
                with self.assertRaises(t.R35Error):
                    t._nwfilter_inventory(raw)

    def test_nwfilter_preflight_uses_only_supported_options(self):
        _, fake = self.host()
        t.host_preflight(self.bundle, runner=fake,
                         which=lambda name: BINARIES.get(name))
        commands = [c[0] for c in fake.calls]
        self.assertIn(['/usr/bin/virsh', '--readonly', '-c',
                       'qemu:///system', 'nwfilter-list'], commands)
        self.assertFalse(any('nwfilter-list' in cmd and
                             any(x in cmd for x in ('--name', '--uuid'))
                             for cmd in commands))

    def test_nwfilter_collision_by_name_rejected(self):
        _, fake = self.host(collision='filter')
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake,
                             which=lambda name: BINARIES.get(name))
        self.assertFalse(fake.nft_installed)

    def test_nwfilter_collision_by_uuid_rejected(self):
        _, fake = self.host(collision='filter_uuid')
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake,
                             which=lambda name: BINARIES.get(name))
        self.assertFalse(fake.nft_installed)

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


    def test_nft_json_accepts_real_host_numeric_priority(self):
        t._verify_nft_json(nft_json_fixture())
        host, fake = self.host()
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                                           which=lambda n: BINARIES.get(n))
        result = t.deploy(self.bundle, preflight, host)
        self.assertEqual(result['status'], 'DEPLOYMENT_COMPLETE_INACTIVE')
        self.assertTrue(any(call[0][4:7] == ['-j', '-a', 'list'] for call in fake.calls))

    def test_nft_json_rejects_priority_or_policy_or_extra_rule(self):
        for issue in ('priority', 'extra_rule', 'accept', 'interfaces',
                      'chain_policy', 'wrong_hook', 'duplicate_rule', 'extra_expression'):
            with self.subTest(issue=issue):
                with self.assertRaises(t.R35Error):
                    t._verify_nft_json(nft_json_fixture(corrupt=issue))

    def test_resume_requires_existing_exact_table(self):
        host, fake = self.host()
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake,
                             which=lambda n: BINARIES.get(n), existing_nft=True)
        self.assertFalse(fake.nft_installed)

    def test_resume_preflight_rejects_corrupt_nft(self):
        _, fake = self.host(nft_corrupt='priority')
        fake.nft_installed=True
        with self.assertRaises(t.R35Error):
            t.host_preflight(self.bundle, runner=fake,
                             which=lambda n: BINARIES.get(n), existing_nft=True)
        self.assertFalse(fake.filter_defined)

    def test_resume_exact_table_no_second_nft_write(self):
        host, fake = self.host()
        fake.nft_installed=True
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                           which=lambda n: BINARIES.get(n), existing_nft=True)
        self.assertTrue(preflight['nft_existing_verified_json'])
        report = t.deploy(self.bundle, preflight, host, reuse_verified_nft=True)
        self.assertEqual(report['status'], 'DEPLOYMENT_COMPLETE_INACTIVE')
        self.assertTrue(report['nft_table_verified'])
        self.assertEqual(report['domains_defined'], list(t.DOMAINS))
        self.assertFalse(any(call[0][3:] == ['/usr/sbin/nft','-f','-']
                             for call in fake.calls))
        self.assertFalse(report['vm_started'])

    def test_resume_never_writes_when_prior_state_invalid(self):
        temp=Path(self.temp.name)/'recibos-instalacion-fake'
        temp.mkdir(mode=0o700)
        with self.assertRaises(t.R35Error):
            t.verify_prior_partial_receipt(temp,self.bundle)

    def test_resume_rejects_changed_table_on_final_readback(self):
        host, fake = self.host()
        fake.nft_installed=True
        preflight, host = t.host_preflight(self.bundle, runner=fake,
                           which=lambda n: BINARIES.get(n), existing_nft=True)
        fake.nft_corrupt='priority'
        report=t.deploy(self.bundle,preflight,host,reuse_verified_nft=True)
        self.assertEqual(report['status'],'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertEqual(report['domains_defined'],[])
        self.assertEqual(report['networks_defined'],[])
        self.assertFalse(fake.filter_defined)

    def test_fresh_install_rejects_bad_json_after_nft_write(self):
        host, fake=self.host(nft_corrupt='interfaces')
        preflight, host=t.host_preflight(self.bundle,runner=fake,
                         which=lambda n: BINARIES.get(n))
        result=t.deploy(self.bundle,preflight,host)
        self.assertEqual(result['status'],'PARTIAL_NO_GO_REVIEW_REQUIRED')
        self.assertTrue(fake.nft_installed)
        self.assertFalse(fake.filter_defined)
        self.assertEqual(result['failure_code'],'nft_interface_set_invalid')

    def test_resume_host_report_cannot_claim_table_absent(self):
        host,fake=self.host();fake.nft_installed=True
        report,_=t.host_preflight(self.bundle,runner=fake,
                  which=lambda n: BINARIES.get(n),existing_nft=True)
        report['nft_table_absent']=True
        report['sha256']=t.sha(t.canon({k:v for k,v in report.items() if k!='sha256'}))
        with self.assertRaises(t.R35Error): t.verify_host_report(report)

    def _historical_partial(self):
        path = self.root / 'recibos-instalacion-test-r35'
        path.mkdir(mode=0o700)
        host,fake=self.host()
        old_host,_=t.host_preflight(self.bundle,runner=fake,
                                     which=lambda n: BINARIES.get(n))
        # Historical R35.1 preflight had no nft_existing_verified_json.
        old_host.pop('nft_existing_verified_json')
        old_host['sha256']=t.sha(t.canon({k:v for k,v in old_host.items() if k!='sha256'}))
        deployment=t.deployment_report(self.bundle,old_host,
            status='PARTIAL_NO_GO_REVIEW_REQUIRED',
            nft_installed=True,failure='installed_nft_table_semantics_mismatch')
        nft_text='table bridge '+t.NFT_TABLE+' {\n chain input { type filter hook input priority filter; policy accept; }\n}\n'
        commands=[
          {'argv':['/usr/bin/sudo','-n','--','/usr/sbin/nft','-f','-'],
           'returncode':0,'stdout_sha256':t.sha(b''),'stderr_sha256':t.sha(b''),'stdout':'','stderr':''},
          {'argv':['/usr/bin/sudo','-n','--','/usr/sbin/nft','list','table','bridge',t.NFT_TABLE],
           'returncode':0,'stdout_sha256':t.sha(nft_text.encode()),
           'stderr_sha256':t.sha(b''),'stdout':nft_text,'stderr':''},
        ]
        t._write_receipts(path,{
            'r35_source_attestation.json':self.bundle['attestation'],
            'r35_host_preflight.json':old_host,
            'r35_deployment.json':deployment,
        },commands)
        return path

    def test_prior_partial_receipt_exact_authentication(self):
        receipt=self._historical_partial()
        old=json.loads((receipt/'r35_deployment.json').read_text())
        with mock.patch.object(t,'R35_PARTIAL_REPORT_SHA256',old['sha256']):
            attestation=t.verify_prior_partial_receipt(receipt,self.bundle)
        self.assertTrue(attestation['old_nft_installed'])
        self.assertTrue(attestation['old_libvirt_definitions_absent'])

    def test_prior_partial_receipt_rejects_changed_file(self):
        receipt=self._historical_partial()
        (receipt/'commands.jsonl').write_bytes(b'changed')
        old=json.loads((receipt/'r35_deployment.json').read_text())
        with mock.patch.object(t,'R35_PARTIAL_REPORT_SHA256',old['sha256']):
            with self.assertRaises(t.R35Error):
                t.verify_prior_partial_receipt(receipt,self.bundle)

    def test_prior_partial_receipt_rejects_extra_libvirt_write(self):
        receipt=self._historical_partial()
        records=[json.loads(x) for x in (receipt/'commands.jsonl').read_text().splitlines()]
        records.append({'argv':['/usr/bin/sudo','-n','--','/usr/bin/virsh',
                         '-c','qemu:///system','net-define','/tmp/a.xml'],
                        'returncode':0,'stdout_sha256':t.sha(b''),'stderr_sha256':t.sha(b'')})
        (receipt/'commands.jsonl').write_bytes(b''.join(t.canon(x)+b'\n' for x in records))
        lines=[]
        for path in sorted(receipt.iterdir()):
            if path.name!='SHA256SUMS':
                lines.append(t.sha(path.read_bytes())+'  '+path.name)
        (receipt/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
        old=json.loads((receipt/'r35_deployment.json').read_text())
        with mock.patch.object(t,'R35_PARTIAL_REPORT_SHA256',old['sha256']):
            with self.assertRaises(t.R35Error):
                t.verify_prior_partial_receipt(receipt,self.bundle)

    def test_resume_readonly_preflight_report(self):
        host,fake=self.host();fake.nft_installed=True
        preflight,_=t.host_preflight(self.bundle,runner=fake,
                           which=lambda n: BINARIES.get(n),existing_nft=True)
        doc=t.deployment_report(self.bundle,preflight,
             status='RESUME_PREFLIGHT_PASS_EXISTING_NFT',
             nft_installed=True,table_verified=True)
        doc['recovery_mode']='EXISTING_NFT_VERIFIED_JSON'
        doc['prior_partial_receipt_sha256']='a'*64
        doc['resume_attestation_sha256']='b'*64
        doc['sha256']=t.sha(t.canon({k:v for k,v in doc.items() if k!='sha256'}))
        t.verify_deployment_report(doc)
        self.assertFalse(any('net-define' in call[0] or 'nwfilter-define' in call[0]
                             or 'define' in call[0] for call in fake.calls))
        self.assertFalse(any(call[0][3:] == ['/usr/sbin/nft','-f','-']
                             for call in fake.calls))

    def test_r353_network_normalization_accepts_only_expected_semantics(self):
        original=self.xml['network-ssh.xml']
        root=ET.fromstring(original)
        root.attrib.pop('ipv6')
        root.insert(3, ET.Element('mac', {'address':t.SSH_BRIDGE_MAC_R353}))
        normalized=ET.tostring(root, encoding='utf-8')
        self.assertEqual(t._network_bridge_mac(normalized, original, 'ssh'),
                         t.SSH_BRIDGE_MAC_R353)
        self.assertIsNone(t._network_bridge_mac(original, original, 'ssh'))
        for bad in ('forward', 'ip', 'dhcp', 'route', 'network'):
            with self.subTest(extra=bad):
                mutated=ET.fromstring(normalized)
                ET.SubElement(mutated,bad)
                with self.assertRaises(t.R35Error):
                    t._network_bridge_mac(ET.tostring(mutated), original, 'ssh')

    def test_r353_network_rejects_ipv6_enable_or_bridge_drift(self):
        original=self.xml['network-ssh.xml']
        for bad in ('ipv6', 'bridge', 'dns', 'uuid', 'extra_root'):
            with self.subTest(bad=bad):
                root=ET.fromstring(original)
                if bad=='ipv6': root.set('ipv6','yes')
                if bad=='bridge': root.find('bridge').set('name','virbr0')
                if bad=='dns': root.find('dns').set('enable','yes')
                if bad=='uuid': root.find('uuid').text='ffffffff-ffff-ffff-ffff-ffffffffffff'
                if bad=='extra_root': root.set('isolated','no')
                with self.assertRaises(t.R35Error):
                    t._network_bridge_mac(ET.tostring(root), original, 'ssh')

    def test_r353_network_rejects_mac_spoof_or_duplicate(self):
        original=self.xml['network-ssh.xml']
        for mac in ('ff:ff:ff:ff:ff:ff', '01:11:22:33:44:55',
                    '02:11:22:33:44:GG', '52:54:00:59:04:5a:11'):
            with self.subTest(mac=mac):
                root=ET.fromstring(original)
                ET.SubElement(root,'mac',{'address':mac})
                with self.assertRaises(t.R35Error):
                    t._network_bridge_mac(ET.tostring(root), original, 'ssh')
        with self.assertRaises(t.R35Error):
            t._verify_network_mac_inventory({'ssh':t.SSH_BRIDGE_MAC_R353,
                 'ftp':t.SSH_BRIDGE_MAC_R353},prior_ssh=True)
        with self.assertRaises(t.R35Error):
            t._verify_network_mac_inventory({'ssh':'52:54:00:11:22:33'},prior_ssh=True)

    def r353_fake(self, **kw):
        host,fake=self.host(normalized_network=True,**kw)
        fake.nft_installed=True
        fake.filter_defined=True
        fake.networks_defined=[t33.NETWORK_PREFIX+'ssh']
        return host,fake

    def test_r353_preflight_reuses_exact_installed_filter_and_ssh_readonly(self):
        _,fake=self.r353_fake()
        report,host=t.host_preflight(self.bundle,runner=fake,
                  which=lambda name:BINARIES.get(name),existing_nft=True,
                  existing_filter=True,existing_networks=('ssh',))
        self.assertTrue(t.verify_host_report(report))
        self.assertEqual(report['existing_network_bridge_macs'],{'ssh':t.SSH_BRIDGE_MAC_R353})
        self.assertEqual(report['qcow2_assets_verified'],12)
        self.assertFalse(any('net-define' in argv or 'nwfilter-define' in argv
                        or argv[4:]==['-f','-'] for argv,_ in fake.calls))

    def test_r353_preflight_rejects_unexpected_existing_resources(self):
        for condition in ('missing_filter', 'missing_ssh','extra_ftp','other_nft'):
            with self.subTest(condition=condition):
                _,fake=self.r353_fake()
                if condition=='missing_filter':fake.filter_defined=False
                if condition=='missing_ssh':fake.networks_defined=[]
                if condition=='extra_ftp':fake.networks_defined.append(t33.NETWORK_PREFIX+'ftp')
                if condition=='other_nft':fake.nft_corrupt='priority'
                with self.assertRaises(t.R35Error):
                    t.host_preflight(self.bundle,runner=fake,
                           which=lambda name:BINARIES.get(name),existing_nft=True,
                           existing_filter=True,existing_networks=('ssh',))

    def test_r353_resume_never_redefines_nft_filter_ssh(self):
        _,fake=self.r353_fake()
        report,host=t.host_preflight(self.bundle,runner=fake,
                  which=lambda name:BINARIES.get(name),existing_nft=True,
                  existing_filter=True,existing_networks=('ssh',))
        result=t.deploy(self.bundle, report, host, reuse_verified_nft=True,
                         reuse_verified_filter_ssh=True)
        self.assertEqual(result['status'],'DEPLOYMENT_COMPLETE_INACTIVE')
        self.assertEqual(result['network_bridge_macs']['ssh'],t.SSH_BRIDGE_MAC_R353)
        self.assertEqual(len(result['networks_defined']),3)
        self.assertEqual(len(result['domains_defined']),4)
        sudo_virsh=[argv for argv,_ in fake.calls if argv[:4]==
               ['/usr/bin/sudo','-n','--','/usr/bin/virsh']]
        self.assertEqual(sum('net-define' in row for row in sudo_virsh),2)
        self.assertFalse(any('nwfilter-define' in row for row in sudo_virsh))
        self.assertFalse(any('network-ssh.xml' in ' '.join(row) for row in sudo_virsh))
        self.assertFalse(any(argv[:4]==['/usr/bin/sudo','-n','--','/usr/sbin/nft']
                and argv[4:]==['-f','-'] for argv,_ in fake.calls))
        self.assertFalse(result['vm_started'])

    def test_r353_second_partial_receipt_authentic_and_negative(self):
        first_dir=self._historical_partial()
        first_old=json.loads((first_dir/'r35_deployment.json').read_text())
        with mock.patch.object(t,'R35_PARTIAL_REPORT_SHA256',first_old['sha256']):
            first=t.verify_prior_partial_receipt(first_dir,self.bundle)
        _,fake=self.host()
        fake.nft_installed=True
        host_report,_=t.host_preflight(self.bundle,runner=fake,
                     which=lambda n:BINARIES.get(n),existing_nft=True)
        old=t.deployment_report(self.bundle,host_report,
            status='PARTIAL_NO_GO_REVIEW_REQUIRED',
            failure='defined_network_xml_mismatch_ssh',nft_installed=True,
            table_verified=True,filter_defined=True,filter_verified=True,
            networks_defined=[t33.NETWORK_PREFIX+'ssh'])
        previous={**first,'current_host_preflight_sha256':host_report['sha256']}
        previous['sha256']=t.sha(t.canon(previous))
        old['recovery_mode']='EXISTING_NFT_VERIFIED_JSON'
        old['prior_partial_receipt_sha256']=first['original_receipt_sha256']
        old['resume_attestation_sha256']=previous['sha256']
        old['sha256']=t.sha(t.canon({k:v for k,v in old.items() if k!='sha256'}))
        partial=self.root/'recibos-recuperacion-r352-test'
        partial.mkdir(mode=0o700)
        xml=self.xml['network-ssh.xml']
        root=ET.fromstring(xml);root.attrib.pop('ipv6')
        root.insert(3,ET.Element('mac',{'address':t.SSH_BRIDGE_MAC_R353}))
        actual=ET.tostring(root).decode()
        def cmd(args,stdout=''):
            return {'argv':args,'returncode':0,'stdout':stdout,'stderr':'',
                    'stdout_sha256':t.sha(stdout.encode()),'stderr_sha256':t.sha(b'')}
        vir=['/usr/bin/sudo','-n','--','/usr/bin/virsh','-c','qemu:///system']
        ro=['/usr/bin/virsh','--readonly','-c','qemu:///system']
        entries=[cmd(vir+['nwfilter-define','/tmp/ardrec-r35-source-abc/'+t.R34_DIR+'/nwfilter-deny.xml']),
                 cmd(ro+['nwfilter-dumpxml',t.FILTER_NAME]),
                 cmd(vir+['net-define','/tmp/ardrec-r35-source-abc/'+t.R33_DIR+'/network-ssh.xml']),
                 cmd(ro+['net-dumpxml',t33.NETWORK_PREFIX+'ssh','--inactive'],actual)]
        t._write_receipts(partial,{
            'r35_source_attestation.json':self.bundle['attestation'],
            'r35_host_preflight.json':host_report,
            'r35_deployment.json':old,
            'r35_resume_attestation.json':previous,
        },entries)
        with mock.patch.object(t,'R352_PARTIAL_REPORT_SHA256',old['sha256']), \
             mock.patch.object(t,'R352_ORIGINAL_PARTIAL_RAW_SHA256',first['original_receipt_sha256']), \
             mock.patch.object(t,'R352_RESUME_ATTESTATION_SHA256',previous['sha256']):
            verified=t.verify_second_partial_receipt(partial,self.bundle,first)
            self.assertEqual(verified['existing_ssh_bridge_mac'],t.SSH_BRIDGE_MAC_R353)
            # Even a re-sealed mutated history is not admitted.
            bad=entries+[cmd(vir+['net-define','/tmp/ardrec-r35-source-abc/'+t.R33_DIR+'/network-ftp.xml'])]
            t._write_receipts if False else None
            lines=b''.join(t.canon(x)+b'\n' for x in bad)
            (partial/'commands.jsonl').write_bytes(lines)
            hashes=[]
            for path in sorted(partial.iterdir()):
                if path.name!='SHA256SUMS':
                    hashes.append(t.sha(path.read_bytes())+'  '+path.name)
            (partial/'SHA256SUMS').write_text('\n'.join(hashes)+'\n')
            with self.assertRaises(t.R35Error):
                t.verify_second_partial_receipt(partial,self.bundle,first)

    def test_r353_partial_preflight_report_claim_is_strict(self):
        _,fake=self.r353_fake()
        pre,host=t.host_preflight(self.bundle,runner=fake,
                    which=lambda n:BINARIES.get(n),existing_nft=True,
                    existing_filter=True,existing_networks=('ssh',))
        doc=t.deployment_report(self.bundle,pre,
            status='RESUME_PREFLIGHT_PASS_EXISTING_NFT_FILTER_SSH',
            nft_installed=True,table_verified=True,
            filter_defined=True,filter_verified=True,
            networks_defined=[t33.NETWORK_PREFIX+'ssh'],
            networks_inactive=[t33.NETWORK_PREFIX+'ssh'],
            network_bridge_macs={'ssh':t.SSH_BRIDGE_MAC_R353},
            recovery_provenance={
                'recovery_mode':'EXISTING_NFT_FILTER_SSH_VERIFIED',
                'prior_partial_receipt_sha256':t.R352_ORIGINAL_PARTIAL_RAW_SHA256,
                'second_partial_receipt_sha256':'b'*64,
                'resume_attestation_sha256':'c'*64,
                'recovery3_attestation_sha256':'d'*64})
        t.verify_deployment_report(doc)
        for key in ('nft_table_verified','nwfilter_verified'):
            other=dict(doc);other[key]=False
            other['sha256']=t.sha(t.canon({k:v for k,v in other.items() if k!='sha256'}))
            with self.assertRaises(t.R35Error):t.verify_deployment_report(other)


if __name__ == '__main__':
    unittest.main()
