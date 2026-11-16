"""R58-C F11 source-only deployment preflight. No host calls in this suite."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import ardrec_p14_r58c_f11_deployment_plan as p

class TestF11Plan(unittest.TestCase):
    def test_targets_are_specific(self):
        self.assertEqual(len(p.PLANNED_PATHS),4)
        self.assertEqual(set(p.PLANNED_PATHS),set(p.SOURCE))

    def test_sources_are_sha256(self):
        for h in p.SOURCE.values():
            self.assertEqual(len(h),64)
            self.assertTrue(all(c in '0123456789abcdef' for c in h))

    def test_planned_paths_no_arbitrary(self):
        self.assertTrue(all(x.startswith(('/etc/libvirt/hooks/', '/etc/systemd/system/')) for x in p.PLANNED_PATHS.values()))

    def test_plan_stays_denied(self):
        doc=p.package_plan(p.SOURCE)
        self.assertEqual(doc['p8'],'NO-GO')
        self.assertFalse(doc['installer_executed'])
        self.assertFalse(doc['safe_to_restart_libvirtd'])
        self.assertFalse(doc['runtime_hook_loaded'])

    def test_malformed_source_rejected(self):
        src=dict(p.SOURCE)
        src['00-ardrec-r33-deny']='0'*64
        with self.assertRaises(p.PlanError):p.package_plan(src)

    def test_inventory_requires_f11(self):
        with self.assertRaises(p.PlanError):p.package_plan(
            p.SOURCE,inventory=dict.fromkeys(p.SOURCE,'NOT_INSTALLED'),
            f11={},domains=set(p.DOMAIN_SET),active=set())

    def test_inventory_requires_all_domains(self):
        with self.assertRaises(p.PlanError):p.package_plan(
            p.SOURCE,inventory=dict.fromkeys(p.SOURCE,'NOT_INSTALLED'),
            f11=self._f11(),domains=set(),active=set())

    def test_inventory_rejects_active_not_defined(self):
        with self.assertRaises(p.PlanError):p.package_plan(
            p.SOURCE,inventory=dict.fromkeys(p.SOURCE,'NOT_INSTALLED'),
            f11=self._f11(),domains=set(p.DOMAIN_SET),active={'unknown'})

    @staticmethod
    def _f11():
        return {'nft_r34':'DENY_STRUCTURALLY_VERIFIED_TWICE',
                'nwfilter_r34':'DROP_ALL_DEFINITION_VERIFIED',
                'dev_vms_off':True,'ftp_network_inactive':True,
                'root_bundle':'THREE_ROOT_BUNDLE_HASHES_MATCH_PIN'}

    def test_foreign_running_guest_flagged(self):
        all_vms=set(p.DOMAIN_SET)|{'production-other-vm'}
        res=p.package_plan(p.SOURCE,
            inventory=dict.fromkeys(p.SOURCE,'NOT_INSTALLED'),
            f11=self._f11(),domains=all_vms,active={'production-other-vm'})
        self.assertEqual(res['foreign_active_vms'],['production-other-vm'])
        self.assertFalse(res['safe_to_restart_libvirtd'])

    def test_conflicting_hook_is_reported_not_overwritten(self):
        inventory=dict.fromkeys(p.SOURCE,'NOT_INSTALLED')
        inventory['00-ardrec-r33-deny']='EXISTS_REQUIRES_INDEPENDENT_REVIEW'
        res=p.package_plan(p.SOURCE,inventory=inventory,f11=self._f11(),
                           domains=set(p.DOMAIN_SET),active=set())
        self.assertEqual(res['existing_path_conflicts'],['00-ardrec-r33-deny'])
        self.assertFalse(res['installer_executed'])

    def test_probe_paths_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            got=p.path_inventory(root)
            self.assertEqual(set(got.values()),{'NOT_INSTALLED'})
            self.assertEqual(list(root.iterdir()),[])

    def test_probe_existing_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); target=root/p.PLANNED_PATHS['00-ardrec-r33-deny'].lstrip('/')
            target.parent.mkdir(parents=True); target.write_text('existing')
            got=p.path_inventory(root)
            self.assertEqual(got['00-ardrec-r33-deny'],'EXISTS_REQUIRES_INDEPENDENT_REVIEW')
            self.assertEqual(target.read_text(),'existing')

    def test_probe_symlink_is_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); target=root/p.PLANNED_PATHS['00-ardrec-r33-deny'].lstrip('/')
            target.parent.mkdir(parents=True); target.symlink_to('/dev/null')
            got=p.path_inventory(root)
            self.assertEqual(got['00-ardrec-r33-deny'],'SYMLINK_BLOCKED')

    def test_invalid_command_rejected_before_subprocess(self):
        with patch.object(p.subprocess,'run',side_effect=AssertionError('called')):
            with self.assertRaises(p.PlanError):p.read_command(['/usr/bin/virsh','start','whatever'])

    def test_no_install_actions_or_vm_starts(self):
        raw=(Path(p.__file__)).read_text()
        for forbidden in ('systemctl start','virsh start','nft -f','libvirt.define','os.replace(', 'os.chmod('):
            self.assertNotIn(forbidden,raw)

    def test_source_offline_on_repository(self):
        self.assertEqual(p.check_source(),p.SOURCE)
