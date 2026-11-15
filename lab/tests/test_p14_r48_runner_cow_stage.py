"""P14-R48: preflight and one-overlayer-only negative/positive tests."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from ardrec.coordination import r48_runner_cow_stage as r48


def chain(*files):
    return json.dumps([{
      'filename': f, 'format': 'qcow2', 'virtual-size': r48.VOL_BYTES,
      **({'backing-filename': files[i+1], 'full-backing-filename': files[i+1]}
         if i+1 < len(files) else {}),
      'format-specific': {'data': {'corrupt': False}},
    } for i,f in enumerate(files)]).encode()


class R48Tests(unittest.TestCase):
    def test_exact_original_chain(self):
        self.assertEqual(len(r48._chain(chain(r48.TOP,r48.PARENT,r48.BASE),
                             (r48.TOP,r48.PARENT,r48.BASE))),3)

    def test_four_layer_expected(self):
        self.assertEqual(len(r48._chain(chain(r48.NEW_DISK,r48.TOP,r48.PARENT,r48.BASE),
                             (r48.NEW_DISK,r48.TOP,r48.PARENT,r48.BASE))),4)

    def test_unknown_extra_image_rejected(self):
        with self.assertRaisesRegex(r48.R48Error,'disk_chain_length'):
            r48._chain(chain(r48.TOP,r48.PARENT,r48.BASE,'other'),
                       (r48.TOP,r48.PARENT,r48.BASE))

    def test_base_not_qcow2_rejected(self):
        d=json.loads(chain(r48.TOP,r48.PARENT,r48.BASE))
        d[2]['format']='raw'
        with self.assertRaisesRegex(r48.R48Error,'disk_chain_identity_2'):
            r48._chain(json.dumps(d).encode(),(r48.TOP,r48.PARENT,r48.BASE))

    def test_backing_replaced_rejected(self):
        d=json.loads(chain(r48.TOP,r48.PARENT,r48.BASE))
        d[0]['backing-filename']='injected.qcow2'
        d[0]['full-backing-filename']='injected.qcow2'
        with self.assertRaisesRegex(r48.R48Error,'disk_chain_backing_0'):
            r48._chain(json.dumps(d).encode(),(r48.TOP,r48.PARENT,r48.BASE))

    def test_corrupt_flag_rejected(self):
        d=json.loads(chain(r48.TOP,r48.PARENT,r48.BASE))
        d[1]['format-specific']['data']['corrupt']=True
        with self.assertRaisesRegex(r48.R48Error,'disk_chain_corrupt'):
            r48._chain(json.dumps(d).encode(),(r48.TOP,r48.PARENT,r48.BASE))

    def test_size_drift_rejected(self):
        d=json.loads(chain(r48.TOP,r48.PARENT,r48.BASE))
        d[0]['virtual-size']=23*1024**3
        with self.assertRaisesRegex(r48.R48Error,'disk_chain_identity_0'):
            r48._chain(json.dumps(d).encode(),(r48.TOP,r48.PARENT,r48.BASE))

    def test_runner_candidate_only_one_nic_and_r33_deny(self):
        raw=r48.runner_domain_candidate()
        root=ET.fromstring(raw)
        self.assertEqual(len(root.findall('./devices/interface')),1)
        self.assertEqual(root.find('./devices/disk/source').get('file'),r48.NEW_DISK)
        self.assertEqual(root.find('./devices/interface/filterref').get('filter'),r48.r33.DENY_FILTER)

    def test_modified_candidate_nic_refused(self):
        root=ET.fromstring(r48.runner_domain_candidate())
        root.find('./devices/interface/mac').set('address','52:54:00:00:00:01')
        with self.assertRaisesRegex(r48.R48Error,'runner_isolation_or_identity_drift'):
            r48.check_runner_candidate(ET.tostring(root))

    def test_modified_candidate_filter_refused(self):
        root=ET.fromstring(r48.runner_domain_candidate())
        root.find('./devices/interface/filterref').set('filter',r48.r45.FILTER_RUNNER)
        with self.assertRaisesRegex(r48.R48Error,'runner_isolation_or_identity_drift'):
            r48.check_runner_candidate(ET.tostring(root))

    def test_invalid_stat_owner_rejected(self):
        def fake(*a, **k):return SimpleNamespace(returncode=0,stdout=b'196992|600|root|root|1\n',stderr=b'')
        with self.assertRaisesRegex(r48.R48Error,'disk_mode_or_owner_invalid'):
            r48._stat_disk(r48.TOP,fake)

    def test_disk_stat_valid(self):
        def fake(*a, **k):return SimpleNamespace(returncode=0,stdout=b'196992|600|libvirt-qemu|libvirt-qemu|1\n',stderr=b'')
        self.assertEqual(r48._stat_disk(r48.TOP,fake)['mode'],'600')

    def test_df_enforces_minimum(self):
        def fake(*a, **k):return SimpleNamespace(returncode=0,stdout=b'Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100000000000 5000000000 1000 5% /\n',stderr=b'')
        with self.assertRaisesRegex(r48.R48Error,'disk_free_space_below_2gib'):
            r48._free_bytes(fake)

    def test_host_invocation_never_shell(self):
        seen=[]
        def fake(argv,**kwargs):
            seen.append((argv,kwargs))
            return SimpleNamespace(returncode=0,stdout=b'good',stderr=b'')
        self.assertEqual(r48._host(r48._cmd('/usr/bin/stat','foo'),run=fake),b'good')
        self.assertIsInstance(seen[0][0],list)
        self.assertEqual(seen[0][1]['stdin'],r48.subprocess.DEVNULL)
        self.assertFalse('shell' in seen[0][1])

    def test_host_failure_closed(self):
        def fake(*a,**k):return SimpleNamespace(returncode=1,stdout=b'',stderr=b'error')
        with self.assertRaisesRegex(r48.R48Error,'host_command_failed'):
            r48._host(r48._cmd('/usr/bin/stat','foo'),run=fake)

    def test_no_reuse_existing_private_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp)/'private';parent.mkdir(mode=0o700)
            d=parent/'r48-runner-overlay-20261115T030000Z-999'
            d.mkdir(mode=0o700)
            with self.assertRaisesRegex(r48.R48Error,'receipt_state_invalid'):
                r48._private_receipt_root(d,exists=False)

    def test_preflight_has_no_qemu_create(self):
        with patch.object(r48,'_sources'), patch.object(r48,'_info',return_value=chain(r48.TOP,r48.PARENT,r48.BASE)), \
             patch.object(r48,'_stat_disk',return_value={'mode':'600','user':'libvirt-qemu','group':'libvirt-qemu','links':1,'bytes':196992}), \
             patch.object(r48,'_free_bytes',return_value=3*1024**3), \
             patch.object(r48,'_top_hash',return_value='0'*64), \
             patch.object(r48,'_host',return_value=b'') as host:
            o=r48.preflight(Path('/r45'),Path('/r46'),Path('/r47'))
        self.assertEqual(o['physical_overlay_created'],False)
        self.assertEqual(host.call_count,2)
        self.assertEqual(host.call_args.args[0],r48._cmd('/usr/bin/test','!','-L',r48.NEW_DIR))

    def _stage_with_fake_host(self,private:Path,failed=False):
        disk_stat={'mode':'600','user':'libvirt-qemu','group':'libvirt-qemu','links':1,'bytes':196992}
        commands=[]
        def fake(argv,*,run=None,out_limit=None):
            commands.append(argv)
            if failed and '/usr/bin/install' in argv:
                raise r48.R48Error('simulated_failure')
            return b''
        with patch.object(r48,'_sources'), patch.object(r48,'_info',side_effect=lambda path,run:chain(*( (r48.NEW_DISK,r48.TOP,r48.PARENT,r48.BASE) if path==r48.NEW_DISK else (r48.TOP,r48.PARENT,r48.BASE)))), \
             patch.object(r48,'_stat_disk',return_value=disk_stat), \
             patch.object(r48,'_free_bytes',return_value=3*1024**3), \
             patch.object(r48,'_top_hash',return_value='f'*64), \
             patch.object(r48,'_host',side_effect=fake):
            if failed:
                with self.assertRaisesRegex(r48.R48Error,'simulated_failure'):
                    r48.stage(Path('/r45'),Path('/r46'),Path('/r47'),private)
                self.assertEqual({x.name for x in private.iterdir()}, {'r48-stage-intent.json','runner-ssh-only-deny-r48.xml'})
                return commands
            report=r48.stage(Path('/r45'),Path('/r46'),Path('/r47'),private)
            self.assertTrue(report['physical_overlay_created'])
            self.assertFalse(report['runner_redefined'])
            self.assertFalse(report['vm_started'])
            self.assertEqual(report['p8_operational'],'NO-GO')
            self.assertEqual({x.name for x in private.iterdir()},set(r48.REC_FILES)|{'SHA256SUMS'})
            v=r48.verify(Path('/r45'),Path('/r46'),Path('/r47'),private)
            self.assertEqual(v['sha256'],report['sha256'])
        return commands

    def test_stage_only_new_disk_and_no_vm(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp)/'private';parent.mkdir(mode=0o700)
            d=parent/'r48-runner-overlay-20261115T030000Z-999'
            cmds=self._stage_with_fake_host(d)
        self.assertTrue(any('/usr/bin/qemu-img' in x and 'create' in x for x in cmds))
        self.assertFalse(any('virsh' in x or 'nft' in x or 'start' in x for x in cmds))
        self.assertTrue(any('/usr/bin/chmod' in x for x in cmds))

    def test_partial_failure_keeps_intent_and_does_not_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp)/'private';parent.mkdir(mode=0o700)
            d=parent/'r48-runner-overlay-20261115T030000Z-999'
            cmds=self._stage_with_fake_host(d,failed=True)
        self.assertFalse(any('/usr/bin/qemu-img' in x and 'create' in x for x in cmds))

    def test_verify_tampering_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp)/'private';parent.mkdir(mode=0o700)
            d=parent/'r48-runner-overlay-20261115T030000Z-999'
            self._stage_with_fake_host(d)
            p=d/'runner-ssh-only-deny-r48.xml'
            p.write_bytes(b'drift')
            with self.assertRaisesRegex(r48.R48Error,'receipt_hashes_invalid'):
                r48.verify(Path('/r45'),Path('/r46'),Path('/r47'),d)

if __name__=='__main__':unittest.main()
