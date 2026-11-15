"""P14-R49: deny-first runner definition/boot; mocked host and adverse controls."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree as ET

from ardrec.coordination import r49_runner_first_boot as r49


class R49Tests(unittest.TestCase):
    def test_expected_candidate_single_ssh_nic(self):
        raw=r49.r48.runner_domain_candidate()
        r49._check_runner_domain(raw)
        root=ET.fromstring(raw)
        self.assertEqual(len(root.findall('./devices/interface')),1)
        self.assertEqual(root.find('./devices/disk/source').get('file'),r49.r48.NEW_DISK)
        self.assertEqual(root.find('./devices/interface/filterref').get('filter'),r49.r33.DENY_FILTER)

    def test_libvirt_kib_memory_is_not_a_false_drift(self):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        memory=root.find('memory')
        memory.text=str(int(memory.text)*1024)
        memory.set('unit','KiB')
        cur=root.find('currentMemory')
        cur.text=str(int(cur.text)*1024)
        cur.set('unit','KiB')
        r49._check_runner_domain(ET.tostring(root))

    def _change(self,tag,field,value):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        root.find(tag).set(field,value)
        return ET.tostring(root)

    def test_runner_rejects_wrong_mac(self):
        with self.assertRaisesRegex(r49.R49Error,'runner_interface_drift'):
            r49._check_runner_domain(self._change('./devices/interface/mac','address','00:00:00:00:00:00'))

    def test_runner_rejects_wrong_tap(self):
        with self.assertRaisesRegex(r49.R49Error,'runner_interface_drift'):
            r49._check_runner_domain(self._change('./devices/interface/target','dev','a33d31r'))

    def test_runner_rejects_allow_filter(self):
        with self.assertRaisesRegex(r49.R49Error,'runner_interface_drift'):
            r49._check_runner_domain(self._change('./devices/interface/filterref','filter',r49.r45.FILTER_RUNNER))

    def test_runner_rejects_wrong_disk(self):
        with self.assertRaisesRegex(r49.R49Error,'runner_disk_drift'):
            r49._check_runner_domain(self._change('./devices/disk/source','file',r49.r48.TOP))

    def test_runner_rejects_extra_nic(self):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        root.find('devices').append(ET.fromstring(ET.tostring(root.find('./devices/interface'))))
        with self.assertRaisesRegex(r49.R49Error,'runner_nic_count_drift'):
            r49._check_runner_domain(ET.tostring(root))

    def test_runner_rejects_graphics(self):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        ET.SubElement(root.find('devices'),'graphics',{'type':'spice'})
        with self.assertRaisesRegex(r49.R49Error,'unexpected_device_graphics'):
            r49._check_runner_domain(ET.tostring(root))

    def test_runner_rejects_memory_drift(self):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        root.find('memory').text='1024'
        with self.assertRaisesRegex(r49.R49Error,'runner_domain_identity_drift'):
            r49._check_runner_domain(ET.tostring(root))

    def test_runner_rejects_current_memory_drift(self):
        root=ET.fromstring(r49.r48.runner_domain_candidate())
        root.find('currentMemory').text='256'
        with self.assertRaisesRegex(r49.R49Error,'runner_domain_identity_drift'):
            r49._check_runner_domain(ET.tostring(root))

    def test_runner_rejects_nonvirtio_interface_model(self):
        with self.assertRaisesRegex(r49.R49Error,'runner_interface_drift'):
            r49._check_runner_domain(self._change('./devices/interface/model','type','e1000'))

    def test_runner_rejects_unapproved_boot(self):
        with self.assertRaisesRegex(r49.R49Error,'boot_order_drift'):
            r49._check_runner_domain(self._change('./os/boot','dev','network'))

    def test_ssh_live_filter_must_remain_r33(self):
        valid=r49.r33.render_xml(r49.r33.R32_RECEIPT_FILE_SHA256)['domain-ssh.xml']
        r49._check_ssh_live(valid)
        root=ET.fromstring(valid)
        root.find('./devices/interface/filterref').set('filter',r49.r45.FILTER_SSH)
        with self.assertRaisesRegex(r49.R49Error,'ssh_live_filter_drift'):
            r49._check_ssh_live(ET.tostring(root))

    def test_states_localized_and_no_unknown(self):
        self.assertEqual(r49._state(b'ejecutando\n'),'RUNNING')
        self.assertEqual(r49._state(b'apagado\n'),'SHUTOFF')
        with self.assertRaisesRegex(r49.R49Error,'unexpected_domain_state'):
            r49._state(b'pausado\n')

    def test_host_calls_are_fixed_non_shell_and_fail_closed(self):
        seen=[]
        def mock(argv,**kwargs):
            seen.append((argv,kwargs))
            return SimpleNamespace(returncode=0,stdout=b'ok',stderr=b'')
        self.assertEqual(r49._host(r49._virsh('domstate',r49.RUNNER),run=mock),b'ok')
        self.assertNotIn('shell',seen[0][1])
        self.assertEqual(seen[0][1]['stdin'],r49.subprocess.DEVNULL)
        self.assertEqual(seen[0][0][3],'/usr/bin/virsh')
        with self.assertRaisesRegex(r49.R49Error,'host_command_invalid'):
            r49._host(['virsh','start',r49.RUNNER],run=mock)
        def denied(*args,**kwargs):
            return SimpleNamespace(returncode=1,stdout=b'',stderr=b'denied')
        with self.assertRaisesRegex(r49.R49Error,'host_command_failed'):
            r49._host(r49._virsh('domstate',r49.RUNNER),run=denied)

    def _private(self,dir,temp,name):
        root=Path(temp)/'private'
        root.mkdir(mode=0o700,exist_ok=True)
        return root/name

    def test_private_receipts_require_separate_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=self._private(None,tmp,'r49-runner-define-20261115T031111Z-998')
            r49._private_root(path,'r49-runner-define',exists=False)
            path.mkdir(mode=0o700)
            with self.assertRaisesRegex(r49.R49Error,'receipt_collision_or_absent'):
                r49._private_root(path,'r49-runner-define',exists=False)
            with self.assertRaisesRegex(r49.R49Error,'receipt_path_invalid'):
                r49._private_root(path,'r49-runner-boot',exists=True)

    def test_seal_readback_and_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=self._private(None,tmp,'r49-runner-boot-20261115T031111Z-998')
            path.mkdir(mode=0o700)
            r49._write(path/'r49-boot-intent.json',b'hello')
            r49._write(path/'r49-boot-verified.json',b'world')
            r49._seal(path,r49.BOOT_FILES)
            self.assertEqual(len(r49._load_private(path,'r49-runner-boot',r49.BOOT_FILES)),3)
            (path/'r49-boot-intent.json').write_bytes(b'altered')
            with self.assertRaisesRegex(r49.R49Error,'receipt_hash_invalid'):
                r49._load_private(path,'r49-runner-boot',r49.BOOT_FILES)

    def test_plan_is_readonly_no_permission(self):
        with patch.object(r49,'_preflight',return_value={'schema':r49.SCHEMA,'domain_defined':False}) as m:
            report=r49.plan(Path('/45'),Path('/46'),Path('/47'),Path('/48'))
        self.assertEqual(report['sha256'],r49.sha(r49.canon({'schema':r49.SCHEMA,'domain_defined':False})))
        m.assert_called_once()

    def test_definition_intent_precedes_one_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-define-20261115T031111Z-998')
            r46dir=Path(tmp)/'r46';r46dir.mkdir()
            source=b'old-vm-xml'
            (r46dir/'runner-inactive.xml').write_bytes(source)
            r48dir=Path(tmp)/'r48';r48dir.mkdir()
            (r48dir/'runner-ssh-only-deny-r48.xml').write_bytes(b'new-vm-xml')
            before={'runner-inactive.xml':source}
            after={'runner-inactive.xml':b'defined-xml'}
            seen=[]
            def host(argv,*,run):
                seen.append(argv)
                self.assertTrue((root/'r49-define-intent.json').is_file())
                self.assertTrue((root/'runner-original-inactive.xml').is_file())
                self.assertNotIn('start',argv)
                return b'defined'
            with patch.object(r49,'_preflight',return_value={'mode':'PREDEFINE_READONLY','source_main':r49.BASE_MAIN}),\
                 patch.object(r49,'_capture',side_effect=[before,after]) as cap,\
                 patch.object(r49,'_host',side_effect=host),\
                 patch.object(r49,'_validate_common'),\
                 patch.object(r49,'_r48_local'):
                report=r49.define(Path('/45'),r46dir,Path('/47'),r48dir,root,capture=cap)
            self.assertEqual(len(seen),1)
            self.assertEqual(seen[0][-2:],["define",str(r48dir/'runner-ssh-only-deny-r48.xml')])
            self.assertFalse(report['runner_started'])
            self.assertEqual(set(p.name for p in root.iterdir()),set(r49.DEFINITION_FILES)|{'SHA256SUMS'})

    def test_failed_define_retains_intent_without_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-define-20261115T031111Z-998')
            r46dir=Path(tmp)/'r46';r46dir.mkdir()
            (r46dir/'runner-inactive.xml').write_bytes(b'old')
            r48dir=Path(tmp)/'r48';r48dir.mkdir()
            (r48dir/'runner-ssh-only-deny-r48.xml').write_bytes(b'new')
            with patch.object(r49,'_preflight',return_value={'mode':'PREDEFINE_READONLY'}),\
                 patch.object(r49,'_capture',return_value={'runner-inactive.xml':b'old'}),\
                 patch.object(r49,'_host',side_effect=r49.R49Error('deny')) as host:
                with self.assertRaisesRegex(r49.R49Error,'deny'):
                    r49.define(Path('/45'),r46dir,Path('/47'),r48dir,root,capture=lambda **kwargs: {'runner-inactive.xml': b'old'})
            self.assertEqual(host.call_count,1)
            self.assertEqual(set(p.name for p in root.iterdir()),
                             {'r49-define-intent.json','runner-original-inactive.xml'})

    def test_first_boot_intent_precedes_one_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-boot-20261115T031111Z-998')
            seen=[]
            def host(argv,*,run):
                seen.append(argv)
                self.assertTrue((root/'r49-boot-intent.json').is_file())
                self.assertNotIn('define',argv)
                return b'Domain started'
            with patch.object(r49,'verify_defined',return_value={'sha256':'f'*64}),\
                 patch.object(r49,'_host',side_effect=host),\
                 patch.object(r49,'_capture',return_value={'vm-states.json':b'{}'}) as cap,\
                 patch.object(r49,'_validate_common'):
                report=r49.boot(Path('/45'),Path('/46'),Path('/47'),Path('/48'),Path('/defined'),root,capture=cap)
            self.assertEqual(len(seen),1)
            self.assertEqual(seen[0][-2:],['start',r49.RUNNER])
            self.assertTrue(report['runner_started'])
            self.assertFalse(report['operational_dispatch'])
            self.assertEqual(report['p8_operational'],'NO-GO')
            self.assertEqual(set(p.name for p in root.iterdir()),set(r49.BOOT_FILES)|{'SHA256SUMS'})

    def test_failed_start_leaves_intent_no_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-boot-20261115T031111Z-998')
            with patch.object(r49,'verify_defined',return_value={'sha256':'f'*64}),\
                 patch.object(r49,'_host',side_effect=r49.R49Error('virsh_start_denied')) as host:
                with self.assertRaisesRegex(r49.R49Error,'virsh_start_denied'):
                    r49.boot(Path('/45'),Path('/46'),Path('/47'),Path('/48'),Path('/defined'),root)
            self.assertEqual(host.call_count,1)
            self.assertEqual(set(p.name for p in root.iterdir()),{'r49-boot-intent.json'})

    def test_restore_intent_precedes_only_redefinition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-restore-20261115T031111Z-998')
            define_root=self._private(None,tmp,'r49-runner-define-20261115T031111Z-998')
            define_root.mkdir(mode=0o700)
            orig=r49.r33.render_xml(r49.r33.R32_RECEIPT_FILE_SHA256)['domain-runner.xml']
            r46dir=Path(tmp)/'r46';r46dir.mkdir()
            (r46dir/'runner-inactive.xml').write_bytes(orig)
            cmds=[]
            def host(argv,*,run):
                cmds.append(argv)
                self.assertTrue((root/'r49-restore-intent.json').is_file())
                self.assertEqual(argv[-2], 'define')
                return b'defined'
            with patch.object(r49,'verify_defined',return_value={'sha256':'9'*64}),\
                 patch.object(r49,'_load_private',return_value={'runner-original-inactive.xml':orig}),\
                 patch.object(r49,'_host',side_effect=host),\
                 patch.object(r49,'_capture',return_value={'runner-inactive.xml':orig}) as cap,\
                 patch.object(r49,'_validate_common'),\
                 patch.object(r49,'_sources_before'),\
                 patch.object(r49,'_assert_sources'),\
                 patch.object(r49,'_r48_local'):
                report=r49.restore_original(Path('/45'),r46dir,Path('/47'),Path('/48'),define_root,root,capture=cap)
            self.assertEqual(len(cmds),1)
            self.assertFalse(report['runner_started'])
            self.assertTrue(report['restoration_readback_verified'])
            self.assertEqual(set(p.name for p in root.iterdir()),set(r49.RESTORE_FILES)|{'SHA256SUMS'})

    def test_restore_definition_failure_preserves_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r49-runner-restore-20261115T031111Z-998')
            define_root=self._private(None,tmp,'r49-runner-define-20261115T031111Z-998')
            define_root.mkdir(mode=0o700)
            orig=r49.r33.render_xml(r49.r33.R32_RECEIPT_FILE_SHA256)['domain-runner.xml']
            r46dir=Path(tmp)/'r46';r46dir.mkdir()
            (r46dir/'runner-inactive.xml').write_bytes(orig)
            with patch.object(r49,'verify_defined',return_value={'sha256':'9'*64}),\
                 patch.object(r49,'_load_private',return_value={'runner-original-inactive.xml':orig}),\
                 patch.object(r49,'_host',side_effect=r49.R49Error('restore_error')) as m:
                with self.assertRaisesRegex(r49.R49Error,'restore_error'):
                    r49.restore_original(Path('/45'),r46dir,Path('/47'),Path('/48'),define_root,root)
            self.assertEqual(m.call_count,1)
            self.assertEqual(set(p.name for p in root.iterdir()),{'r49-restore-intent.json'})

    def test_common_vm_status_requires_ftp_smb_off(self):
        states={r49.SSH:'RUNNING',r49.RUNNER:'SHUTOFF',r49.FTP:'RUNNING',r49.SMB:'SHUTOFF'}
        with self.assertRaisesRegex(r49.R49Error,'vm_state_drift'):
            r49._validate_common({'vm-states.json':r49.canon(states)},Path('/46'),Path('/45'),
                                 state='SHUTOFF',candidate=False)

    def test_common_vm_status_requires_bridge_no_ipv4(self):
        states={r49.SSH:'RUNNING',r49.RUNNER:'SHUTOFF',r49.FTP:'SHUTOFF',r49.SMB:'SHUTOFF'}
        current={'vm-states.json':r49.canon(states),'ssh-inactive.xml':b'a',
                 'ssh-live.xml':b'b','runner-inactive.xml':b'c',
                 'r33-deny-nwfilter.xml':b'd','r34-bridge-deny.txt':b'e',
                 'bridge-ipv4.txt':b'2: br33d30 inet 192.0.2.4/24',
                 'active-networks.txt':(r49.NETWORK_SSH+'\n').encode()}
        with patch.object(r49.r46,'verify_domain'),\
             patch.object(r49,'_check_ssh_live'),\
             patch.object(r49.r46,'verify_original_filter'),\
             patch.object(r49.r46,'verify_nft_guard'):
            with self.assertRaisesRegex(r49.R49Error,'bridge_ipv4_drift'):
                r49._validate_common(current,Path('/46'),Path('/45'),
                                     state='SHUTOFF',candidate=False)

    def test_common_networks_refuse_active_ftp(self):
        states={r49.SSH:'RUNNING',r49.RUNNER:'SHUTOFF',r49.FTP:'SHUTOFF',r49.SMB:'SHUTOFF'}
        current={'vm-states.json':r49.canon(states),'ssh-inactive.xml':b'a',
                 'ssh-live.xml':b'b','runner-inactive.xml':b'c',
                 'r33-deny-nwfilter.xml':b'd','r34-bridge-deny.txt':b'e',
                 'bridge-ipv4.txt':b'',
                 'active-networks.txt':(r49.NETWORK_SSH+'\n'+r49.NETWORK_FTP+'\n').encode()}
        with patch.object(r49.r46,'verify_domain'),\
             patch.object(r49,'_check_ssh_live'),\
             patch.object(r49.r46,'verify_original_filter'),\
             patch.object(r49.r46,'verify_nft_guard'):
            with self.assertRaisesRegex(r49.R49Error,'network_state_drift'):
                r49._validate_common(current,Path('/46'),Path('/45'),
                                     state='SHUTOFF',candidate=False)

    def test_readonly_cli_requires_explicit_separate_authorizations(self):
        import importlib.util
        import contextlib
        import io
        script=(Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r49_runner_first_boot.py')
        spec=importlib.util.spec_from_file_location('r49_cli_for_tests',script)
        self.assertIsNotNone(spec)
        mod=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        base=[]
        for name in ('r45','r46','r47','r48'):
            base.extend(['--'+name+'-dir','/not/accessed'])
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(['--define-ssh-only-runner',*base,
                 '--definition-receipt-dir','/not/created']),2)
            self.assertEqual(mod.main(['--start-isolated-runner',*base,
                 '--definition-receipt-dir','/not/created',
                 '--boot-receipt-dir','/not/created']),2)
            self.assertEqual(mod.main(['--restore-original-when-shutoff',*base,
                 '--definition-receipt-dir','/not/created',
                 '--restore-receipt-dir','/not/created']),2)

    def test_r48_stale_top_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self._private(None,tmp,'r48-runner-overlay-20261115T031111Z-998')
            for name in r49.r48.REC_FILES:
                (Path(tmp)/'private').mkdir(mode=0o700,exist_ok=True)
            with self.assertRaises((ValueError,OSError)):
                r49._r48_local(root,run=lambda *a,**k:None)

    def test_domain_no_unbounded_access(self):
        source=Path(r49.__file__).read_text(encoding='utf-8')
        self.assertNotIn('shell=True',source)
        self.assertNotIn('nft -f',source)
        self.assertNotIn('sshpass',source)
        self.assertNotIn('virsh destroy',source)
        self.assertNotIn('flush ruleset',source)

if __name__=='__main__':
    unittest.main()
