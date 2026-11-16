"""Synthetic adversarial tests for F11-P; no subprocess to host or libvirt."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import os
import unittest
from unittest.mock import patch

MOD_PATH=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r58a_f11p_boot_readiness.py'
spec=importlib.util.spec_from_file_location('f11p',MOD_PATH)
f11p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(f11p)


def fixtures():
    taps=sorted(f11p.TAPS)
    nftables=[{'metainfo':{'version':'1.1.7'}}]
    nftables.append({'table':{'family':'bridge','name':f11p.R34,'handle':1}})
    for n in ('input','output','forward'):
        nftables.append({'chain':{'family':'bridge','table':f11p.R34,'name':n,
            'type':'filter','hook':n,'prio':-200,'policy':'accept','handle':3}})
    for n,side in (('input','iifname'),('output','oifname'),('forward','iifname'),('forward','oifname')):
        nftables.append({'rule':{'family':'bridge','table':f11p.R34,'chain':n,
            'expr':[{'match':{'op':'==','left':{'meta':{'key':side}},'right':{'set':taps}}},
                    {'counter':{'packets':0,'bytes':0}},{'drop':None}], 'handle':6}})
    nft=(json.dumps({'nftables':nftables})+'\n').encode()
    filter_xml=("<filter name='ardrec-r33-block-until-containment' chain='root'>\n"
                "<uuid>ebb30562-34ae-5367-9c24-a9b9160190b5</uuid>\n"
                "<rule action='drop' direction='inout' priority='1000'><all/></rule></filter>\n").encode()
    root_stat=b'0|0|700|1|directory\n'+b'0|0|600|1|regular file\n'*3
    boot = {
        'LoadState':'loaded','UnitFileState':'enabled','ActiveState':'inactive','SubState':'dead',
        'NeedDaemonReload':'no','ExecMainStartTimestamp':'','ExecMainExitTimestamp':'',
        'InvocationID':'','Result':'success','FragmentPath':f11p.UNIT_PATH,
        'Type':'oneshot','RemainAfterExit':'yes',
    }
    lib = {'LoadState':'loaded','ActiveState':'active','Requires':'sysinit.target system.slice',
           'Requisite':'','BindsTo':'','Wants':'systemd-machined.service',
           'After':'remote-fs.target ardrec-r34-boot-deny.service systemd-machined.service'}
    unit=(f'# {f11p.UNIT_PATH}\n[Unit]\n'
          'Description=ARDREC R34 DENY bootstrap\n'
          'Before=libvirtd.service multi-user.target\n'
          'RequiresMountsFor=/var/lib/ardrec/r58a-r34-boot\n'
          '[Service]\nType=oneshot\nUser=root\nGroup=root\n'
          'ExecStart=/usr/bin/python3 -I -B /var/lib/ardrec/r58a-r34-boot/boot-guard.py\n'
          'RemainAfterExit=yes\nProtectSystem=strict\nNoNewPrivileges=yes\n'
          'PrivateTmp=yes\nProtectHome=yes\nProtectKernelTunables=yes\n'
          'ProtectKernelModules=yes\nProtectControlGroups=yes\nTimeoutStartSec=60\n'
          '[Install]\nWantedBy=multi-user.target\n').encode()
    def props(data):
        return (''.join(f'{k}={data[k]}\n' for k in data)).encode()
    hashes = ''.join(f'{f11p.BUNDLE[k]}  {f11p.STAGE/k}\n'
                     for k in ('boot-guard.py','manifest.json','r34-deny.nft')).encode()
    return dict(hashes=hashes,root_stat=root_stat,boot_show=props(boot),libvirt_show=props(lib),
                unit_text=unit,nft_first=nft,nft_second=nft,filter_xml=filter_xml,
                vm_states={r:'shut off' for r in ('runner','ssh','ftp','smb')},
                active_networks=set(),link_target=f11p.UNIT_PATH,
                source_head=f11p.ANCESTOR)


def mutate_nft(blob, mutation):
    value=json.loads(blob)
    mutation(value['nftables'])
    return json.dumps(value).encode()

class TestF11P(unittest.TestCase):
    def setUp(self):
        self.f=fixtures()

    def check_error(self,reason,**overrides):
        f={**self.f,**overrides}
        with self.assertRaises(f11p.Blocked) as err:
            f11p.assess(**f)
        self.assertEqual(str(err.exception),reason)

    def test_current_host_state_is_blocked_not_pass(self):
        report=f11p.assess(**self.f)
        self.assertEqual(report['decision'],'BLOCKED_F11_BOOT_GUARD_UNSTARTED')
        self.assertFalse(report['boot_service_start_recorded'])
        self.assertFalse(report['manual_vm_boot_block_attested'])
        self.assertFalse(report['first_boot_attested'])
        self.assertFalse(report['independent_runtime_watchdog_attested'])
        self.assertFalse(report['libvirt_hard_dependency_on_boot_guard'])
        self.assertEqual(report['host_mutations'],0)

    def test_unit_first_start_not_first_boot_proof(self):
        raw=self.f['boot_show'].decode()
        raw=raw.replace('ActiveState=inactive','ActiveState=active').replace('SubState=dead','SubState=exited')
        raw=raw.replace('ExecMainStartTimestamp=\n','ExecMainStartTimestamp=Sun 2026-11-15 22:00:00\n')
        raw=raw.replace('InvocationID=\n','InvocationID=facade\n')
        report=f11p.assess(**{**self.f,'boot_show':raw.encode()})
        self.assertEqual(report['decision'],'BLOCKED_F11_NO_INDEPENDENT_BOOT_ATTESTATION')
        self.assertTrue(report['boot_service_start_recorded'])
        self.assertFalse(report['first_boot_attested'])

    def test_with_requires_is_still_not_authorization(self):
        lib=self.f['libvirt_show'].replace(b'Requires=sysinit.target',
                                         b'Requires=ardrec-r34-boot-deny.service sysinit.target')
        report=f11p.assess(**{**self.f,'libvirt_show':lib})
        self.assertTrue(report['libvirt_hard_dependency_on_boot_guard'])
        self.assertFalse(report['manual_vm_boot_block_attested'])

    def test_root_bundle_hash_mismatch(self):
        self.check_error('ROOT_BUNDLE_HASH_MISMATCH',hashes=self.f['hashes'].replace(b'd2b251',b'000000'))

    def test_missing_root_bundle_file(self):
        hashes=self.f['hashes'].splitlines(keepends=True)[:-1]
        self.check_error('ROOT_BUNDLE_HASH_MISMATCH',hashes=b''.join(hashes))

    def test_bad_root_bundle_mode(self):
        bad=self.f['root_stat'].replace(b'0|0|700|1|directory',b'0|0|755|1|directory')
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=bad)

    def test_bad_root_file_mode(self):
        bad=self.f['root_stat'].replace(b'0|0|600|1|regular file',b'0|0|644|1|regular file',1)
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=bad)

    def test_directory_two_hardlinks_accepted(self):
        root_stat=self.f['root_stat'].replace(b'700|1|directory',b'700|2|directory')
        result=f11p.assess(**{**self.f,'root_stat':root_stat})
        self.assertEqual(result['decision'],'BLOCKED_F11_BOOT_GUARD_UNSTARTED')
        self.assertEqual(result['root_permissions'],'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK')

    def test_directory_three_hardlinks_accepted(self):
        root_stat=self.f['root_stat'].replace(b'700|1|directory',b'700|3|directory')
        self.assertEqual(f11p.audit_root_permissions(root_stat),
                         'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK')

    def test_directory_one_link_accepted(self):
        self.assertEqual(f11p.audit_root_permissions(self.f['root_stat']),
                         'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK')

    def test_directory_large_link_count_accepted(self):
        root_stat=self.f['root_stat'].replace(b'700|1|directory',b'700|128|directory')
        self.assertEqual(f11p.audit_root_permissions(root_stat),
                         'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK')

    def test_directory_zero_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700|0|directory'))

    def test_directory_nonnumeric_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700|abc|directory'))

    def test_directory_negative_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700|-2|directory'))

    def test_directory_empty_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700||directory'))

    def test_directory_leading_zero_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700|02|directory'))

    def test_regular_file_two_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'600|1|regular file',b'600|2|regular file',1))

    def test_regular_file_zero_links_rejected(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'600|1|regular file',b'600|0|regular file',1))

    def test_directory_wrong_mode_still_rejected_with_two_links(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'755|2|directory'))

    def test_directory_wrong_owner_still_rejected_with_two_links(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'0|0|700|1|directory',b'1000|0|700|2|directory'))

    def test_directory_wrong_group_still_rejected_with_two_links(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'0|0|700|1|directory',b'0|1000|700|2|directory'))

    def test_regular_file_mode_enforced_with_two_dir_links(self):
        self.check_error('ROOT_STAT_PERMISSION_DRIFT',root_stat=
                         self.f['root_stat'].replace(b'700|1|directory',b'700|2|directory').replace(
                         b'600|1|regular file',b'640|1|regular file',1))

    def test_real_directory_link_count_accepted(self):
        # Uses a disposable local fixture; no access to Prometheus root stage.
        import stat
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            file_paths=[folder/('file-'+str(n)) for n in range(3)]
            for file_path in file_paths:
                file_path.write_bytes(b'test')
            dir_st=folder.stat()
            directory=f'0|0|700|{dir_st.st_nlink}|directory\n'
            # Deterministic permissions and owner are fixture values; only nlink is live.
            files='0|0|600|1|regular file\n'*3
            self.assertEqual(f11p.audit_root_permissions((directory+files).encode()),
                             'ROOT_700_FILES_600_ALL_ROOT_SINGLE_LINK')

    def test_duplicate_show_field(self):
        self.check_error('SYSTEMD_SHOW_UNEXPECTED_OR_DUPLICATE',boot_show=self.f['boot_show']+b'LoadState=loaded\n')

    def test_enabled_link_missing(self):
        self.check_error('BOOT_UNIT_NOT_EFFECTIVELY_ENABLED_AS_EXPECTED',link_target=None)

    def test_unit_changed(self):
        raw=self.f['unit_text'].replace(b'Type=oneshot',b'Type=simple')
        self.check_error('UNIT_CONTRACT_DRIFT',unit_text=raw)

    def test_unit_with_dropin(self):
        raw=self.f['unit_text']+b'\n# /etc/systemd/system/ardrec-r34-boot-deny.service.d/override.conf\n'
        self.check_error('UNIT_OR_DROPIN_DRIFT',unit_text=raw)

    def test_need_daemon_reload(self):
        self.check_error('BOOT_UNIT_NOT_EFFECTIVELY_ENABLED_AS_EXPECTED',
                         boot_show=self.f['boot_show'].replace(b'NeedDaemonReload=no',b'NeedDaemonReload=yes'))

    def test_ftp_network_active_blocks(self):
        self.check_error('FTP_NETWORK_ACTIVE',active_networks={'ardrec-r33-dev-net-ftp'})

    def test_guest_active_blocks(self):
        states=dict(self.f['vm_states']);states['ftp']='running'
        self.check_error('DEV_VM_NOT_ALL_OFF',vm_states=states)

    def test_nft_missing_drop_blocks(self):
        bad=mutate_nft(self.f['nft_first'], lambda rows: rows[-1]['rule']['expr'][-1].update({'drop':'continue'}))
        self.check_error('R34_NFT_RULE_VERDICT',nft_first=bad)

    def test_nft_extra_allow_blocks(self):
        bad=mutate_nft(self.f['nft_first'], lambda rows: rows.append({'rule':{'family':'bridge'}}))
        self.check_error('R34_NFT_OBJECT_COUNT',nft_first=bad)

    def test_nft_tap_set_changed_blocks(self):
        bad=mutate_nft(self.f['nft_first'],lambda rows: rows[-1]['rule']['expr'][0]['match']['right']['set'].pop())
        self.check_error('R34_NFT_SET',nft_first=bad)

    def test_nft_second_read_drift_blocks(self):
        bad=mutate_nft(self.f['nft_second'], lambda rows: rows[-1]['rule']['expr'][-1].update({'drop':'accept'}))
        self.check_error('R34_NFT_RULE_VERDICT',nft_second=bad)

    def test_filter_allow_blocks(self):
        bad=self.f['filter_xml'].replace(b"action='drop'",b"action='accept'")
        self.check_error('NWFILTER_NOT_DENY',filter_xml=bad)

    def test_no_direct_execution_of_boot_guard_allowlist(self):
        with self.assertRaisesRegex(f11p.Blocked,'HOST_COMMAND_NOT_ALLOWLISTED'):
            f11p.run_readonly(['/usr/bin/python3','-I','-B',str(f11p.STAGE/'boot-guard.py')])

    def test_no_systemctl_enable_allowlist(self):
        with self.assertRaisesRegex(f11p.Blocked,'HOST_COMMAND_NOT_ALLOWLISTED'):
            f11p.run_readonly(['systemctl','enable',f11p.BOOT])

    def test_no_nft_file_write_allowlist(self):
        with self.assertRaisesRegex(f11p.Blocked,'HOST_COMMAND_NOT_ALLOWLISTED'):
            f11p.run_readonly(['/usr/sbin/nft','-f','-'])

    def test_no_libvirt_define_allowlist(self):
        with self.assertRaisesRegex(f11p.Blocked,'HOST_COMMAND_NOT_ALLOWLISTED'):
            f11p.run_readonly(['/usr/bin/virsh','-c','qemu:///system','define','/tmp/file.xml'])

    def test_host_readonly_reads_only_allowlisted_sources(self):
        with tempfile.TemporaryDirectory() as d:
            tmp=Path(d)
            wants=tmp/'unit.enabled'
            wants.symlink_to(f11p.UNIT_PATH)
            f=self.f
            calls=[]
            def fake(argv):
                calls.append(argv)
                if argv[-2:]==['rev-parse','HEAD']:
                    return (f11p.ANCESTOR+'\n').encode()
                if 'merge-base' in argv:
                    return b''
                if argv[:2]==['systemctl','show']:
                    return f['boot_show'] if argv[2]==f11p.BOOT else f['libvirt_show']
                if argv[:2]==['systemctl','cat']:
                    return f['unit_text']
                if '/usr/bin/sha256sum' in argv:
                    return f['hashes']
                if '/usr/bin/stat' in argv:
                    return f['root_stat']
                if '/usr/sbin/nft' in argv:
                    return f['nft_first']
                if argv[-2:]==['nwfilter-dumpxml',f11p.FILTER]:
                    return f['filter_xml']
                if argv[-2:]==['net-list','--name']:
                    return b''
                if argv[-2]=='domstate':
                    return b'shut off\n'
                raise AssertionError('unexpected command '+str(argv))
            previous=Path.cwd()
            try:
                os.chdir(tmp)
                with patch.object(f11p,'REPO',tmp),patch.object(f11p,'LINK',wants), \
                     patch.object(f11p,'run_readonly',side_effect=fake):
                    report=f11p.host_readonly()
            finally:
                os.chdir(previous)
            self.assertEqual(report['decision'],'BLOCKED_F11_BOOT_GUARD_UNSTARTED')
            self.assertEqual(report['host_mutations'],0)
            self.assertEqual(sum('/usr/sbin/nft' in argv for argv in calls),2)
            self.assertFalse(any('enable' in argv or 'start' in argv or 'define' in argv
                                 for argv in calls))

    def test_host_readonly_rejects_repository_drift(self):
        with tempfile.TemporaryDirectory() as d:
            tmp=Path(d)
            wants=tmp/'unit.enabled';wants.symlink_to(f11p.UNIT_PATH)
            f=self.f
            seen_git=0
            def fake(argv):
                nonlocal seen_git
                if argv[-2:]==['rev-parse','HEAD']:
                    seen_git+=1
                    return ((f11p.ANCESTOR if seen_git==1 else 'a'*40)+'\n').encode()
                if 'merge-base' in argv:return b''
                if argv[:2]==['systemctl','show']:
                    return f['boot_show'] if argv[2]==f11p.BOOT else f['libvirt_show']
                if argv[:2]==['systemctl','cat']:return f['unit_text']
                if '/usr/bin/sha256sum' in argv:return f['hashes']
                if '/usr/bin/stat' in argv:return f['root_stat']
                if '/usr/sbin/nft' in argv:return f['nft_first']
                if argv[-2:]==['nwfilter-dumpxml',f11p.FILTER]:return f['filter_xml']
                if argv[-2:]==['net-list','--name']:return b''
                if argv[-2]=='domstate':return b'shut off\n'
                raise AssertionError(str(argv))
            previous=Path.cwd()
            try:
                os.chdir(tmp)
                with patch.object(f11p,'REPO',tmp),patch.object(f11p,'LINK',wants), \
                     patch.object(f11p,'run_readonly',side_effect=fake):
                    with self.assertRaisesRegex(f11p.Blocked,'GIT_CHANGED_DURING_READ'):
                        f11p.host_readonly()
            finally:
                os.chdir(previous)

    def test_bad_git_head(self):
        self.check_error('GIT_HEAD_INVALID',source_head='not-a-sha')

    def test_cannot_claim_first_boot_via_present_service(self):
        report=f11p.assess(**self.f)
        self.assertEqual(report['p8'],'NO-GO')
        self.assertFalse(report['manual_vm_boot_block_attested'])

if __name__ == '__main__':
    unittest.main()
