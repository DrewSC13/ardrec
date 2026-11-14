"""R40 independent synthetic oracles. No libvirt/net/guest operations."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r40_ssh_resume_preflight as r40
from ardrec.coordination import r39_ssh_reconciliation as r39
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r365_first_boot as r365

S='a'*64
CAPTURE='2026-11-14T22:15:00Z'

def live():
    return {'phase':'NETWORK_ONLY', 'active_networks':[r365.SSH_NETWORK],
            'active_domains':[], 'reserved_links':[r365.t33.NET_BRIDGE['ssh']],
            'bridge_macs':copy.deepcopy(r35.R354_EXISTING_BRIDGE_MACS),
            'deny_first_still_verified':True}

def chain():
    return {'r39_report_sha256':S,'r39_file_sha256':'b'*64,
            'r365_first_boot_report_sha256':'c'*64,
            'r365_preflight_report_sha256':'d'*64,
            'r365_first_boot_commands_sha256':'e'*64,
            'r39_host_readback':live(), 'source_evidence':{'synthetic':True}}

def storage():
    assets=[]
    for role in r35.t33.ROLES:
        assets.append({'role':role, 'runtime_sha256_observed':S,
                       'runtime_preboot_sha256':('b'*64 if role=='ssh' else S),
                       'runtime_sha256_policy':('POSTBOOT_OBSERVATION_NOT_PREBOOT_ORACLE'
                           if role=='ssh' else 'UNMODIFIED_PREBOOT_EXPECTED'),
                       'immutable_layers_verified':True,'qcow2_structure_verified':True,
                       'runtime_observation_stable':True})
    return {'verified_roles':4,'assets':assets,'source_images_mutated_by_r40':False,
            'ssh_runtime_preboot_hash_enforced':False,
            'non_ssh_runtime_preboot_hash_enforced':True}

def r32():
    rows=[];assets=[]
    for role in r35.t33.ROLES:
        root=f'/var/lib/libvirt/images/ardrec-dev-point4-v4/{role}-base.qcow2'
        par=f'/var/lib/libvirt/images/ardrec-dev-point4-v6/{role}-runtime.qcow2'
        runtime=f'{r35.t33.R32_STAGE}/{role}-runtime.qcow2'
        rows.append({'role':role,'source_base':root,'parent_overlay':par,
                     'new_overlay':runtime,'virtual_size':1024,
                     'source_base_sha256':'a'*64,'parent_overlay_sha256':'b'*64})
        assets.append({'role':role,'path':runtime,'backing_filename':par,
                       'virtual_size':1024,'sha256':'c'*64})
    return {'roles':rows,'new_assets':assets}

class FakeFiles:
    def __init__(self, runtime_change=False, wrong_nonssh=False, changed_during_read=False,
                 bad_mode=False, wrong_base=False, wrong_backing=False):
        self.rows=r32()
        self.runtime_change=runtime_change
        self.wrong_nonssh=wrong_nonssh
        self.changed_during_read=changed_during_read
        self.bad_mode=bad_mode
        self.wrong_base=wrong_base
        self.wrong_backing=wrong_backing
        self.counts={}
        self.seen=[]
    def stat(self,h,path):
        self.seen.append(('stat',path))
        if path in ('/var','/var/lib','/var/lib/libvirt','/var/lib/libvirt/images'):
            return {'kind':'directory','uid':0,'gid':0,'mode':0o755}
        if path == r35.t33.R32_STAGE:
            return {'kind':'directory','uid':0,'gid':r35.QEMU_GID,'mode':0o750}
        role=next(r for r in r35.t33.ROLES if f'/{r}-' in path)
        is_base=path.endswith('-base.qcow2')
        is_run=path.startswith(r35.t33.R32_STAGE)
        result={'kind':'regular file','uid':r35.QEMU_UID,'gid':r35.QEMU_GID,
                'mode':(0o600 if not is_base else 0o400),'nlink':1,
                'size':33,'inode':100,'mtime':10,'ctime':10}
        if is_run and self.bad_mode:result['mode']=0o644
        if is_run and self.changed_during_read:
            n=self.counts.get(('stat',path),0)
            self.counts[('stat',path)]=n+1
            result['mtime']=10+n
        return result
    def digest(self,h,path):
        self.seen.append(('hash',path))
        if path.endswith('-base.qcow2'):
            return '0'*64 if self.wrong_base else 'a'*64
        if '/ardrec-dev-point4-v6/' in path:return 'b'*64
        role=next(r for r in r35.t33.ROLES if f'/{r}-' in path)
        if role=='ssh' and self.runtime_change:return 'd'*64
        if role=='ftp' and self.wrong_nonssh:return 'd'*64
        return 'c'*64
    def info(self,h,path):
        self.seen.append(('info',path))
        obj={'format':'qcow2','virtual-size':1024}
        if '/ardrec-dev-point4-v6/' in path:
            role=next(r for r in r35.t33.ROLES if f'/{r}-' in path)
            obj['backing-filename']=f'/var/lib/libvirt/images/ardrec-dev-point4-v4/{role}-base.qcow2'
        elif path.startswith(r35.t33.R32_STAGE):
            role=next(r for r in r35.t33.ROLES if f'/{r}-' in path)
            obj['backing-filename']=('/other/image.qcow2' if self.wrong_backing else
                                     f'/var/lib/libvirt/images/ardrec-dev-point4-v6/{role}-runtime.qcow2')
        return obj

class R40Tests(unittest.TestCase):
    def test_report_valid_keeps_no_go(self):
        data=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        self.assertTrue(r40.verify_report(data))
        self.assertEqual(data['status'],r40.STATUS)
        self.assertFalse(data['permission_to_resume'])
        self.assertFalse(data['guest_isolation_tested'])
        self.assertIsNone(data['final_risk'])
        self.assertEqual(data, r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE))

    def test_report_rehash_false_resume_authority_rejected(self):
        x=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        x['permission_to_resume']=True
        x['sha256']=r40.sha(r40.canon({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaisesRegex(r40.R40Error,'false_authority'):r40.verify_report(x)

    def test_rehash_isolation_claim_rejected(self):
        x=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        x['guest_isolation_tested']=True
        x['sha256']=r40.sha(r40.canon({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaises(r40.R40Error):r40.verify_report(x)

    def test_report_unhashed_mutation_rejected(self):
        x=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        x['experimental_validation']='RUN'
        with self.assertRaisesRegex(r40.R40Error,'digest_invalid'):r40.verify_report(x)

    def test_report_rehashed_storage_false_claim_rejected(self):
        x=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        x['storage']['assets'][1]['immutable_layers_verified']=False
        x['sha256']=r40.sha(r40.canon({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaisesRegex(r40.R40Error,'storage_false_claim'):r40.verify_report(x)

    def test_report_nonssh_runtime_drift(self):
        x=storage(); x['assets'][1]['runtime_sha256_observed']='e'*64
        with self.assertRaisesRegex(r40.R40Error,'storage_readback_invalid'):
            r40.make_report(chain(),live(),live(),x,captured_at_utc=CAPTURE)

    def test_report_network_drift(self):
        after=live();after['active_domains']=[r365.SSH_DOMAIN]
        with self.assertRaisesRegex(r40.R40Error,'physical_readback_drift'):
            r40.make_report(chain(),live(),after,storage(),captured_at_utc=CAPTURE)

    def test_report_bad_time(self):
        with self.assertRaisesRegex(r40.R40Error,'capture_time_noncanonical'):
            r40.make_report(chain(),live(),live(),storage(),captured_at_utc='2026-11-14T22:15:0Z')

    def test_source_chain_rehashed_drift(self):
        summary={'preflight_report_sha256':'d'*64,'preflight_file_sha256':'1'*64,
                 'first_boot_report_sha256':'c'*64,'first_boot_file_sha256':'2'*64,
                 'first_boot_commands_sha256':'e'*64,'source_evidence':{'ok':True}}
        doc=r39.reconcile(summary,live(),captured_at_utc=CAPTURE)
        doc['source_first_boot_report_sha256']='f'*64
        doc['sha256']=r40.sha(r40.canon({k:v for k,v in doc.items() if k!='sha256'}))
        raw=r40.canon(doc)
        with mock.patch.object(r40,'verified_directory',return_value={'r39_reconciliation.json':raw}),\
             mock.patch.object(r40.r39,'read_r365_chain',return_value=summary):
            with self.assertRaisesRegex(r40.R40Error,'r39_to_r365_chain_drift'):
                r40.verify_r39_source(Path('/r39'),Path('/pre'),Path('/boot'))

    def test_source_chain_valid_summary(self):
        summary={'preflight_report_sha256':'d'*64,'preflight_file_sha256':'1'*64,
                 'first_boot_report_sha256':'c'*64,'first_boot_file_sha256':'2'*64,
                 'first_boot_commands_sha256':'e'*64,'source_evidence':{'ok':True}}
        doc=r39.reconcile(summary,live(),captured_at_utc=CAPTURE)
        raw=r40.canon(doc)
        with mock.patch.object(r40,'verified_directory',return_value={'r39_reconciliation.json':raw}),\
             mock.patch.object(r40.r39,'read_r365_chain',return_value=summary):
            result=r40.verify_r39_source(Path('/r39'),Path('/pre'),Path('/boot'))
        self.assertEqual(result['r39_report_sha256'],doc['sha256'])
        self.assertEqual(result['r365_first_boot_report_sha256'],'c'*64)

    def test_storage_readonly_accepts_postboot_ssh_digest(self):
        fake=FakeFiles(runtime_change=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            out=r40.verify_storage_postboot(object(),r32())
        self.assertEqual(out['verified_roles'],4)
        self.assertFalse(out['ssh_runtime_preboot_hash_enforced'])
        self.assertEqual(out['assets'][0]['runtime_sha256_observed'],'d'*64)
        self.assertEqual(out['assets'][1]['runtime_sha256_observed'],'c'*64)
        self.assertTrue(all(verb in ('stat','hash','info') for verb,path in fake.seen))

    def test_storage_unchanged_ssh_digest_also_allowed(self):
        fake=FakeFiles()
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            out=r40.verify_storage_postboot(object(),r32())
        self.assertEqual(out['verified_roles'],4)

    def test_storage_rejects_unmodified_nonssh_drift(self):
        fake=FakeFiles(wrong_nonssh=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            with self.assertRaisesRegex(r40.R40Error,'other_runtime_changed_ftp'):
                r40.verify_storage_postboot(object(),r32())

    def test_storage_rejects_overlay_change_during_read(self):
        fake=FakeFiles(changed_during_read=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            with self.assertRaisesRegex(r40.R40Error,'runtime_overlay_changed_during_read'):
                r40.verify_storage_postboot(object(),r32())

    def test_storage_rejects_bad_permissions(self):
        fake=FakeFiles(bad_mode=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            with self.assertRaisesRegex(r40.R40Error,'runtime_overlay_permissions_drift'):
                r40.verify_storage_postboot(object(),r32())

    def test_storage_rejects_wrong_base_sha(self):
        fake=FakeFiles(wrong_base=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            with self.assertRaisesRegex(r40.R40Error,'immutable_layer_digest_drift'):
                r40.verify_storage_postboot(object(),r32())

    def test_storage_rejects_wrong_backing(self):
        fake=FakeFiles(wrong_backing=True)
        with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
             mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
             mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
            with self.assertRaises(Exception):
                r40.verify_storage_postboot(object(),r32())

    def test_storage_rejects_r32_order_wrong(self):
        x=r32();x['new_assets'][0]['role']='foreign'
        with self.assertRaisesRegex(r40.R40Error,'r32_asset_binding_invalid'):
            fake=FakeFiles()
            with mock.patch.object(r35,'_stat_command',side_effect=fake.stat),\
                 mock.patch.object(r35,'_hash_command',side_effect=fake.digest),\
                 mock.patch.object(r35,'_qemu_info',side_effect=fake.info):
                r40.verify_storage_postboot(object(),x)

    def test_readonly_host_forbids_activations(self):
        host=object.__new__(r40.ReadOnlyHost)
        for method,arg in (('activate_ssh_network',()),('activate_ssh_domain',()),
                           ('virsh_write',(['start',r365.SSH_DOMAIN],))):
            with self.assertRaises(r40.R40Error):getattr(host,method)(*arg)

    def test_receipt_private_and_exclusive(self):
        report=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700);d=p/'r40'
            r40.persist_private(d,report)
            raw=(d/'r40_preflight.json').read_bytes()
            self.assertEqual(json.loads(raw),report)
            self.assertEqual((d/'SHA256SUMS').read_bytes(),hashlib.sha256(raw).hexdigest().encode()+b'  r40_preflight.json\n')
            self.assertEqual(stat.S_IMODE(d.stat().st_mode),0o700)
            self.assertEqual(stat.S_IMODE((d/'r40_preflight.json').stat().st_mode),0o600)
            with self.assertRaises(r40.R40Error):r40.persist_private(d,report)

    def test_receipt_rejects_world_readable_parent(self):
        report=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o755)
            with self.assertRaisesRegex(r40.R40Error,'r40_parent_not_private'):
                r40.persist_private(p/'r40',report)

    def test_receipt_rejects_parent_symlink(self):
        report=r40.make_report(chain(),live(),live(),storage(),captured_at_utc=CAPTURE)
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);(p/'private').mkdir(mode=0o700)
            (p/'link').symlink_to(p/'private',target_is_directory=True)
            with self.assertRaisesRegex(r40.R40Error,'r40_receipt_destination_invalid'):
                r40.persist_private(p/'link'/'r40',report)

    def test_perform_no_host_mutation(self):
        src=chain(); fakehost=mock.Mock()
        state=live();seen=[]
        def capture(h):seen.append('read');return copy.deepcopy(state)
        sample=r32()
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(r40,'verify_r39_source',return_value=src),\
             mock.patch.object(r40.r39,'capture_current',side_effect=capture),\
             mock.patch.object(r40.r35,'verify_source_bundle',return_value={'r32':sample}),\
             mock.patch.object(r40.r35.t33,'verify_r32'),\
             mock.patch.object(r40,'verify_storage_postboot',return_value=storage()),\
             mock.patch.object(r40,'persist_private') as persist:
            result=r40.perform(source_archive=Path('/fixture'),r39_dir=Path('/r39'),
                  r365_preflight_dir=Path('/pre'),r365_boot_dir=Path('/boot'),
                  receipt_dir=Path(td)/'dst',host=fakehost)
        self.assertEqual(seen,['read','read'])
        self.assertEqual(result['status'],r40.STATUS)
        fakehost.activate_ssh_network.assert_not_called()
        fakehost.activate_ssh_domain.assert_not_called()
        persist.assert_called_once()

    def test_perform_refuses_r39_host_drift(self):
        src=chain();fakehost=mock.Mock();state=live();state['active_domains']=['foreign']
        with mock.patch.object(r40,'verify_r39_source',return_value=src),\
             mock.patch.object(r40.r39,'capture_current',return_value=state):
            with self.assertRaisesRegex(r40.R40Error,'host_state_drift_since_r39'):
                r40.perform(source_archive=Path('/fixture'),r39_dir=Path('/r39'),
                    r365_preflight_dir=Path('/pre'),r365_boot_dir=Path('/boot'),
                    receipt_dir=Path('/receipt'),host=fakehost)

if __name__=='__main__':
    unittest.main()
