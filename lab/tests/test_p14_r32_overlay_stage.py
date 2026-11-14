"""P14-R32: exact-scope tests for reversible COW storage staging."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))

from ardrec.coordination import overlay_stage as m
from ardrec.coordination.qcow2_readonly_attestation import (
    SCHEMA as R31_SCHEMA, canonical, sha256, ROLES, HISTORIC_BASES, file_path,
)


def valid_r31():
    doc={
      'schema':R31_SCHEMA,'source_r30_file_sha256':'b'*64,
      'source_r30_report_sha256':'c'*64,'mode':'EXPLICIT_SUDO_READONLY',
      'host':'Prometheus','roles':[{
        'role':role,
        'base':{'path':file_path(role,'base'),'status':'READONLY_VERIFIED',
                'sha256_current':HISTORIC_BASES[role][0],
                'historical_base_hash_match':True,'metadata_match':True},
        'overlay':{'path':file_path(role,'overlay'),'status':'READONLY_VERIFIED',
                   'sha256_current':str(i+1)*64,
                   'historical_base_hash_match':False,'metadata_match':True}
      } for i,role in enumerate(ROLES)],
      'base_hashes_matching_count':4,'overlay_metadata_matching_count':4,
      'summary':'FOUR_BASES_AND_OVERLAYS_READONLY_OBSERVED_NOT_RESTORABLE',
      'images_mutated':False,'vm_started':False,'network_probe_performed':False,
      'restoration_performed':False,'operational_dispatch':False,'can_restore':False,
      'backing_chain_custody_accredited':False,'technical_truth_accredited':False,
      'final_risk':None,'published_generation':None,'p8_operational':'NO-GO',
      'experimental_validation':'NOT_RUN'}
    doc['sha256']=sha256(canonical(doc))
    return doc


class R32Tests(unittest.TestCase):
    def setUp(self):
        self.doc=valid_r31()
        self.plan=m.build_plan(self.doc,'a'*64)

    def test_plan_is_fixed(self):
        self.assertTrue(m.verify_plan(self.plan))
        self.assertFalse(self.plan['can_restore'])
        self.assertEqual(self.plan['stage_directory'],m.STAGE_DIR)
        self.assertEqual(len(self.plan['roles']),4)

    def test_plan_canonical_replay(self):
        self.assertEqual(m.canonical(self.plan),m.canonical(m.build_plan(self.doc,'a'*64)))

    def test_plan_cannot_grant_dispatch_even_with_rehash(self):
        x=copy.deepcopy(self.plan);x['operational_dispatch']=True
        x['sha256']=m.sha256(m.canonical({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaises(m.StageError):m.verify_plan(x)

    def test_plan_cannot_redirect_target_even_with_rehash(self):
        x=copy.deepcopy(self.plan);x['roles'][0]['new_overlay']='/tmp/rogue.qcow2'
        x['sha256']=m.sha256(m.canonical({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaises(m.StageError):m.verify_plan(x)

    def test_plan_cannot_redirect_parent_even_with_rehash(self):
        x=copy.deepcopy(self.plan);x['roles'][0]['parent_overlay']='/tmp/rogue.qcow2'
        x['sha256']=m.sha256(m.canonical({k:v for k,v in x.items() if k!='sha256'}))
        with self.assertRaises(m.StageError):m.verify_plan(x)

    def test_r31_load_exact_file_and_hash(self):
        # The genuine R31 verifier is used by load_r31.
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r31.json';b=m.canonical(self.doc)+b'\n';p.write_bytes(b)
            doc,h=m.load_r31(p,m.sha256(b))
            self.assertEqual(doc['sha256'],self.doc['sha256'])
            self.assertEqual(h,m.sha256(b))

    def test_reject_r31_file_digest(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r31.json';p.write_bytes(m.canonical(self.doc)+b'\n')
            with self.assertRaises(ValueError):m.load_r31(p,'f'*64)

    def test_reject_unverified_r31(self):
        d=copy.deepcopy(self.doc);d['roles'][0]['overlay']['status']='NOT_RUN'
        d['overlay_metadata_matching_count']=3
        d['summary']='CURRENT_ASSET_CUSTODY_INCOMPLETE'
        d['sha256']=m.sha256(m.canonical({k:v for k,v in d.items() if k!='sha256'}))
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r31.json';raw=m.canonical(d)+b'\n';p.write_bytes(raw)
            with self.assertRaises(m.StageError):m.load_r31(p,m.sha256(raw))

    def test_fixed_scope_mkdir(self):
        def fake(*a,**kw):
            from subprocess import CompletedProcess
            return CompletedProcess(a[0],0,b'',b'')
        rc,_,_=m.run_command(['/usr/bin/sudo','-n','--','/usr/bin/mkdir',
                              '--mode=0750','--',m.STAGE_DIR],runner=fake)
        self.assertEqual(rc,0)
        with self.assertRaises(m.StageError):
            m.run_command(['/usr/bin/sudo','-n','--','/usr/bin/mkdir',
                           '--mode=0750','--','/tmp/x'],runner=fake)

    def test_deny_unscoped_qemu_create(self):
        with self.assertRaises(m.StageError):
            m.run_command(['/usr/bin/sudo','-n','--','/usr/bin/qemu-img',
                           'create','-f','qcow2','/tmp/rogue'],runner=lambda *a,**k:None)

    def test_deny_shell_or_power_tools(self):
        for cmd in (['/bin/sh','-c','true'],['/usr/bin/virsh','start','x'],
                    ['/usr/bin/rm','-rf','/'],['/usr/bin/chmod','0777','--',m.STAGE_DIR]):
            with self.subTest(cmd=cmd):
                with self.assertRaises(m.StageError):
                    m.run_command(['/usr/bin/sudo','-n','--',*cmd],runner=lambda *a,**k:None)

    def test_readonly_virsh_only(self):
        for bad in (['/usr/bin/virsh','start','x'],
                    ['/usr/bin/virsh','--readonly','-c','qemu:///system','destroy','x']):
            with self.assertRaises(m.StageError):
                m.run_command(bad,runner=lambda *a,**k:None,elevated=False)

    def test_preserve_failure_before_mkdir(self):
        with patch.object(m,'host_is_idle',side_effect=m.StageError('ardrec_resource_residual')):
            r=m.execute_staging(self.plan)
        self.assertEqual(r['stage_status'],'INCOMPLETE_REVIEW_REQUIRED')
        self.assertEqual(r['new_overlays_created'],0)
        self.assertFalse(r['stage_directory_created'])

    def test_fails_disk_floor(self):
        with self.assertRaises(m.StageError):
            m.execute_staging(self.plan,min_free_bytes=0)

    def test_stage_creates_four_and_keeps_nogo(self):
        stat_result={'kind':'directory','uid':0,'gid':64055,'nlink':2,'mode':0o750}
        child_stat={'kind':'regular file','uid':64055,'gid':64055,'nlink':1,'mode':0o600}
        def fake_info(path, runner):
            role=next(role for role in ROLES if path==m.target_path(role))
            return {'format':'qcow2','virtual-size':HISTORIC_BASES[role][1]*1024**3,
                    'backing-filename':file_path(role,'overlay')}
        with patch.object(m,'host_is_idle'),patch.object(m,'check_storage_parent'),\
             patch.object(m,'check_source_unchanged') as c,\
             patch.object(m.shutil,'disk_usage',return_value=type('D',(),{'free':90*1024**3})()),\
             patch.object(m,'sudo',return_value=b''),\
             patch.object(m,'stage_stat',side_effect=lambda p,r:stat_result if p==m.STAGE_DIR else child_stat),\
             patch.object(m,'stage_info',side_effect=fake_info),\
             patch.object(m,'stage_hash',return_value='d'*64):
            x=m.execute_staging(self.plan)
        self.assertEqual(c.call_count,2)
        self.assertEqual(x['stage_status'],'FOUR_NEW_COW_OVERLAYS_VERIFIED_NOT_STARTED')
        self.assertTrue(x['storage_prepared'])
        self.assertEqual(len(x['new_assets']),4)
        self.assertEqual(x['new_overlays_created'],4)
        self.assertFalse(x['can_restore'])
        self.assertEqual(x['p8_operational'],'NO-GO')

    def test_failure_after_partial_preserves_and_blocks(self):
        with patch.object(m,'host_is_idle'),patch.object(m,'check_storage_parent'),\
             patch.object(m,'check_source_unchanged'),\
             patch.object(m.shutil,'disk_usage',return_value=type('D',(),{'free':90*1024**3})()),\
             patch.object(m,'sudo',side_effect=lambda args,*a,**k:(_ for _ in ()).throw(m.StageError('fail_after_create')) if args[0]=='/usr/bin/chown' and args[-1].endswith('.qcow2') else b''),\
             patch.object(m,'stage_stat',return_value={'kind':'directory','uid':0,'gid':64055,'mode':0o750}):
            x=m.execute_staging(self.plan)
        self.assertEqual(x['stage_status'],'INCOMPLETE_REVIEW_REQUIRED')
        self.assertEqual(x['new_overlays_created'],1)
        self.assertTrue(x['stage_directory_created'])
        self.assertFalse(x['storage_prepared'])

    def test_private_receipt_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700);f=p/'r32_staging.json'
            m.write_receipt(f,self.plan)
            with self.assertRaises(m.StageError):m.write_receipt(f,self.plan)

    def test_symlink_receipt_root_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700);link=p/'ln';link.symlink_to(p,target_is_directory=True)
            with self.assertRaises(m.StageError):m.write_receipt(link/'r32_staging.json',self.plan)

    def test_world_writable_receipt_root_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o777)
            with self.assertRaises(m.StageError):m.write_receipt(p/'r32_staging.json',self.plan)

    def test_empty_argv_rejected(self):
        with self.assertRaises(m.StageError):
            m.run_command([],runner=lambda *a,**k:None)

    def test_host_idle_three_readonly_queries(self):
        from subprocess import CompletedProcess
        history=[]
        def fake(cmd,**kw):
            history.append(cmd)
            return CompletedProcess(cmd,0,b'',b'')
        m.host_is_idle(fake)
        self.assertEqual(len(history),3)
        self.assertTrue(all('--readonly' in x for x in history))

    def test_host_active_domain_denied(self):
        from subprocess import CompletedProcess
        def fake(cmd,**kw):
            return CompletedProcess(cmd,0,b'other-active-vm\n' if cmd[-2:]==['list','--name'] else b'',b'')
        with self.assertRaisesRegex(m.StageError,'active_libvirt_domain'):
            m.host_is_idle(fake)

    def test_host_ardrec_residual_denied(self):
        from subprocess import CompletedProcess
        def fake(cmd,**kw):
            return CompletedProcess(cmd,0,b'ardrec-dev-ssh\n' if cmd[-3:]==['list','--all','--name'] else b'',b'')
        with self.assertRaisesRegex(m.StageError,'ardrec_resource_residual'):
            m.host_is_idle(fake)

    def test_receipt_emits_unique_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td);p.chmod(0o700)
            f=m.write_receipt(p/'r32_staging.json',self.plan)
            self.assertEqual(f.read_bytes(),m.canonical(self.plan)+b'\n')
            self.assertEqual(f.stat().st_mode & 0o777,0o600)

    def test_new_qcow_scope_uses_real_parent(self):
        from subprocess import CompletedProcess
        calls=[]
        def fake(cmd,**kw):
            calls.append(cmd)
            return CompletedProcess(cmd,0,b'Formatting...\n',b'')
        row=self.plan['roles'][0]
        m.sudo(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2',
                '-b',row['parent_overlay'],row['new_overlay']],fake)
        self.assertEqual(len(calls),1)
        with self.assertRaises(m.StageError):
            m.sudo(['/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2',
                    '-b',row['source_base'],row['new_overlay']],fake)

    def test_no_mutation_on_plan(self):
        with patch.object(m,'subprocess') as s:
            x=m.build_plan(self.doc,'a'*64)
        s.run.assert_not_called()
        self.assertEqual(x['mode'],'PLAN_ONLY')


if __name__=='__main__': unittest.main()
