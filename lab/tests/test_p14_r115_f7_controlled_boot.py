"""R115-F7: independent signed boot permit + strict lifecycle; zero host boots in tests."""
from __future__ import annotations

import copy
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from ardrec.coordination import r115_f7_controlled_boot as f
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f5_lifecycle_readiness as f5
from test_p14_r115_f5_lifecycle_readiness import fixture
from test_p14_r115_f3_f11_authority import keypair,seal

NOW=datetime(2026,11,20,16,0,tzinfo=timezone.utc)


def plan(role='ssh'):
    # Pure intentionally non-authoritative draft; not an executable lease.
    return {'schema':f.PLAN_SCHEMA,'head':f.BASE,'role':role,'guest':f.guest(role),
            'command':list(f.command(role)),
            'created_at':'2026-11-20T15:59:00Z',
            'expires_at':'2026-11-21T15:59:00Z',
            'f5_snapshot_sha256':'a'*64,'f5_preflight':{},
            'legacy_snapshot_sha256':'c'*64,
            'contract_sha256':f1.digest(b'contract'),
            'authorization_sha256':f1.digest(b'auth'),
            'predecessor':None if role=='ssh' else {},
            'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'}


def signatures(folder,one, *, revoked=False, expiry=110, wrong_role=False):
    private1,pub1=keypair(folder,'boot')
    private2,pub2=keypair(folder,'revocation')
    trust={'schema':'ARDREC-R115-F7-EXTERNAL-BOOT-TRUST-v1',
           'boot_signer':{'key_id':'bootstrap-boot-key','public_key_pem':pub1},
           'revocation_signer':{'key_id':'bootstrap-revoke-key','public_key_pem':pub2}}
    permit_statement={
        'schema':'ARDREC-R115-F7-ONE-BOOT-PERMIT-v1',
        'permit_id':'approval-F7-SSH-01',
        'role':'ftp' if wrong_role else one['role'],
        'guest':f.guest(one['role']), 'head':one['head'],
        'plan_sha256':f.digest(one),
        'contract_sha256':one['contract_sha256'],
        'authorization_sha256':one['authorization_sha256'],
        'valid_from':'2026-11-20T15:59:55Z',
        'valid_until':(NOW+timedelta(seconds=expiry)).isoformat(),
        'action':'SINGLE_DENY_BOOT_ONLY','network_traffic_authorized':False}
    permit=seal(permit_statement,private1,'bootstrap-boot-key',f.PERMIT_PREFIX,
                folder,'bootpermit')
    revstmt={'schema':'ARDREC-R115-F7-BOOT-REVOCATION-v1',
             'permit_sha256':f.digest(permit),'permit_id':permit_statement['permit_id'],
             'issued_at':'2026-11-20T15:59:45Z',
             'valid_until':'2026-11-20T16:00:45Z',
             'revoked':revoked,'reason_code':'REVOKED' if revoked else 'NOT_REVOKED'}
    rev=seal(revstmt,private2,'bootstrap-revoke-key',f.REVOKE_PREFIX,
             folder,'bootrevoke')
    roots={f.PERMIT_TRUST:f1.canonical(trust),
           f.PERMIT_REVOCATION:f1.canonical(rev)}
    return f1.canonical(permit),lambda path: roots[path]

class F7State(unittest.TestCase):
    def test_order_and_commands(self):
        self.assertEqual(f.pre_states('ssh'),{r:'OFF' for r in f.ALL})
        self.assertEqual(f.pre_states('runner')['ssh'],'RUNNING')
        self.assertEqual(f.pre_states('ftp')['runner'],'RUNNING')
        self.assertEqual(f.post_states('ftp')['ftp'],'RUNNING')
        self.assertEqual(f.command('ssh')[-1],'ardrec-r33-dev-ssh')
        self.assertEqual(f.command('ftp')[-1],'ardrec-r33-dev-ftp')
        with self.assertRaises(f.Stop):f.command('smb')
    def test_offline_is_only_ssh_prepared(self):
        capture=fixture()
        self.assertEqual(f.state_gate(capture,'ssh')['all_deny'],'MATCH')
        with self.assertRaisesRegex(f.Stop,'WRONG_RUNNING'):
            f.state_gate(capture,'runner')
        with self.assertRaisesRegex(f.Stop,'WRONG_RUNNING'):
            f.state_gate(capture,'ssh',after=True)
    def test_ssh_active_denied_stage(self):
        captured=fixture(states={'ssh':'RUNNING','runner':'OFF','ftp':'OFF','smb':'OFF'},
                         active=['ssh'])
        self.assertEqual(f.state_gate(captured,'ssh',after=True)['phase'],'AFTER')
        self.assertEqual(f.state_gate(captured,'runner')['phase'],'BEFORE')
    def test_runner_ftp_sequence(self):
        s={'ssh':'RUNNING','runner':'RUNNING','ftp':'OFF','smb':'OFF'}
        capture=fixture(states=s,active=['ssh','runner_ssh','runner_ftp','runner_smb'])
        self.assertEqual(f.state_gate(capture,'ftp')['role'],'ftp')
        with self.assertRaisesRegex(f.Stop,'WRONG_RUNNING'):
            f.state_gate(capture,'runner')
    def test_drift_nft_denied(self):
        v=fixture();v['probes']['nft']['rc']=1
        with self.assertRaisesRegex(f.Stop,'DENY_OR_F11'):
            f.state_gate(v,'ssh')
    def test_hook_drift_denied(self):
        v=fixture();v['probes']['hook_sha']['stdout']='Y2hhbmdlZA=='
        with self.assertRaisesRegex(f.Stop,'DENY_OR_F11'):
            f.state_gate(v,'ssh')
    def test_definition_drift_denied(self):
        v=fixture();v['probes']['xml_ssh']['rc']=1
        with self.assertRaisesRegex(f.Stop,'VM_DEFINITION'):
            f.state_gate(v,'ssh')
    def test_missing_binding_for_running_denied(self):
        v=fixture(states={'ssh':'RUNNING','runner':'OFF','ftp':'OFF','smb':'OFF'},active=[])
        with self.assertRaisesRegex(f.Stop,'DENY_BINDING'):
            f.state_gate(v,'ssh',after=True)
    def test_live_binding_while_off_denied(self):
        v=fixture(states={r:'OFF' for r in f.ALL},active=['ssh'])
        with self.assertRaisesRegex(f.Stop,'DENY_BINDING'):
            f.state_gate(v,'ssh')
    def test_readonly_inspection_keeps_p8(self):
        with patch.object(f.f5,'capture',return_value=fixture()):
            r=f.read_only(role='ssh')
        self.assertEqual(r['status'],'DENY_STAGE_READY_NO_BOOT_AUTHORITY')
        self.assertFalse(r['traffic_authorized'])
        self.assertEqual(r['p8'],'NO-GO')
        self.assertEqual(r['vm_starts'],0)
    def test_readonly_inspection_denies_incompatible_role(self):
        with patch.object(f.f5,'capture',return_value=fixture()):
            r=f.read_only(role='ftp')
        self.assertEqual(r['status'],'NO-GO')
    def test_unknown_role(self):
        with self.assertRaises(f.Stop):f.pre_states('unknown')
    def test_command_guard(self):
        with self.assertRaisesRegex(f.Stop,'COMMAND_ARGUMENTS'):
            f._run(('echo',1))

class F7Permit(unittest.TestCase):
    def prepare(self): return plan()
    def check(self,doc,permit,roots,now=NOW):
        return f.signed_boot_permit(doc,b'contract',b'auth',permit,
                                     now=now,root_loader=roots)
    def test_valid_distinct_signed_boot_permit_no_traffic(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc)
            out=self.check(doc,permit,roots)
            self.assertEqual(out['role'],'ssh')
            self.assertEqual(out['boot_permit_sha256'],f.digest(f1.load(permit)))
            self.assertNotIn('traffic_authorized',out)
    def test_signed_revocation_forbids(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc,revoked=True)
            with self.assertRaisesRegex(f.Stop,'REVOKED'):
                self.check(doc,permit,roots)
    def test_signed_wrong_role_forbids(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc,wrong_role=True)
            with self.assertRaisesRegex(f.Stop,'SCOPE_MISMATCH'):
                self.check(doc,permit,roots)
    def test_expired_boot_permit_forbids(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc,expiry=-1)
            with self.assertRaisesRegex(f.Stop,'EXPIRED'):
                self.check(doc,permit,roots)
    def test_stale_boot_revocation_forbids(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc)
            with self.assertRaisesRegex(f.Stop,'REVOCATION_NOT_CURRENT'):
                self.check(doc,permit,roots,now=NOW+timedelta(seconds=100))
    def test_authorization_bytes_binding(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc)
            with self.assertRaisesRegex(f.Stop,'AUTHORIZATION_BYTES_CHANGED'):
                f.signed_boot_permit(doc,b'other',b'auth',permit,now=NOW,root_loader=roots)
    def test_permit_tamper_signature_is_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc)
            obj=f1.load(permit);obj['statement']['permit_id']='approval-IMPOSTOR'
            with self.assertRaises(f.f3.Stop):
                self.check(doc,f1.canonical(obj),roots)
    def test_missing_root_provisioning(self):
        with tempfile.TemporaryDirectory() as t:
            doc=self.prepare();permit,roots=signatures(Path(t),doc)
            with self.assertRaises(FileNotFoundError):
                self.check(doc,permit,lambda p:(_ for _ in ()).throw(FileNotFoundError()))
    def test_plan_expired(self):
        doc=self.prepare();cap=fixture()
        doc['f5_snapshot_sha256']=f1.digest(f1.canonical(cap))
        doc['f5_preflight']=f.state_gate(cap,'ssh')
        with self.assertRaisesRegex(f.Stop,'PLAN_EXPIRED'):
            f.verify_plan({k:v for k,v in doc.items() if k!='legacy_snapshot_sha256'},
                          cap,now=NOW+timedelta(days=3),head=f.BASE)
    def test_plan_head_change(self):
        doc=self.prepare();cap=fixture()
        with self.assertRaisesRegex(f.Stop,'PLAN_SCOPE'):
            f.verify_plan({k:v for k,v in doc.items() if k!='legacy_snapshot_sha256'},
                          cap,now=NOW,head='b'*40)
    def test_expected_predecessor_requires_prior(self):
        with self.assertRaisesRegex(f.Stop,'MISSING_PREDECESSOR'):
            f.expected_predecessor('runner',None)
        self.assertIsNone(f.expected_predecessor('ssh',None))
        with self.assertRaisesRegex(f.Stop,'UNEXPECTED_PREDECESSOR'):
            f.expected_predecessor('ssh',{})
    def test_no_unknown_root_paths(self):
        with self.assertRaises(f.Stop):
            f._secure_root(Path('/tmp/fake-permit.json'))
    def test_ssh_role_only_physical_gate(self):
        self.assertIn('ssh',f.ORDER)
        self.assertNotIn('smb',f.ORDER)
    def test_no_readonly_root_mutation_apis(self):
        self.assertEqual(f.BRANCH,'feat/p14-r115-a3-p7-a6-real')
        self.assertEqual(f.ACTIVE_BRANCH,'feat/ardrec-a1-a10-cierre-integral-v1')
        self.assertEqual(f.ACTIVE_BASE,'5c7770c1548585f8eac7f50d5f68b8fb77a10614')
        self.assertEqual(f.BASE,'6ce42a1143d50f7adf69ea3159b56c0e993c45cb')
    def test_command_timeout_fails_closed(self):
        import subprocess
        def timeout(*args,**kwargs):
            raise subprocess.TimeoutExpired(args[0],2)
        rec=f._run(f.command('ssh'),runner=timeout)
        self.assertIsNone(rec['rc']);self.assertTrue(rec['timeout'])
        with self.assertRaises(f.Stop):f.ok(rec,'NO_ACK')


class F7SourceGuard(unittest.TestCase):
    def fake(self, *, branch=None, status='', signature='G', tracked=True):
        import subprocess
        branch=branch or f.BRANCH
        def respond(argv,**kwargs):
            args=list(argv)
            if args[:3]==['git','rev-parse','--show-toplevel']:
                text=str(Path.cwd().resolve())
            elif args[:3]==['git','branch','--show-current']:
                text=branch
            elif args[:3]==['git','rev-parse','HEAD']:
                text=f.BASE
            elif args[:3]==['git','status','--porcelain=v1']:
                text=status
            elif args[:3]==['git','log','-1']:
                text=signature
            elif args[:3]==['git','ls-files','--error-unmatch']:
                return subprocess.CompletedProcess(args,0 if tracked else 1,b'',b'')
            elif args[:3]==['git','diff','--quiet']:
                return subprocess.CompletedProcess(args,0,b'',b'')
            elif args[:3]==['git','merge-base','--is-ancestor']:
                return subprocess.CompletedProcess(args,0,b'',b'')
            else:
                raise AssertionError(args)
            return subprocess.CompletedProcess(args,0,(text+'\n').encode(),b'')
        return respond
    def test_committed_signed_clean_source_can_pass(self):
        with patch.object(f,'REPO',Path.cwd().resolve()):
            self.assertEqual(f.git_guard(for_boot=True,runner=self.fake()),f.BASE)
    def test_historical_branch_rejected(self):
        with patch.object(f,'REPO',Path.cwd().resolve()):
            with self.assertRaisesRegex(f.Stop,'BRANCH_MISMATCH'):
                f.git_guard(runner=self.fake(branch='feat/p14-r111-r114-real-lab'))
    def test_uncommitted_executor_rejected(self):
        with patch.object(f,'REPO',Path.cwd().resolve()):
            with self.assertRaisesRegex(f.Stop,'SOURCE_NOT_COMMITTED'):
                f.git_guard(for_boot=True,runner=self.fake(tracked=False))
    def test_unsigned_head_rejected(self):
        with patch.object(f,'REPO',Path.cwd().resolve()):
            with self.assertRaisesRegex(f.Stop,'UNTRUSTED_OR_UNSIGNED'):
                f.git_guard(runner=self.fake(signature='N'))
    def test_dirty_tree_rejected(self):
        with patch.object(f,'REPO',Path.cwd().resolve()):
            with self.assertRaisesRegex(f.Stop,'SOURCE_TREE_NOT_CLEAN'):
                f.git_guard(runner=self.fake(status=' M a.py'))

class F7PhysicalOneUse(unittest.TestCase):
    """Simulate the physical boundary with strictly fake command results."""
    def build(self,folder,role='ssh'):
        pre=fixture()
        d=plan(role)
        d['f5_snapshot_sha256']=f1.digest(f1.canonical(pre))
        d['f5_preflight']=f.state_gate(pre,'ssh')
        d['created_at']='2026-11-20T15:59:00Z'
        d['expires_at']='2026-11-21T15:59:00Z'
        root=Path(folder)/'private'
        root.mkdir(mode=0o700)
        staged=Path(tempfile.mkdtemp(prefix='plan-',dir=root))
        return root,staged,d,pre

    def exercise(self,root,staged,doc,pre,*,fail_start=False):
        after=fixture(states={'ssh':'RUNNING','runner':'OFF','ftp':'OFF','smb':'OFF'},active=['ssh'])
        paths=[];starts=[];ticket_bytes=[None]
        def fake_run(argv,*,timeout=20,runner=None):
            command=list(argv)
            paths.append(command)
            if command==list(f.command('ssh')):
                starts.append(command)
                return {'argv':command,'rc':23 if fail_start else 0,'timeout':False,
                        'truncated':False,'stdout':'','stderr':''}
            value=''
            if command[2:4]==['stat','-Lc']:
                path=command[-1]
                if path==f.f12.ROOT_LEASE:
                    value='0:0 700 '+path+'\n'
                elif path==f.f12.lease('ssh'):
                    size=len(ticket_bytes[0])
                    value=f'0:0 600 1 {size} {path}\n'
                else:
                    value='0:0 600 1 65 '+path+'\n'
            if command[2:3]==['sha256sum']:
                value=f1.digest(ticket_bytes[0])+'  '+command[-1]+'\n'
            if command[2:3]==['cat']:
                value=f1.digest(ticket_bytes[0])+'\n'
            if command[2:3]==['install'] and command[-1]==f.f12.lease('ssh'):
                ticket_bytes[0]=Path(command[-2]).read_bytes()
            if command[-3:]==['dumpxml','ardrec-r33-dev-ssh'] or (
                command[:2]==['virsh','--readonly']):
                value='<domain/>'
            return {'argv':command,'rc':0,'timeout':False,'truncated':False,
                    'stdout':value,'stderr':''}
        path1=Path(root.parent)/'contract.json'
        path2=Path(root.parent)/'authorization.json'
        path3=Path(root.parent)/'bootpermit.json'
        for path,raw in ((path1,b'contract'),(path2,b'auth'),(path3,b'permit')):
            path.write_bytes(raw);path.chmod(0o600)
        patches=[
          patch.object(f,'ROOT',root),
          patch.object(f,'git_guard',return_value=f.BASE),
          patch.object(f,'_read_plan',return_value=(doc,pre,{'legacy':True})),
          patch.object(f,'scope_required',return_value=('VERDADERO','SIGNED','a'*64)),
          patch.object(f,'signed_boot_permit',return_value={
              'boot_permit_sha256':'1'*64,
              'valid_until':'2026-11-20T16:01:40Z'}),
          patch.object(f.f5,'capture',side_effect=[pre,after]),
          patch.object(f,'_capture_legacy',return_value={'legacy':True}),
          patch.object(f,'_audit_legacy',return_value=True),
          patch.object(f.f12,'boundary',return_value=True),
          patch.object(f,'_no_markers',return_value=None),
          patch.object(f,'_run',side_effect=fake_run),
          patch.object(f,'_old_classifier_ssh',return_value={'proof':'PASS'}),
        ]
        from contextlib import ExitStack
        with ExitStack() as stack:
            for x in patches:stack.enter_context(x)
            if fail_start:
                with self.assertRaisesRegex(f.Stop,'PHYSICAL_ATTEMPT_NOT_ATTESTED'):
                    f._boot_ssh(staged,path1,path2,path3,clock=lambda:NOW)
                self.assertTrue((staged/'boot.once').exists())
                with self.assertRaisesRegex(f.Stop,'ALREADY_ATTEMPTED'):
                    f._boot_ssh(staged,path1,path2,path3,clock=lambda:NOW)
                self.assertEqual(len(starts),1)
                found=list(root.glob('boot-*/incident.json'))
                self.assertEqual(len(found),1)
                self.assertFalse(f1.load(found[0].read_bytes())['retry_permitted'])
            else:
                folder,rec=f._boot_ssh(staged,path1,path2,path3,clock=lambda:NOW)
                self.assertEqual(rec['vm_starts'],1)
                self.assertEqual(rec['p8'],'NO-GO')
                self.assertFalse(rec['traffic_authorized'])
                self.assertEqual(len(starts),1)
                self.assertTrue((staged/'boot.once').exists())
                self.assertTrue((folder/'receipt.json').is_file())
        return paths

    def test_success_has_one_boot_and_journal(self):
        with tempfile.TemporaryDirectory() as t:
            root,staged,doc,pre=self.build(t)
            paths=self.exercise(root,staged,doc,pre)
            self.assertEqual(sum(p[-2:]==['start',f.guest('ssh')] for p in paths),1)
    def test_failure_never_retries_or_cleans_lease(self):
        with tempfile.TemporaryDirectory() as t:
            root,staged,doc,pre=self.build(t)
            paths=self.exercise(root,staged,doc,pre,fail_start=True)
            self.assertEqual(sum(p[-2:]==['start',f.guest('ssh')] for p in paths),1)

if __name__=='__main__':unittest.main()
