"""R115-F8: stage ordering, signed handoff, one-shot denial-only runner/FTP."""
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
import tempfile

from ardrec.coordination import r115_f8_runner_ftp_boot as f
from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_dev_admission_contract as f1

NOW = datetime(2026,11,20,16,30,tzinfo=timezone.utc)


def prior(role):
    return {'role':'ssh' if role=='runner' else 'runner',
            'plan_dir':'/private/plan-1','boot_dir':'/private/boot-1',
            'receipt_sha256':'e'*64}


def base(role):
    return {'schema':f.SCHEMA+'-plan','role':role,'guest':f7.guest(role),
            'head':f7.BASE,'command':list(f7.command(role)),
            'created_at':'2026-11-20T16:29:00Z',
            'expires_at':'2026-11-20T16:59:00Z',
            'contract_sha256':f1.digest(b'c'),'authorization_sha256':f1.digest(b'a'),
            'f5_snapshot_sha256':f1.digest(f1.canonical({'foo':1})),
            'r112_snapshot_sha256':f1.digest(f1.canonical({'old':1})),
            'f5_stage_gate':{'guard':'DENY'},'predecessor':prior(role),
            'traffic_authorized':False,'a5':'NO-GO','a6':'ND','p8':'NO-GO'}

class StageTests(TestCase):
    def test_exact_roles_and_command(self):
        self.assertEqual(f.ROLES,('runner','ftp'))
        self.assertIn('runner',f7.command('runner')[-1])
        self.assertIn('ftp',f7.command('ftp')[-1])
        with self.assertRaises(f.Stop):f.plan_spec('smb',f7.BASE,b'c',b'a',{}, {},prior('runner'),NOW)

    def test_plan_runner(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            record=f.plan_spec('runner',f7.BASE,b'c',b'a',{'foo':1},{'old':1},prior('runner'),NOW)
            self.assertEqual(record['a5'],'NO-GO')
            self.assertFalse(record['traffic_authorized'])
            f.verify_spec(record,{'foo':1},{'old':1},prior('runner'),head=f7.BASE,now=NOW)

    def test_plan_ftp(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            record=f.plan_spec('ftp',f7.BASE,b'c',b'a',{'foo':1},{'old':1},prior('ftp'),NOW)
            self.assertEqual(record['role'],'ftp')
            f.verify_spec(record,{'foo':1},{'old':1},prior('ftp'),head=f7.BASE,now=NOW)

    def test_predecessor_must_match(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            with self.assertRaisesRegex(f.Stop,'BAD_PREDECESSOR'):
                f.plan_spec('ftp',f7.BASE,b'c',b'a',{'foo':1},{'old':1},prior('runner'),NOW)

    def test_plan_expired(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            d=base('runner')
            with self.assertRaisesRegex(f.Stop,'PLAN_EXPIRED'):
                f.verify_spec(d,{'foo':1},{'old':1},prior('runner'),head=f7.BASE,
                              now=datetime(2026,11,20,17,15,tzinfo=timezone.utc))

    def test_plan_different_head(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            with self.assertRaisesRegex(f.Stop,'PLAN_SCOPE_CHANGED'):
                f.verify_spec(base('runner'),{'foo':1},{'old':1},prior('runner'),head='0'*40,now=NOW)

    def test_false_traffic_rejected(self):
        with patch.object(f7,'state_gate',return_value={'guard':'DENY'}):
            d=base('ftp');d['traffic_authorized']=True
            with self.assertRaisesRegex(f.Stop,'PLAN_SCOPE_CHANGED'):
                f.verify_spec(d,{'foo':1},{'old':1},prior('ftp'),head=f7.BASE,now=NOW)

    def test_no_previous_no_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'vault';root.mkdir(mode=0o700)
            with patch.object(f,'ROOT',root):
                f._no_attempt('runner')
                (root/'one-runner.once').write_text('ATTEMPTED\n')
                with self.assertRaisesRegex(f.Stop,'ROLE_ALREADY_ATTEMPTED'):
                    f._no_attempt('runner')

    def test_unsigned_uncommitted_guard(self):
        with patch.object(f7,'git_guard',return_value=f7.BASE), \
             patch.object(f7,'_run',return_value={'rc':1,'stdout':'','stderr':'',
                  'timeout':False,'truncated':False}):
            with self.assertRaisesRegex(f.Stop,'F8_SOURCE_NOT_COMMITTED'):
                f._check_sources()

    def test_partial_stage_requires_denied_predecessors(self):
        with patch.object(f7,'state_gate',side_effect=f7.Stop('DENY_BINDING_NOT_VERIFIED')):
            with self.assertRaises(f7.Stop):
                f7.state_gate({'untrusted':True},'runner')

    def test_inspect_never_calls_boot(self):
        with patch.object(f.f5,'capture',return_value={'raw':True}), \
             patch.object(f.f5,'report',return_value={'nft':'MATCH'}), \
             patch.object(f7,'state_gate',side_effect=f7.Stop('VM_OFF')):
            result=f.inspect('runner')
            self.assertEqual(result['status'],'NO-GO')
            self.assertFalse(result['traffic_authorized'])
            self.assertEqual(result['p8'],'NO-GO')

    def test_inspect_invalid_role(self):
        with self.assertRaises(f.Stop):f.inspect('ssh')

    def test_physical_boot_needs_committed_source(self):
        with patch.object(f,'_check_sources',side_effect=f.Stop('NOT_SIGNED')):
            with self.assertRaisesRegex(f.Stop,'NOT_SIGNED'):
                f.boot(Path('/tmp/no'),Path('/tmp/no'),Path('/tmp/no'),Path('/tmp/no'))

    def test_before_role_claim_invalid_is_no_boot(self):
        with patch.object(f,'_check_sources',return_value=f7.BASE), \
             patch.object(f,'_read_plan',return_value=(base('runner'),{'foo':1},{'old':1})), \
             patch.object(f,'predecessor',side_effect=f.Stop('PREDECESSOR_REVOKED')):
            with self.assertRaisesRegex(f.Stop,'PREDECESSOR_REVOKED'):
                f.boot(Path('/tmp/no'),Path('/tmp/no'),Path('/tmp/no'),Path('/tmp/no'))

class PhysicalOneShotTests(TestCase):
    def exercise(self,role,fail=False):
        from contextlib import ExitStack
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'records';root.mkdir(mode=0o700)
            plan_dir=root/'plan-for-test';plan_dir.mkdir(mode=0o700)
            context=[patch.object(f,'ROOT',root),
                     patch.object(f,'_check_sources',return_value=f7.BASE),
                     patch.object(f,'_read_plan',return_value=(base(role),{'foo':1},{'old':1})),
                     patch.object(f,'predecessor',return_value=prior(role)),
                     patch.object(f,'verify_spec',return_value=True),
                     patch.object(f.f2,'private_read',side_effect=[b'c',b'a',b'p']),
                     patch.object(f7,'scope_required',return_value=('VERDADERO',)),
                     patch.object(f7,'signed_boot_permit',return_value={
                         'boot_permit_sha256':'b'*64,
                         'valid_until':'2026-11-20T16:31:50Z'}),
                     patch.object(f.f5,'capture',side_effect=[{'foo':1},{'foo':2}]),
                     patch.object(f7,'state_gate',return_value={'guard':'DENY'}),
                     patch.object(f7,'_capture_legacy',return_value={'old':1}),
                     patch.object(f7,'_audit_legacy',return_value=True),
                     patch.object(f7,'_no_markers',return_value=None),
                     patch.object(f7.f12,'boundary',return_value=True),
                     patch.object(f.f10,'audited',return_value=True),
                     patch.object(f,'_legacy_proof',return_value={'proof':'PASS'})]
            fake_paths=[]
            ticket=[None]
            def fake_run(argv,*,timeout=20,runner=None):
                cmd=list(argv);fake_paths.append(cmd)
                if cmd==list(f7.command(role)):
                    rc=19 if fail else 0
                    return {'argv':cmd,'rc':rc,'timeout':False,
                            'truncated':False,'stdout':'','stderr':''}
                value=''
                lease,markers,lease_root=f7._lease(role)
                if cmd[2:4]==['stat','-Lc']:
                    path=cmd[-1]
                    if path==lease_root: value='0:0 700 '+path+'\n'
                    elif path==lease: value=f'0:0 600 1 {len(ticket[0])} {path}\n'
                    else: value='0:0 600 1 65 '+path+'\n'
                if cmd[2:3]==['sha256sum']:
                    value=f1.digest(ticket[0])+'  '+cmd[-1]+'\n'
                if cmd[2:3]==['cat']:
                    value=f1.digest(ticket[0])+'\n'
                if cmd[2:3]==['install'] and cmd[-1]==lease:
                    ticket[0]=Path(cmd[-2]).read_bytes()
                if cmd[:2]==['virsh','--readonly']:
                    value='<domain/>'
                return {'argv':cmd,'rc':0,'timeout':False,
                        'truncated':False,'stdout':value,'stderr':''}
            context += [patch.object(f7,'_run',side_effect=fake_run),
                        patch.object(f7,'_ticket',return_value=f7._ticket(role))]
            with ExitStack() as stack:
                for item in context:stack.enter_context(item)
                if fail:
                    with self.assertRaisesRegex(f.Stop,'ATTEMPT_FAILED_OR_UNCERTAIN'):
                        f.boot(plan_dir,Path('/tmp/c'),Path('/tmp/a'),
                               Path('/tmp/p'),clock=lambda:NOW)
                    self.assertTrue((root/('one-'+role+'.once')).exists())
                    self.assertEqual(len(list(root.glob('boot-*/incident.json'))),1)
                else:
                    folder,rec=f.boot(plan_dir,Path('/tmp/c'),Path('/tmp/a'),
                                      Path('/tmp/p'),clock=lambda:NOW)
                    self.assertEqual(rec['role'],role)
                    self.assertEqual(rec['vm_starts'],1)
                    self.assertEqual(rec['p8'],'NO-GO')
                    self.assertFalse(rec['traffic_authorized'])
                    self.assertTrue((folder/'receipt.json').exists())
            boots=[cmd for cmd in fake_paths if cmd==list(f7.command(role))]
            self.assertEqual(len(boots),1)

    def test_runner_success(self): self.exercise('runner')
    def test_ftp_success(self): self.exercise('ftp')
    def test_runner_failure_no_retry(self): self.exercise('runner',True)
    def test_ftp_failure_no_retry(self): self.exercise('ftp',True)

class PredecessorChainTests(TestCase):
    def test_runner_requires_replayed_ssh_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f7';root.mkdir(mode=0o700)
            p=root/'plan-ssh';p.mkdir(mode=0o700)
            b=root/'boot-ssh';b.mkdir(mode=0o700)
            receipt={'role':'ssh','state':'SSH_RUNNING_DENY_ATTESTED',
                     'traffic_authorized':False,'p8':'NO-GO'}
            with patch.object(f7,'ROOT',root), \
                 patch.object(f7,'_replay_ssh',return_value=receipt) as replay:
                result=f.predecessor('runner',p,b)
                self.assertEqual(result['role'],'ssh')
                self.assertEqual(result['receipt_sha256'],f7.digest(receipt))
                replay.assert_called_once_with(p,b)

    def test_forged_ssh_receipt_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f7';root.mkdir(mode=0o700)
            p=root/'plan-ssh';p.mkdir(mode=0o700)
            b=root/'boot-ssh';b.mkdir(mode=0o700)
            with patch.object(f7,'ROOT',root), \
                 patch.object(f7,'_replay_ssh',return_value={
                       'role':'ssh','state':'SSH_RUNNING_DENY_ATTESTED',
                       'traffic_authorized':True,'p8':'NO-GO'}):
                with self.assertRaisesRegex(f.Stop,'SSH_PREDECESSOR_NOT_ATTESTED'):
                    f.predecessor('runner',p,b)

    def test_ftp_requires_replayed_runner_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f8';root.mkdir(mode=0o700)
            p=root/'plan-runner';p.mkdir(mode=0o700)
            b=root/'boot-runner';b.mkdir(mode=0o700)
            receipt={'role':'runner','state':'RUNNER_RUNNING_DENY_ATTESTED',
                     'traffic_authorized':False,'p8':'NO-GO'}
            with patch.object(f,'ROOT',root), \
                 patch.object(f,'replay',return_value=receipt) as replay:
                result=f.predecessor('ftp',p,b)
                self.assertEqual(result['role'],'runner')
                self.assertEqual(result['receipt_sha256'],f7.digest(receipt))
                replay.assert_called_once_with(p,b)

    def test_forged_runner_receipt_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f8';root.mkdir(mode=0o700)
            p=root/'plan-runner';p.mkdir(mode=0o700)
            b=root/'boot-runner';b.mkdir(mode=0o700)
            with patch.object(f,'ROOT',root), \
                 patch.object(f,'replay',return_value={
                       'role':'runner','state':'RUNNER_RUNNING_DENY_ATTESTED',
                       'traffic_authorized':False,'p8':'GO'}):
                with self.assertRaisesRegex(f.Stop,'RUNNER_PREDECESSOR_NOT_ATTESTED'):
                    f.predecessor('ftp',p,b)

    def test_ftp_cannot_use_ssh_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f8';root.mkdir(mode=0o700)
            p=root/'plan-ssh';p.mkdir(mode=0o700)
            b=root/'boot-ssh';b.mkdir(mode=0o700)
            with patch.object(f,'ROOT',root), \
                 patch.object(f,'replay',return_value={
                       'role':'ssh','state':'SSH_RUNNING_DENY_ATTESTED',
                       'traffic_authorized':False,'p8':'NO-GO'}):
                with self.assertRaisesRegex(f.Stop,'RUNNER_PREDECESSOR_NOT_ATTESTED'):
                    f.predecessor('ftp',p,b)

    def test_boot_cli_without_explicit_consent_never_calls_boot(self):
        with patch.object(f,'boot',side_effect=AssertionError('MUST_NOT_BOOT')):
            rc=f.main(['--boot','--role','runner','--contract','/tmp/a',
                       '--authorization','/tmp/b','--permit','/tmp/c',
                       '--plan-dir','/tmp/d'])
            self.assertEqual(rc,23)

    def test_replay_without_claim_rejected_before_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'f8';root.mkdir(mode=0o700)
            with patch.object(f,'ROOT',root), \
                 patch.object(f,'_read_plan',return_value=(base('runner'),
                           {'foo':1},{'old':1})), \
                 patch.object(f,'predecessor',return_value=prior('runner')), \
                 patch.object(f,'verify_spec',return_value=True), \
                 patch.object(f,'_read_boot',side_effect=AssertionError('MUST_NOT_READ_PROOF')):
                with self.assertRaises(OSError):
                    f.replay(root/'plan-a',root/'boot-a')
