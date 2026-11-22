"""B9: one prebound FTP guest execution, documentary + safety tests only.

No privileged execution, no network, nft or virsh; signed Ed25519 fixtures
use ephemeral, independently generated test-only key pairs.
"""
from __future__ import annotations

import copy
from datetime import datetime,timezone
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r128_prebound_session_v2 as bind
from test_p14_r126_root_session_guard import make_fixture, m as b4, BOOT
from test_p14_r115_f11_p8_signed_window import NOW, keypair, signed

SOURCE=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r128_root_v2_executor.py'
spec=importlib.util.spec_from_file_location('ardrec_r128_b9_root_test',SOURCE)
x=importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)
HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
SESSION='a1b2c3d4e5f60718'
CASE='FTP-T01-S01-01'


def signed_fixture():
    d=make_fixture()['d']
    key1,pub1=keypair('ardrec.r128.traffic.grant.test')
    key2,pub2=keypair('ardrec.r128.traffic.rev.test')
    trust={'schema':x.TRUST_SCHEMA,'traffic_signer':pub1,'revocation_signer':pub2}
    deny=d['grant']['statement']
    budget=d['traffic_window']['statement']['budget']
    handoff={'schema':x.HANDOFF_SCHEMA,
       'head':deny['head'],'session':SESSION,'case_id':deny['case_id'],
       'case_key':'0'*64,'assessment_index':1,'attempt_id':'ATT_B9',
       'contract_sha256':deny['contract_sha256'],
       'scope_authorization_sha256':deny['scope_authorization_sha256'],
       'window_sha256':deny['window_sha256'],
       'reservation_sha256':'1'*64,'spent_sha256':'2'*64,
       'budget_sha256':x.digest(budget),
       'target':{'ip':'10.203.31.2','port':21},
       'once_consumed_without_physical_claim':True,
       'root_approval_issued':False,'a6':'ND','p8':'NO-GO'}
    handoff['sha256']=x.digest(handoff)
    stmt={'schema':x.GRANT_SCHEMA,'traffic_id':'R128_B9_TEST_PILOT_1',
          'session':SESSION,'case_id':deny['case_id'],
          'head':deny['head'],'boot_id':BOOT,
          'f13_handoff_sha256':x.digest(handoff),
          'root_deny_grant_sha256':x.digest(d['grant']),
          'window_sha256':deny['window_sha256'],
          'budget_sha256':deny['budget_sha256'],
          'valid_from':'2026-11-20T16:59:55Z',
          'valid_until':'2026-11-20T17:00:55Z',
          'action':'ONE_FTP_T01_GUEST_GREETING',
          'guest':'ardrec-r33-dev-runner',
          'destination':{'ip':'10.203.31.2','port':21},
          'one_shot':True,'traffic_pilot_exception_only':True,
          'a6':'ND','p8':'NO-GO'}
    grant=signed(stmt,key1,pub1,x.GRANT_PREFIX)
    rs={'schema':x.REV_SCHEMA,'traffic_id':stmt['traffic_id'],
        'traffic_grant_sha256':x.digest(grant),
        'issued_at':'2026-11-20T16:59:59Z',
        'valid_until':'2026-11-20T17:00:55Z',
        'revoked':False,'reason_code':'CURRENT_CLEAR'}
    rev=signed(rs,key2,pub2,x.REV_PREFIX)
    return {'d':d,'traffic':grant,'trust':trust,'rev':rev,
            'grant_key':key1,'grant_pub':pub1,
            'rev_key':key2,'rev_pub':pub2,
            'handoff':handoff,'budget':budget}


@unittest.skipIf(os.geteuid()==0, 'F13 must run as nonroot')
class F13Prebound(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='ardrec-r128-b9-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.intent=f13.make_intent(case_id=CASE,session_id=SESSION,
          assessment_index=1,attempt_id='ATT_B9_ONCE',head=HEAD,
          contract_sha256='a'*64,scope_authorization_sha256='b'*64,
          p8_window_sha256='c'*64)
        self.journal=f13.reserve(self.intent,f12.DRAFT_BUDGET.copy(),root=self.root/'f13')

    def spend(self):return bind.spend_before_root(journal=self.journal,head=HEAD,session=SESSION)

    def test_01_cannot_build_before_spent(self):
        with self.assertRaisesRegex(bind.Stop,'F13_SPENT'):
            bind.build(journal=self.journal,head=HEAD,session=SESSION)

    def test_02_spend_precedes_root(self):
        out=self.spend()
        self.assertEqual(f13.inspect(self.journal)['status'],'ATTEMPT_CONSUMED_UNRESOLVED')
        self.assertEqual(out['a6'],'ND')
        self.assertFalse(out['root_approval_issued'])

    def test_03_replay_exact(self):
        self.assertEqual(self.spend(),bind.build(journal=self.journal,head=HEAD,session=SESSION))

    def test_04_double_spend_rejected(self):
        self.spend()
        with self.assertRaisesRegex(bind.Stop,'ALREADY_SPENT'):
            self.spend()

    def test_05_other_head_refused_before_write(self):
        with self.assertRaisesRegex(bind.Stop,'PREBOUND'):
            bind.spend_before_root(journal=self.journal,head='f'*40,session=SESSION)
        self.assertEqual(f13.inspect(self.journal)['status'],'RESERVED_NO_RETRY')

    def test_06_other_session_refused_before_write(self):
        with self.assertRaisesRegex(bind.Stop,'PREBOUND'):
            bind.spend_before_root(journal=self.journal,head=HEAD,session='f'*16)
        self.assertEqual(f13.inspect(self.journal)['status'],'RESERVED_NO_RETRY')

    def test_07_no_second_socket_reader(self):
        with patch('socket.socket',side_effect=AssertionError('socket must never be touched')):
            self.spend()

    def test_08_target_fixed(self):
        r=self.spend()
        self.assertEqual(r['target'],{'ip':'10.203.31.2','port':21})
        self.assertTrue(bind.validate_handoff(r,session=SESSION,head=HEAD,
            case_id=CASE,window_sha256='c'*64,contract_sha256='a'*64,
            scope_sha256='b'*64,budget_sha256=r['budget_sha256']))

    def test_09_mutation_refused(self):
        r=self.spend();r['target']['ip']='1.1.1.1'
        with self.assertRaises(bind.Stop):
            bind.validate_handoff(r,session=SESSION,head=HEAD,case_id=CASE,
               window_sha256='c'*64,contract_sha256='a'*64,
               scope_sha256='b'*64,budget_sha256=r['budget_sha256'])

    def test_10_forge_a6_refused(self):
        r=self.spend();r['a6']='VERDADERO'
        r['sha256']=bind.digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(bind.Stop):
            bind.validate_handoff(r,session=SESSION,head=HEAD,case_id=CASE,
               window_sha256='c'*64,contract_sha256='a'*64,
               scope_sha256='b'*64,budget_sha256=r['budget_sha256'])

    def test_11_spent_without_physical_evidence(self):
        self.spend()
        state=f13.inspect(self.journal)
        self.assertFalse(state['physical_provenance_attested'])
        self.assertEqual(state['a6'],'ND')

    def test_12_new_attempt_id_cannot_repeat_same_case(self):
        self.spend()
        new=dict(self.intent);new['attempt_id']='ATT_B9_OTHER'
        with self.assertRaises(FileExistsError):
            f13.reserve(new,f12.DRAFT_BUDGET.copy(),root=self.root/'f13')

    def test_13_spent_hash_changes_rejected(self):
        v=self.spend();v['spent_sha256']='f'*64
        with self.assertRaises(bind.Stop):
            bind.validate_handoff(v,session=SESSION,head=HEAD,case_id=CASE,
                 window_sha256='c'*64,contract_sha256='a'*64,
                 scope_sha256='b'*64,budget_sha256=v['budget_sha256'])

    def test_14_no_authority(self):
        self.assertFalse(bind.capabilities()['root_authorization_created'])
        self.assertFalse(bind.capabilities()['spent_means_physical_probe_completed'])


class RootOneSessionB9(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.sample=signed_fixture()

    def setUp(self):self.f=copy.deepcopy(self.sample)

    def validate(self,**kw):
        return x.signed_traffic(auth_module=b4,grant=self.f['traffic'],
                trust=self.f['trust'],revocation=self.f['rev'],
                handoff=self.f['handoff'],b4docs=self.f['d'],
                approved_head=kw.get('head',self.f['d']['grant']['statement']['head']),
                boot_id=kw.get('boot_id',BOOT),now=kw.get('now',NOW))

    def resign_grant(self):
        self.f['traffic']=signed(self.f['traffic']['statement'],
             self.f['grant_key'],self.f['grant_pub'],x.GRANT_PREFIX)
        self.resign_rev()

    def resign_rev(self):
        self.f['rev']['statement']['traffic_grant_sha256']=x.digest(self.f['traffic'])
        self.f['rev']=signed(self.f['rev']['statement'],
             self.f['rev_key'],self.f['rev_pub'],x.REV_PREFIX)

    def test_15_ed25519_genuine_verification(self):
        self.assertEqual(self.validate()['session'],SESSION)

    def test_16_tamper_unsigned_grant(self):
        self.f['traffic']['statement']['guest']='evil-guest'
        with self.assertRaises(b4.Stop): self.validate()

    def test_17_traffic_not_a_general_p8(self):
        self.f['traffic']['statement']['p8']='GO';self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):self.validate()

    def test_18_guest_fixed(self):
        self.f['traffic']['statement']['guest']='ssh';self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):self.validate()

    def test_19_destination_fixed(self):
        self.f['traffic']['statement']['destination']['ip']='10.0.0.1'
        self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):self.validate()

    def test_20_session_bound(self):
        self.f['traffic']['statement']['session']='f'*16;self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):self.validate()

    def test_21_head_bound(self):
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate(head='f'*40)

    def test_22_boot_bound(self):
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate(boot_id='00000000-0000-0000-0000-000000000000')

    def test_23_handoff_digest_bound(self):
        self.f['handoff']['sha256']='f'*64
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate()

    def test_24_root_deny_grant_digest(self):
        self.f['traffic']['statement']['root_deny_grant_sha256']='f'*64
        self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):self.validate()

    def test_25_revocation_active(self):
        self.f['rev']['statement']['revoked']=True;self.resign_rev()
        with self.assertRaisesRegex(b4.Stop,'REVOCATION'):
            self.validate()

    def test_26_revocation_stale(self):
        self.f['traffic']['statement']['valid_from']='2026-11-20T17:00:26Z'
        self.f['traffic']['statement']['valid_until']='2026-11-20T17:01:26Z'
        self.resign_grant()
        with self.assertRaisesRegex(b4.Stop,'REVOCATION_NOT_FRESH'):
            self.validate(now=datetime(2026,11,20,17,0,31,tzinfo=timezone.utc))

    def test_27_revocation_tampered(self):
        self.f['rev']['statement']['issued_at']='2026-11-20T16:55:00Z'
        with self.assertRaises(b4.Stop):self.validate()

    def test_28_same_signing_key_reused(self):
        self.f['trust']['traffic_signer']=self.f['d']['root_trust']['grant_signer']
        with self.assertRaisesRegex(x.Stop,'TEN_SEPARATE'):
            self.validate()

    def test_29_same_revocation_key_reused(self):
        self.f['trust']['revocation_signer']=self.f['d']['pilot_trust']['revocation_signer']
        with self.assertRaisesRegex(x.Stop,'TEN_SEPARATE'):
            self.validate()

    def test_30_grant_expires(self):
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_GRANT_NOT'):
            self.validate(now=datetime(2026,11,20,17,1,tzinfo=timezone.utc))

    def test_31_window_too_long(self):
        self.f['traffic']['statement']['valid_until']='2026-11-20T17:02:00Z'
        self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_GRANT_NOT'):
            self.validate()

    def test_32_missing_one_shot(self):
        self.f['traffic']['statement']['one_shot']=False;self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate()

    def test_33_root_source_execution_rejected(self):
        with self.assertRaisesRegex(x.Stop,'INDEPENDENT_ROOT_STAGING_REQUIRED'):
            x.stage()

    def test_34_capabilities_are_not_installed(self):
        cap=x.capabilities()
        self.assertFalse(cap['installed_from_this_package'])
        self.assertFalse(cap['pilot_real_execution_proven'])
        self.assertFalse(cap['automatic_network'])

    def test_35_cli_capabilities_nonprivileged(self):
        self.assertEqual(x.main(['--capabilities']),0)

    def test_36_reject_duplicate_fields(self):
        with self.assertRaisesRegex(x.Stop,'JSON_DUPLICATE_KEY'):
            x.parse(b'{"a":1,"a":2}\n')

    def test_37_reject_noncanonical(self):
        with self.assertRaisesRegex(x.Stop,'DOCUMENT_CANONICAL_REQUIRED'):
            x.parse(b'{"a":1}   ')

    def test_38_legacy_fixed_shas(self):
        self.assertEqual(len(x.F3_PIN),64)
        self.assertEqual(len(x.B4_PIN),64)
        self.assertNotEqual(x.F3_PIN,x.B4_PIN)

    def test_39_wrong_traffic_id(self):
        self.f['traffic']['statement']['traffic_id']='../../bad'
        self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate()

    def test_40_forbid_regular_authority(self):
        self.f['traffic']['statement']['traffic_pilot_exception_only']=False
        self.resign_grant()
        with self.assertRaisesRegex(x.Stop,'TRAFFIC_SCOPE'):
            self.validate()

    def test_41_capabilities_one_guest(self):
        self.assertTrue(x.capabilities()['one_guest_qga_socket_reader_only'])

    def test_42_no_automatic_network(self):
        self.assertFalse(x.capabilities()['automatic_network'])

    def test_43_refusal_without_real_root_stage(self):
        self.assertEqual(x.main(['--inspect-root']),23)

    def test_44_negative_unsealed_handoff(self):
        h=self.f['handoff'];h['once_consumed_without_physical_claim']=False
        with self.assertRaisesRegex(x.Stop,'F13_HANDOFF_NOT_BOUND'):
            x.validate_handoff(h,head=h['head'],session=SESSION,
                 b4grant=self.f['d']['grant']['statement'],
                 budget=self.f['budget'])

    def test_45_wrong_case_format(self):
        h=self.f['handoff']
        with self.assertRaisesRegex(x.Stop,'F13_HANDOFF_NOT_BOUND'):
            x.validate_handoff(h,head=h['head'],session=SESSION,
                 b4grant=self.f['d']['grant']['statement'],
                 budget=self.f['budget'])

if __name__=='__main__':unittest.main()

class _FakePolicy:
    def five_one(self, value):return True
    def timer_remaining(self,*args,**kwargs):return 44
    def permit_margin(self,**kwargs):return True


class _FakeLegacy:
    ONE='pilot-attempted.once'
    def __init__(self,root,*,fail=None):
        self.ROOT=root
        self.fail=fail
        self.calls=[]
    def staged(self):self.calls.append('staged')
    def modules(self):return (_FakePolicy(),None,None,None,None)
    def root_guard(self,flag):
        self.calls.append(flag)
        if flag=='--restore-deny':return {'status':'DENY_RESTORED'}
        return {'deny':'MATCH'}
    def old_ftp_material(self,policy):
        self.calls.append('material')
        class Audit:
            def audit_live_nft(self,raw):return True
        return Audit(),{'r34-ftp-only.nft':b'add rule...' }
    def review_boot_provenance(self,m):self.calls.append('boot');return {}
    def root_guard_library(self):
        class Guard:
            def historical(self):return None,{'unused':'fixed'}
        return Guard()
    def run(self,cmd,**kwargs):
        self.calls.append(cmd)
        return b'{}'
    def transition_to_ftp_candidate(self,*args):
        self.calls.append('binding')
        if self.fail=='transition':raise x.Stop('INJECTED_TRANSITION_FAILURE')
        args[-1]()
    def execute_one_guest_probe(self,folder,gate,*,budget,case_id):
        self.calls.append('guest')
        if self.fail=='guest':raise x.Stop('INJECTED_GUEST_FAILURE')
        gate()
        return {'schema':'GUEST','case_id':case_id,'response':'RECEIVED'}


class _FakeRootGuard:
    def __init__(self,session,*,fail=False):
        self.GUARD=Path('/nonexistent/ardrec-test-r116-guard.py')
        self.session=session
        self.fail=fail
        self.calls=[]
    def arm(self,*args,**kwargs):
        self.calls.append('arm')
        if self.fail:raise x.Stop('INJECTED_ARM_FAILURE')
        return {'session':self.session,'timer':{'timer_active':True}}


class SimulatedRootFlow(unittest.TestCase):
    """Mocked host commands: ONLY test sequencing; never invoke real root."""
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='ardrec-r128-b9-root-sim-')
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.legacy_root=self.root/'legacy';self.legacy_root.mkdir()
        self.f=copy.deepcopy(RootOneSessionB9.sample)
        self.legacy=_FakeLegacy(self.legacy_root)
        self.auth=_FakeRootGuard(SESSION)
        self.manifest={'approved_head':HEAD}
        self.handoff={'session':SESSION,'case_id':CASE,'head':HEAD}
        self.ready={'session':SESSION,'case_id':CASE,'budget':{'ordinary_attempts':1},'p8':'NO-GO'}
        self.patches=[patch.object(x,'ROOT',self.root),
             patch.object(x,'SCRIPT',SOURCE),
             patch.object(x.os,'geteuid',return_value=0),
             patch.object(x,'preflight',return_value=self.ready),
             patch.object(x,'fresh_gate',return_value=None)]
        for p in self.patches:
            p.start();self.addCleanup(p.stop)

    def go(self):
        return x.execute(manifest=self.manifest,auth=self.auth,
             b4docs=self.f['d'],handoff=self.handoff,
             traffic_grant=self.f['traffic'],traffic_trust=self.f['trust'],
             traffic_revocation=self.f['rev'],boot_id=BOOT,legacy=self.legacy)

    def test_46_single_guest_and_deny_restore(self):
        result=self.go()
        self.assertEqual(result['result'],'FTP_GUEST_CANDIDATE_ONLY')
        self.assertEqual(self.legacy.calls.count('guest'),1)
        self.assertEqual(self.legacy.calls.count('--restore-deny'),1)
        self.assertTrue(result['denies_restored_and_verified'])
        self.assertEqual(result['a6'],'ND')
        self.assertTrue((self.root/'attempt-consumed.once').exists())

    def test_47_second_attempt_refused_before_guest(self):
        self.go()
        with self.assertRaises(FileExistsError):self.go()
        self.assertEqual(self.legacy.calls.count('guest'),1)

    def test_48_transition_failure_restores_deny(self):
        self.legacy.fail='transition'
        result=self.go()
        self.assertEqual(result['result'],'NO_GO_ATTEMPT_CONSUMED')
        self.assertEqual(self.legacy.calls.count('guest'),0)
        self.assertEqual(self.legacy.calls.count('--restore-deny'),1)
        self.assertTrue(result['denies_restored_and_verified'])

    def test_49_guest_failure_restores_deny(self):
        self.legacy.fail='guest'
        result=self.go()
        self.assertEqual(result['result'],'NO_GO_ATTEMPT_CONSUMED')
        self.assertEqual(self.legacy.calls.count('guest'),1)
        self.assertEqual(self.legacy.calls.count('--restore-deny'),1)

    def test_50_arm_failure_consumes_without_traffic(self):
        self.auth.fail=True
        result=self.go()
        self.assertEqual(result['result'],'NO_GO_ATTEMPT_CONSUMED')
        self.assertEqual(self.legacy.calls.count('guest'),0)
        self.assertFalse(result['traffic_window_opened'])
        self.assertTrue((self.root/'attempt-consumed.once').exists())

    def test_51_receipt_manifest_consistency(self):
        result=self.go()
        stored=x.parse((self.root/('pilot-'+SESSION)/'receipt.json').read_bytes())
        self.assertEqual(stored,result)

    def test_52_no_external_shell_binary(self):
        from unittest.mock import patch as fake
        with fake('subprocess.run',side_effect=AssertionError('no host commands')):
            self.assertEqual(x.capabilities()['p8'],'NO-GO')
