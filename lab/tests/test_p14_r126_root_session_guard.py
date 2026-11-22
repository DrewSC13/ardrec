"""B4: eight independent Ed25519 signers and root-only DENY watchdog arming.

No test runs root-owned code or a physical command. All key material is
fresh test-only and all host calls are mocked in memory.
"""
from __future__ import annotations
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r115_f11_p8_signed_window as f11
from ardrec.coordination import r126_scope_v2 as scope
from test_p14_r115_f11_p8_signed_window import NOW,HEAD,keypair,signed,budget
from test_p14_r126_window_v2 import fixture as upstream_fixture

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r126_root_session_guard.py'
spec=importlib.util.spec_from_file_location('ardrec_r126_root_guard_b4_test',SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
BOOT='d9a08ced-b621-4763-bd39-3e569795a9a1'


def make_fixture():
    f=upstream_fixture()
    root_grant_key,root_grant_pub=keypair('r126.b4.root.grant')
    root_rev_key,root_rev_pub=keypair('r126.b4.root.revocation')
    trust={'schema':m.TRUST_SCHEMA,'grant_signer':root_grant_pub,
           'revocation_signer':root_rev_pub}
    c=f1.load(f['contract'])
    w=f1.load(f['window'])
    g_stmt={
        'schema':m.GRANT_SCHEMA,'session':'a1b2c3d4e5f60718','head':HEAD,
        'case_id':c['case_id'],'target':c['target'],
        'catalog_sha256':c['catalog_sha256'],
        'contract_sha256':f1.digest(f['contract']),
        'scope_authorization_sha256':f1.digest(f['auth']),
        'pilot_sha256':f1.digest(f['pilot']),
        'window_sha256':f1.digest(f['window']),
        'budget_sha256':f1.digest(f1.canonical(w['statement']['budget'])),
        'guard_sha256':m.GUARD_PIN,'boot_id':BOOT,
        'valid_from':'2026-11-20T16:59:55Z',
        'valid_until':'2026-11-20T17:00:55Z',
        'action':'ARM_DENY_BACKUP_ONLY','network_traffic_authorized':False,
        'one_shot':True,'p8':'NO-GO'
    }
    grant=signed(g_stmt,root_grant_key,root_grant_pub,m.GRANT_PREFIX)
    revoke_stmt={
        'schema':m.REV_SCHEMA,'session':g_stmt['session'],
        'grant_sha256':f1.digest(f1.canonical(grant)),
        'issued_at':'2026-11-20T16:59:59Z',
        'valid_until':'2026-11-20T17:00:55Z',
        'revoked':False,'reason_code':'CURRENT_CLEAR',
    }
    revoke=signed(revoke_stmt,root_rev_key,root_rev_pub,m.REV_PREFIX)
    d={
        'root_trust':trust,'root_revocation':revoke,
        'scope_trust':f1.load(f['root'][scope.TRUST]),
        'scope_revocation':f1.load(f['root'][scope.REVOCATION]),
        'pilot_trust':f1.load(f['root'][f15.TRUST]),
        'pilot_revocation':f1.load(f['root'][f15.REVOCATION]),
        'window_trust':f1.load(f['root'][f11.TRUST]),
        'window_revocation':f1.load(f['root'][f11.REVOCATION]),
        'grant':grant,'contract':c,
        'scope_authorization':f1.load(f['auth']),
        'pilot_permit':f1.load(f['pilot']),
        'traffic_window':w,
    }
    return {'d':d,'grant_key':root_grant_key,'grant_pub':root_grant_pub,
            'rev_key':root_rev_key,'rev_pub':root_rev_pub,
            'window_rev_private':f['window_rev_private'],
            'window_rev_public':f['window_rev_public']}


def guard_check_fixture():
    return {
        'schema':'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-check',
        'deny':'MATCH','host_writes':0,'p8':'NO-GO',
        'states':{'ssh':'RUNNING','runner':'RUNNING',
                  'ftp':'RUNNING','smb':'OFF'},
        'policy':{'active_count':5,'absent_count':1,
                  'active':['ftp','runner_ftp','runner_smb','runner_ssh','ssh'],
                  'absent':['smb'],'allow_traffic':False,'p8':'NO-GO'}
    }


def run_fixture(commands):
    def execute(cmd,timeout=12):
        commands.append(tuple(cmd))
        if tuple(cmd)==('/usr/bin/python3','-I','-B',str(m.GUARD),'--check'):
            return m.canonical(guard_check_fixture())
        if tuple(cmd)==('/usr/bin/python3','-I','-B',str(m.GUARD),
                        '--arm-deny','a1b2c3d4e5f60718'):
            return m.canonical({'schema':'ARDREC-R116-F1-FIVE_ONE_DENY_GUARD-v1-arm',
                                'session':'a1b2c3d4e5f60718',
                                'timer_verified':True,'backup_delay_seconds':45,
                                'duration_seconds':60,'opens_ports':False,'p8':'NO-GO'})
        if cmd[0]=='/usr/bin/systemctl':
            return (b'LoadState=loaded\nActiveState=active\n'
                    b'Unit=ardrec-r116-f1-deny-a1b2c3d4e5f60718.service\n'
                    b'NextElapseUSecMonotonic=7min 54s\n')
        raise AssertionError('UNEXPECTED_HOST_COMMAND:'+repr(cmd))
    return execute


class RootGuardB4(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=make_fixture()

    def setUp(self):
        self.f=copy.deepcopy(self.fixture)
        self.d=self.f['d']
        self.calls=[]

    def validate(self,**kw):
        return m.validate_bundle(self.d,now=kw.get('now',NOW),
                                expected_head=kw.get('head',HEAD),
                                boot_id=kw.get('boot_id',BOOT))

    def resign_grant(self):
        stmt=self.d['grant']['statement']
        self.d['grant']=signed(stmt,self.f['grant_key'],self.f['grant_pub'],
                               m.GRANT_PREFIX)
        self.resign_rev()

    def resign_rev(self):
        stmt=self.d['root_revocation']['statement']
        stmt['grant_sha256']=f1.digest(f1.canonical(self.d['grant']))
        self.d['root_revocation']=signed(stmt,self.f['rev_key'],self.f['rev_pub'],
                                         m.REV_PREFIX)

    def test_01_valid_signed_chain(self):
        value=self.validate()
        self.assertEqual(value['p8'],'NO-GO')
        self.assertFalse(value['network_traffic_authorized'])

    def test_02_source_head_bound(self):
        with self.assertRaisesRegex(m.Stop,'APPROVED_HEAD|GRANT_SCOPE'):
            self.validate(head='f'*40)

    def test_03_boot_id_bound(self):
        with self.assertRaisesRegex(m.Stop,'GRANT_SCOPE'):
            self.validate(boot_id='x'*36)

    def test_04_grant_signature_tamper(self):
        self.d['grant']['statement']['session']='a'*16
        with self.assertRaisesRegex(m.Stop,'SIGNATURE_INVALID'):
            self.validate()

    def test_05_grant_network_promotion(self):
        self.d['grant']['statement']['network_traffic_authorized']=True
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'GRANT_SCOPE'):
            self.validate()

    def test_06_grant_wrong_action(self):
        self.d['grant']['statement']['action']='OPEN_PORT'
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'GRANT_SCOPE'):
            self.validate()

    def test_07_grant_wrong_guard_hash(self):
        self.d['grant']['statement']['guard_sha256']='f'*64
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'GRANT_SCOPE'):
            self.validate()

    def test_08_grant_too_long(self):
        self.d['grant']['statement']['valid_until']='2026-11-20T17:02:00Z'
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'GRANT_TIME'):
            self.validate()

    def test_09_grant_too_little_time_left(self):
        with self.assertRaisesRegex(m.Stop,'GRANT_TIME'):
            self.validate(now=NOW+timedelta(seconds=11))

    def test_10_grant_one_shot_only(self):
        self.d['grant']['statement']['one_shot']=False
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'GRANT_SCOPE'):
            self.validate()

    def test_11_revocation_signed_current(self):
        self.d['root_revocation']['statement']['revoked']=True
        self.resign_rev()
        with self.assertRaisesRegex(m.Stop,'REVOCATION_NOT_BOUND_OR_REVOKED'):
            self.validate()

    def test_12_revocation_expired(self):
        self.d['root_revocation']['statement']['valid_until']='2026-11-20T16:59:59Z'
        self.resign_rev()
        with self.assertRaisesRegex(m.Stop,'REVOCATION_NOT_FRESH'):
            self.validate()

    def test_13_revocation_unknown_hash(self):
        self.d['root_revocation']['statement']['grant_sha256']='f'*64
        self.d['root_revocation']=signed(self.d['root_revocation']['statement'],
            self.f['rev_key'],self.f['rev_pub'],m.REV_PREFIX)
        with self.assertRaisesRegex(m.Stop,'REVOCATION_NOT_BOUND'):
            self.validate()

    def test_14_revocation_malformed_signature(self):
        self.d['root_revocation']['signature_b64']='!'
        with self.assertRaisesRegex(m.Stop,'SIGNATURE_ENCODING'):
            self.validate()

    def test_15_same_root_signer_for_both(self):
        self.d['root_trust']['revocation_signer']=self.d['root_trust']['grant_signer']
        with self.assertRaisesRegex(m.Stop,'EIGHT_INDEPENDENT'):
            self.validate()

    def test_16_reused_pilot_signer(self):
        self.d['root_trust']['grant_signer']=self.d['pilot_trust']['pilot_signer']
        with self.assertRaisesRegex(m.Stop,'EIGHT_INDEPENDENT'):
            self.validate()

    def test_17_cross_protocol_credential(self):
        self.d['root_trust']['grant_signer']=self.d['window_trust']['window_signer']
        with self.assertRaisesRegex(m.Stop,'EIGHT_INDEPENDENT'):
            self.validate()

    def test_18_pilot_revoked(self):
        self.d['pilot_revocation']['statement']['revoked']=True
        with self.assertRaisesRegex(m.Stop,'SIGNATURE_INVALID'):
            self.validate()

    def test_19_window_revocation_stale(self):
        state=self.d['window_revocation']['statement']
        state['issued_at']='2026-11-20T16:59:00Z'
        self.d['window_revocation']=signed(state,
            self.f['window_rev_private'],self.f['window_rev_public'],
            f11.REV_PREFIX)
        with self.assertRaisesRegex(m.Stop,'REVOCATION_NOT_FRESH'):
            self.validate()

    def test_20_contract_change(self):
        self.d['contract']['case_id']='WRONG'
        with self.assertRaisesRegex(m.Stop,'CONTRACT_SOURCE_MISMATCH'):
            self.validate()

    def test_21_window_id_change(self):
        self.d['traffic_window']['statement']['window_id']='OTHER'
        with self.assertRaisesRegex(m.Stop,'SIGNATURE_INVALID'):
            self.validate()

    def test_22_pilot_budget_tamper(self):
        self.d['pilot_permit']['statement']['budget']['ordinary_attempts']=2
        with self.assertRaisesRegex(m.Stop,'SIGNATURE_INVALID'):
            self.validate()

    def test_23_case_target_change(self):
        self.d['grant']['statement']['target']['ip']='127.0.0.1'
        self.resign_grant()
        with self.assertRaisesRegex(m.Stop,'TARGET_OUTSIDE'):
            self.validate()

    def test_24_duplicate_json_keys(self):
        with self.assertRaisesRegex(m.Stop,'JSON_PARSE_INVALID'):
            m.parse(b'{"a":1,"a":2}\n')

    def test_25_noncanonical_json(self):
        with self.assertRaisesRegex(m.Stop,'JSON_NOT_CANONICAL'):
            m.parse(b'{"a": 1}\n')

    def test_26_guard_deny_five_one(self):
        self.assertEqual(m.validate_guard_check(guard_check_fixture())['deny'],'MATCH')

    def test_27_guard_must_reject_all_off(self):
        g=guard_check_fixture()
        g['policy']['active_count']=0
        with self.assertRaisesRegex(m.Stop,'R116_FIVE_ONE'):
            m.validate_guard_check(g)

    def test_28_guard_must_reject_traffic_allow(self):
        g=guard_check_fixture()
        g['policy']['allow_traffic']=True
        with self.assertRaisesRegex(m.Stop,'R116_FIVE_ONE'):
            m.validate_guard_check(g)

    def test_29_preflight_uses_only_fixed_commands(self):
        ready=m.preflight({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
                          run=run_fixture(self.calls))
        self.assertFalse(ready['timer_armed'])
        self.assertEqual(len(self.calls),1)

    def test_30_preflight_must_refuse_spent(self):
        with patch.object(m.MARKER.__class__,'exists',return_value=True):
            with self.assertRaisesRegex(m.Stop,'SESSION_ALREADY_CONSUMED'):
                m.preflight({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
                            run=run_fixture(self.calls))
        self.assertEqual(self.calls,[])

    def test_31_arm_uses_r116_only(self):
        writes=[]
        def write(root,name,raw):writes.append((name,m.parse(raw)))
        times=iter((1_000_000_000,2_000_000_000))
        def run(cmd,timeout=12):
            self.calls.append(tuple(cmd))
            if cmd[-1]=='--check':return m.canonical(guard_check_fixture())
            if '--arm-deny' in cmd:
                return m.canonical({'schema':'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-arm',
                         'session':'a1b2c3d4e5f60718',
                         'timer_verified':True,'backup_delay_seconds':45,
                         'duration_seconds':60,'opens_ports':False,'p8':'NO-GO'})
            if cmd[0]=='/usr/bin/systemctl':
                return (b'LoadState=loaded\nActiveState=active\n'
                        b'Unit=ardrec-r116-f1-deny-a1b2c3d4e5f60718.service\n'
                        b'NextElapseUSecMonotonic=46s\n')
            raise AssertionError(cmd)
        receipt=m.arm({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
              run=run,write=write,clock=lambda:next(times),fresh_clock=lambda:NOW)
        self.assertEqual([x[0] for x in writes],['attempt-consumed.once','arm-a1b2c3d4e5f60718.json'])
        self.assertFalse(receipt['network_traffic_authorized'])
        self.assertEqual(receipt['p8'],'NO-GO')
        self.assertEqual(len(self.calls),3)

    def test_32_arm_denied_if_check_fails_before_marker(self):
        writes=[]
        def badrun(cmd,timeout=12):raise m.Stop('GUARD_FAIL')
        with self.assertRaisesRegex(m.Stop,'GUARD_FAIL'):
            m.arm({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
              run=badrun,write=lambda *args:writes.append(args),fresh_clock=lambda:NOW)
        self.assertEqual(writes,[])

    def test_33_arm_claim_consumed_even_if_r116_fails(self):
        writes=[]
        def run(cmd,timeout=12):
            if cmd[-1]=='--check':return m.canonical(guard_check_fixture())
            raise m.Stop('R116_TIMER_FAILURE')
        with self.assertRaisesRegex(m.Stop,'R116_TIMER_FAILURE'):
            m.arm({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
              run=run,write=lambda root,name,raw:writes.append(name),
              fresh_clock=lambda:NOW)
        self.assertEqual(writes,['attempt-consumed.once'])

    def test_34_arm_expiry_race_blocks_before_claim(self):
        writes=[]
        with self.assertRaisesRegex(m.Stop,'GRANT_TIME'):
            m.arm({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
              run=run_fixture(self.calls),
              write=lambda *args:writes.append(args),
              fresh_clock=lambda:NOW+timedelta(seconds=11))
        self.assertEqual(writes,[])

    def test_35_arm_timer_inactive_consumes(self):
        writes=[]
        def run(cmd,timeout=12):
            if cmd[-1]=='--check':return m.canonical(guard_check_fixture())
            if '--arm-deny' in cmd:
                return m.canonical({'schema':'ARDREC-R116-F1-FIVE-ONE-DENY-GUARD-v1-arm',
                      'session':'a1b2c3d4e5f60718','timer_verified':True,
                      'backup_delay_seconds':45,'duration_seconds':60,
                      'opens_ports':False,'p8':'NO-GO'})
            return (b'LoadState=loaded\nActiveState=inactive\n'
                    b'Unit=ardrec-r116-f1-deny-a1b2c3d4e5f60718.service\n'
                    b'NextElapseUSecMonotonic=0\n')
        with self.assertRaisesRegex(m.Stop,'R116_SESSION_TIMER_NOT_ACTIVE'):
            m.arm({'approved_head':HEAD},self.d,now=NOW,boot_id=BOOT,
                  run=run,write=lambda root,name,raw:writes.append(name),
                  fresh_clock=lambda:NOW)
        self.assertEqual(writes,['attempt-consumed.once'])

    def test_36_arm_receipt_cannot_promote_p8(self):
        x=m.capabilities()
        self.assertFalse(x['issues_p8'])
        self.assertFalse(x['opens_traffic'])
        self.assertTrue(x['root_staging_required'])

    def test_37_capabilities_no_root_needed(self):
        self.assertEqual(m.main(['--capabilities']),0)

    def test_38_preflight_from_repo_rejected(self):
        with self.assertRaisesRegex(m.Stop,'IMMUTABLE_ROOT_STAGING_REQUIRED'):
            m.protected_root()

if __name__=='__main__':unittest.main()
