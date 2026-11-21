"""R124 installed R116 guard attestation: exhaustive no-host mock tests."""
from __future__ import annotations
import copy
from datetime import datetime,timezone
import hashlib
import json
import socket
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from ardrec.coordination import r124_root_deny_readback as m

NOW=datetime(2026,11,21,21,0,0,tzinfo=timezone.utc)
HEAD='3e5fce9ae13a6837e408486092add91e26f937a9'
ROOT=Path(__file__).resolve().parents[2]


def guard_report(running=()):
    states={role:'RUNNING' if role in running else 'OFF' for role in m.VM_KEYS}
    active={key for role in running for key in m.VM_KEYS[role]}
    policy={'running':sorted(running),'active':sorted(active),
            'absent':sorted(m.KEYS-active),'active_count':len(active),
            'absent_count':len(m.KEYS-active),'allow_traffic':False,'p8':'NO-GO'}
    return {'schema':m.R116_SCHEMA,'states':states,'policy':policy,
            'deny':'MATCH','host_writes':0,'p8':'NO-GO'}

def timer(name=m.R34,state='active',load='loaded'):
    return (f'LoadState={load}\nActiveState={state}\n'
            f'Unit={name.removesuffix(".timer")}.service\n'
            'NextElapseUSecMonotonic=1h 48min 57.094297s\n').encode()

class Fake:
    def __init__(self,running=(),session=None):
        self.calls=[]
        self.state=guard_report(running)
        self.session=session
        self.mutate={}
    def __call__(self,cmd):
        self.calls.append(cmd)
        if cmd in self.mutate:return self.mutate[cmd]
        if cmd[-2:] == ('/usr/bin/sha256sum',m.GUARD):
            return 0,(m.PIN+'  '+m.GUARD+'\n').encode()
        if '--check' in cmd:return 0,m.canonical(self.state)
        if cmd[-3:] == ('/usr/bin/test','-e',m.MARKER):
            return (1 if self.session is None else 0),b''
        if cmd[-2:] == ('/usr/bin/cat',m.MARKER):
            if self.session is None:raise AssertionError('NO_SESSION_MARKER')
            return 0,m.canonical({'session':self.session,'arm_attempted':True,'ordinary_p8':'NO-GO'})
        if cmd[0] == m.SYSCTL:
            return 0,timer(cmd[2])
        raise AssertionError('UNEXPECTED_COMMAND:'+repr(cmd))

class Readback(unittest.TestCase):
    def test_01_pin_source_matches_exact(self):
        self.assertEqual(hashlib.sha256((ROOT/'scripts/ardrec_p14_r116_f1_root_deny_guard.py').read_bytes()).hexdigest(),m.PIN)
    def test_02_baseline(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake())
        self.assertEqual(x['host']['stage'],'OFFLINE_DENY_MATCH')
        self.assertEqual(x['root_guard'],'PINNED_INSTALLED_DENY_CHECK_OK')
    def test_03_five_one(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake(('ssh','runner','ftp')))
        self.assertEqual((x['host']['active_count'],x['host']['absent_count']),(5,1))
        self.assertEqual(x['host']['stage'],'FIVE_ONE_DENY_MATCH')
    def test_04_r34_not_session(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake())
        self.assertFalse(x['r34_is_session_45s_watchdog'])
    def test_05_no_forged_p8(self):self.assertEqual(m.inspect(head=HEAD,now=NOW,run=Fake())['p8'],'NO-GO')
    def test_06_no_forged_a6(self):self.assertEqual(m.inspect(head=HEAD,now=NOW,run=Fake())['a6'],'ND')
    def test_07_no_a9(self):self.assertIsNone(m.inspect(head=HEAD,now=NOW,run=Fake())['a9'])
    def test_08_no_network(self):self.assertEqual(m.inspect(head=HEAD,now=NOW,run=Fake())['network_connections_by_r124'],0)
    def test_09_no_nft_writes(self):self.assertEqual(m.inspect(head=HEAD,now=NOW,run=Fake())['nft_writes_by_r124'],0)
    def test_10_no_vm_boot(self):self.assertEqual(m.inspect(head=HEAD,now=NOW,run=Fake())['guest_starts_by_r124'],0)
    def test_11_digest_stable(self):
        h=Fake();self.assertEqual(m.inspect(head=HEAD,now=NOW,run=h),m.inspect(head=HEAD,now=NOW,run=h))
    def test_12_no_sudo_password_prompt(self):
        h=Fake();m.inspect(head=HEAD,now=NOW,run=h)
        self.assertTrue(all(x[0]!=m.SUDO or x[:3]==(m.SUDO,'-n','--') for x in h.calls))
    def test_13_no_systemd_run(self):
        h=Fake();m.inspect(head=HEAD,now=NOW,run=h)
        self.assertFalse(any('systemd-run' in repr(x) for x in h.calls))
    def test_14_five_one_without_session_not_armed(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake(('ssh','runner','ftp')))
        self.assertIn('SESSION_45S_TIMER_NOT_ARMED',x['blockers'])
    def test_15_valid_marker_active_not_proof(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake(('ssh','runner','ftp'),'0123456789abcdef'))
        self.assertTrue(x['session_marker_consumed'])
        self.assertEqual(x['session_timer_state'],'active')
        self.assertFalse(x['root_60s_deadline_verified'])
        self.assertIn('SESSION_TIMER_ACTIVE_NOT_CLOSURE_PROOF',x['blockers'])
    def test_16_marker_consumed_offline_not_pilot(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake((), '0123456789abcdef'))
        self.assertIn('FTP_5_1_STAGE_NOT_PRESENT',x['blockers'])
    def test_17_root_sha_read_twice(self):
        h=Fake();m.inspect(head=HEAD,now=NOW,run=h)
        self.assertEqual(sum('/usr/bin/sha256sum' in x for x in h.calls),2)

class Refusals(unittest.TestCase):
    def fails(self,h,code=None):
        with self.assertRaises(m.Stop) as ctx:m.inspect(head=HEAD,now=NOW,run=h)
        if code:self.assertIn(code,str(ctx.exception))
    def test_18_wrong_sha(self):
        f=Fake();f.mutate[(m.SUDO,'-n','--','/usr/bin/sha256sum',m.GUARD)]=(0,('0'*64+'  '+m.GUARD+'\n').encode())
        self.fails(f,'ROOT_GUARD_PIN_MISMATCH')
    def test_19_changed_host_report(self):
        f=Fake();f.state['deny']='DRIFT';self.fails(f,'DENY_REFUSED')
    def test_20_wrong_host_writes(self):
        f=Fake();f.state['host_writes']=1;self.fails(f,'DENY_REFUSED')
    def test_21_boolean_host_writes(self):
        f=Fake();f.state['host_writes']=False;self.fails(f,'DENY_REFUSED')
    def test_22_traffic_allowed(self):
        f=Fake();f.state['policy']['allow_traffic']=True;self.fails(f,'POLICY_COUNT_OR_IDENTITY_MISMATCH')
    def test_23_hidden_fifth_vm(self):
        f=Fake();f.state['states']['rogue']='RUNNING';self.fails(f,'GUEST_STATES_INVALID')
    def test_24_bad_p8(self):
        f=Fake();f.state['p8']='GO';self.fails(f,'DENY_REFUSED')
    def test_25_wrong_count(self):
        f=Fake();f.state['policy']['active_count']=3;self.fails(f,'POLICY_COUNT_OR_IDENTITY_MISMATCH')
    def test_26_duplicate_json(self):
        f=Fake();guard=(m.SUDO,'-n','--','/usr/bin/python3','-I','-B',m.GUARD,'--check')
        f.mutate[guard]=(0,b'{"deny":"MATCH","deny":"MATCH"}\n')
        self.fails(f,'INVALID_JSON')
    def test_27_noncanonical_json(self):
        f=Fake();guard=(m.SUDO,'-n','--','/usr/bin/python3','-I','-B',m.GUARD,'--check')
        f.mutate[guard]=(0,json.dumps(f.state).encode()+b'\n');self.fails(f,'INVALID_JSON')
    def test_28_root_command_failed(self):
        f=Fake();guard=(m.SUDO,'-n','--','/usr/bin/python3','-I','-B',m.GUARD,'--check')
        f.mutate[guard]=(1,b'');self.fails(f,'ROOT_READ_FAILED')
    def test_29_bool_rc_rejected(self):
        f=Fake();guard=(m.SUDO,'-n','--','/usr/bin/python3','-I','-B',m.GUARD,'--check')
        f.mutate[guard]=(False,m.canonical(f.state));self.fails(f,'ROOT_READ_FAILED')
    def test_30_marker_bad_session(self):
        f=Fake((), 'wrong');self.fails(f,'SESSION_MARKER_REJECTED')
    def test_31_marker_bad_state(self):
        f=Fake((), '0123456789abcdef');marker=(m.SUDO,'-n','--','/usr/bin/cat',m.MARKER)
        f.mutate[marker]=(0,m.canonical({'session':'0123456789abcdef','arm_attempted':False,'ordinary_p8':'NO-GO'}))
        self.fails(f,'SESSION_MARKER_REJECTED')
    def test_32_marker_bad_p8(self):
        f=Fake((), '0123456789abcdef');marker=(m.SUDO,'-n','--','/usr/bin/cat',m.MARKER)
        f.mutate[marker]=(0,m.canonical({'session':'0123456789abcdef','arm_attempted':True,'ordinary_p8':'GO'}))
        self.fails(f,'SESSION_MARKER_REJECTED')
    def test_33_marker_rc_2_rejected(self):
        f=Fake();f.mutate[(m.SUDO,'-n','--','/usr/bin/test','-e',m.MARKER)]=(2,b'')
        self.fails(f,'ROOT_READ_FAILED')
    def test_34_rogue_timer(self):
        f=Fake();cmd=(m.SYSCTL,'show',m.R34,'--no-pager','-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic')
        f.mutate[cmd]=(0,timer('rogue.timer'));self.fails(f,'TIMER_OUTPUT_UNTRUSTED')
    def test_35_r34_inactive(self):
        f=Fake();cmd=(m.SYSCTL,'show',m.R34,'--no-pager','-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic')
        f.mutate[cmd]=(0,timer(state='inactive'))
        x=m.inspect(head=HEAD,now=NOW,run=f)
        self.assertIn('PERIODIC_R34_NOT_ACTIVE',x['blockers'])
    def test_36_session_timer_missing(self):
        f=Fake((), '0123456789abcdef');cmd=(m.SYSCTL,'show','ardrec-r116-f1-deny-0123456789abcdef.timer','--no-pager','-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic')
        f.mutate[cmd]=(0,timer('ardrec-r116-f1-deny-0123456789abcdef.timer',state='inactive',load='not-found'))
        x=m.inspect(head=HEAD,now=NOW,run=f)
        self.assertIn('SESSION_TIMER_NOT_ACTIVE_OR_EXPIRED',x['blockers'])
    def test_37_wrong_head(self):
        with self.assertRaises(m.Stop):m.inspect(head='not-head',now=NOW,run=Fake())
    def test_38_naive_clock(self):
        with self.assertRaises(m.Stop):m.inspect(head=HEAD,now=NOW.replace(tzinfo=None),run=Fake())
    def test_39_boolean_count(self):
        f=Fake();f.state['policy']['active_count']=False;self.fails(f,'POLICY_COUNT_OR_IDENTITY_MISMATCH')
    def test_40_ftp_without_runner(self):
        f=Fake();f.state=guard_report(('ftp',));self.fails(f,'UNEXPECTED_GUEST_LIFECYCLE')
    def test_41_smb_running(self):
        f=Fake();f.state=guard_report(('ssh','runner','ftp','smb'));self.fails(f,'UNEXPECTED_GUEST_LIFECYCLE')
    def test_42_manifest_output_extra_fields(self):
        f=Fake();f.state['another']='ok';self.fails(f,'DENY_FIELDS')
    def test_43_shell_injection_not_allowed(self):
        with self.assertRaises(m.Stop):m.fixed_run((m.SYSCTL,'show',';sh','--no-pager','-p','LoadState','-p','ActiveState','-p','Unit','-p','NextElapseUSecMonotonic'))
    def test_44_sudo_any_command_not_allowed(self):
        with self.assertRaises(m.Stop):m.fixed_run((m.SUDO,'-n','--','/usr/bin/true'))
    def test_45_no_connections_or_subprocess_in_mock(self):
        with patch.object(socket,'socket',side_effect=AssertionError('SOCKET')),patch.object(subprocess,'run',side_effect=AssertionError('SUBPROCESS')):
            m.inspect(head=HEAD,now=NOW,run=Fake())
    def test_46_capability_nogo(self):
        a=m.capabilities();self.assertEqual(a['p8'],'NO-GO');self.assertFalse(a['proves_physical_60s_closure'])
    def test_47_missing_stdout(self):
        f=Fake();f.mutate[(m.SUDO,'-n','--','/usr/bin/sha256sum',m.GUARD)]=(0,b'')
        self.fails(f,'SHA_OUTPUT_INVALID')
    def test_48_invalid_stdout_type(self):
        f=Fake();f.mutate[(m.SUDO,'-n','--','/usr/bin/sha256sum',m.GUARD)]=(0,'bytes')
        self.fails(f,'ROOT_READ_FAILED')
    def test_49_root_timer_r34_not_session(self):
        x=m.inspect(head=HEAD,now=NOW,run=Fake(('ssh','runner','ftp')))
        self.assertFalse(x['r34_is_session_45s_watchdog'])
    def test_50_pin_constant(self):self.assertEqual(len(m.PIN),64)

if __name__=='__main__':unittest.main()
