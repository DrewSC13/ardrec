"""R113-F4C: arranque controlado, precedencia y replay sin tráfico."""
from __future__ import annotations
import base64
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from ardrec.coordination import r113_f4c_service_activation as core
import ardrec_p14_r113_f4c_service_activation as cli

def unit(role,active=False,**changes):
    props={
        'Id':core.f4b.UNITS[role],'LoadState':'loaded',
        'ActiveState':'active' if active else 'inactive',
        'SubState':'running' if active else 'dead','UnitFileState':'disabled',
        'FragmentPath':'/lib/systemd/system/'+core.f4b.UNITS[role],
        'ExecStart':'{ path=/usr/sbin/example ; argv[]=example ; }',
        'Result':'success',
    }
    props.update(changes)
    return ('\n'.join(k+'='+v for k,v in props.items())+'\n').encode()

def capture(role,phase,out=None,exitcode=0):
    if out is None:
        if phase=='pre':out=unit(role)
        elif phase=='post':out=unit(role,True)
        elif phase=='socket':
            port=core.listeners.TARGETS[role][1]
            out=f'LISTEN 0 10 0.0.0.0:{port} 0.0.0.0:*\n'.encode()
        else:out=b''
    return {'role':role,'phase':phase,'command':core.command(role,phase),
            'start':{'return':{'pid':123}},
            'completion':{'return':{'exited':True,'exitcode':exitcode,
                     'out-data':base64.b64encode(out).decode('ascii'),'err-data':''}}}

def all_captures(role):
    return {p:capture(role,p) for p in ('pre','start','post','socket')}

class ServiceStartTests(unittest.TestCase):
    def test_ftp_start_allowlist(self):
        self.assertEqual(core.command('ftp','start'),['/usr/bin/systemctl','start','vsftpd.service'])
    def test_smb_start_allowlist(self):
        self.assertEqual(core.command('smb','start'),['/usr/bin/systemctl','start','smbd.service'])
    def test_no_enable_or_restart(self):
        for role in core.ROLES:
            for phase in ('pre','start','post','socket'):
                c=core.command(role,phase)
                self.assertNotIn('enable',c)
                self.assertNotIn('restart',c)
                self.assertNotIn('stop',c)
                self.assertNotIn('nmbd.service',c)
    def test_invalid_role_rejected(self):
        with self.assertRaises(core.GuardError):core.command('runner','start')
    def test_invalid_phase_rejected(self):
        with self.assertRaises(core.GuardError):core.command('ftp','delete')
    def test_ftp_confirmed_local_listener(self):
        self.assertEqual(core.classify('ftp',all_captures('ftp'))['outcome'],
                         'ACTIVE_WITH_LAB_IPV4_LISTENER')
    def test_smb_confirmed_local_listener(self):
        self.assertEqual(core.classify('smb',all_captures('smb'))['outcome'],
                         'ACTIVE_WITH_LAB_IPV4_LISTENER')
    def test_active_without_ipv4_listener_is_not_passed(self):
        caps=all_captures('ftp')
        caps['socket']=capture('ftp','socket',b'LISTEN 0 9 127.0.0.1:21 0.0.0.0:*\n')
        self.assertEqual(core.classify('ftp',caps)['outcome'],
                         'ACTIVE_WITHOUT_VERIFIED_LAB_IPV4_LISTENER')
    def test_no_listening_socket_is_not_passed(self):
        caps=all_captures('smb')
        caps['socket']=capture('smb','socket',b'')
        self.assertEqual(core.classify('smb',caps)['outcome'],
                         'ACTIVE_WITHOUT_VERIFIED_LAB_IPV4_LISTENER')
    def test_prestart_must_be_inactive(self):
        caps=all_captures('ftp')
        caps['pre']=capture('ftp','pre',unit('ftp',True))
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_active_state_required_after_start(self):
        caps=all_captures('ftp')
        caps['post']=capture('ftp','post',unit('ftp'))
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_failed_start_denied(self):
        caps=all_captures('ftp')
        caps['start']=capture('ftp','start',b'',exitcode=1)
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_changed_command_denied(self):
        caps=all_captures('ftp')
        caps['start']['command']=['/usr/bin/systemctl','restart','vsftpd.service']
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_wrong_role_denied(self):
        caps=all_captures('ftp')
        caps['start']['role']='smb'
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_missing_phase_denied(self):
        caps=all_captures('ftp');del caps['socket']
        with self.assertRaises(core.GuardError):core.classify('ftp',caps)
    def test_no_unapproved_start(self):
        with mock.patch('sys.argv',['x','--activate','--role','ftp']):
            self.assertEqual(cli.main(),23)
    def test_replay_disallows_auth_flag(self):
        with mock.patch('sys.argv',['x','--replay','/tmp/a',
                                     '--i-authorize-one-real-guest-service-start']):
            self.assertEqual(cli.main(),23)
    def test_preflight_never_starts(self):
        with mock.patch.object(cli,'preflight',return_value=({}, {}, {})),\
             mock.patch('sys.argv',['x','--preflight','--role','ftp']):
            self.assertEqual(cli.main(),0)
    def test_integrated_receipt_and_replay(self):
        with tempfile.TemporaryDirectory() as temp:
            records=Path(temp)/'private'
            records.mkdir(mode=0o700)
            previous={'session':'test-only','sha256':'aa','class_sha256':'bb'}
            phasecount=[]
            def qga(role,payload):
                if payload['execute']=='guest-exec':
                    command=payload['arguments']['arg']
                    if command[0]=='start':phase='start'
                    elif command[0]=='show':phase='pre' if 'pre' not in phasecount else 'post'
                    else:phase='socket'
                    phasecount.append(phase)
                    return {'return':{'pid':100+len(phasecount)}}
                phase=phasecount[-1]
                return capture(role,phase)['completion']
            with mock.patch.object(cli,'ROOT',records),\
                 mock.patch.object(cli,'predecessor',return_value=previous),\
                 mock.patch.object(cli,'preflight',return_value=(previous,{},{})),\
                 mock.patch.object(cli.f4b.f4a.f3t.f3,'qga',side_effect=qga),\
                 mock.patch.object(cli.f4b.f4a.f3t.f3,'live',return_value={}):
                self.assertEqual(cli.activate('ftp'),0)
                self.assertEqual(phasecount,['pre','start','post','socket'])
                session=next(records.iterdir())
                verified=cli.verify(session)
                self.assertEqual(verified['outcome'],'ACTIVE_WITH_LAB_IPV4_LISTENER')
                self.assertTrue((session/'started-start.once').exists())
                self.assertEqual(len(list(records.iterdir())),1)
    def test_tampered_capture_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            records=Path(temp)/'private';records.mkdir(mode=0o700)
            previous={'session':'test-only','sha256':'aa','class_sha256':'bb'}
            calls=[]
            def qga(role,payload):
                if payload['execute']=='guest-exec':
                    arg=payload['arguments']['arg']
                    phase='start' if arg[0]=='start' else ('socket' if arg[0]=='-H' else ('pre' if 'pre' not in calls else 'post'))
                    calls.append(phase)
                    return {'return':{'pid':100+len(calls)}}
                return capture(role,calls[-1])['completion']
            with mock.patch.object(cli,'ROOT',records),\
                 mock.patch.object(cli,'predecessor',return_value=previous),\
                 mock.patch.object(cli,'preflight',return_value=(previous,{},{})),\
                 mock.patch.object(cli.f4b.f4a.f3t.f3,'qga',side_effect=qga),\
                 mock.patch.object(cli.f4b.f4a.f3t.f3,'live',return_value={}):
                cli.activate('smb')
                session=next(records.iterdir())
                (session/'socket.json').write_bytes((session/'socket.json').read_bytes()+b'\n')
                with self.assertRaises(core.GuardError):cli.verify(session)
    def test_no_network_mutators_source(self):
        source=(ROOT/'scripts/ardrec_p14_r113_f4c_service_activation.py').read_text()
        for forbidden in ("'net-start'", "'net-destroy'", "'destroy'", "'firewall-cmd'", "'nft'", "'enable'"):
            self.assertNotIn(forbidden,source)

if __name__=='__main__':unittest.main()
