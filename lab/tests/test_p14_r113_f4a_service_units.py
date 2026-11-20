"""R113-F4A: rechazos adversariales y simulación end-to-end sin virsh real."""
import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts')]
from ardrec.coordination import r113_f4a_service_units as core
import ardrec_p14_r113_f4a_service_units as runner


def example(role):
    if role=='ftp':
        return {'unit-files':b'vsftpd.service enabled enabled\nproftpd.service disabled enabled\n',
                'units':b'vsftpd.service loaded inactive dead vsftpd server\n'}
    return {'unit-files':b'smbd.service enabled enabled\nnmbd.service disabled enabled\n',
            'units':b'\xe2\x97\x8f smbd.service loaded failed failed Samba daemon\n'}


class ParserTests(unittest.TestCase):
    def test_ftp_inventory_state(self):
        result=core.inventory('ftp',example('ftp'))
        self.assertEqual(result['observed']['vsftpd.service']['unit-files'],
                         'vsftpd.service enabled enabled')
        self.assertFalse(result['installation_proven'])
        self.assertFalse(result['protocol_connectivity_proven'])

    def test_smb_failed_unit(self):
        result=core.inventory('smb',example('smb'))
        self.assertIn('failed',result['observed']['smbd.service']['units'])
        self.assertEqual(result['p8_operational'],'NO-GO')

    def test_unrelated_unit_not_included(self):
        result=core.inventory('ftp',{'unit-files':b'ssh.service enabled enabled\n',
                                    'units':b''})
        self.assertEqual(result['observed'],{})

    def test_description_not_matched(self):
        result=core.inventory('ftp',{'unit-files':b'abc.service enabled vsftpd.service\n',
                                    'units':b''})
        # Coincidencias ambigüas como atributo no acreditan un servicio instalado.
        self.assertNotIn('vsftpd.service',result['observed'])

    def test_reject_role(self):
        with self.assertRaises(core.GuardError):core.inventory('runner',example('ftp'))

    def test_reject_partial_commands(self):
        with self.assertRaises(core.GuardError):core.inventory('ftp',{'units':b''})

    def test_reject_extra_command(self):
        with self.assertRaises(core.GuardError):core.inventory('ftp',dict(example('ftp'),arbitrary=b''))

    def test_reject_bad_encoding(self):
        with self.assertRaises(core.GuardError):core.inventory('ftp',{'unit-files':b'\xff', 'units':b''})

    def test_reject_overlong_output(self):
        with self.assertRaises(core.GuardError):core.inventory('ftp',{'unit-files':b'a'*48001,'units':b''})

    def test_reject_oversize_line(self):
        with self.assertRaises(core.GuardError):core.inventory('ftp',{'unit-files':b'a'*2049+b'\n','units':b''})

    def test_commands_exact(self):
        self.assertEqual(len(core.CMDS),2)
        for path,args in core.CMDS.values():
            self.assertEqual(path,'/usr/bin/systemctl')
            self.assertIn('--no-pager',args)
            self.assertIn('--no-legend',args)
            self.assertNotIn('start',args)
            self.assertNotIn('enable',args)

    def test_no_host_network_mutators(self):
        source=(REPO/'scripts/ardrec_p14_r113_f4a_service_units.py').read_text()
        self.assertNotIn("'net-start'",source)
        self.assertNotIn("'domif-setlink'",source)
        self.assertNotIn("'firewall-cmd'",source)
        self.assertNotIn("'systemctl','start'",source)

    def test_guest_completion_requires_zero(self):
        reply={'role':'ftp','kind':'units',
               'command':['/usr/bin/systemctl',*core.CMDS['units'][1]],
               'start':{'return':{'pid':12}},
               'completion':{'return':{'exited':True,'exitcode':1,
                                       'out-data':'','err-data':''}}}
        with self.assertRaises(core.GuardError):runner.validated_capture('ftp','units',reply)

    def test_guest_completion_requires_matching_command(self):
        reply={'role':'ftp','kind':'units',
               'command':['/bin/sh','-c','true'],
               'start':{'return':{'pid':12}},
               'completion':{'return':{'exited':True,'exitcode':0,
                                       'out-data':'','err-data':''}}}
        with self.assertRaises(core.GuardError):runner.validated_capture('ftp','units',reply)

    def test_preflight_requires_authorization(self):
        with mock.patch('sys.argv',['x','--audit']):
            self.assertEqual(runner.main(),23)

    def test_preflight_does_not_execute_guest(self):
        with mock.patch.object(runner,'preflight',return_value=({}, {}, {}, {})),\
             mock.patch('sys.argv',['x','--preflight']):
            self.assertEqual(runner.main(),0)

    def test_replay_cannot_request_guest_exec(self):
        with mock.patch('sys.argv',['x','--replay','/tmp/x',
                                    '--i-authorize-four-local-systemctl-queries']):
            self.assertEqual(runner.main(),23)


class LifecycleTests(unittest.TestCase):
    def test_durable_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'private'
            root.mkdir(mode=0o700)
            prev={'session':'/predecessor','manifest_sha256':runner.F3T_SHA,
                  'classification_sha256':'abc'}
            proc=[]
            pid=100
            samples={(role,kind):raw for role in core.UNITS for kind,raw in example(role).items()}
            def qga(role,request):
                nonlocal pid
                op=request['execute']
                if op=='guest-exec':
                    pid+=1
                    info=request['arguments']
                    kind=next(k for k,(path,args) in core.CMDS.items() if
                              info['path']==path and info['arg']==list(args))
                    proc.append((pid,role,kind))
                    return {'return':{'pid':pid}}
                if op=='guest-exec-status':
                    _,r,k=next(it for it in proc if it[0]==request['arguments']['pid'])
                    return {'return':{'exited':True,'exitcode':0,
                                      'out-data':base64.b64encode(samples[(r,k)]).decode(),
                                      'err-data':''}}
                raise AssertionError('Only QGA inventory commands permitted: '+op)
            with mock.patch.object(runner,'ROOT',root),\
                 mock.patch.object(runner,'preflight',return_value=(prev,{}, {}, {})),\
                 mock.patch.object(runner,'predecessor',return_value=prev),\
                 mock.patch.object(runner.f3t.f3,'qga',side_effect=qga),\
                 mock.patch.object(runner.f3t.f3,'live',return_value={}):
                self.assertEqual(runner.audit(),0)
                folders=list(root.glob('inventory-*'))
                self.assertEqual(len(folders),1)
                folder=folders[0]
                self.assertEqual(len(proc),4)
                self.assertEqual(runner.verify(folder)['ftp']['role'],'ftp')
                self.assertEqual((folder/'manifest.json').stat().st_mode & 0o777,0o600)
                self.assertEqual(len(list(folder.glob('started-*.once'))),4)
                self.assertEqual(len(list(folder.glob('capture-*.json'))),4)
                raw=(folder/'capture-ftp-units.json').read_bytes()
                # Rechazo de alteraciones del recibo original, sin reintentar guest-exec.
                (folder/'capture-ftp-units.json').write_bytes(raw+b' ')
                with self.assertRaises(core.GuardError):runner.verify(folder)
                self.assertEqual(len(proc),4)

    def test_f3t_fingerprint_is_pinned(self):
        self.assertEqual(runner.F3T_SHA,'08ff65f60f3967276e03ef9f47f24ea21ee574e095c0c07f304d91426b63afd0')
        self.assertEqual(set(runner.ROLES),{'ftp','smb'})
        self.assertEqual(len(runner.FILE_NAMES),15)
