"""R113-F4B: clasificación adversarial y no ejecución sin autorización."""
import sys
import json
import base64
import tempfile
import unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from ardrec.coordination import r113_f4b_unit_readiness as core
import ardrec_p14_r113_f4b_unit_readiness as cli


def valid(role='ftp',**overrides):
    data={
        'Id':core.UNITS[role], 'LoadState':'loaded', 'ActiveState':'inactive',
        'SubState':'dead','UnitFileState':'disabled',
        'FragmentPath':'/lib/systemd/system/'+core.UNITS[role],
        'ExecStart':'{ path=/usr/sbin/'+('vsftpd' if role=='ftp' else 'smbd')+' ; argv[]=daemon ; }',
        'Result':'success',
    }
    data.update(overrides)
    return ('\n'.join(k+'='+v for k,v in data.items())+'\n').encode()

class ReadinessTest(unittest.TestCase):
    def test_ftp_candidate(self):
        d=core.classify('ftp',valid())
        self.assertEqual(d['readiness'],'CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION')
        self.assertFalse(d['guest_service_started'])
    def test_smb_candidate(self):
        d=core.classify('smb',valid('smb'))
        self.assertEqual(d['unit'],'smbd.service')
    def test_active_needs_socket_recheck(self):
        d=core.classify('ftp',valid(ActiveState='active',SubState='running'))
        self.assertEqual(d['readiness'],'ALREADY_ACTIVE_RECHECK_LISTENER')
    def test_failed_blocks(self):
        d=core.classify('ftp',valid(ActiveState='failed',SubState='failed',Result='exit-code'))
        self.assertEqual(d['readiness'],'FAILED_REQUIRES_DIAGNOSIS')
    def test_masked_blocks(self):
        d=core.classify('ftp',valid(UnitFileState='masked'))
        self.assertEqual(d['readiness'],'BLOCKED_OR_INCONCLUSIVE')
    def test_missing_execstart_blocks(self):
        d=core.classify('ftp',valid(ExecStart=''))
        self.assertEqual(d['readiness'],'BLOCKED_OR_INCONCLUSIVE')
    def test_not_found_blocks(self):
        d=core.classify('ftp',valid(LoadState='not-found',FragmentPath=''))
        self.assertEqual(d['readiness'],'BLOCKED_OR_INCONCLUSIVE')
    def test_no_fragment_blocks(self):
        self.assertEqual(core.classify('ftp',valid(FragmentPath=''))['readiness'],
                         'BLOCKED_OR_INCONCLUSIVE')
    def test_wrong_unit_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid(Id='ssh.service'))
    def test_unknown_role_rejected(self):
        with self.assertRaises(core.GuardError):core.command('runner')
    def test_extra_key_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid()+b'Fake=1\n')
    def test_duplicate_key_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid()+b'Id=vsftpd.service\n')
    def test_missing_key_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid().replace(b'Result=success\n',b''))
    def test_fragment_traversal_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid(FragmentPath='/lib/../var/x'))
    def test_oversize_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',b'x'*48001)
    def test_error_encoding_rejected(self):
        with self.assertRaises(core.GuardError):core.classify('ftp',valid()+b'\xff')
    def test_allowlist_has_only_show(self):
        for role in core.UNITS:
            self.assertEqual(core.command(role)[0],'/usr/bin/systemctl')
            self.assertEqual(core.command(role)[1],'show')
            self.assertNotIn('start',core.command(role))
    def test_requires_authorization_for_audit(self):
        with mock.patch('sys.argv',['x','--audit']):
            self.assertEqual(cli.main(),23)
    def test_preflight_no_guest_process(self):
        with mock.patch.object(cli,'preflight',return_value=({}, {}, {}, {})),\
             mock.patch('sys.argv',['x','--preflight']):
            self.assertEqual(cli.main(),0)
    def test_checked_capture_requires_exit_zero(self):
        fake={'role':'ftp','command':core.command('ftp'),
              'start':{'return':{'pid':100}},
              'completion':{'return':{'exited':True,'exitcode':1,
                                      'out-data':'','err-data':''}}}
        with self.assertRaises(core.GuardError):cli.checked_capture('ftp',fake)
    def test_integrated_capture_and_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'records'
            root.mkdir(mode=0o700)
            prev={'session':'test-only','manifest_sha256':'x','classification_sha256':'y'}
            count=[0]
            def qga(role,request):
                if request['execute']=='guest-exec':
                    count[0]+=1
                    return {'return':{'pid':100+count[0]}}
                return {'return':{'exited':True,'exitcode':0,
                       'out-data':base64.b64encode(valid(role)).decode(),
                       'err-data':''}}
            with mock.patch.object(cli,'ROOT',root), \
                 mock.patch.object(cli,'predecessor',return_value=prev), \
                 mock.patch.object(cli,'preflight',return_value=(prev,{}, {},{})), \
                 mock.patch.object(cli.f4a.f3t.f3,'qga',side_effect=qga), \
                 mock.patch.object(cli.f4a.f3t.f3,'live',return_value={}):
                self.assertEqual(cli.audit(),0)
                self.assertEqual(count[0],2)
                sessions=list(root.iterdir())
                self.assertEqual(len(sessions),1)
                results=cli.verify(sessions[0])
                self.assertEqual(results['ftp']['readiness'],
                                 'CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION')
                self.assertEqual(results['smb']['readiness'],
                                 'CANDIDATE_FOR_SEPARATE_START_AUTHORIZATION')

    def test_integrated_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'records'
            root.mkdir(mode=0o700)
            prev={'session':'test-only','manifest_sha256':'x','classification_sha256':'y'}
            def qga(role,request):
                if request['execute']=='guest-exec':
                    return {'return':{'pid':101}}
                return {'return':{'exited':True,'exitcode':0,
                       'out-data':base64.b64encode(valid(role)).decode(),
                       'err-data':''}}
            with mock.patch.object(cli,'ROOT',root), \
                 mock.patch.object(cli,'predecessor',return_value=prev), \
                 mock.patch.object(cli,'preflight',return_value=(prev,{}, {},{})), \
                 mock.patch.object(cli.f4a.f3t.f3,'qga',side_effect=qga), \
                 mock.patch.object(cli.f4a.f3t.f3,'live',return_value={}):
                self.assertEqual(cli.audit(),0)
                session=next(root.iterdir())
                path=session/'capture-ftp.json'
                path.write_bytes(path.read_bytes()+b'\n')
                with self.assertRaises(core.GuardError):
                    cli.verify(session)

    def test_source_contains_no_start_and_no_firewall_mutation(self):
        s=(ROOT/'scripts/ardrec_p14_r113_f4b_unit_readiness.py').read_text()
        self.assertNotIn("'net-start'",s)
        self.assertNotIn("'systemctl','start'",s)
        self.assertNotIn("'domif-setlink'",s)
        self.assertNotIn("'firewall-cmd'",s)

if __name__=='__main__':unittest.main()
