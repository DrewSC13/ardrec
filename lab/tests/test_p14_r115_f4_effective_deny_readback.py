"""R115-F4 offline negative tests, independent of host root privileges."""
import base64
import copy
import json
import unittest
from types import SimpleNamespace
from ardrec.coordination import r115_f4_effective_deny_readback as m
from ardrec.coordination import r115_f2_a3_current_sources as f2
from test_p14_r115_f3_f11_authority import capture as f3_capture, BASE


def one(out,rc=0,err=b''):
    return {'rc':rc,'timeout':False,'truncated':False,
            'start':f2.iso(BASE),'end':f2.iso(BASE),
            'stdout':base64.b64encode(out).decode(),
            'stderr':base64.b64encode(err).decode()}


def example(root=True):
    probes={} if not root else {
        'helper_sha':one((m.HELPER_SHA+'  '+str(m.HELPER)+'\n').encode()),
        'hook_sha':one((m.six.R34_HOOK+'  '+str(m.f3.HOOK)+'\n').encode()),
        'deny_attest':one(b'{"result":"SIX_BINDING_DENY_ATTESTED",'
                           b'"bindings":6,"host_writes":0,"p8":"NO-GO"}')}
    return {'schema':m.SCHEMA,'start':f2.iso(BASE),'end':f2.iso(BASE),
            'f3_capture':f3_capture(),'root_readback_requested':root,
            'probes':probes,'origin':'OPERATOR_REQUESTED_NO_AUTHORITY'}


class Tests(unittest.TestCase):
    def test_01_no_root_stays_nd(self):
        result=m.report(example(False))
        self.assertEqual(result['checks'],{'helper':'ND','hook':'ND',
                         'six_deny_bindings_and_nft':'ND'})
        self.assertEqual(result['dispatch'],'NO-GO')

    def test_02_pinned_readback_still_no_go(self):
        r=m.report(example())
        self.assertTrue(r['six_denies_at_capture'])
        self.assertEqual(r['a3_status']['SERVICE_READY'],'FALSO')
        self.assertEqual(r['a3_status']['SCOPE_APPROVED'],'ND')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'ND')
        self.assertFalse(r['external_authority_attested'])
        self.assertEqual(r['a6'],'ND')

    def test_03_helper_drift_fails_closed(self):
        v=example();v['probes']['helper_sha']=one(b'0'*64+b'  '+str(m.HELPER).encode()+b'\n')
        r=m.report(v)
        self.assertEqual(r['checks']['helper'],'DRIFT')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')

    def test_04_hook_drift_fails_closed(self):
        v=example();v['probes']['hook_sha']=one(b'0'*64+b'  '+str(m.f3.HOOK).encode()+b'\n')
        self.assertEqual(m.report(v)['checks']['hook'],'DRIFT')

    def test_05_nonzero_attest_nd(self):
        v=example();v['probes']['deny_attest']=one(b'',rc=23,err=b'STOP_DENY_REVIEW_REQUIRED')
        self.assertEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'ND')

    def test_06_denial_is_not_success(self):
        v=example();v['probes']['deny_attest']=one(b'{"result":"SIX_BINDING_DENY_RESTORED"}')
        self.assertEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'DRIFT')

    def test_07_malformed_json_drift(self):
        v=example();v['probes']['deny_attest']=one(b'not json')
        self.assertEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'DRIFT')

    def test_08_duplicate_json_drift(self):
        v=example();v['probes']['deny_attest']=one(b'{"result":"SIX_BINDING_DENY_ATTESTED","result":"GO"}')
        self.assertEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'DRIFT')

    def test_09_timeout_is_nd(self):
        v=example();v['probes']['hook_sha']['timeout']=True
        self.assertEqual(m.report(v)['checks']['hook'],'ND')

    def test_10_unrequested_probes_rejected(self):
        v=example();v['root_readback_requested']=False
        with self.assertRaises(m.Stop):m.report(v)

    def test_11_extra_probe_rejected(self):
        v=example();v['probes']['arbitrary_command']=one(b'ok')
        with self.assertRaises(m.Stop):m.report(v)

    def test_12_partial_only_helper_allowed(self):
        v=example();v['probes']={'helper_sha':one(b'',rc=1)}
        self.assertEqual(m.report(v)['checks']['helper'],'ND')
        self.assertEqual(m.report(v)['dispatch'],'NO-GO')

    def test_13_wrong_end_before_capture(self):
        v=example();v['end']='2026-11-19T00:00:00Z'
        with self.assertRaises(m.Stop):m.report(v)

    def test_14_corrupt_base_capture_rejected(self):
        v=example();v['f3_capture']['extra'].pop('ssh_xml')
        with self.assertRaises(Exception):m.report(v)

    def test_15_root_command_set_static(self):
        self.assertEqual(set(m.COMMANDS),{'helper_sha','hook_sha','deny_attest'})
        for argv in m.COMMANDS.values():
            self.assertEqual(argv[:3],('/usr/bin/sudo','-n','--'))
            self.assertNotIn('--restore-deny',argv)

    def test_16_root_mismatch_does_not_run_helper(self):
        calls=[]
        def fake(argv,**kwargs):
            calls.append(argv)
            if argv==list(m.COMMANDS['helper_sha']):
                return SimpleNamespace(stdout=b'0'*64+b'  '+str(m.HELPER).encode()+b'\n',stderr=b'',returncode=0)
            raise AssertionError('root helper must not run')
        record=m.capture_probe('helper_sha',fake,lambda:BASE)
        self.assertEqual(m.sha_status(record,m.HELPER,m.HELPER_SHA)[0],'DRIFT')

    def test_17_host_writes_false_not_accepted(self):
        v=example()
        v['probes']['deny_attest']=one(b'{"result":"SIX_BINDING_DENY_ATTESTED",'
                                      b'"bindings":6,"host_writes":false,"p8":"NO-GO"}')
        self.assertNotEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'MATCH')

    def test_18_root_readback_output_truncation_nd(self):
        v=example();v['probes']['deny_attest']['truncated']=True
        self.assertEqual(m.report(v)['checks']['six_deny_bindings_and_nft'],'ND')

if __name__=='__main__':unittest.main()

from unittest.mock import patch as _patch

class RootProbeSequenceTests(unittest.TestCase):
    def test_19_unpinned_helper_never_invokes_other_sudo(self):
        calls=[]
        def fake(argv,**_):
            calls.append(tuple(argv))
            return SimpleNamespace(stdout=b'0'*64+b'  '+str(m.HELPER).encode()+b'\n',
                                   stderr=b'',returncode=0)
        with _patch.object(m.f3,'acquire',return_value=f3_capture()):
            d=m.capture(root_readback=True,runner=fake,clock=lambda:BASE)
        self.assertEqual(set(d['probes']),{'helper_sha'})
        self.assertEqual(calls,[m.COMMANDS['helper_sha']])
        self.assertEqual(m.report(d)['dispatch'],'NO-GO')

    def test_20_hook_drift_never_invokes_f6_helper(self):
        calls=[]
        def fake(argv,**_):
            calls.append(tuple(argv))
            if tuple(argv)==m.COMMANDS['helper_sha']:
                raw=(m.HELPER_SHA+'  '+str(m.HELPER)+'\n').encode()
            else:
                raw=(('0'*64)+'  '+str(m.f3.HOOK)+'\n').encode()
            return SimpleNamespace(stdout=raw,stderr=b'',returncode=0)
        with _patch.object(m.f3,'acquire',return_value=f3_capture()):
            d=m.capture(root_readback=True,runner=fake,clock=lambda:BASE)
        self.assertEqual(set(d['probes']),{'helper_sha','hook_sha'})
        self.assertEqual(calls,[m.COMMANDS['helper_sha'],m.COMMANDS['hook_sha']])
        self.assertEqual(m.report(d)['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')
