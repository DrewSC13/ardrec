"""R115-F2 adversarial regression with mocked host reads, NEVER real commands."""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from ardrec.coordination import r115_f2_a3_current_sources as m
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r112_runner_nic_definition as nic
from ardrec.coordination import r112_f4_isolated_networks as net4

CAT_RAW = (Path(__file__).resolve().parents[2] /
           'lab/operational-catalog-v1/catalog.json').read_bytes()
CAT = f1.load(CAT_RAW)
BASE = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def xml_vm(role):
    rows = nic.NIC[role] + (nic.ADDED if role=='runner' else [])
    xml = '<domain type="kvm"><name>ardrec-r33-dev-'+role+'</name><devices><disk device="disk"/>'
    for net, mac, tap in rows:
        xml += ('<interface type="network"><source network="ardrec-r33-dev-net-'+net+'"/>'
                '<mac address="'+mac+'"/><target dev="'+tap+'"/>'
                '<model type="virtio"/><filterref filter="'+nic.FILTER+'"/></interface>')
    return (xml+'</devices></domain>').encode('utf-8')


def nft_fixture(*, altered=False):
    taps = ['a33d30r','a33d30t','a33d31r','a33d31t','a33d32r','a33d32t']
    rules=[]
    for chain,key in (('input','iifname'),('output','oifname'),
                      ('forward','iifname'),('forward','oifname')):
        rules.append({'rule':{'table':'ardrec_r34_guard','family':'bridge','chain':chain,
                    'expr':[{'match':{'left':{'meta':{'key':key}},'op':'==',
                                      'right':{'set':taps}}},
                            {'counter':{'packets':0,'bytes':0}},
                            {'accept':None} if altered else {'drop':None}]}})
    return f1.canonical({'nftables':[
        {'table':{'name':'ardrec_r34_guard','family':'bridge'}},
        *[{'chain':{'name':k}} for k in ('input','output','forward')],
        *rules]})


def outputs(*, ftp_state=b'shut off\n', runner_state=b'shut off\n'):
    return {
      'ftp_state':ftp_state, 'runner_state':runner_state,
      'ftp_xml':xml_vm('ftp'), 'runner_xml':xml_vm('runner'),
      'ftp_net_info':('Name: ardrec-r33-dev-net-ftp\nUUID: '+net4.UUIDS['ftp']+'\nActive: no\nPersistent: yes\nAutostart: no\nBridge: br33d31\n').encode(),
      'ftp_net_xml':b'<network><name>ardrec-r33-dev-net-ftp</name><bridge name="br33d31"/></network>',
      'nft_r34':nft_fixture(),
      'watchdog_timer':b'LoadState=loaded\nActiveState=active\n',
    }


def snapshot(data=None, *, rc=None):
    data = outputs() if data is None else data
    rc = {} if rc is None else rc
    probes = {}
    for name in m.COMMANDS:
        raw = data.get(name,b'')
        probes[name] = {'rc':rc.get(name,0), 'timed_out':False,'truncated':False,
                        'started_at':m.iso(BASE),'completed_at':m.iso(BASE),
                        'elapsed_ms':0,
                        'stdout_b64':base64.b64encode(raw).decode(),
                        'stderr_b64':''}
    return {'schema':m.SCHEMA,'started_at':m.iso(BASE),'completed_at':m.iso(BASE),
            'commands':probes,'source_kind':'LOCAL_COMMANDS_READONLY_UNPRIVILEGED',
            'not_an_authority_or_traffic_grant':True}


def contract(*, mac=m.TARGET_MAC, from_date='2026-11-20T11:00:00Z',
             to_date='2026-11-20T13:00:00Z'):
    return {
      'schema':f1.SCHEMA,'case_id':'FTP-T01-R115-F2-DEV',
      'family_id':'FTP-T01','stage':'DEV','created_at':'2026-11-20T11:00:00Z',
      'valid_from':from_date,'valid_until':to_date,
      'source_commit':'a652195a544a549dbad6a44120e3d447cf4d4994',
      'catalog_sha256':f1.digest(CAT_RAW),
      'target':{'vm':m.TARGET_VM,'ip':'10.203.31.2','port':21,
                'mac':mac,'network':m.FTP_NET},
      **{name:{'id':'R115_NO_AUTHORITY','sha256':'0'*64}
         for name in ('client','profile','authority','isolation','service')},
      'limits':{'ordinary_attempts':1,'additional_attempts':0,'timeout_seconds':10,
                'operation_count':1,'request_count':1,'transfer_bytes':1024,
                'output_bytes':2048,'memory_mib':64},
    }


class A3CurrentTests(unittest.TestCase):
    def test_01_off_vm_causes_false_service_but_never_go(self):
        r=m.report(snapshot())
        self.assertEqual(r['a3_status']['SERVICE_READY'], 'FALSO')
        self.assertEqual(r['a3_status']['SCOPE_APPROVED'], 'ND')
        self.assertEqual(r['a3_status']['DESTINATION_AUTHORIZED'], 'ND')
        self.assertFalse(r['a5_executable'])
        self.assertEqual(r['p8'],'NO-GO')
        self.assertEqual(r['source_checks']['vm_definition']['status'],'MATCH')
        self.assertEqual(r['source_checks']['ftp_network_definition']['status'],'MATCH')
        self.assertEqual(r['source_checks']['ftp_network_runtime']['status'],'MATCH')
        self.assertEqual(r['source_checks']['r34_nft']['status'],'MATCH')

    def test_02_running_vm_is_not_service_readiness(self):
        d=outputs(ftp_state=b'running\n',runner_state=b'running\n')
        r=m.report(snapshot(d))
        self.assertEqual(r['a3_status']['SERVICE_READY'],'ND')
        self.assertEqual(set(r['a3_status'].values()),{'ND'})

    def test_03_unreadable_ftp_state_is_nd_not_false(self):
        s=snapshot(rc={'ftp_state':1})
        self.assertEqual(m.report(s)['a3_status']['SERVICE_READY'],'FALSO')  # runner OFF
        s['commands']['runner_state']['rc']=1
        self.assertEqual(m.report(s)['a3_status']['SERVICE_READY'],'ND')

    def test_04_nft_allow_instead_of_drop_is_false(self):
        d=outputs();d['nft_r34']=nft_fixture(altered=True)
        r=m.report(snapshot(d))
        self.assertEqual(r['source_checks']['r34_nft']['status'],'DRIFT')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')
        self.assertFalse(r['a3_all_true'])

    def test_05_nft_missing_read_permission_is_nd(self):
        s=snapshot(rc={'nft_r34':1})
        r=m.report(s)
        self.assertEqual(r['source_checks']['r34_nft']['status'],'ND')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'ND')

    def test_06_network_forward_or_ip_causes_false(self):
        for xml in (b'<network><name>ardrec-r33-dev-net-ftp</name><bridge name="br33d31"/><forward mode="nat"/></network>',
                    b'<network><name>ardrec-r33-dev-net-ftp</name><bridge name="br33d31"/><ip address="192.168.1.1"/></network>'):
            d=outputs();d['ftp_net_xml']=xml
            with self.subTest(xml=xml):
                self.assertEqual(m.report(snapshot(d))['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')

    def test_07_vm_identity_drift_causes_false_destination(self):
        d=outputs();d['ftp_xml']=d['ftp_xml'].replace(m.TARGET_MAC.encode(),b'52:54:00:ad:31:03')
        r=m.report(snapshot(d))
        self.assertEqual(r['a3_status']['DESTINATION_AUTHORIZED'],'FALSO')

    def test_08_contract_mac_not_pinned_causes_false(self):
        r=m.report(snapshot(),contract=contract(mac='52:54:00:ad:31:03'),
                   catalogue=CAT,catalog_raw=CAT_RAW)
        self.assertEqual(r['a3_status']['DESTINATION_AUTHORIZED'],'FALSO')

    def test_09_contract_expiry_false_scope(self):
        r=m.report(snapshot(),contract=dict(contract(from_date='2026-11-20T08:00:00Z',
                                                  to_date='2026-11-20T09:00:00Z'), created_at='2026-11-20T07:00:00Z'),
                   catalogue=CAT,catalog_raw=CAT_RAW)
        self.assertEqual(r['a3_status']['SCOPE_APPROVED'],'FALSO')

    def test_10_contract_in_window_cannot_issue_scope_grant(self):
        r=m.report(snapshot(),contract=contract(),catalogue=CAT,catalog_raw=CAT_RAW)
        self.assertEqual(r['contract_binding'],'STATIC_VALID_CURRENT_WINDOW')
        self.assertEqual(r['a3_status']['SCOPE_APPROVED'],'ND')
        self.assertFalse(r['operational_authority_granted'])

    def test_11_corrupt_contract_rejected(self):
        c=contract();c['limits']['additional_attempts']=1
        with self.assertRaises(f1.Rejected):
            m.report(snapshot(),contract=c,catalogue=CAT,catalog_raw=CAT_RAW)

    def test_12_watchdog_inactive_false_isolation(self):
        d=outputs();d['watchdog_timer']=b'LoadState=loaded\nActiveState=inactive\n'
        self.assertEqual(m.report(snapshot(d))['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')

    def test_12b_network_runtime_drift_false_isolation(self):
        d=outputs();d['ftp_net_info']=d['ftp_net_info'].replace(b'br33d31',b'br00bad')
        r=m.report(snapshot(d))
        self.assertEqual(r['source_checks']['ftp_network_runtime']['status'],'DRIFT')
        self.assertEqual(r['a3_status']['LAB_ISOLATION_CONFIRMED'],'FALSO')

    def test_13_snapshot_missing_command_rejected(self):
        s=snapshot();s['commands'].pop('ftp_xml')
        with self.assertRaises(m.Stop):m.report(s)

    def test_14_snapshot_bad_base64_rejected(self):
        s=snapshot();s['commands']['ftp_xml']['stdout_b64']='(not-base64)'
        with self.assertRaises(m.Stop):m.report(s)

    def test_15_snapshot_timeline_rejected(self):
        s=snapshot();s['completed_at']=m.iso(BASE-timedelta(seconds=3))
        with self.assertRaises(m.Stop):m.report(s)

    def test_16_snapshot_long_capture_rejected(self):
        s=snapshot();s['completed_at']=m.iso(BASE+timedelta(minutes=3))
        with self.assertRaises(m.Stop):m.report(s)

    def test_17_capture_runs_only_immutable_allowlist_no_shell(self):
        called=[]
        def fake_runner(argv, **kwargs):
            called.append((argv,kwargs))
            return SimpleNamespace(stdout=b'shut off\n',stderr=b'',returncode=0)
        s=m.collect(runner=fake_runner,clock=lambda: BASE)
        self.assertEqual(set(s['commands']),set(m.COMMANDS))
        self.assertEqual(len(called),len(m.COMMANDS))
        self.assertTrue(all(x[1]['shell'] is False for x in called))
        self.assertTrue(all(x[0]==list(m.COMMANDS[key]) for x,key in zip(called,m.COMMANDS)))
        self.assertFalse(any('start' in x[0] or 'create' in x[0] for x in called))
        self.assertEqual(m.check_snapshot(s),s)

    def test_18_timeout_is_unknown(self):
        def fake_runner(argv, **kw):
            raise m.subprocess.TimeoutExpired(cmd=argv,timeout=8,output=b'',stderr=b'')
        result=m.capture_command('ftp_state',runner=fake_runner,clock=lambda:BASE)
        self.assertTrue(result['timed_out'])
        self.assertIsNone(result['rc'])
        self.assertIsNone(m.output(snapshot(rc={'ftp_state':1}),'ftp_state'))

    def test_19_unknown_command_refused(self):
        with self.assertRaises(m.Stop):m.capture_command('virsh_destroy')

    def test_20_private_receipt_created_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'store'
            if m.os.geteuid()==0:
                self.skipTest('root process must never create operational receipts')
            path=m.persist(snapshot(),m.report(snapshot()),root=root)
            self.assertEqual((path/'manifest.json').stat().st_mode & 0o777,0o600)
            self.assertEqual((path/'snapshot.json').stat().st_mode & 0o777,0o600)
            manifest=f1.load((path/'manifest.json').read_bytes())
            self.assertEqual(manifest['files_sha256']['snapshot.json'],
                             m.sha((path/'snapshot.json').read_bytes()))

    def test_21_root_execution_refused(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(m.Stop):m.persist(snapshot(),m.report(snapshot()))

    def test_22_replay_is_deterministic(self):
        s=snapshot()
        self.assertEqual(m.canonical(m.report(s)),m.canonical(m.report(copy.deepcopy(s))))
        self.assertEqual(m.report(s)['a6_classification'],'ND')
        self.assertIsNone(m.report(s)['a9_published_generation'])


if __name__=='__main__':unittest.main()
