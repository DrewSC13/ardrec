"""R70: oráculos independientes para publicación estructural DEV sin despacho."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.durable_dev import open_or_create_dev
from ardrec.coordination.safe_generation import open_or_publish_safe, DurableDevError
from ardrec.coordination.safe_dashboard_bridge import build_safe_dashboard, SafeViewError
from ardrec.coordination.dashboard_tui import DashboardState, render_dashboard_frame, detail_rows, validate_dashboard_report, DashboardError
from ardrec.persistence.codec import canonical, digest
from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.state import ServicePhase

FIXTURE = ROOT/'lab/p14-r26-session-v1/scenario.json'

@unittest.skipIf(os.geteuid()==0, 'R70 no admite root (seguridad de R69)')
class R70SafeAnalyticalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-r70-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'session'
        self.fixture=read_fixed_scenario(FIXTURE)
        self.initial=open_or_create_dev(self.root,self.fixture)

    def advance(self):
        return open_or_publish_safe(self.root,self.fixture,publish=True)

    def test_01_actual_generation_1_and_real_archive(self):
        doc=self.advance()
        self.assertEqual(doc['generation'],1)
        self.assertEqual(doc['analytical_validation'],'structural_only')
        self.assertEqual(doc['a8_transition'],'DETENER')
        self.assertTrue((self.root/'analytical-archive'/doc['analytical_snapshot_sha256']).is_dir())
        with AnalyticalArchive(self.root/'analytical-archive') as archive:
            with DurableStore.open(self.root/'generational-store',
                     record_id=doc['record_id'],configuration_sha256=doc['configuration_sha256'],
                     analytical_archive=archive) as store:
                self.assertEqual(store.state.confirmed.generation,1)
                self.assertEqual(len(store.state.attempts),0)
                self.assertTrue(all(x.phase is ServicePhase.DETENIDO for x in store.state.services))
                self.assertEqual(store.analytical_snapshot_sha256,doc['analytical_snapshot_sha256'])

    def test_02_reopen_no_journal_or_snapshot_mutation(self):
        first=self.advance()
        journal=list((self.root/'generational-store'/'journal').glob('*.json'))
        before={str(p):p.read_bytes() for p in journal}
        doc=open_or_publish_safe(self.root,self.fixture)
        again=self.advance()
        self.assertEqual(canonical(first),canonical(doc))
        self.assertEqual(canonical(first),canonical(again))
        self.assertEqual(before,{str(p):p.read_bytes() for p in journal})

    def test_03_a1_original_frozen_and_all_10_stages(self):
        doc=self.advance()
        report=build_safe_dashboard(doc,self.fixture)
        self.assertEqual(len(report['a10']['stages']),10)
        self.assertIn('FTP_DEV: ND','\n'.join(detail_rows(report,0)))
        self.assertIn('GEN 1 PUBLICADA','\n'.join(detail_rows(report,8)))
        self.assertEqual(report['r27']['a5_start_count'],0)
        self.assertIsNone(report['final_risk'])
        frame='\n'.join(render_dashboard_frame(report,DashboardState(),140,34))
        for marker in ('ALGORITMOS','DETALLE','ESTADO / AUDITORIA','GEN 1 ANALITICA DEV'):
            self.assertIn(marker,frame)

    def test_04_no_physical_and_nd_fields(self):
        doc=self.advance()
        for key in ('physical_observation_attested','operational_dispatch','a9_technical_evidence_published'):
            self.assertFalse(doc[key])
        self.assertEqual(doc['a5_attempt_count'],0)
        self.assertIsNone(doc['a7_confirmed_rf'])
        with AnalyticalArchive(self.root/'analytical-archive') as archive:
            snap=archive.load(doc['analytical_snapshot_sha256'])
            self.assertEqual(len(snap.projections),3)
            self.assertEqual([p.analysis.recalibrated_risk.reason_code for p in snap.projections],['NO_EVIDENCE']*3)

    def test_05_changed_fixture_rejected(self):
        doc=self.advance()
        altered=copy.deepcopy(self.fixture)
        altered['services'][0]['id']='FORGED'
        with self.assertRaises(ValueError):open_or_publish_safe(self.root,altered)

    def test_06_stale_head_rejected(self):
        self.advance()
        with self.assertRaises(ValueError):
            open_or_publish_safe(self.root,self.fixture, expected_head_sha256=self.initial['store_head_sha256'])

    def test_07_corrupt_archive_refused(self):
        doc=self.advance()
        path=next(p for p in (self.root/'analytical-archive'/doc['analytical_snapshot_sha256']).glob('*.json')
                  if p.is_file())
        path.chmod(0o600)
        path.write_bytes(b'{}')
        with self.assertRaises(ValueError):open_or_publish_safe(self.root,self.fixture)

    def test_08_corrupt_r69_receipt_refused(self):
        self.advance()
        path=self.root/'a1-generation-0.json'
        doc=copy.deepcopy(self.initial)
        doc['a1_decisions']['FTP_DEV']['r68']['status']='VERDADERO'
        doc['sha256']=digest(canonical({k:v for k,v in doc.items() if k!='sha256'}))
        path.write_bytes(canonical(doc))
        with self.assertRaises(ValueError):open_or_publish_safe(self.root,self.fixture)

    def test_09_dashboard_forgery_refused(self):
        report=build_safe_dashboard(self.advance(),self.fixture)
        for key,value in (('operational_dispatch',True),('final_risk','1'),('p8_operational','GO')):
            altered=copy.deepcopy(report)
            altered[key]=value
            altered['sha256']=digest(canonical({k:v for k,v in altered.items() if k!='sha256'}))
            with self.assertRaises(DashboardError):validate_dashboard_report(altered)

    def test_10_cli_normal_auto_reopens_r70(self):
        self.advance()
        result=subprocess.run([sys.executable,'-B','-m','ardrec',
            '--durable-dev-root',str(self.root),'--json'],cwd=ROOT,
            env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout.strip(),canonical(open_or_publish_safe(self.root,self.fixture)))

    def test_11_cli_safe_cycle_from_fresh_and_idempotent(self):
        other=Path(self.tmp.name)/'another'
        cmd=[sys.executable,'-B','-m','ardrec','--durable-dev-root',str(other),'--safe-cycle','--json']
        first=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True)
        self.assertEqual(first.returncode,0,first.stderr.decode())
        second=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True)
        self.assertEqual(second.returncode,0,second.stderr.decode())
        self.assertEqual(first.stdout,second.stdout)

    def test_12_no_generation_if_readonly(self):
        doc=open_or_publish_safe(self.root,self.fixture,publish=False)
        self.assertEqual(doc['generation'],0)
        self.assertFalse((self.root/'analytical-archive').exists())

    def test_13_a9_no_duplicate_if_restarted(self):
        self.advance()
        self.assertEqual(len(list((self.root/'generational-store'/'generations').glob('*.json'))),2)
        self.advance()
        self.assertEqual(len(list((self.root/'generational-store'/'generations').glob('*.json'))),2)

    def test_15_recover_partial_transition_without_repeat(self):
        from ardrec.coordination.safe_generation import _stop_context
        from ardrec.state import Transition
        with DurableStore.open(self.root/'generational-store',
            record_id=self.initial['record_id'],
            configuration_sha256=self.initial['configuration_sha256']) as store:
            store.transition('FTP_DEV',Transition.DETENER,_stop_context(store.state,'FTP_DEV'))
        doc=self.advance()
        self.assertEqual(doc['generation'],1)
        with AnalyticalArchive(self.root/'analytical-archive') as archive:
            with DurableStore.open(self.root/'generational-store',
                record_id=self.initial['record_id'],
                configuration_sha256=self.initial['configuration_sha256'],
                analytical_archive=archive) as store:
                self.assertEqual(len(store.state.confirmed.incorporated_events),4)
                self.assertEqual(len(store.state.attempts),0)

    def test_16_foreign_staged_transition_blocks_publication(self):
        from ardrec.coordination.safe_generation import _stop_context
        from ardrec.state import Transition, GuardFact, Truth
        from dataclasses import replace
        with DurableStore.open(self.root/'generational-store',
            record_id=self.initial['record_id'],
            configuration_sha256=self.initial['configuration_sha256']) as store:
            ctx = replace(_stop_context(store.state,'FTP_DEV'),
                          reason_reference='UNEXPECTED_STOP',
                          facts=(GuardFact(
                              'cause_verified',Truth.VERDADERO,
                              'UNEXPECTED_STOP'),
                              _stop_context(store.state,'FTP_DEV').facts[1]))
            store.transition('FTP_DEV',Transition.DETENER,ctx)
        with self.assertRaisesRegex(ValueError,'foreign_staged_stop_refused'):
            self.advance()
        with DurableStore.open(self.root/'generational-store',
            record_id=self.initial['record_id'],
            configuration_sha256=self.initial['configuration_sha256']) as store:
            self.assertEqual(store.state.confirmed.generation,0)

    def test_17_readonly_does_not_adopt_staged_unconfirmed_state(self):
        from ardrec.coordination.safe_generation import _stop_context
        from ardrec.state import Transition
        with DurableStore.open(self.root/'generational-store',
            record_id=self.initial['record_id'],
            configuration_sha256=self.initial['configuration_sha256']) as store:
            store.transition('FTP_DEV',Transition.DETENER,_stop_context(store.state,'FTP_DEV'))
        with self.assertRaisesRegex(ValueError,'candidate_or_events_present|candidate_requires_review'):
            open_or_publish_safe(self.root,self.fixture,publish=False)

    def test_19_forged_genesis_head_even_if_rehashed_is_refused(self):
        self.advance()
        file=self.root/'a1-generation-0.json'
        doc=copy.deepcopy(self.initial)
        doc['store_head_sha256']='0'*64
        doc['sha256']=digest(canonical({k:v for k,v in doc.items() if k!='sha256'}))
        file.write_bytes(canonical(doc))
        with self.assertRaisesRegex(ValueError,'genesis_head_receipt_mismatch'):
            open_or_publish_safe(self.root,self.fixture)

    def test_18_real_curses_r38_gen1_opens_and_exits_q(self):
        import pty, select, time, fcntl, termios, struct
        self.advance()
        master, slave = pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',35,150,0,0))
        self.addCleanup(lambda: os.close(master))
        proc = subprocess.Popen(
            [sys.executable,'-B','-m','ardrec','--durable-dev-root',str(self.root),'--tui'],
            cwd=ROOT, env={**os.environ,'PYTHONPATH':str(ROOT/'src'),'TERM':'xterm-256color'},
            stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave)
        try:
            received=b''
            deadline=time.monotonic()+12
            while time.monotonic()<deadline and proc.poll() is None:
                r,_,_=select.select([master],[],[],0.2)
                if r:
                    try: received+=os.read(master,65536)
                    except OSError: break
                if b'ALGORITMOS' in received and b'GEN 1' in received:
                    break
            self.assertIn(b'ALGORITMOS',received,received[:300])
            self.assertIn(b'ESTADO',received,received[:300])
            self.assertIn(b'GEN 1',received,received[:300])
            os.write(master,b'9q')
            self.assertEqual(proc.wait(timeout=8),0)
        finally:
            if proc.poll() is None:
                proc.kill();proc.wait(timeout=5)

    def test_14_r70_preserves_r69_record_bytes(self):
        source=(self.root/'a1-generation-0.json').read_bytes()
        self.advance()
        self.assertEqual((self.root/'a1-generation-0.json').read_bytes(),source)

if __name__ == '__main__':unittest.main()
