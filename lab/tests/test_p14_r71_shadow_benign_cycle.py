"""R71: integración positiva hipotética + proceso benigno local y R38 sin autoridad."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination.demo_session import read_fixed_scenario
from ardrec.coordination.durable_dev import open_or_create_dev
from ardrec.coordination.safe_generation import open_or_publish_safe
from ardrec.coordination.shadow_cycle import run_shadow_cycle,ShadowError
from ardrec.coordination.shadow_dashboard_bridge import build_shadow_dashboard,ShadowViewError
from ardrec.coordination.dashboard_tui import (
    DashboardState,render_dashboard_frame,detail_rows,validate_dashboard_report,DashboardError)
from ardrec.persistence.codec import canonical,digest

SCENARIO=ROOT/'lab/p14-r26-session-v1/scenario.json'

@unittest.skipIf(os.geteuid()==0, 'DurableStore impide usuario root')
class R71ShadowCycleTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='ardrec-r71-')
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)/'durable'
        self.benign=Path(tmp.name)/'benign'
        self.fixture=read_fixed_scenario(SCENARIO)
        self.gen0=open_or_create_dev(self.root,self.fixture)
        self.gen1=open_or_publish_safe(self.root,self.fixture,publish=True)

    def run_shadow(self):
        return run_shadow_cycle(self.root,self.benign,self.fixture)

    def test_01_selection_and_benign_A5_are_distinct(self):
        doc=self.run_shadow()
        self.assertEqual(doc['a4_shadow_selection']['service_id'],'SSH_DEV')
        self.assertEqual(doc['a4_shadow_selection']['case_id'],'CASE_REFERENCE')
        self.assertIsNone(doc['a4_confirmed_selection'])
        self.assertEqual(doc['a5_local_benign_outcome'],'BENIGN_EXIT_ZERO')
        self.assertEqual(doc['a5_local_benign_starts'],1)
        self.assertFalse(doc['physical_observation_attested'])
        self.assertFalse(doc['operational_dispatch'])
        self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_02_exact_oracle_is_hypothetical_not_Rf(self):
        doc=self.run_shadow()
        self.assertEqual(doc['a7_hypothetical_rf'],'5/12')
        self.assertIsNone(doc['a7_confirmed_rf'])
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertFalse(doc['a9_new_generation_published'])

    def test_03_r70_gen1_is_unchanged(self):
        before=self.gen1
        original=(self.root/'a1-generation-0.json').read_bytes()
        journal=sorted((self.root/'generational-store'/'journal').glob('*.json'))
        bytes_before={p.name:p.read_bytes() for p in journal}
        doc=self.run_shadow()
        after=open_or_publish_safe(self.root,self.fixture)
        self.assertEqual(doc['r70_head_sha256'],before['head_sha256'])
        self.assertEqual(doc['r70_snapshot_sha256'],before['analytical_snapshot_sha256'])
        self.assertEqual(canonical(before),canonical(after))
        self.assertEqual(original,(self.root/'a1-generation-0.json').read_bytes())
        self.assertEqual(bytes_before,{p.name:p.read_bytes() for p in journal})

    def test_04_restart_no_second_start_no_changed_document(self):
        first=self.run_shadow()
        second=self.run_shadow()
        self.assertEqual(first['sha256'],second['sha256'])
        self.assertEqual(canonical(first),canonical(second))
        self.assertEqual(first['a5_local_benign_starts'],1)

    def test_05_source_head_pin_refuses_obsolete(self):
        with self.assertRaises(ValueError):
            run_shadow_cycle(self.root,self.benign,self.fixture,
                             expected_head_sha256=self.gen0['store_head_sha256'])
        self.assertFalse(self.benign.exists())

    def test_06_gen0_is_not_a_shadow_source(self):
        other=self.root.parent/'fresh-gen0'
        open_or_create_dev(other,self.fixture)
        with self.assertRaisesRegex(ValueError,'safe_gen1_required'):
            run_shadow_cycle(other,self.benign,self.fixture)
        self.assertFalse(self.benign.exists())

    def test_07_same_or_nested_root_refused_before_writes(self):
        for candidate in (self.root,self.root/'children',self.root.parent):
            with self.subTest(root=str(candidate)):
                with self.assertRaisesRegex(ValueError,'journal_not_separate'):
                    run_shadow_cycle(self.root,candidate,self.fixture)

    def test_08_source_scenario_tamper_rejected(self):
        changed=copy.deepcopy(self.fixture)
        changed['services'][0]['id']='WRONG'
        with self.assertRaises(ValueError):run_shadow_cycle(self.root,self.benign,changed)
        self.assertFalse(self.benign.exists())

    def test_09_r71_r38_is_three_panels_and_all_10_stages(self):
        doc=self.run_shadow()
        report=build_shadow_dashboard(doc,self.fixture,self.gen1)
        self.assertEqual([s['algorithm'] for s in report['a10']['stages']],
                         [f'A{i}' for i in range(1,11)])
        frame='\n'.join(render_dashboard_frame(report,DashboardState(selected=4),140,36))
        for marker in ('ALGORITMOS','DETALLE','ESTADO / AUDITORIA',
                       'SOMBRA BENIGNA','R71'):
            self.assertIn(marker,frame)
        self.assertIn('BENIGNA LOCAL','\n'.join(detail_rows(report,4)))
        self.assertIn('HIPOTETICO','\n'.join(detail_rows(report,6)))
        self.assertIn('HEAD INMUTABLE','\n'.join(detail_rows(report,8)))

    def test_10_rehash_false_go_and_false_rf_rejected(self):
        base=build_shadow_dashboard(self.run_shadow(),self.fixture,self.gen1)
        for key,value in (('p8_operational','GO'),('operational_dispatch',True),('final_risk','5/12')):
            altered=copy.deepcopy(base)
            altered[key]=value
            altered['sha256']=digest(canonical({k:v for k,v in altered.items() if k!='sha256'}))
            with self.assertRaises(DashboardError):validate_dashboard_report(altered)

    def test_11_rehash_false_A5_and_fake_technical_publication_rejected(self):
        base=build_shadow_dashboard(self.run_shadow(),self.fixture,self.gen1)
        changed=copy.deepcopy(base)
        changed['r27']['a5_start_count']=2
        changed['sha256']=digest(canonical({k:v for k,v in changed.items() if k!='sha256'}))
        with self.assertRaises(DashboardError):validate_dashboard_report(changed)
        changed=copy.deepcopy(base)
        changed['a9']['technical_generation_published']=True
        changed['sha256']=digest(canonical({k:v for k,v in changed.items() if k!='sha256'}))
        with self.assertRaises(DashboardError):validate_dashboard_report(changed)

    def test_12_source_bridge_checks_r70_binder(self):
        doc=self.run_shadow()
        altered=copy.deepcopy(doc)
        altered['r70_head_sha256']='0'*64
        altered['sha256']=digest(canonical({k:v for k,v in altered.items() if k!='sha256'}))
        with self.assertRaises(ShadowViewError):
            build_shadow_dashboard(altered,self.fixture,self.gen1)

    def test_13_cli_json_idempotent_and_head_unmodified(self):
        cmd=[sys.executable,'-B','-m','ardrec','--durable-dev-root',str(self.root),
             '--shadow-cycle','--shadow-journal-root',str(self.benign),'--json']
        env={**os.environ,'PYTHONPATH':str(ROOT/'src')}
        out1=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True)
        out2=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True)
        self.assertEqual(out1.returncode,0,out1.stderr.decode())
        self.assertEqual(out2.returncode,0,out2.stderr.decode())
        self.assertEqual(out1.stdout,out2.stdout)
        self.assertEqual(json.loads(out1.stdout)['r70_head_sha256'],self.gen1['head_sha256'])

    def test_14_curses_real_normal_entry_q_exit(self):
        import pty,fcntl,termios,struct,select,time
        master,slave=pty.openpty()
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',34,155,0,0))
        proc=subprocess.Popen([sys.executable,'-B','-m','ardrec',
                '--durable-dev-root',str(self.root),'--shadow-cycle',
                '--shadow-journal-root',str(self.benign),'--tui'],
            cwd=ROOT,env={**os.environ,'PYTHONPATH':str(ROOT/'src'),'TERM':'xterm-256color'},
            stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
        os.close(slave)
        try:
            data=b'';deadline=time.monotonic()+14
            while time.monotonic()<deadline and proc.poll() is None:
                ready,_,_=select.select([master],[],[],0.2)
                if ready:
                    try:data+=os.read(master,65536)
                    except OSError:break
                if b'SOMBRA BENIGNA' in data and b'ALGORITMOS' in data:break
            self.assertIn(b'ALGORITMOS',data,data[-500:])
            self.assertIn(b'SOMBRA BENIGNA',data,data[-500:])
            os.write(master,b'6q')
            self.assertEqual(proc.wait(timeout=8),0)
        finally:
            if proc.poll() is None: proc.kill();proc.wait(timeout=5)
            os.close(master)

    def test_15_local_artifact_corruption_fails_closed(self):
        self.run_shadow()
        evidence=next((self.benign/'artifacts').glob('*.stdout'))
        evidence.write_bytes(b'FORGED')
        with self.assertRaises(RuntimeError): self.run_shadow()

    def test_16_normal_r70_entry_remains_r70(self):
        proc=subprocess.run([sys.executable,'-B','-m','ardrec',
             '--durable-dev-root',str(self.root),'--json'],cwd=ROOT,
             env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stderr.decode())
        self.assertEqual(json.loads(proc.stdout)['schema'],self.gen1['schema'])
        self.assertEqual(json.loads(proc.stdout)['head_sha256'],self.gen1['head_sha256'])

if __name__=='__main__':unittest.main()
