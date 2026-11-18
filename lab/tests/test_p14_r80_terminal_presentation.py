"""R80: verificación y selección de vistas de terminal, sin ninguna operación física."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO/'src'))
sys.path.insert(0, str(REPO/'scripts'))
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r78_a7_whatif_sensitivity as r78
import ardrec_p14_r79_tutor_walkthrough as r79
import ardrec_p14_r80_terminal_presentation as r80
from ardrec.persistence.codec import canonical, digest

@unittest.skipIf(os.geteuid()==0,'R80 requiere usuario no privilegiado')
class TerminalPresentation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ardrec-r80-')
        cls.root=Path(cls.temp.name)/'r75'
        r75.create(cls.root)
        cls.d76=r76.build(cls.root)
        cls.d78=r78.build(cls.root,cls.d76)
        cls.d79=r79.build(cls.root,cls.d76,cls.d78)
        for name,doc in [('r76',cls.d76),('r78',cls.d78),('r79',cls.d79)]:
            f=Path(cls.temp.name)/(name+'.json')
            f.write_bytes(canonical(doc)+b'\n')
            f.chmod(0o600)
        cls.p76=Path(cls.temp.name)/'r76.json'
        cls.p78=Path(cls.temp.name)/'r78.json'
        cls.p79=Path(cls.temp.name)/'r79.json'

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def read(self):
        return r80.load(self.root,self.p76,self.p78,self.p79)

    def text(self,view,**kwargs):
        return r80.render(self.d79,view,**kwargs)

    def test_01_exact_authenticated_sources(self):
        self.assertEqual(self.read(),self.d79)

    def test_02_summary_no_false_authority(self):
        s=self.text('resumen')
        for expected in ('R80=PASS_VERIFIED_READONLY','NOT_RUN',
                         '54 unidades','A6=ND','P8=NO-GO','GEN2 inexistente'):
            self.assertIn(expected,s)

    def test_03_ten_stages(self):
        text=self.text('etapas')
        for n in range(1,11):
            self.assertIn('A'+str(n)+':',text)
        self.assertIn('NO-GO',text)

    def test_04_every_stage_individual(self):
        for n in range(1,11):
            value='A'+str(n)
            with self.subTest(value=value):
                text=self.text('etapa',stage=value)
                self.assertIn('INTERPRETACION:',text)
                self.assertIn('VALIDACION EXPERIMENTAL: NOT_RUN',text)
                self.assertIn('AUTORIDAD OPERACIONAL: NO-GO',text)

    def test_05_all_25_families(self):
        text=self.text('familias')
        for row in self.d79['families']:
            self.assertIn(row['family_id'],text)
        self.assertIn('HIPOTESIS',text)

    def test_06_ssh_filter_eight(self):
        text=self.text('familias',protocol='SSH')
        self.assertEqual(sum(x.startswith('SSH-T') for x in text.splitlines()),8)
        self.assertNotIn('SMB-T01',text)

    def test_07_ftp_filter_eight(self):
        text=self.text('familias',protocol='FTP')
        self.assertEqual(sum(x.startswith('FTP-T') for x in text.splitlines()),8)

    def test_08_smb_filter_nine(self):
        text=self.text('familias',protocol='SMB')
        self.assertEqual(sum(x.startswith('SMB-T') for x in text.splitlines()),9)

    def test_09_each_family_shows_exact_fractions(self):
        for row in self.d79['families']:
            with self.subTest(row=row['family_id']):
                text=self.text('familia',family=row['family_id'])
                for key in ('hypothetical_rf_E0','hypothetical_rf_Ehalf',
                            'hypothetical_rf_E1'):
                    self.assertIn(row[key],text)
                self.assertIn('Rf CONFIRMADO: NULL',text)

    def test_10_unknown_family_rejected(self):
        with self.assertRaisesRegex(r80.R80Error,'UNKNOWN_OR_DUPLICATED_FAMILY'):
            self.text('familia',family='SSH-T99')

    def test_11_invalid_stage_rejected(self):
        with self.assertRaisesRegex(r80.R80Error,'STAGE_OUT_OF_RANGE'):
            self.text('etapa',stage='A11')

    def test_12_argument_boundaries(self):
        for view,kwargs in [
            ('resumen',{'stage':'A1'}),('etapa',{}),
            ('familia',{}),('familias',{'stage':'A1'}),
            ('resumen',{'protocol':'SSH'}),('familia',{'protocol':'SMB','family':'SSH-T01'}),
            ('r38',{})]:
            with self.subTest(view=view,kwargs=kwargs),self.assertRaises(r80.R80Error):
                self.text(view,**kwargs)

    def test_13_evidence_links_exact(self):
        text=self.text('evidencias')
        for key,value in self.d79['source_links'].items():
            self.assertIn(value,text,key)
        self.assertIn('no procedencia fisica',text)

    def test_14_monitor_original_three_panels(self):
        monitor=r75.read_file(self.root/'reports'/'r38_pantalla.txt').decode()
        text=self.text('r38',monitor=monitor)
        for marker in ('ALGORITMOS','DETALLE','ESTADO / AUDITORIA',
                       'SOMBRA BENIGNA'):
            self.assertIn(marker,text)

    def test_15_forged_monitor_rejected(self):
        with self.assertRaisesRegex(r80.R80Error,'R38_SOURCE_FRAME_INVALID'):
            self.text('r38',monitor='FAKE MONITOR')

    def test_16_overview_all_no_operational_claim(self):
        text=self.text('todo')
        self.assertIn('SSH-T01',text)
        self.assertIn('SMB-T09',text)
        self.assertIn('R77: sin registro',text)
        self.assertNotIn('RF CONFIRMADO: 5/12',text)

    def test_17_no_subprocess_during_load(self):
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_CHILD')):
            self.assertEqual(self.read(),self.d79)

    def test_18_forged_r79_rehashed_go_rejected(self):
        fake=copy.deepcopy(self.d79)
        fake['p8_operational']='GO'
        fake['sha256']=digest(canonical({k:v for k,v in fake.items() if k!='sha256'}))
        self.p79.write_bytes(canonical(fake)+b'\n')
        try:
            with self.assertRaises(ValueError):
                self.read()
        finally:
            self.p79.write_bytes(canonical(self.d79)+b'\n')

    def test_19_forged_r78_risk_rejected(self):
        fake=copy.deepcopy(self.d78)
        fake['a7_confirmed_rf']='5/12'
        fake['sha256']=digest(canonical({k:v for k,v in fake.items() if k!='sha256'}))
        self.p78.write_bytes(canonical(fake)+b'\n')
        try:
            with self.assertRaises(ValueError):
                self.read()
        finally:
            self.p78.write_bytes(canonical(self.d78)+b'\n')

    def test_20_unsafe_input_permissions_rejected(self):
        self.p76.chmod(0o644)
        try:
            with self.assertRaises(ValueError):
                self.read()
        finally:
            self.p76.chmod(0o600)

    def test_21_cli_real_and_no_mutations(self):
        before={p.name:p.read_bytes() for p in (self.p76,self.p78,self.p79)}
        base=[sys.executable,'-B',str(REPO/'scripts/ardrec_p14_r80_terminal_presentation.py'),
              '--receipt-dir',str(self.root),'--r76-report',str(self.p76),
              '--r78-report',str(self.p78),'--r79-report',str(self.p79)]
        for view,extra in [('resumen',[]),('etapa',['--etapa','A7']),
                           ('familia',['--familia','FTP-T01']),
                           ('r38',[])]:
            with self.subTest(view=view):
                p=subprocess.run(base+['--vista',view]+extra,cwd=REPO,
                                 capture_output=True,timeout=60)
                self.assertEqual(p.returncode,0,p.stderr.decode())
                self.assertIn(b'PASS_VERIFIED_READONLY',p.stdout)
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.p76,self.p78,self.p79)})

    def test_22_nonroot_contract(self):
        self.assertIn('NONROOT_CANONICAL_REPO_REQUIRED',r80.load.__code__.co_consts)
        self.assertEqual(r80.SCHEMA,'ardrec-p14-r80-terminal-readonly-presentation-v1')

    def test_23_no_operational_commands_in_source(self):
        raw=(REPO/'scripts/ardrec_p14_r80_terminal_presentation.py').read_text()
        for bad in ('subprocess.run(', 'os.system(', 'shell=True',
                    'systemctl ', 'virsh ', 'sudo ', 'nft ',
                    'git push','gh pr merge','socket.'):
            self.assertNotIn(bad,raw)

if __name__=='__main__':
    unittest.main()
