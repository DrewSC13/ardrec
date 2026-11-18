"""R75: prueba integrada de paquete sintético, repetición y rechazo de alteraciones."""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import importlib.util

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'scripts/ardrec_p14_r75_integrated_demo.py'
spec=importlib.util.spec_from_file_location('r75_integrated',SCRIPT)
r75=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r75)

@unittest.skipIf(os.geteuid()==0, 'R75 requiere usuario no root')
class IntegratedDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='ardrec-r75-test-')
        cls.root=Path(cls.tmp.name)/'receipt'
        cls.manifest=r75.create(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def docs(self):
        return {name:r75.read_file(p) for name,p in r75.report_paths(self.root).items()}

    def test_01_create_verify(self):
        self.assertEqual(r75.verify(self.root), self.manifest)
        self.assertEqual(self.manifest['a6'],'ND')
        self.assertIsNone(self.manifest['confirmed_rf'])

    def test_02_all_stages(self):
        data=self.docs()
        links=r75.validated_reports(data)
        self.assertEqual(links,self.manifest['source_links'])
        self.assertEqual(len(json.loads(data['r38_report.json'])['a10']['stages']),10)
        for term in (b'ALGORITMOS',b'DETALLE',b'ESTADO / AUDITORIA'):
            self.assertIn(term,data['r38_pantalla.txt'])

    def test_03_verify_no_child_process(self):
        with patch.object(r75.subprocess,'run',side_effect=AssertionError('no exec')):
            self.assertEqual(r75.verify(self.root),self.manifest)

    def test_04_no_double_create(self):
        with self.assertRaisesRegex(r75.R75Error,'receipt_already_exists'):
            r75.create(self.root)

    def test_05_private_parent_required(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);parent.chmod(0o755)
            with self.assertRaisesRegex(r75.R75Error,'private_parent_0700'):
                r75.create(parent/'new')

    def test_06_symlink_rejected(self):
        link=Path(self.tmp.name)/'link'
        link.symlink_to(self.root)
        try:
            with self.assertRaisesRegex(r75.R75Error,'symlink_parent'):
                r75.verify(link)
        finally:link.unlink()

    def test_07_fake_authority_rejected(self):
        base=self.docs()
        cases=(('shadow.json','p8_operational','GO'),
               ('shadow.json','a7_confirmed_rf','5/12'),
               ('gen1.json','a5_start_count',2),
               ('29_cases.json','technical_truth_accredited',True))
        for name,key,value in cases:
            with self.subTest(name=name,key=key):
                changed=dict(base);doc=json.loads(changed[name]);doc[key]=value
                changed[name]=r75.canonical(doc)
                with self.assertRaises(r75.R75Error):
                    r75.validated_reports(changed)

    def test_08_fake_monitor_rejected(self):
        changed=self.docs();doc=json.loads(changed['r38_report.json'])
        doc['a10']['stages'][5]['status']='ACREDITADO'
        changed['r38_report.json']=r75.canonical(doc)
        with self.assertRaises(r75.R75Error):r75.validated_reports(changed)

    def test_09_tampered_report_detected(self):
        file=self.root/'reports'/'54_units.json';before=file.read_bytes()
        try:
            file.write_bytes(before+b'\n')
            with self.assertRaisesRegex(r75.R75Error,'inventory_or_digest_drift'):
                r75.verify(self.root)
        finally:file.write_bytes(before)

    def test_10_extra_file_detected(self):
        file=self.root/'reports'/'extra.txt'
        try:
            r75.write_file(file,b'extra')
            with self.assertRaisesRegex(r75.R75Error,'inventory_or_digest_drift'):
                r75.verify(self.root)
        finally:file.unlink()

    def test_11_invalid_python_command_rejected(self):
        for cmd in (['-c','print(1)'],['-m','ardrec','--tui'],
                    ['-m','ardrec','--scenario','/tmp/unsafe'],['scripts/x.py']):
            with self.subTest(cmd=cmd),self.assertRaises(r75.R75Error):
                r75.run_python(cmd)

    def test_12_verify_cli(self):
        p=subprocess.run([sys.executable,'-B',str(SCRIPT),'--verify',
                          '--receipt-dir',str(self.root)],cwd=ROOT,capture_output=True,timeout=15)
        self.assertEqual(p.returncode,0,p.stderr.decode())
        self.assertIn(b'PASS_VERIFIED_NO_EXECUTION',p.stdout)

    def test_13_forged_manifest_authority_rejected(self):
        file=self.root/'MANIFEST.json';before=file.read_bytes()
        try:
            forged=dict(self.manifest);forged['p8']='GO'
            file.write_bytes(r75.canonical(forged))
            with self.assertRaisesRegex(r75.R75Error,'manifest_contract_invalid'):
                r75.verify(self.root)
        finally:file.write_bytes(before)

    def test_14_full_inventory(self):
        entries=set(self.manifest['files'])
        self.assertTrue({'reports/'+n for n in r75.REPORTS} <= entries)
        self.assertIn('benign/attempts.sqlite3',entries)
        self.assertTrue(any(s.startswith('session/generational-store/journal/') for s in entries))

    def test_15_no_test_authenticating_hosts(self):
        raw=SCRIPT.read_text()
        for verb in ('os.system(', 'shell=True', 'systemctl restart', 'gh pr merge'):
            self.assertNotIn(verb,raw)

    def test_18_sqlite_is_normalized_to_owner_private_mode(self):
        import stat
        db=self.root/'benign'/'attempts.sqlite3'
        self.assertEqual(stat.S_IMODE(db.stat().st_mode),0o600)

    def test_19_umask_022_sqlite_candidate_normalized(self):
        import stat
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'benign').mkdir(mode=0o700)
            db=root/'benign'/'attempts.sqlite3'
            db.write_bytes(b'bounded-synthetic-fixture')
            db.chmod(0o644)
            r75.normalize_benign_sqlite_mode(root)
            self.assertEqual(stat.S_IMODE(db.stat().st_mode),0o600)
            r75.normalize_benign_sqlite_mode(root)
            self.assertEqual(stat.S_IMODE(db.stat().st_mode),0o600)

    def test_20_unexpected_sqlite_mode_refused_before_chmod(self):
        import stat
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'benign').mkdir(mode=0o700)
            db=root/'benign'/'attempts.sqlite3'
            db.write_bytes(b'bounded-synthetic-fixture')
            for mode in (0o640,0o444,0o666):
                with self.subTest(mode=oct(mode)):
                    db.chmod(mode)
                    with self.assertRaisesRegex(r75.R75Error,'benign_sqlite_initial_mode_invalid'):
                        r75.normalize_benign_sqlite_mode(root)
                    self.assertEqual(stat.S_IMODE(db.stat().st_mode),mode)

    def test_21_sqlite_symlink_refused_without_target_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'benign').mkdir(mode=0o700)
            target=root/'safe-file'
            target.write_bytes(b'unchanged')
            (root/'benign'/'attempts.sqlite3').symlink_to(target)
            with self.assertRaises(OSError):
                r75.normalize_benign_sqlite_mode(root)
            self.assertEqual(target.read_bytes(),b'unchanged')

    def test_22_sqlite_hardlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'benign').mkdir(mode=0o700)
            original=root/'benign'/'attempts.sqlite3'
            original.write_bytes(b'bounded-synthetic-fixture')
            original.chmod(0o644)
            (root/'linked').hardlink_to(original)
            with self.assertRaisesRegex(r75.R75Error,'benign_sqlite_initial_mode_invalid'):
                r75.normalize_benign_sqlite_mode(root)

    def test_23_verify_refuses_sqlite_permission_downgrade(self):
        db=self.root/'benign'/'attempts.sqlite3'
        try:
            db.chmod(0o644)
            with self.assertRaisesRegex(r75.R75Error,'file_permissions_benign/attempts.sqlite3'):
                r75.verify(self.root)
        finally:
            db.chmod(0o600)

class GateShape(unittest.TestCase):
    def test_16_one_mode_is_mandatory(self):
        p=subprocess.run([sys.executable,'-B',str(SCRIPT),'--receipt-dir','/tmp/a'],
                         cwd=ROOT,capture_output=True,timeout=10)
        self.assertNotEqual(p.returncode,0)

    def test_17_p8_fail_closed_label(self):
        self.assertEqual(r75.SOURCE,'SYNTHETIC_A1_A10_NO_OPERATIONAL_AUTHORITY')
        self.assertIn('NO systemd, libvirt, nft',SCRIPT.read_text())

if __name__=='__main__':unittest.main()
