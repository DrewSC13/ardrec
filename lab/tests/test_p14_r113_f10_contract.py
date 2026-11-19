import ast
import importlib.util
import json
import pathlib
import sys
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.coordination import r113_f10_contract as c

class ContractTests(unittest.TestCase):
    def test_one_triplet_per_target(self):
        self.assertEqual({v[1] for v in c.ROWS.values()},{'ssh','ftp','smb'})
    def test_six_roles(self): self.assertEqual(len(c.ROWS),6)
    def test_unique_taps(self): self.assertEqual(len({v[2] for v in c.ROWS.values()}),6)
    def test_unique_macs(self): self.assertEqual(len({v[3] for v in c.ROWS.values()}),6)
    def test_expected_ports(self): self.assertEqual([c.ROWS[x][6] for x in ('ssh','ftp','smb')],[22,21,445])
    def test_subnets(self):
        self.assertEqual([c.ROWS[x][4] for x in ('runner-ssh','runner-ftp','runner-smb')],
                         ['10.203.30.1','10.203.31.1','10.203.32.1'])
    def test_names(self): self.assertEqual(len(c.NAMES),7)
    def test_name_rejects_unknown(self):
        with self.assertRaises(c.Stop):c.name('runner_http')
    def test_ssh_name(self): self.assertEqual(c.name('runner-ssh'),'ardrec-r113-runner-ssh-tcp-v1')
    def test_fixed_window(self): self.assertEqual((c.DURATION,c.OPEN_DEADLINE),(120,60))
    def test_probe_compile(self): compile(c.probe_source(),'<guest-exec>','exec')
    def test_probe_no_shell(self):
        text=c.probe_source()
        self.assertNotIn('subprocess',text);self.assertNotIn('os.system',text)
    def test_probe_fixed_single_smb_request(self):self.assertEqual(c.probe_source().count('s.sendall('),1)
    def test_probe_has_no_passwords(self):
        text=c.probe_source().lower()
        self.assertNotIn('password=',text);self.assertNotIn('username=',text)
    def test_probe_three_targets(self):
        self.assertIn("('ssh','10.203.30.1','10.203.30.2',22)",c.probe_source())
        self.assertIn("('ftp','10.203.31.1','10.203.31.2',21)",c.probe_source())
        self.assertIn("('smb','10.203.32.1','10.203.32.2',445)",c.probe_source())
    def test_probe_result_valid(self):
        rows=[{'role':role,'src':src,'dst':dst,'port':port,'tcp':'CONNECTED'} for role,src,dst,port in
              [('ssh','10.203.30.1','10.203.30.2',22),('ftp','10.203.31.1','10.203.31.2',21),('smb','10.203.32.1','10.203.32.2',445)]]
        c.validate_probe(json.dumps({'schema':'ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1','results':rows}).encode())
    def test_probe_rejects_wrong_dest(self):
        rows=[{'role':role,'src':src,'dst':dst,'port':port,'tcp':'CONNECTED'} for role,src,dst,port in
              [('ssh','10.203.30.1','1.1.1.1',22),('ftp','10.203.31.1','10.203.31.2',21),('smb','10.203.32.1','10.203.32.2',445)]]
        with self.assertRaises(c.Stop):c.validate_probe(json.dumps({'schema':'ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1','results':rows}).encode())
    def test_probe_rejects_extra(self):
        with self.assertRaises(c.Stop):c.validate_probe(b'{"schema":"ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1","results":[]}')
    def test_canonical_deterministic(self):self.assertEqual(c.canonical({'b':2,'a':1}),c.canonical({'a':1,'b':2}))
    def test_sha_empty(self):self.assertEqual(c.sha(b''),'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    def test_f9_hash_rejects_random(self):
        with self.assertRaises(c.Stop):c.validate_f9r(b'{}',b'{}')
    def test_f9_hash_pinned(self):self.assertEqual(len(c.F9R_HASH),64)
    def test_replay_schema_stable(self):
        self.assertIn('ARDREC-R113-F10-ROOT-EVENT-v1',(ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text())
    def test_restore_in_finally(self):
        tree=ast.parse((ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text())
        func=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='window')
        finally_nodes=[x for x in ast.walk(func) if isinstance(x,ast.Try) and x.finalbody]
        self.assertTrue(any('f6_restore_final' in ast.unparse(z.finalbody) for z in finally_nodes))
    def test_nft_open_after_timer_and_bindings(self):
        text=(ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text()
        self.assertLess(text.index("run('timer_arm'"),text.index("run('delete_'+role"))
        self.assertLess(text.index("run('delete_'+role"),text.index("run('nft_open'"))
    def test_one_shot_marker(self):
        text=(ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text()
        self.assertIn("'window-attempted.once'",text)
    def test_no_auto_cleanup_partial(self):
        text=(ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text()
        self.assertIn('R113_F10_NO_AUTORETRY=TRUE',text)
    def test_root_script_compiles(self):
        compile((ROOT/'scripts/ardrec_p14_r113_f10_root_window.py').read_text(),'<root>','exec')
    def test_root_path_pinned(self):
        self.assertEqual(str(c.ROOT),'/var/lib/ardrec/r113-f10-window-v1')

if __name__=='__main__':unittest.main()
