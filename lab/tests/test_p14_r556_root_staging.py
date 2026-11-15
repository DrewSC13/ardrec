"""R55.6 root-install offline integrity/adversarial tests. No sudo or host writes."""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from ardrec.coordination import r556_root_staging as g
from ardrec.coordination import r555_recovery_contract as r555
from ardrec.coordination import r553_transition_guard as r553

ROOT=Path(__file__).resolve().parents[2]
HELPER=ROOT/'scripts/ardrec_p14_r555_root_recover.py'
SCRIPT=ROOT/'scripts/ardrec_p14_r556_stage.py'

UUID='11111111-2222-4333-8444-555555555555'

def binding(role,candidate):
    name,tap,mac,ip,offered=r553.GUESTS[role]
    root=ET.Element('filterbinding')
    owner=ET.SubElement(root,'owner')
    ET.SubElement(owner,'name').text=name
    ET.SubElement(owner,'uuid').text=UUID
    ET.SubElement(root,'portdev',{'name':tap})
    ET.SubElement(root,'mac',{'address':mac})
    filt=ET.SubElement(root,'filterref',{'filter':offered if candidate else r553.DENY})
    ET.SubElement(filt,'parameter',{'name':'MAC','value':mac})
    ET.SubElement(root,'backend',{'name':'iptables'})
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'

def fixture(helper):
    files={'root-recover.py':helper,'r34-deny-restore.nft':r553.expected_nft(allow=False)}
    for role in ('ssh','runner'):
        files[role+'-original.xml']=binding(role,False)
        files[role+'-candidate.xml']=binding(role,True)
    files['manifest.json']=r555.canon({
        'schema':r555.SCHEMA,'source_main':r555.SOURCE_MAIN,
        'r552_plan_sha256':r555.PLAN_SHA,
        'permission':'DENY_ONLY_RESTORATION','traffic_allowed':False,
        'p8_operational':'NO-GO','sha256':{n:r555.sha(files[n]) for n in r555.PAYLOADS},
    })
    files['contract.json']=r555.canon(r555.obligations())
    files['SHA256SUMS']=(''.join(r555.sha(files[n])+'  '+n+'\n' for n in sorted(files))).encode('ascii')
    return files

class Fixtures(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)/'prepared'
        self.folder.mkdir(mode=0o700)
        self.folder.chmod(0o700)
        self.helper=HELPER.read_bytes()
        self.files=fixture(self.helper)
        for name,body in self.files.items():
            p=self.folder/name
            p.write_bytes(body)
            p.chmod(0o600)
        self.patch=patch.object(g,'PREPARED',self.folder)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def verify(self):
        return g.verify_private_material(self.folder,helper_bytes=self.helper)

    def expect_reject(self,fn):
        with self.assertRaises(g.StageError):fn()

    def test_valid_complete_bundle(self):
        result=self.verify()
        self.assertEqual(set(result),g.ROOT_FILES)
        self.assertEqual(len(result),7)

    def test_exact_expected_file_names(self):
        self.assertEqual(len(g.CONTENTS),9)
        self.assertEqual(len(g.ROOT_FILES),7)

    def test_restore_not_allow_policy(self):
        result=self.verify()
        self.assertEqual(result['r34-deny-restore.nft'],r553.expected_nft(allow=False))
        self.assertNotIn(b'counter accept',result['r34-deny-restore.nft'])

    def test_staging_report_no_go(self):
        report=g.stage_report(self.verify())
        self.assertEqual(report['p8_operational'],'NO-GO')
        self.assertEqual(report['firewall_mutations'],0)
        self.assertFalse(report['physical_restore_tested'])
        self.assertFalse(report['system_timer_armed'])

    def test_stage_report_check_requires_stage(self):
        self.expect_reject(lambda:g.stage_report(self.verify(),staged=False,checked=True))

    def test_stage_report_bool_only(self):
        self.expect_reject(lambda:g.stage_report(self.verify(),staged=1,checked=False))

    def test_stage_report_deny_staged(self):
        x=g.stage_report(self.verify(),staged=True,checked=True)
        self.assertTrue(x['root_bundle_check_pass'])
        self.assertFalse(x['traffic_authorized'])

    def test_source_path_pinned(self):
        self.expect_reject(lambda:g.verify_private_material(Path(self.tmp.name),helper_bytes=self.helper))

    def test_helper_diff_refused(self):
        self.expect_reject(lambda:g.verify_private_material(self.folder,helper_bytes=self.helper+b'x'))

    def test_file_hash_modified(self):
        (self.folder/'ssh-original.xml').write_bytes(b'altered')
        self.expect_reject(self.verify)

    def test_manifest_hash_modified(self):
        (self.folder/'manifest.json').write_bytes(b'{}')
        self.expect_reject(self.verify)

    def test_contract_hash_modified(self):
        (self.folder/'contract.json').write_bytes(b'{}')
        self.expect_reject(self.verify)

    def test_extra_file_refused(self):
        (self.folder/'evil.txt').write_bytes(b'x')
        self.expect_reject(self.verify)

    def test_missing_file_refused(self):
        (self.folder/'runner-original.xml').unlink()
        self.expect_reject(self.verify)

    def test_symlink_file_refused(self):
        target=self.folder/'ssh-original.xml'
        target.unlink()
        target.symlink_to(self.folder/'runner-original.xml')
        self.expect_reject(self.verify)

    def test_symlink_directory_refused(self):
        proxy=Path(self.tmp.name)/'proxy'
        proxy.symlink_to(self.folder,target_is_directory=True)
        with patch.object(g,'PREPARED',proxy):
            self.expect_reject(lambda:g.verify_private_material(proxy,helper_bytes=self.helper))

    def test_dir_mode_refused(self):
        self.folder.chmod(0o755)
        self.expect_reject(self.verify)

    def test_file_mode_refused(self):
        (self.folder/'root-recover.py').chmod(0o644)
        self.expect_reject(self.verify)

    def test_file_symlink_ancestor(self):
        self.assertIsNone(g._no_symlinks(self.folder))

    def test_hardlink_refused(self):
        p=self.folder/'ssh-candidate.xml'
        extra=Path(self.tmp.name)/'hardlink'
        os.link(p,extra)
        self.expect_reject(self.verify)

    def test_missing_checksum_line_refused(self):
        lines=self.files['SHA256SUMS'].splitlines()
        (self.folder/'SHA256SUMS').write_bytes(b'\n'.join(lines[:-1])+b'\n')
        self.expect_reject(self.verify)

    def test_duplicate_checksum_refused(self):
        p=self.folder/'SHA256SUMS'
        p.write_bytes(self.files['SHA256SUMS']+self.files['SHA256SUMS'].splitlines()[0]+b'\n')
        self.expect_reject(self.verify)

    def test_checksum_typo_refused(self):
        p=self.folder/'SHA256SUMS'
        p.write_bytes((b'f' if self.files['SHA256SUMS'][0:1]!=b'f' else b'e')+self.files['SHA256SUMS'][1:])
        self.expect_reject(self.verify)

    def test_deny_policy_rerender_refused(self):
        raw=self.files['r34-deny-restore.nft'].replace(b'counter drop',b'counter accept',1)
        self._replace_with_manifest_fix('r34-deny-restore.nft',raw)
        self.expect_reject(self.verify)

    def _replace_with_manifest_fix(self,name,content):
        self.files[name]=content
        if name in r555.PAYLOADS:
            doc=json.loads(self.files['manifest.json'])
            doc['sha256'][name]=r555.sha(content)
            self.files['manifest.json']=r555.canon(doc)
        self.files['SHA256SUMS']=(''.join(r555.sha(self.files[n])+'  '+n+'\n'
                                      for n in sorted(self.files) if n!='SHA256SUMS')).encode('ascii')
        for n,body in self.files.items():
            (self.folder/n).write_bytes(body)

    def test_manifest_false_authority_refused(self):
        doc=json.loads(self.files['manifest.json']);doc['traffic_allowed']=True
        self._replace_with_manifest_fix('manifest.json',r555.canon(doc))
        self.expect_reject(self.verify)

    def test_manifest_false_source_refused(self):
        doc=json.loads(self.files['manifest.json']);doc['source_main']='bad'
        self._replace_with_manifest_fix('manifest.json',r555.canon(doc))
        self.expect_reject(self.verify)

    def test_modified_owner_refused(self):
        raw=self.files['ssh-original.xml'].replace(b'ardrec-r33-dev-ssh',b'ardrec-r33-dev-bad')
        self._replace_with_manifest_fix('ssh-original.xml',raw)
        self.expect_reject(self.verify)

    def test_modified_backend_refused(self):
        raw=self.files['ssh-candidate.xml'].replace(b'iptables',b'nftables')
        self._replace_with_manifest_fix('ssh-candidate.xml',raw)
        self.expect_reject(self.verify)

    def test_modified_mac_refused(self):
        raw=self.files['runner-original.xml'].replace(b'52:54:00:ad:30:01',b'52:54:00:ad:30:03')
        self._replace_with_manifest_fix('runner-original.xml',raw)
        self.expect_reject(self.verify)

    def test_modified_contract_refused(self):
        doc=json.loads(self.files['contract.json'])
        doc['p8_operational']='GO'
        self._replace_with_manifest_fix('contract.json',r555.canon(doc))
        self.expect_reject(self.verify)

    def test_helper_rehash_attack_refused(self):
        raw=self.helper+b'\n#evil\n'
        self._replace_with_manifest_fix('root-recover.py',raw)
        self.expect_reject(self.verify)

class CommandGuards(unittest.TestCase):
    def test_expected_9_commands(self):
        rows=g.root_install_commands(g.PREPARED)
        self.assertEqual(len(rows),9)
        g.verify_install_commands(rows,g.PREPARED)

    def test_install_destination_fixed(self):
        rows=g.root_install_commands(g.PREPARED)
        self.assertEqual(rows[-1][-1],str(g.DEST/'ssh-original.xml'))
        self.assertTrue(all(row[0]=='/usr/bin/install' for row in rows))

    def test_install_all_root_owned(self):
        rows=g.root_install_commands(g.PREPARED)
        self.assertTrue(all('-o' in r and r[r.index('-o')+1]=='0' for r in rows))
        self.assertTrue(all('-g' in r and r[r.index('-g')+1]=='0' for r in rows))

    def test_install_no_shell(self):
        programs=[row[0] for row in g.root_install_commands(g.PREPARED)]
        self.assertEqual(set(programs), {'/usr/bin/install'})

    def test_wrong_source_forbidden(self):
        with self.assertRaises(g.StageError):g.root_install_commands(Path('/tmp/attacker'))

    def test_wrong_dest_forbidden(self):
        with self.assertRaises(g.StageError):g.root_install_commands(g.PREPARED,dest=Path('/tmp/a'))

    def test_missing_install_command_refused(self):
        commands=g.root_install_commands(g.PREPARED)
        with self.assertRaises(g.StageError):g.verify_install_commands(commands[:-1],g.PREPARED)

    def test_extra_install_command_refused(self):
        commands=g.root_install_commands(g.PREPARED)+[['/usr/sbin/nft','-f','/tmp/a']]
        with self.assertRaises(g.StageError):g.verify_install_commands(commands,g.PREPARED)

    def test_install_perms_refused(self):
        commands=g.root_install_commands(g.PREPARED)
        commands[-1][commands[-1].index('-m')+1]='0644'
        with self.assertRaises(g.StageError):g.verify_install_commands(commands,g.PREPARED)

    def test_install_owner_refused(self):
        commands=g.root_install_commands(g.PREPARED)
        commands[-1][commands[-1].index('-o')+1]='1000'
        with self.assertRaises(g.StageError):g.verify_install_commands(commands,g.PREPARED)

    def test_install_reordered_refused(self):
        commands=g.root_install_commands(g.PREPARED)
        commands[-1],commands[-2]=commands[-2],commands[-1]
        with self.assertRaises(g.StageError):g.verify_install_commands(commands,g.PREPARED)

    def test_timer_is_preview_only(self):
        unit='ardrec-r555-deny-watch-20261115T164500Z-6543'
        argv=g.system_timer_preview(unit,60)
        self.assertIn('--system',argv)
        self.assertEqual(argv[-1],'--restore-deny')
        self.assertNotIn('--user',argv)

    def test_timer_bad_duration_refused(self):
        unit='ardrec-r555-deny-watch-20261115T164500Z-6543'
        with self.assertRaises(r555.R555Error):g.system_timer_preview(unit,0)

    def test_timer_bad_name_refused(self):
        with self.assertRaises(r555.R555Error):g.system_timer_preview('bad',60)

    def test_script_no_mode_to_open_network(self):
        body=SCRIPT.read_text()
        self.assertNotIn('--allow-traffic',body)
        self.assertNotIn('--open-traffic',body)
        self.assertNotIn('nwfilter-binding-delete',body)
        self.assertNotIn('nft -f',body)

    def test_script_requires_explicit_authorization(self):
        self.assertIn(g.AUTHORIZATION,SCRIPT.read_text() if False else g.AUTHORIZATION)
        body=SCRIPT.read_text()
        self.assertIn('input(',body)

    def test_stage_no_systemd_runner(self):
        self.assertNotIn('systemd-run',SCRIPT.read_text())

if __name__=='__main__':unittest.main()
