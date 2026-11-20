"""R116-F4 nonroot, zero network, read-only inventory regression."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
from ardrec.coordination import r116_f4_root_inventory as m
REPO=Path(__file__).resolve().parents[2]
LOCK=json.loads((REPO/'lab/operational-controller/r116-f3-root-source-lock-v1.json').read_text())

class Fixture:
    def __init__(self,mode=stat.S_IFREG|0o600,uid=0,nlink=1):
        self.st_mode=mode;self.st_uid=uid;self.st_nlink=nlink

def s_file(p):return Fixture()
def s_dir(p):return Fixture(stat.S_IFDIR|0o700)
def s_missing(p):raise FileNotFoundError()
def s_unreadable(p):raise PermissionError()
def s_slink(p):return Fixture(stat.S_IFLNK|0o777)
def s_bad_owner(p):return Fixture(uid=1000)
def s_bad_mode(p):return Fixture(mode=stat.S_IFREG|0o666)
def s_bad_nlink(p):return Fixture(nlink=2)

class Inventory(unittest.TestCase):
    def test_paths(self):self.assertEqual(len(m.ROOT_FILES),14)
    def test_root_paths(self):self.assertEqual(len(m.ROOT_DIRS),4)
    def test_file_metadata(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_file),'PRESENT_METADATA_ONLY')
    def test_dir_metadata(self):self.assertEqual(m.inspect_node('/tmp/f',directory=True,stat_reader=s_dir),'PRESENT_METADATA_ONLY')
    def test_file_wrong_type(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_dir),'REJECT_TYPE')
    def test_dir_wrong_type(self):self.assertEqual(m.inspect_node('/tmp/f',directory=True,stat_reader=s_file),'REJECT_TYPE')
    def test_no_symlink(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_slink),'REJECT_SYMLINK')
    def test_bad_owner(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_bad_owner),'REJECT_OWNER_PERMISSIONS')
    def test_bad_mode(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_bad_mode),'REJECT_OWNER_PERMISSIONS')
    def test_hardlink(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_bad_nlink),'REJECT_OWNER_PERMISSIONS')
    def test_missing(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_missing),'ABSENT')
    def test_permission(self):self.assertEqual(m.inspect_node('/tmp/f',stat_reader=s_unreadable),'UNKNOWN_ACCESS')
    def test_all_missing(self):
        doc=m.inventory(stat_reader=s_missing)
        self.assertEqual(doc['result'],'NO-GO')
        self.assertEqual(len(doc['files']),14)
        self.assertIn('ROOT_FILE_R116_F1_GUARD_ABSENT',doc['blockers'])
    def test_all_present_still_no_go(self):
        def fs(p):return s_dir(p) if p in m.ROOT_DIRS.values() else s_file(p)
        doc=m.inventory(stat_reader=fs)
        self.assertEqual(doc['result'],'NO-GO')
        self.assertIn('ROOT_STAGE_CONTENTS_NOT_VERIFIED_BY_METADATA',doc['blockers'])
        self.assertFalse(doc['physical_authority_verified'])
    def test_unknown_is_not_absent(self):
        doc=m.inventory(stat_reader=s_unreadable)
        self.assertIn('ROOT_DIR_F1_STAGE_UNKNOWN_ACCESS',doc['blockers'])
        self.assertNotIn('ROOT_DIR_F1_STAGE_ABSENT',doc['blockers'])
    def test_never_reports_true_a6(self):self.assertEqual(m.inventory(stat_reader=s_file)['a6'],'ND')
    def test_never_reports_p8_go(self):self.assertEqual(m.inventory(stat_reader=s_file)['p8'],'NO-GO')
    def test_no_commands_invoked(self):self.assertEqual(m.inventory(stat_reader=s_file)['root_commands_invoked'],0)
    def test_pin_count(self):self.assertEqual(m.check_source_lock(repo=REPO,source_lock=LOCK),31)
    def test_pin_mutation(self):
        fake=copy.deepcopy(LOCK);fake['files']['root-pilot.py']='0'*64
        with self.assertRaisesRegex(m.Stop,'SOURCE_HASH_MISMATCH'):m.check_source_lock(repo=REPO,source_lock=fake)
    def test_pin_extra(self):
        fake=copy.deepcopy(LOCK);fake['files']['runtime/ardrec/evidence/extra.py']='0'*64
        with self.assertRaisesRegex(m.Stop,'ROOT_LOCK_FILE_COUNT'):m.check_source_lock(repo=REPO,source_lock=fake)
    def test_pin_catalog(self):
        fake=copy.deepcopy(LOCK);fake['catalog_sha256']='0'*64
        with self.assertRaisesRegex(m.Stop,'CATALOG_LOCK_INVALID'):m.check_source_lock(repo=REPO,source_lock=fake)
    def test_pin_no_p8(self):
        fake=copy.deepcopy(LOCK);fake['p8']='GO'
        with self.assertRaisesRegex(m.Stop,'ROOT_LOCK_SCHEMA_INVALID'):m.check_source_lock(repo=REPO,source_lock=fake)
    def test_pin_escape(self):
        fake=copy.deepcopy(LOCK);old=next(k for k in fake['files'] if k!='root-pilot.py')
        fake['files']['runtime/ardrec/coordination/../escape.py']=fake['files'].pop(old)
        with self.assertRaisesRegex(m.Stop,'SOURCE_LOCK_PATH_INVALID'):m.check_source_lock(repo=REPO,source_lock=fake)
    def test_report(self):
        doc=m.report(repo=REPO,stat_reader=s_missing)
        self.assertEqual(doc['source_pins_verified'],31)
        self.assertFalse(doc['signature_verified_by_this_module'])
    def test_canonical(self):self.assertEqual(m.canonical({'b':2,'a':1}),b'{"a":1,"b":2}\n')
    def test_receipt_sha(self):self.assertEqual(len(m.sha(m.canonical(m.inventory(stat_reader=s_missing)))),64)
    def test_lock_sha(self):self.assertEqual(len(m.report(repo=REPO,stat_reader=s_missing)['source_lock_sha256']),64)
    def test_root_simulation_strict(self):
        doc=m.inventory(stat_reader=s_file)
        self.assertFalse(doc['root_stage_performed'])
        self.assertFalse(doc['watchdog_armed'])
        self.assertFalse(doc['physical_pilot_performed'])
    def test_denied_structure(self):
        doc=m.inventory(stat_reader=s_missing)
        self.assertEqual(doc['vm_starts'],0)
        self.assertEqual(doc['network_connections'],0)
if __name__=='__main__':unittest.main()
